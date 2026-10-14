package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The property the spike proved and the product has to keep.
func TestAcquisitionIsSingleFlight(t *testing.T) {
	var calls atomic.Int64
	a := &Acquirer{
		Material: func(string) (Material, error) { return Material{FieldToken: "long-lived"}, nil },
		Exchange: func(ctx context.Context, s string, m Material) (string, time.Time, error) {
			calls.Add(1)
			time.Sleep(120 * time.Millisecond) // make a race obvious
			return "short-lived-token", time.Now().Add(time.Hour), nil
		},
	}

	var wg sync.WaitGroup
	got := make([]string, 20)
	errs := make([]error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = a.Token(context.Background(), "svc")
		}(i)
	}
	wg.Wait()

	for i := range got {
		if errs[i] != nil {
			t.Fatalf("caller %d failed: %v", i, errs[i])
		}
		if got[i] != "short-lived-token" {
			t.Fatalf("caller %d got %q", i, got[i])
		}
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("the provider was asked %d times, want exactly 1", n)
	}
}

func TestCachedTokenIsReusedUntilNearExpiry(t *testing.T) {
	var calls atomic.Int64
	a := &Acquirer{
		Early:    10 * time.Millisecond,
		Material: func(string) (Material, error) { return Material{}, nil },
		Exchange: func(ctx context.Context, s string, m Material) (string, time.Time, error) {
			calls.Add(1)
			return fmt.Sprintf("token-%d", calls.Load()), time.Now().Add(60 * time.Millisecond), nil
		},
	}
	first, _ := a.Token(context.Background(), "svc")
	second, _ := a.Token(context.Background(), "svc")
	if first != second {
		t.Fatalf("a fresh token was not reused: %q then %q", first, second)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
	// Past the early window, it must exchange again — once.
	time.Sleep(70 * time.Millisecond)
	third, _ := a.Token(context.Background(), "svc")
	if third == first {
		t.Fatal("an expired token was reused")
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2", calls.Load())
	}
}

// A failure must not be cached, or one bad moment poisons the cache's lifetime.
func TestFailedExchangeIsNotCached(t *testing.T) {
	var calls atomic.Int64
	a := &Acquirer{
		Material: func(string) (Material, error) { return Material{}, nil },
		Exchange: func(ctx context.Context, s string, m Material) (string, time.Time, error) {
			if calls.Add(1) == 1 {
				return "", time.Time{}, fmt.Errorf("provider was down")
			}
			return "token-after-retry", time.Now().Add(time.Hour), nil
		},
	}
	if _, err := a.Token(context.Background(), "svc"); err == nil {
		t.Fatal("the first call should have failed")
	}
	tok, err := a.Token(context.Background(), "svc")
	if err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	if tok != "token-after-retry" {
		t.Fatalf("token = %q, want the retried value", tok)
	}
}

func TestInvalidateForcesAFreshExchange(t *testing.T) {
	var calls atomic.Int64
	a := &Acquirer{
		Material: func(string) (Material, error) { return Material{}, nil },
		Exchange: func(ctx context.Context, s string, m Material) (string, time.Time, error) {
			calls.Add(1)
			return fmt.Sprintf("t%d", calls.Load()), time.Now().Add(time.Hour), nil
		},
	}
	a.Token(context.Background(), "svc")
	a.Invalidate("svc")
	if _, err := a.Token(context.Background(), "svc"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want 2 after Invalidate", calls.Load())
	}
}

// The GitHub App shape, against a provider that checks what it was sent.
func TestGitHubAppExchangeSendsAJWTAndNotTheKey(t *testing.T) {
	keyPEM, _ := testKeyPEM(t, false)
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		if !strings.HasSuffix(r.URL.Path, "/app/installations/987/access_tokens") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_installation_token",
			"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
		})
	}))
	defer srv.Close()

	m := Material{FieldAppID: "123456", FieldPrivateKey: keyPEM, FieldInstallationID: "987"}
	ex := ExchangeGitHubApp(srv.URL, srv.Client())
	tok, exp, err := ex(context.Background(), "github-app", m)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "ghs_installation_token" {
		t.Fatalf("token = %q", tok)
	}
	if time.Until(exp) < 30*time.Minute {
		t.Errorf("expiry %v is sooner than expected", exp)
	}
	// What went to the provider must be a JWT, never the key.
	if !strings.HasPrefix(sawAuth, "Bearer ") || strings.Count(sawAuth, ".") != 2 {
		t.Fatalf("Authorization sent was %q, want a Bearer JWT", sawAuth)
	}
	if strings.Contains(sawAuth, "PRIVATE KEY") {
		t.Fatal("the private key was sent to the provider")
	}
}

func TestGitHubAppExchangeRefusesIncompleteMaterial(t *testing.T) {
	ex := ExchangeGitHubApp("https://example.invalid", http.DefaultClient)
	_, _, err := ex(context.Background(), "github-app", Material{FieldAppID: "1"})
	if err == nil {
		t.Fatal("the exchange proceeded with incomplete material")
	}
	for _, want := range []string{FieldPrivateKey, FieldInstallationID} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name the missing %q", err, want)
		}
	}
}

func TestGitHubAppExchangeErrorDoesNotLeakTheKey(t *testing.T) {
	keyPEM, _ := testKeyPEM(t, false)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()
	ex := ExchangeGitHubApp(srv.URL, srv.Client())
	_, _, err := ex(context.Background(), "github-app",
		Material{FieldAppID: "1", FieldPrivateKey: keyPEM, FieldInstallationID: "9"})
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "MII") {
		t.Fatalf("the error leaked key material: %v", err)
	}
}

// The failure that surfaces hours later: a provider rotates the refresh token,
// the rotation is not written back, and the next refresh is refused.
func TestRotatedRefreshTokenIsPersistedBeforeTheAccessTokenIsReturned(t *testing.T) {
	stored := Material{FieldClientID: "cid", FieldRefreshToken: "r1"}
	var persisted []string

	ex := ExchangeRefresh(
		func(_ context.Context, _ string, m Material) (string, string, time.Time, error) {
			// Behave like a rotating provider: r1 -> r2.
			if m[FieldRefreshToken] != "r1" {
				return "", "", time.Time{}, fmt.Errorf("the provider refused a stale refresh token")
			}
			return "access-1", "r2", time.Now().Add(2 * time.Hour), nil
		},
		func(service string, m Material) error {
			persisted = append(persisted, m[FieldRefreshToken])
			stored = m
			return nil
		},
	)

	access, expires, err := ex(context.Background(), "x", stored)
	if err != nil {
		t.Fatal(err)
	}
	if access != "access-1" {
		t.Errorf("access = %q", access)
	}
	if expires.IsZero() {
		t.Error("no expiry, so the token would be cached forever")
	}
	if len(persisted) != 1 || persisted[0] != "r2" {
		t.Fatalf("persisted %v, want the rotated token written back exactly once", persisted)
	}
	if stored[FieldRefreshToken] != "r2" {
		t.Errorf("the store still holds %q", stored[FieldRefreshToken])
	}
	// The client id must survive the rotation — a Material that loses it cannot
	// refresh again.
	if stored[FieldClientID] != "cid" {
		t.Error("the rotation dropped the client id")
	}
}

// A rotation with nowhere to go is an error now rather than a lockout later.

func TestRotationWithNoPlaceToStoreFailsNow(t *testing.T) {
	ex := ExchangeRefresh(
		func(_ context.Context, _ string, m Material) (string, string, time.Time, error) {
			return "access", "rotated", time.Now().Add(time.Hour), nil
		}, nil)
	_, _, err := ex(context.Background(), "x", Material{FieldClientID: "c", FieldRefreshToken: "old"})
	if err == nil {
		t.Fatal("a rotation with nowhere to store it was accepted")
	}
	if !strings.Contains(err.Error(), "next refresh would fail") {
		t.Errorf("err = %v, want it to say what breaks", err)
	}
}

// A failed write is reported, because the access token in hand still works and
// the breakage is entirely in the future.
func TestFailedPersistenceSaysToReconnect(t *testing.T) {
	ex := ExchangeRefresh(
		func(_ context.Context, _ string, m Material) (string, string, time.Time, error) {
			return "access", "rotated", time.Now().Add(time.Hour), nil
		},
		func(string, Material) error { return fmt.Errorf("disk full") })
	_, _, err := ex(context.Background(), "x", Material{FieldClientID: "c", FieldRefreshToken: "old"})
	if err == nil {
		t.Fatal("a failed write was ignored")
	}
	if !strings.Contains(err.Error(), "reconnect") {
		t.Errorf("err = %v, want it to say what the operator should do", err)
	}
}

// A provider that does not rotate must not cause a pointless write on every
// single refresh.
func TestNonRotatingProviderWritesNothing(t *testing.T) {
	writes := 0
	ex := ExchangeRefresh(
		func(_ context.Context, _ string, m Material) (string, string, time.Time, error) {
			return "access", m[FieldRefreshToken], time.Now().Add(time.Hour), nil
		},
		func(string, Material) error { writes++; return nil })
	if _, _, err := ex(context.Background(), "x", Material{FieldClientID: "c", FieldRefreshToken: "same"}); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Errorf("wrote %d times for a provider that did not rotate", writes)
	}
}
