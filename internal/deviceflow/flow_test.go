package deviceflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	theDeviceCode = "dev-code-this-is-what-a-poll-redeems"
	theToken      = "gho_the_real_token_from_the_provider"
)

// provider behaves like a real one: it issues codes and answers polls with a
// script, so each RFC 8628 case can be exercised deliberately.
type provider struct {
	polls    atomic.Int64
	script   []string // the error code to return per poll; "" means issue the token
	srv      *httptest.Server
	seen     []string
	interval int
}

func newProvider(t *testing.T, script []string, interval int) *provider {
	t.Helper()
	p := &provider{script: script, interval: interval}
	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"device_code":      theDeviceCode,
			"user_code":        "WDJB-MJHT",
			"verification_uri": "https://example.test/device",
			"interval":         p.interval,
			"expires_in":       900,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		p.seen = append(p.seen, r.Form.Get("device_code"))
		n := int(p.polls.Add(1)) - 1
		code := ""
		if n < len(p.script) {
			code = p.script[n]
		}
		if code != "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": code})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": theToken, "token_type": "bearer", "scope": "repo",
		})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *provider) cfg() Config {
	return Config{
		AuthorizationURL: p.srv.URL + "/device",
		TokenURL:         p.srv.URL + "/token",
		ClientID:         "client-id",
		Scopes:           []string{"repo"},
		Client:           p.srv.Client(),
	}
}

func TestStartReturnsTheCodeAndWhereToUseIt(t *testing.T) {
	p := newProvider(t, nil, 1)
	auth, err := Start(context.Background(), p.cfg())
	if err != nil {
		t.Fatal(err)
	}
	if auth.UserCode != "WDJB-MJHT" {
		t.Errorf("UserCode = %q", auth.UserCode)
	}
	if auth.VerificationURI == "" {
		t.Error("no verification URI, so nobody knows where to go")
	}
	if auth.Interval != time.Second {
		t.Errorf("Interval = %v, want the provider's 1s", auth.Interval)
	}
	if auth.ExpiresAt.Before(time.Now()) {
		t.Error("the authorization is already expired")
	}
}

// RFC 8628 §3.2: five seconds when the provider does not say.
func TestMissingIntervalDefaultsToFiveSeconds(t *testing.T) {
	p := newProvider(t, nil, 0)
	auth, err := Start(context.Background(), p.cfg())
	if err != nil {
		t.Fatal(err)
	}
	if auth.Interval != 5*time.Second {
		t.Fatalf("Interval = %v, want the spec's 5s default", auth.Interval)
	}
}

// The normal case: the person has not finished yet.
func TestAuthorizationPendingIsNotAnError(t *testing.T) {
	p := newProvider(t, []string{"authorization_pending", "authorization_pending", ""}, 1)
	auth, _ := Start(context.Background(), p.cfg())
	auth.Interval = 10 * time.Millisecond

	tok, err := Poll(context.Background(), p.cfg(), auth)
	if err != nil {
		t.Fatalf("pending polls ended the flow: %v", err)
	}
	if tok.AccessToken != theToken {
		t.Fatalf("AccessToken = %q", tok.AccessToken)
	}
	if p.polls.Load() != 3 {
		t.Errorf("polls = %d, want 3", p.polls.Load())
	}
}

// RFC 8628 §3.5. Retrying at the same rate is how a client gets rate-limited at
// the exact moment a person is trying to help it.
func TestSlowDownWidensTheInterval(t *testing.T) {
	p := newProvider(t, []string{"slow_down", ""}, 1)
	auth, _ := Start(context.Background(), p.cfg())
	auth.Interval = 10 * time.Millisecond

	start := time.Now()
	if _, err := Poll(context.Background(), p.cfg(), auth); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// First poll after 10ms, then the interval must have grown by five seconds.
	if elapsed < 5*time.Second {
		t.Fatalf("the flow took %v; slow_down must widen the interval by five seconds", elapsed)
	}
}

func TestDenialAndExpiryAreReportedAsThemselves(t *testing.T) {
	for _, tc := range []struct {
		code string
		want Reason
	}{
		{"access_denied", Denied},
		{"expired_token", Expired},
		{"something_unexpected", Failed},
	} {
		t.Run(tc.code, func(t *testing.T) {
			p := newProvider(t, []string{tc.code}, 1)
			auth, _ := Start(context.Background(), p.cfg())
			auth.Interval = 5 * time.Millisecond
			_, err := Poll(context.Background(), p.cfg(), auth)
			if err == nil {
				t.Fatal("want an error")
			}
			fe, ok := err.(*Error)
			if !ok {
				t.Fatalf("error is %T, want a *Error a caller can act on", err)
			}
			if fe.Reason != tc.want {
				t.Fatalf("Reason = %q, want %q", fe.Reason, tc.want)
			}
		})
	}
}

// The device code is the value a poll redeems, so it must not reach an error
// message, a log, or anything an operator might paste somewhere.
func TestNoErrorContainsTheDeviceCode(t *testing.T) {
	for _, code := range []string{"access_denied", "expired_token", "nonsense"} {
		p := newProvider(t, []string{code}, 1)
		auth, _ := Start(context.Background(), p.cfg())
		auth.Interval = 5 * time.Millisecond
		_, err := Poll(context.Background(), p.cfg(), auth)
		if err == nil {
			t.Fatal("want an error")
		}
		if strings.Contains(err.Error(), theDeviceCode) {
			t.Fatalf("the error leaked the device code: %v", err)
		}
	}
	// And it was actually sent, so the test is not passing vacuously.
	p := newProvider(t, []string{""}, 1)
	auth, _ := Start(context.Background(), p.cfg())
	auth.Interval = 5 * time.Millisecond
	Poll(context.Background(), p.cfg(), auth)
	if len(p.seen) == 0 || p.seen[0] != theDeviceCode {
		t.Fatalf("the device code was not sent: %v", p.seen)
	}
}

func TestExpiredAuthorizationStopsWithoutPolling(t *testing.T) {
	p := newProvider(t, []string{""}, 1)
	auth, _ := Start(context.Background(), p.cfg())
	auth.Interval = 5 * time.Millisecond
	auth.ExpiresAt = time.Now().Add(-time.Second)

	_, err := Poll(context.Background(), p.cfg(), auth)
	fe, ok := err.(*Error)
	if !ok || fe.Reason != Expired {
		t.Fatalf("err = %v, want an expiry", err)
	}
	if p.polls.Load() != 0 {
		t.Errorf("polled %d times after expiry; it should not have asked", p.polls.Load())
	}
}

// Ctrl-C must end the flow rather than leaving it running.
func TestContextCancelsThePoll(t *testing.T) {
	p := newProvider(t, []string{"authorization_pending", "authorization_pending", "authorization_pending", ""}, 1)
	auth, _ := Start(context.Background(), p.cfg())
	auth.Interval = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if _, err := Poll(ctx, p.cfg(), auth); err == nil {
		t.Fatal("Poll() ignored a cancelled context")
	}
}

func TestStartReportsAProviderThatRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	cfg := Config{AuthorizationURL: srv.URL, TokenURL: srv.URL, ClientID: "x", Client: srv.Client()}
	if _, err := Start(context.Background(), cfg); err == nil {
		t.Fatal("Start() ignored a refusal")
	}
}
