package credential

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func cacheStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir(), "cache passphrase")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestACachedTokenIsReusedUntilItNearsExpiry(t *testing.T) {
	s := cacheStore(t)
	if err := s.CacheToken("x", "access-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _, ok := s.CachedToken("x", time.Minute)
	if !ok || got != "access-1" {
		t.Fatalf("CachedToken = %q %v", got, ok)
	}
	// One expiring inside the early window must not be handed out: a call must
	// never go out with a token that expires mid-flight.
	if err := s.CacheToken("x", "access-2", time.Now().Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.CachedToken("x", time.Minute); ok {
		t.Error("a token expiring within the early window was handed out")
	}
}

// A cached access token is a working credential until it expires. Storing it in
// the clear would undo the point of sealing the thing that minted it.
func TestTheCachedTokenIsSealedAndOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir, "cache passphrase")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "access-token-that-must-not-be-readable"
	if err := s.CacheToken("x", secret, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "cache", "x.tok")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("the cached token is on disk in the clear")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", fi.Mode().Perm())
	}
	// And the directory itself.
	di, _ := os.Stat(filepath.Join(dir, "cache"))
	if di.Mode().Perm() != 0o700 {
		t.Errorf("cache dir mode = %o, want 700", di.Mode().Perm())
	}
}

// A cached token must not be substitutable for the long-lived credential it
// was minted from.
func TestACachedTokenCannotBeOpenedAsACredential(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir, "cache passphrase")
	s.CacheToken("github", "access", time.Now().Add(time.Hour))

	raw, err := os.ReadFile(filepath.Join(dir, "cache", "github.tok"))
	if err != nil {
		t.Fatal(err)
	}
	// Move it where the credential lives and try to read it as one.
	if err := os.WriteFile(filepath.Join(dir, "github.cred"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Material("github"); err == nil {
		t.Fatal("a cached token opened as a credential; the two are bound to the same purpose")
	}
}

// The failure this exists to remove.
//
// `stk run` is a fresh process per invocation, so each starts with no token in
// memory and must exchange. Against a provider that rotates its refresh token
// on every exchange — X does — concurrent invocations each exchange the same
// stored token, one wins, and the rest are refused.
func TestConcurrentProcessesExchangeOnlyOnce(t *testing.T) {
	s := cacheStore(t)
	var exchanges atomic.Int64

	// Each "process" gets its own Acquirer, as a separate `stk run` would,
	// sharing only the on-disk cache.
	newProcess := func() *Acquirer {
		return &Acquirer{
			Material: func(string) (Material, error) {
				return Material{FieldClientID: "c", FieldRefreshToken: "r"}, nil
			},
			Shared: s,
			Exchange: func(_ context.Context, _ string, _ Material) (string, time.Time, error) {
				n := exchanges.Add(1)
				time.Sleep(20 * time.Millisecond) // a token endpoint round trip
				return fmt.Sprintf("access-%d", n), time.Now().Add(time.Hour), nil
			},
		}
	}

	var wg sync.WaitGroup
	tokens := make([]string, 6)
	errs := make([]error, 6)
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = newProcess().Token(context.Background(), "x")
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("process %d failed: %v", i, err)
		}
	}
	if n := exchanges.Load(); n != 1 {
		t.Fatalf("%d exchanges for 6 concurrent processes; against a rotating provider all but one would be refused", n)
	}
	// And they all got the same token, which is the one that was stored.
	for i, tok := range tokens {
		if tok != tokens[0] {
			t.Errorf("process %d got %q, process 0 got %q", i, tok, tokens[0])
		}
	}
}

// A later, entirely separate process must reuse the cache rather than exchange
// from cold — which is the per-invocation exchange that started all this.
func TestAFreshProcessReusesTheCache(t *testing.T) {
	s := cacheStore(t)
	var exchanges atomic.Int64
	mk := func() *Acquirer {
		return &Acquirer{
			Material: func(string) (Material, error) { return Material{FieldClientID: "c", FieldRefreshToken: "r"}, nil },
			Shared:   s,
			Exchange: func(_ context.Context, _ string, _ Material) (string, time.Time, error) {
				exchanges.Add(1)
				return "access", time.Now().Add(time.Hour), nil
			},
		}
	}
	for i := 0; i < 5; i++ {
		if _, err := mk().Token(context.Background(), "x"); err != nil {
			t.Fatal(err)
		}
	}
	if n := exchanges.Load(); n != 1 {
		t.Fatalf("%d exchanges across 5 sequential processes, want 1", n)
	}
}

// A lock whose holder died must not block every other process forever.
func TestAnUnownedLegacyRefreshLockCanMigrate(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir, "p")
	os.MkdirAll(filepath.Join(dir, "cache"), 0o700)
	p := filepath.Join(dir, "cache", "x.lock")
	os.WriteFile(p, []byte("2147483647"), 0o600)
	old := time.Now().Add(-time.Hour)
	os.Chtimes(p, old, old)

	release, ok := s.LockRefresh("x", time.Second)
	if !ok {
		t.Fatal("a stale lock was never taken over; every later process would block")
	}
	release()
}

// A live lock is respected, and the waiter gives up rather than hanging.
func TestALiveLockIsRespectedButNotForever(t *testing.T) {
	s := cacheStore(t)
	release, ok := s.LockRefresh("x", time.Second)
	if !ok {
		t.Fatal("could not take the lock")
	}
	defer release()

	start := time.Now()
	_, got := s.LockRefresh("x", 200*time.Millisecond)
	if got {
		t.Error("a second process took a lock that was held")
	}
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Errorf("gave up after %v, before the wait elapsed", d)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("waited %v; a wedged peer must cost a delay, not an outage", d)
	}
}

func TestAnOldTimestampDoesNotProveTheRefreshOwnerIsDead(t *testing.T) {
	s := cacheStore(t)
	release, ok := s.LockRefresh("x", time.Second)
	if !ok {
		t.Fatal("first owner could not acquire")
	}
	defer release()
	p := s.lockPath("x")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	otherRelease, second := s.LockRefresh("x", 100*time.Millisecond)
	if second {
		otherRelease()
		t.Fatal("timestamp-based takeover stole a live refresh owner")
	}
}

func TestForgettingCachedTokensCannotUnlinkALiveRefreshLock(t *testing.T) {
	s := cacheStore(t)
	release, ok := s.LockRefresh("x", time.Second)
	if !ok {
		t.Fatal("first owner could not acquire")
	}
	defer release()
	if err := s.ForgetCachedTokens("x"); err != nil {
		t.Fatal(err)
	}
	other, ok := s.LockRefresh("x", 100*time.Millisecond)
	if ok {
		other()
		t.Fatal("cache invalidation detached the live refresh lock inode")
	}
}
