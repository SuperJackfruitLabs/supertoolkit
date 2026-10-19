package credential

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Independent clients share the production disk cache and refresh lock. Every
// client deliberately starts with the same stale material snapshot. The shared
// cache must make the others reuse the winner's access token, instead of asking
// the rotating provider again. This is same-process concurrency through separate
// store handles, not a claim of a real multi-process provider rehearsal.
func TestConcurrentClientsSharingCacheRefreshRotatingTokenOnce(t *testing.T) {
	shared := cacheStore(t)
	var mu sync.Mutex
	stored := Material{FieldClientID: "cid", FieldRefreshToken: "r0"}
	var issued atomic.Int64
	live := map[string]bool{"r0": true} // which refresh tokens the provider still accepts

	// provider behaves like X: rotate on every use, invalidate the old one.
	provider := func(_ context.Context, _ string, m Material) (string, string, time.Time, error) {
		mu.Lock()
		defer mu.Unlock()
		old := m[FieldRefreshToken]
		if !live[old] {
			return "", "", time.Time{}, fmt.Errorf("the provider refused the grant — invalid_grant")
		}
		delete(live, old)
		next := fmt.Sprintf("r%d", issued.Add(1))
		live[next] = true
		return "access-" + next, next, time.Now().Add(2 * time.Hour), nil
	}
	persist := func(_ string, m Material) error {
		mu.Lock()
		defer mu.Unlock()
		stored = m
		return nil
	}

	// Snapshot the original material before the barrier. This deliberately makes
	// the shared cache necessary, even if a caller retained an early snapshot.
	snapshot := func() Material {
		mu.Lock()
		defer mu.Unlock()
		c := Material{}
		for k, v := range stored {
			c[k] = v
		}
		return c
	}
	// Two phases. Every process reads the store, then they all wait for each
	// other, and only then does any of them refresh. That is what two `stk run`
	// invocations starting at the same moment actually look like, and a single
	// barrier before the whole operation is not enough to produce it — the
	// first goroutine simply finishes before the second is scheduled.
	var readAll sync.WaitGroup
	readAll.Add(4)
	run := func() error {
		mine := snapshot()
		readAll.Done()
		readAll.Wait()
		// Separate store handles share only on-disk credentials/cache/lock, as production
		// constructs them. The fallback alone does not serialize four token rotations.
		storeHandle := *shared
		acq := &Acquirer{
			Shared:   &storeHandle,
			Material: func(string) (Material, error) { return mine, nil },
			Exchange: ExchangeRefresh(provider, persist, func(string) (Material, error) {
				return snapshot(), nil
			}),
		}
		_, err := acq.Token(context.Background(), "x")
		return err
	}

	// A barrier, so every process has read the stored token before any of them
	// writes a new one. Without it the fake provider's own lock serialises the
	// callers and each reads the already-rotated value — the instrument
	// quietly preventing the race it was built to find.
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = run()
		}(i)
	}
	close(start)
	wg.Wait()

	failed := 0
	for _, err := range errs {
		if err != nil {
			failed++
			t.Logf("  one process was refused: %v", err)
		}
	}
	t.Logf("  %d of 4 concurrent refreshes failed", failed)
	if failed > 0 {
		t.Errorf("%d of 4 clients failed despite the production shared cache", failed)
	}
	if issued.Load() != 1 {
		t.Fatal("concurrent clients rotated more than once instead of reusing the shared access token")
	}

	// The question that matters is not whether some calls failed — it is
	// whether the store is left holding a token the provider still accepts.
	// If not, every future call fails and the operator must reconnect.
	mu.Lock()
	final := stored[FieldRefreshToken]
	usable := live[final]
	mu.Unlock()
	if !usable {
		t.Fatalf("the store holds %q, which the provider no longer accepts — the connection is dead and only reconnecting fixes it", final)
	}
}

func TestRefreshFallbackRetriesOnlyAChangedStoredTokenOnce(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			calls, reads, writes := 0, 0, 0
			exchange := ExchangeRefresh(func(_ context.Context, _ string, m Material) (string, string, time.Time, error) {
				calls++
				if m[FieldRefreshToken] == "old" {
					return "", "", time.Time{}, fmt.Errorf("invalid_grant")
				}
				return "fixture-access", "rotated", time.Now().Add(time.Hour), nil
			}, func(_ string, m Material) error {
				writes++
				if m[FieldRefreshToken] != "rotated" {
					t.Error("wrong rotated value persisted")
				}
				return nil
			}, func(string) (Material, error) {
				reads++
				value := "old"
				if changed {
					value = "fresh"
				}
				return Material{FieldClientID: "fixture", FieldRefreshToken: value}, nil
			})
			_, _, err := exchange(context.Background(), "fixture", Material{FieldClientID: "fixture", FieldRefreshToken: "old"})
			if changed {
				if err != nil || calls != 2 || reads != 1 || writes != 1 {
					t.Fatal("known changed token did not get exactly one bounded fallback")
				}
			} else if err == nil || calls != 1 || reads != 1 || writes != 0 {
				t.Fatal("unchanged token refusal was retried or persisted")
			}
		})
	}
}
