package credential

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Two processes refreshing a rotating token at the same moment.
//
// A provider that rotates invalidates the old refresh token the instant it
// issues a new one. The Acquirer single-flights, but only inside one process —
// and `stk run` is a fresh process per invocation, so two concurrent runs each
// refresh with the same stored token. One wins; the other is refused, and
// whichever writes last decides what the store holds.
func TestConcurrentProcessesRefreshingARotatingToken(t *testing.T) {
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

	// Each "process" gets its own Acquirer, reading the same store.
	// Each process reads the store once, up front, the way a fresh `stk run`
	// does when it starts.
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
		acq := &Acquirer{
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
		t.Errorf("%d of 4 concurrent refreshes failed; a loser must re-read and retry with whatever the winner stored", failed)
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
