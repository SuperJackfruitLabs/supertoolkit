package managedmcp

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func request() Request {
	r := Request{Version: 1, RootDigest: strings.Repeat("a", 64), InvocationID: "fixture-call-1", ProfileDigest: strings.Repeat("b", 64), Service: "fixture", Action: "update", Args: map[string]string{"text": "reviewed fixture"}, Approval: true, ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli()}
	return r
}
func open(t *testing.T, dir string) *Ledger {
	t.Helper()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return l
}
func prepare(t *testing.T, l *Ledger, r Request) Receipt {
	t.Helper()
	v, err := l.Prepare(r)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestManagedRecordsAreInvisibleToLegacyApprovalPathsAndImmutable(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	r := request()
	first := prepare(t, l, r)
	if first.State != AwaitingDecision {
		t.Fatal("broker approval gate was skipped")
	}
	if _, err := os.Stat(filepath.Join(dir, "approvals", first.ID+".req")); !os.IsNotExist(err) {
		t.Fatal("legacy decider could interpret managed metadata as an unbound request")
	}
	if same := prepare(t, open(t, dir), r); same != first {
		t.Fatal("reopen replaced the original invocation")
	}
	r.Args = map[string]string{"text": "changed"}
	if _, err := l.Prepare(r); err == nil {
		t.Fatal("same invocation changed its approved bytes")
	}
}

func TestOnlyTheOwnedExecutorPerformsAfterHumanDecisionAndDuplicatesNeverRegrant(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	r := request()
	v := prepare(t, l, r)
	if _, err := l.Decide(v.ID, "human-decision-1", true); err != nil {
		t.Fatal(err)
	}
	var grants, effects atomic.Int32
	authorize := func(context.Context, Request) error { grants.Add(1); return nil }
	execute := func(context.Context, Request) (string, error) {
		effects.Add(1)
		return `{"protocol_result":"returned"}`, nil
	}
	first, err := l.Execute(context.Background(), v.ID, v.RequestDigest, authorize, execute)
	if err != nil {
		t.Fatal(err)
	}
	if first.State != Returned || effects.Load() != 1 || grants.Load() != 1 {
		t.Fatal("one decision did not produce exactly one owned invocation")
	}
	saved, err := open(t, dir).Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { t.Fatal("saved receipt tested a fresh grant"); return nil }, execute)
	if err != nil || saved != first || effects.Load() != 1 {
		t.Fatal("recovery duplicated a returned invocation")
	}
}

func TestConcurrentIndependentLedgerInstancesDispatchOnce(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	r := request()
	r.Approval = false
	v := prepare(t, l, r)
	var grants, effects atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := open(t, dir).Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { grants.Add(1); return nil }, func(context.Context, Request) (string, error) { effects.Add(1); return `{}`, nil })
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if grants.Load() != 1 || effects.Load() != 1 {
		t.Fatal("independent processes could claim the same invocation")
	}
}

func TestRevocationWhileAuthorizationIsPendingCannotDispatch(t *testing.T) {
	l := open(t, t.TempDir())
	r := request()
	r.Approval = false
	v := prepare(t, l, r)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan Receipt, 1)
	go func() {
		out, err := l.Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { close(entered); <-release; return nil }, func(context.Context, Request) (string, error) {
			t.Error("revoked owner performed an effect")
			return `{}`, nil
		})
		if err != nil {
			t.Error(err)
		}
		done <- out
	}()
	<-entered
	if err := l.RevokeRoot(r.RootDigest); err != nil {
		t.Fatal(err)
	}
	close(release)
	if (<-done).State != Cancelled {
		t.Fatal("revocation during the grant check was lost")
	}
}

func TestInterruptedOrLostResponseIsUnknownAndCannotReplay(t *testing.T) {
	dir := t.TempDir()
	l := open(t, dir)
	r := request()
	r.Approval = false
	v := prepare(t, l, r)
	var effects atomic.Int32
	first, err := l.Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { return nil }, func(context.Context, Request) (string, error) {
		effects.Add(1)
		return "", errors.New("fixture remote accepted but response lost")
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.State != OutcomeUnknown {
		t.Fatal("a lost effect response looked successful")
	}
	same, err := open(t, dir).Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { t.Error("unknown operation requested new authority"); return nil }, func(context.Context, Request) (string, error) { effects.Add(1); return `{}`, nil })
	if err != nil || same != first || effects.Load() != 1 {
		t.Fatal("uncertain mutation was replayed")
	}
}

func TestExpiredDeniedForeignOrCancelledInvocationNeverReachesExecutor(t *testing.T) {
	for _, mode := range []string{"expired", "denied", "foreign-digest", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			l := open(t, t.TempDir())
			r := request()
			v := prepare(t, l, r)
			switch mode {
			case "expired":
				l.now = func() time.Time { return time.UnixMilli(r.ExpiresAtMS).Add(time.Second) }
			case "denied":
				if _, err := l.Decide(v.ID, "decision", false); err != nil {
					t.Fatal(err)
				}
			case "foreign-digest":
				v.RequestDigest = strings.Repeat("f", 64)
			case "cancelled":
				if _, err := l.Cancel(v.ID, v.RequestDigest); err != nil {
					t.Fatal(err)
				}
			}
			_, _ = l.Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { t.Error("invalid invocation obtained a grant"); return nil }, func(context.Context, Request) (string, error) {
				t.Error("invalid invocation performed")
				return `{}`, nil
			})
		})
	}
}

func TestRevokingOneRootDoesNotCancelAnotherRootsOwnedEffect(t *testing.T) {
	l := open(t, t.TempDir())
	r := request()
	r.RootDigest = strings.Repeat("c", 64)
	r.Approval = false
	v := prepare(t, l, r)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan Receipt, 1)
	go func() {
		out, err := l.Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { return nil }, func(ctx context.Context, _ Request) (string, error) {
			close(entered)
			<-release
			if ctx.Err() != nil {
				t.Error("foreign root revocation cancelled this effect")
			}
			return `{}`, nil
		})
		if err != nil {
			t.Error(err)
		}
		done <- out
	}()
	<-entered
	if err := l.RevokeRoot(strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	close(release)
	if (<-done).State != Returned {
		t.Fatal("foreign root revocation changed the receipt")
	}
}

func TestCorruptOrLinkedPrivateControlFilesFailClosed(t *testing.T) {
	for _, mode := range []string{"corrupt-revocation", "symlink-record", "public-record"} {
		t.Run(mode, func(t *testing.T) {
			l := open(t, t.TempDir())
			r := request()
			r.Approval = false
			v := prepare(t, l, r)
			switch mode {
			case "corrupt-revocation":
				if err := os.WriteFile(filepath.Join(l.dir, r.RootDigest+".revoked"), []byte(`{}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink-record":
				original := l.path(v.ID)
				target := original + ".target"
				if err := os.Rename(original, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, original); err != nil {
					t.Fatal(err)
				}
			case "public-record":
				if err := os.Chmod(l.path(v.ID), 0644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := l.Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { t.Error("damaged control state obtained authority"); return nil }, func(context.Context, Request) (string, error) {
				t.Error("damaged control state performed an effect")
				return `{}`, nil
			})
			if err == nil {
				t.Fatal("damaged control state was accepted")
			}
		})
	}
}

func TestAnUnknownEffectFencesAnotherInvocationBeforeItObtainsAuthority(t *testing.T) {
	l := open(t, t.TempDir())
	r := request()
	r.Approval = false
	v := prepare(t, l, r)
	_, err := l.Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { return nil }, func(context.Context, Request) (string, error) { return "", errors.New("response lost") })
	if err != nil {
		t.Fatal(err)
	}
	r.InvocationID = "fixture-call-2"
	next := prepare(t, l, r)
	_, err = l.Execute(context.Background(), next.ID, next.RequestDigest, func(context.Context, Request) error { t.Error("unresolved work allowed another grant"); return nil }, func(context.Context, Request) (string, error) {
		t.Error("unresolved work allowed another effect")
		return `{}`, nil
	})
	if err == nil {
		t.Fatal("unknown effect did not fence its root")
	}
}
