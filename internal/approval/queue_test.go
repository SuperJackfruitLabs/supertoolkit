package approval

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSubmittedEffectIsPending(t *testing.T) {
	q := mustOpen(t, time.Minute)
	e := q.Submit("github", "create_issue", "Open an issue on o/r", map[string]string{"owner": "o"})
	if e.State != Pending {
		t.Fatalf("State = %q, want %q", e.State, Pending)
	}
	if len(q.Pending()) != 1 {
		t.Fatalf("Pending() = %d, want 1", len(q.Pending()))
	}
}

// Deciding twice must not produce a second effect.
func TestDecideIsOnceOnly(t *testing.T) {
	q := mustOpen(t, time.Minute)
	e := q.Submit("github", "create_issue", "s", nil)
	if _, err := q.Decide(e.ID, true, "operator"); err != nil {
		t.Fatal(err)
	}
	_, err := q.Decide(e.ID, true, "operator")
	if err == nil {
		t.Fatal("a second Decide() succeeded; the effect could run twice")
	}
	if !strings.Contains(err.Error(), "already") {
		t.Errorf("error = %q, want it to say the effect is already decided", err)
	}
}

func TestAwaitReturnsTheDecision(t *testing.T) {
	q := mustOpen(t, time.Minute)
	e := q.Submit("github", "create_issue", "s", nil)
	go func() {
		time.Sleep(20 * time.Millisecond)
		q.Decide(e.ID, true, "operator")
	}()
	d, err := q.Await(context.Background(), e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed() || d.DecidedBy != "operator" {
		t.Fatalf("Decision = %+v, want approved by operator", d)
	}
}

// Expiry is not approval. This is the fail-closed assertion.
func TestExpiryIsNotApproval(t *testing.T) {
	q := mustOpen(t, 30*time.Millisecond)
	e := q.Submit("github", "delete_repo", "s", nil)
	d, err := q.Await(context.Background(), e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed() {
		t.Fatal("an expired effect reported as allowed")
	}
	if d.State != Expired {
		t.Fatalf("State = %q, want %q", d.State, Expired)
	}
	got, _ := q.Get(e.ID)
	if got.State != Expired {
		t.Fatalf("stored state = %q, want %q", got.State, Expired)
	}
}

func TestRefusalIsNotApproval(t *testing.T) {
	q := mustOpen(t, time.Minute)
	e := q.Submit("github", "create_issue", "s", nil)
	if _, err := q.Decide(e.ID, false, "operator"); err != nil {
		t.Fatal(err)
	}
	d, _ := q.Await(context.Background(), e.ID)
	if d.Allowed() {
		t.Fatal("a refused effect reported as allowed")
	}
}

// An expired effect cannot be rescued by a late approval.
func TestDecideAfterExpiryIsRefused(t *testing.T) {
	q := mustOpen(t, 20*time.Millisecond)
	e := q.Submit("github", "delete_repo", "s", nil)
	time.Sleep(40 * time.Millisecond)
	if _, err := q.Decide(e.ID, true, "operator"); err == nil {
		t.Fatal("approving an expired effect succeeded")
	}
	d, _ := q.Await(context.Background(), e.ID)
	if d.Allowed() {
		t.Fatal("a late approval made an expired effect allowed")
	}
}

func TestAwaitUnknownEffectIsAnError(t *testing.T) {
	q := mustOpen(t, time.Minute)
	if _, err := q.Await(context.Background(), "nope"); err == nil {
		t.Fatal("Await() on an unknown id returned no error")
	}
}

func TestManyWaitersAllSeeTheSameDecision(t *testing.T) {
	q := mustOpen(t, time.Minute)
	e := q.Submit("github", "create_issue", "s", nil)
	results := make(chan Decision, 5)
	for i := 0; i < 5; i++ {
		go func() {
			d, _ := q.Await(context.Background(), e.ID)
			results <- d
		}()
	}
	time.Sleep(20 * time.Millisecond)
	q.Decide(e.ID, true, "operator")
	for i := 0; i < 5; i++ {
		select {
		case d := <-results:
			if !d.Allowed() {
				t.Fatalf("waiter %d saw %+v, want approved", i, d)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("waiter %d never woke", i)
		}
	}
}

func mustOpen(t *testing.T, ttl time.Duration) *Queue {
	t.Helper()
	q, err := Open(t.TempDir(), ttl)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// The hole a walkthrough found: three processes each built their own queue, so
// an approval the agent raised landed somewhere nobody could decide it. Two
// Queue values over one directory stand in for two processes.
func TestTwoProcessesShareOneQueue(t *testing.T) {
	dir := t.TempDir()
	agent, err := Open(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := Open(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	e := agent.Submit("github", "create_issue", "Open an issue.", map[string]string{"title": "t"})
	if e.State != Pending {
		t.Fatalf("state = %s", e.State)
	}

	// The operator's process must see it. This is the assertion that was false.
	pending := operator.Pending()
	if len(pending) != 1 || pending[0].ID != e.ID {
		t.Fatalf("the operator's process sees %d pending effect(s); the agent's request was invisible", len(pending))
	}
	if pending[0].Summary != "Open an issue." {
		t.Errorf("summary = %q", pending[0].Summary)
	}

	// And the operator's decision must reach the agent's process.
	if _, err := operator.Decide(e.ID, true, "operator"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d, err := agent.Await(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed() {
		t.Fatalf("the agent saw %s; the decision did not cross the process boundary", d.State)
	}
	if d.DecidedBy != "operator" {
		t.Errorf("decided by %q", d.DecidedBy)
	}
}

// Two people answering at the same moment in two processes: one wins, the
// other is told. A mutex cannot do this — it only orders one process.
func TestDecideOnceAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	a, _ := Open(dir, time.Minute)
	b, _ := Open(dir, time.Minute)
	e := a.Submit("github", "delete_repo", "Delete a repository.", nil)

	_, errA := a.Decide(e.ID, true, "alice")
	_, errB := b.Decide(e.ID, false, "bob")
	if errA != nil {
		t.Fatalf("the first decision failed: %v", errA)
	}
	if errB == nil {
		t.Fatal("the second decision succeeded; the effect was decided twice")
	}
	if !strings.Contains(errB.Error(), "already") {
		t.Errorf("err = %v, want it to say it was already decided", errB)
	}
	// The outcome is the first decision, not the last.
	got, _ := b.Get(e.ID)
	if got.State != Approved || got.DecidedBy != "alice" {
		t.Errorf("state = %s by %q, want approved by alice", got.State, got.DecidedBy)
	}
}

// An expired effect must not become approvable later. Someone returning to a
// stale browser tab and clicking allow must not cause the effect.
func TestAnExpiredEffectCannotBeApproved(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir, time.Minute)
	e := q.Submit("github", "create_issue", "Open an issue.", nil)
	q.now = func() time.Time { return time.Now().Add(2 * time.Minute) }

	if got, _ := q.Get(e.ID); got.State != Expired {
		t.Fatalf("state = %s, want expired", got.State)
	}
	_, err := q.Decide(e.ID, true, "late")
	if err == nil {
		t.Fatal("an expired effect was approved")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("err = %v, want it to say it expired", err)
	}
	if got, _ := q.Get(e.ID); got.State == Approved {
		t.Fatal("the effect became approved anyway")
	}
}

// An id arrives in a protocol message, so it is input. It must not be able to
// name a file outside the queue.
func TestIDsCannotEscapeTheQueueDirectory(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir, time.Minute)
	for _, bad := range []string{"../../etc/passwd", "..", "a/b", "ZZZZ", "", strings.Repeat("a", 200)} {
		if _, ok := q.Get(bad); ok {
			t.Errorf("Get(%q) resolved to something", bad)
		}
		if _, err := q.Decide(bad, true, "x"); err == nil {
			t.Errorf("Decide(%q) succeeded", bad)
		}
	}
}
