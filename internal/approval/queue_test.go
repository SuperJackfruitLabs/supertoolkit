package approval

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSubmittedEffectIsPending(t *testing.T) {
	q := New(time.Minute)
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
	q := New(time.Minute)
	e := q.Submit("github", "create_issue", "s", nil)
	if err := q.Decide(e.ID, true, "operator"); err != nil {
		t.Fatal(err)
	}
	err := q.Decide(e.ID, true, "operator")
	if err == nil {
		t.Fatal("a second Decide() succeeded; the effect could run twice")
	}
	if !strings.Contains(err.Error(), "already") {
		t.Errorf("error = %q, want it to say the effect is already decided", err)
	}
}

func TestAwaitReturnsTheDecision(t *testing.T) {
	q := New(time.Minute)
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
	q := New(30 * time.Millisecond)
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
	q := New(time.Minute)
	e := q.Submit("github", "create_issue", "s", nil)
	if err := q.Decide(e.ID, false, "operator"); err != nil {
		t.Fatal(err)
	}
	d, _ := q.Await(context.Background(), e.ID)
	if d.Allowed() {
		t.Fatal("a refused effect reported as allowed")
	}
}

// An expired effect cannot be rescued by a late approval.
func TestDecideAfterExpiryIsRefused(t *testing.T) {
	q := New(20 * time.Millisecond)
	e := q.Submit("github", "delete_repo", "s", nil)
	time.Sleep(40 * time.Millisecond)
	if err := q.Decide(e.ID, true, "operator"); err == nil {
		t.Fatal("approving an expired effect succeeded")
	}
	d, _ := q.Await(context.Background(), e.ID)
	if d.Allowed() {
		t.Fatal("a late approval made an expired effect allowed")
	}
}

func TestAwaitUnknownEffectIsAnError(t *testing.T) {
	q := New(time.Minute)
	if _, err := q.Await(context.Background(), "nope"); err == nil {
		t.Fatal("Await() on an unknown id returned no error")
	}
}

func TestManyWaitersAllSeeTheSameDecision(t *testing.T) {
	q := New(time.Minute)
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
