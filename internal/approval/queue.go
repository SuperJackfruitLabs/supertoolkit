// Package approval holds effects that need a human before they happen.
//
// An MCP server's stdio is the protocol channel, so it cannot ask a question
// there. An effect at `approval` is submitted here, returns `pending` with an
// id, and performs nothing until someone decides. With nothing to decide
// through, the effect simply does not happen — the queue fails closed.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"time"
)

// State is where an effect has got to.
type State string

const (
	Pending  State = "pending"
	Approved State = "approved"
	Refused  State = "refused"
	Expired  State = "expired"
)

// Effect is one thing waiting on a person.
type Effect struct {
	ID         string
	Service    string
	Capability string
	// Summary is what a human reads before deciding. It must describe the
	// effect, never carry a credential.
	Summary   string
	Args      map[string]string
	Submitted time.Time
	Expires   time.Time

	State     State
	DecidedBy string
	DecidedAt time.Time
}

// Decision is the outcome of waiting.
type Decision struct {
	State     State
	DecidedBy string
}

// Allowed reports whether the effect may proceed. Only an explicit approval
// counts: expiry and refusal both mean no.
func (d Decision) Allowed() bool { return d.State == Approved }

// Queue is the set of effects awaiting a person.
type Queue struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	effects map[string]*Effect
	waiters map[string][]chan Decision
}

// New makes a queue. ttl is how long an undecided effect survives.
func New(ttl time.Duration) *Queue {
	return &Queue{
		ttl: ttl, now: time.Now,
		effects: map[string]*Effect{},
		waiters: map[string][]chan Decision{},
	}
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Submit queues an effect and returns its id.
func (q *Queue) Submit(service, capability, summary string, args map[string]string) *Effect {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	e := &Effect{
		ID: newID(), Service: service, Capability: capability, Summary: summary,
		Args: args, Submitted: now, Expires: now.Add(q.ttl), State: Pending,
	}
	q.effects[e.ID] = e
	return e
}

// Get returns one effect, refreshing its state if it has expired.
func (q *Queue) Get(id string) (*Effect, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.effects[id]
	if !ok {
		return nil, false
	}
	q.expireLocked(e)
	copy := *e
	return &copy, true
}

// List returns every effect, newest first, expiring any that are due.
func (q *Queue) List() []*Effect {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*Effect, 0, len(q.effects))
	for _, e := range q.effects {
		q.expireLocked(e)
		c := *e
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Submitted.After(out[j].Submitted) })
	return out
}

// Pending returns only what is still waiting.
func (q *Queue) Pending() []*Effect {
	var out []*Effect
	for _, e := range q.List() {
		if e.State == Pending {
			out = append(out, e)
		}
	}
	return out
}

// Decide records a human's answer. An effect may be decided exactly once: a
// second decision is an error rather than a second effect.
func (q *Queue) Decide(id string, allow bool, who string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	e, ok := q.effects[id]
	if !ok {
		return fmt.Errorf("no effect %q is waiting", id)
	}
	q.expireLocked(e)
	if e.State != Pending {
		return fmt.Errorf("effect %q is already %s", id, e.State)
	}
	e.State = Refused
	if allow {
		e.State = Approved
	}
	e.DecidedBy = who
	e.DecidedAt = q.now()
	q.notifyLocked(e)
	return nil
}

// Await blocks until the effect is decided, expires, or the context ends.
func (q *Queue) Await(ctx context.Context, id string) (Decision, error) {
	q.mu.Lock()
	e, ok := q.effects[id]
	if !ok {
		q.mu.Unlock()
		return Decision{}, fmt.Errorf("no effect %q is waiting", id)
	}
	q.expireLocked(e)
	if e.State != Pending {
		d := Decision{State: e.State, DecidedBy: e.DecidedBy}
		q.mu.Unlock()
		return d, nil
	}
	ch := make(chan Decision, 1)
	q.waiters[id] = append(q.waiters[id], ch)
	until := e.Expires
	q.mu.Unlock()

	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case d := <-ch:
		return d, nil
	case <-timer.C:
		q.mu.Lock()
		if e, ok := q.effects[id]; ok {
			q.expireLocked(e)
			q.notifyLocked(e)
		}
		q.mu.Unlock()
		// Expiry is not approval.
		return Decision{State: Expired}, nil
	case <-ctx.Done():
		return Decision{State: Pending}, ctx.Err()
	}
}

func (q *Queue) expireLocked(e *Effect) {
	if e.State == Pending && q.now().After(e.Expires) {
		e.State = Expired
	}
}

func (q *Queue) notifyLocked(e *Effect) {
	d := Decision{State: e.State, DecidedBy: e.DecidedBy}
	for _, ch := range q.waiters[e.ID] {
		select {
		case ch <- d:
		default:
		}
	}
	delete(q.waiters, e.ID)
}
