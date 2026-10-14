// Package approval holds effects that need a human before they happen.
//
// An MCP server's stdio is the protocol channel, so it cannot ask a question
// there. An effect at `approval` is submitted here, returns `pending` with an
// id, and performs nothing until someone decides. With nothing to decide
// through, the effect simply does not happen — the queue fails closed.
//
// # Why this is on disk
//
// The queue was in memory until a walkthrough found the hole: `stk mcp`,
// `stk ui` and `stk serve` each built their own, so an approval raised by the
// agent landed somewhere no other process could read. The gate held — nothing
// happened without a decision — but no decision could ever be made, so in the
// configuration `stk mcp install` writes, every write was permanently refused.
//
// The same shape as the audit ledger before it: state owned by one process and
// needed by another. So the queue lives in a directory, every process shares
// it, and decide-once is enforced by the filesystem rather than by a mutex that
// only orders one process's own callers.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	ID         string `json:"id"`
	Service    string `json:"service"`
	Capability string `json:"capability"`
	// Summary is what a human reads before deciding. It must describe the
	// effect, never carry a credential.
	Summary   string            `json:"summary"`
	Args      map[string]string `json:"args,omitempty"`
	Submitted time.Time         `json:"submitted"`
	Expires   time.Time         `json:"expires"`

	State     State     `json:"state"`
	DecidedBy string    `json:"decided_by,omitempty"`
	DecidedAt time.Time `json:"decided_at,omitempty"`

	// Outcome is what happened when the approved effect ran, and Error is why
	// it did not. They are empty while an effect is pending, and empty forever
	// for a refusal.
	//
	// They exist because approving used to record `approved` and do nothing:
	// the decision was written and no code anywhere performed the effect. An
	// operator reading the trail would reasonably believe the thing had
	// happened. A record that says what a person authorised but not what
	// occurred is worse than no record.
	Outcome string `json:"outcome,omitempty"`
	Error   string `json:"error,omitempty"`

	// Performs says the decider is carrying the effect out, so a waiter must
	// report the result rather than act on it. Exactly one party performs.
	Performs bool `json:"performs,omitempty"`
}

// Decision is the outcome of waiting.
type Decision struct {
	State     State
	DecidedBy string
	// Outcome and Err describe what actually happened once approved.
	Outcome string
	Err     string
	// Performed says the decider already carried the effect out, so the waiter
	// must not do it again. Exactly one party performs an approved effect.
	Performed bool
}

// Allowed reports whether the effect may proceed. Only an explicit approval
// counts: expiry and refusal both mean no.
func (d Decision) Allowed() bool { return d.State == Approved }

// pollInterval is how often a waiter checks for a decision made in another
// process. There is no cross-process notification to wait on, and one stat of
// one file is cheap enough that a quarter second costs nothing while making a
// human's click feel immediate.
const pollInterval = 250 * time.Millisecond

// keepDecided is how long a decided effect stays readable, so the UI and
// `stk approvals` can show what was just answered before it is tidied away.
const keepDecided = 24 * time.Hour

// outcomeGrace is how long a waiter gives the decider to record what happened
// before reporting an approval without its result.
const outcomeGrace = 30 * time.Second

// Queue is the set of effects awaiting a person, shared by every process.
type Queue struct {
	dir string
	ttl time.Duration
	now func() time.Time
}

// Open prepares the queue in dir, creating it if needed.
//
// Every process that can reach this directory shares one queue, which is the
// whole point: the agent submits in one process and the person decides in
// another.
func Open(dir string, ttl time.Duration) (*Queue, error) {
	d := filepath.Join(dir, "approvals")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, fmt.Errorf("approvals: %w", err)
	}
	return &Queue{dir: d, ttl: ttl, now: time.Now}, nil
}

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (q *Queue) reqPath(id string) string { return filepath.Join(q.dir, id+".req") }
func (q *Queue) decPath(id string) string { return filepath.Join(q.dir, id+".dec") }
func (q *Queue) outPath(id string) string { return filepath.Join(q.dir, id+".out") }

// decision is what a decider writes. It is a separate file from the request so
// that creating it with O_EXCL is the decide-once guarantee: the first writer
// wins and every other gets EEXIST, across processes, with no lock.
type decision struct {
	State     State     `json:"state"`
	DecidedBy string    `json:"decided_by"`
	DecidedAt time.Time `json:"decided_at"`
	// Performs says the decider took responsibility for carrying the effect
	// out. Exactly one party may perform an approved effect, and this records
	// which. A waiter reads it to know whether an outcome is coming, and
	// whether it must not act itself.
	Performs bool `json:"performs,omitempty"`
}

// outcome is what happened when the approved effect ran. A third file again,
// because the decision is written by whoever clicked and the outcome only
// exists afterwards; rewriting the decision file would race with a reader.
type outcome struct {
	Outcome string `json:"outcome"`
	Error   string `json:"error"`
}

// Submit queues an effect and returns it.
func (q *Queue) Submit(service, capability, summary string, args map[string]string) *Effect {
	now := q.now()
	e := &Effect{
		ID: newID(), Service: service, Capability: capability, Summary: summary,
		Args: args, Submitted: now, Expires: now.Add(q.ttl), State: Pending,
	}
	body, err := json.Marshal(e)
	if err != nil {
		return e
	}
	// A write that fails must not look like a queued effect, so the state says
	// so rather than leaving a caller waiting on something that was never
	// written. Failing closed here means the effect does not happen.
	if err := writeNew(q.reqPath(e.ID), body); err != nil {
		e.State = Refused
		e.DecidedBy = "supertoolkit"
	}
	return e
}

// writeNew creates a file that must not already exist.
func writeNew(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Get returns one effect with its current state.
func (q *Queue) Get(id string) (*Effect, bool) {
	if !validID(id) {
		return nil, false
	}
	e, err := q.read(id)
	if err != nil {
		return nil, false
	}
	return e, true
}

// validID keeps an id from reaching outside the queue directory. An id comes
// from a protocol message, so it is input rather than something we chose.
func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func (q *Queue) read(id string) (*Effect, error) {
	raw, err := os.ReadFile(q.reqPath(id))
	if err != nil {
		return nil, err
	}
	var e Effect
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	if d, err := q.readDecision(id); err == nil {
		e.State, e.DecidedBy, e.DecidedAt = d.State, d.DecidedBy, d.DecidedAt
		e.Performs = d.Performs
		if o, err := q.readOutcome(id); err == nil {
			e.Outcome, e.Error = o.Outcome, o.Error
		}
		return &e, nil
	}
	// Undecided: expiry is a function of the clock, not of a write, so a
	// process that was not running when the effect expired still sees it
	// expired.
	if q.now().After(e.Expires) {
		e.State = Expired
	} else {
		e.State = Pending
	}
	return &e, nil
}

func (q *Queue) readOutcome(id string) (outcome, error) {
	var o outcome
	raw, err := os.ReadFile(q.outPath(id))
	if err != nil {
		return o, err
	}
	if err := json.Unmarshal(raw, &o); err != nil {
		return o, err
	}
	return o, nil
}

// RecordOutcome stores what happened when an approved effect ran.
//
// Only the process that won the decision calls this, so there is one writer
// and no race. It is written once; a second call is ignored rather than
// overwriting a result someone may already have read.
func (q *Queue) RecordOutcome(id, result string, cause error) error {
	if !validID(id) {
		return fmt.Errorf("no effect %q is waiting", id)
	}
	o := outcome{Outcome: result}
	if cause != nil {
		o.Error = cause.Error()
	}
	body, err := json.Marshal(o)
	if err != nil {
		return err
	}
	if err := writeNew(q.outPath(id), body); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

func (q *Queue) readDecision(id string) (decision, error) {
	var d decision
	raw, err := os.ReadFile(q.decPath(id))
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return d, err
	}
	return d, nil
}

// List returns every effect, newest first, and tidies away what is long done.
func (q *Queue) List() []*Effect {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil
	}
	var out []*Effect
	cutoff := q.now().Add(-keepDecided)
	for _, de := range entries {
		name := de.Name()
		if !strings.HasSuffix(name, ".req") {
			continue
		}
		id := strings.TrimSuffix(name, ".req")
		e, err := q.read(id)
		if err != nil {
			continue
		}
		// An effect nobody will ask about again is removed, so the directory
		// does not grow for the life of the install.
		if e.State != Pending && e.Submitted.Before(cutoff) {
			os.Remove(q.reqPath(id))
			os.Remove(q.decPath(id))
			continue
		}
		out = append(out, e)
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

// Decide records a human's answer.
//
// An effect may be decided exactly once, and that is enforced by the
// filesystem: the decision is a file created with O_EXCL, so if two people
// answer at the same moment in two different processes, one write succeeds and
// the other is told it was already decided. A mutex could not do this — it
// would only order the callers inside one process.
// It returns the effect it just claimed, because approving is no longer the end
// of the story: the caller must then perform what was approved, and it needs
// the service, capability and arguments to do so.
// DecideAndPerform records a decision and carries out what was approved.
//
// This is the call every real decider makes. `do` runs after the decision is
// claimed, so it runs exactly once however many processes are deciding, and its
// result is recorded against the effect. A refusal performs nothing.
func (q *Queue) DecideAndPerform(id string, allow bool, who string, do func(*Effect) (string, error)) (*Effect, error) {
	e, err := q.decide(id, allow, who, allow)
	if err != nil {
		return nil, err
	}
	if !allow {
		return e, nil
	}
	status, perr := do(e)
	if rerr := q.RecordOutcome(id, status, perr); rerr != nil {
		return e, rerr
	}
	e.Outcome = status
	if perr != nil {
		e.Error = perr.Error()
	}
	return e, perr
}

// Decide records a decision and performs nothing.
//
// It exists for a decider that only answers — a test, or a front end that
// cannot reach the broker. A waiter will not expect an outcome from it.
func (q *Queue) Decide(id string, allow bool, who string) (*Effect, error) {
	return q.decide(id, allow, who, false)
}

func (q *Queue) decide(id string, allow bool, who string, performs bool) (*Effect, error) {
	if !validID(id) {
		return nil, fmt.Errorf("no effect %q is waiting", id)
	}
	e, err := q.read(id)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no effect %q is waiting", id)
	}
	if err != nil {
		return nil, fmt.Errorf("could not read effect %q: %w", id, err)
	}
	switch e.State {
	case Pending:
	case Expired:
		return nil, fmt.Errorf("effect %q expired at %s and cannot be approved now — ask the agent again",
			id, e.Expires.Local().Format(time.Kitchen))
	default:
		return nil, fmt.Errorf("effect %q is already %s", id, e.State)
	}

	state := Refused
	if allow {
		state = Approved
	}
	body, err := json.Marshal(decision{State: state, DecidedBy: who, DecidedAt: q.now(), Performs: performs})
	if err != nil {
		return nil, err
	}
	if err := writeNew(q.decPath(id), body); err != nil {
		if errors.Is(err, os.ErrExist) {
			d, rerr := q.readDecision(id)
			if rerr == nil {
				return nil, fmt.Errorf("effect %q was already %s by %s", id, d.State, d.DecidedBy)
			}
			return nil, fmt.Errorf("effect %q was already decided", id)
		}
		return nil, err
	}
	e.State, e.DecidedBy = state, who
	return e, nil
}

// Await blocks until the effect is decided, expires, or the context ends.
//
// It polls, because the decision arrives in another process and there is
// nothing shared to wait on. The alternative — a socket the agent's process
// listens on — would make the daemon mandatory, which is exactly the property
// `stk mcp` exists to avoid.
func (q *Queue) Await(ctx context.Context, id string) (Decision, error) {
	e, err := q.read(id)
	if err != nil {
		return Decision{}, fmt.Errorf("no effect %q is waiting", id)
	}
	if e.State != Pending {
		return Decision{State: e.State, DecidedBy: e.DecidedBy,
			Outcome: e.Outcome, Err: e.Error, Performed: e.Performs}, nil
	}

	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return Decision{State: Pending}, ctx.Err()
		case <-t.C:
			cur, err := q.read(id)
			if err != nil {
				return Decision{}, fmt.Errorf("effect %q disappeared while waiting", id)
			}
			switch cur.State {
			case Pending:
				continue
			case Expired:
				// Expiry is not approval.
				return Decision{State: Expired}, nil
			case Approved:
				// The decider performs what it approved, so give it a moment to
				// record the result rather than reporting an approval with no
				// outcome. If it never arrives the caller still learns it was
				// approved, which is true.
				if cur.Performs && cur.Outcome == "" && cur.Error == "" &&
					q.now().Before(cur.DecidedAt.Add(outcomeGrace)) {
					continue
				}
				return Decision{State: cur.State, DecidedBy: cur.DecidedBy,
					Outcome: cur.Outcome, Err: cur.Error, Performed: cur.Performs}, nil
			default:
				return Decision{State: cur.State, DecidedBy: cur.DecidedBy}, nil
			}
		}
	}
}
