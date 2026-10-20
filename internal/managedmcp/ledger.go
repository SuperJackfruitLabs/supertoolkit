// Package managedmcp records broker invocations under an external execution owner.
// It grants no authority: the executor must obtain a fresh grant from that owner.
// Its versioned directory deliberately cannot be consumed by the legacy approval queue.
package managedmcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type State string

const (
	Prepared            State = "prepared"
	AwaitingDecision    State = "awaiting_decision"
	Approved            State = "approved"
	Denied              State = "denied"
	Claiming            State = "claiming"
	Dispatching         State = "dispatching"
	Returned            State = "returned"
	OutcomeUnknown      State = "outcome_unknown"
	OutcomeAcknowledged State = "outcome_acknowledged"
	Cancelled           State = "cancelled"
)

type Request struct {
	Version       int               `json:"version"`
	RootDigest    string            `json:"root_digest"`
	InvocationID  string            `json:"invocation_id"`
	ProfileDigest string            `json:"profile_digest"`
	Service       string            `json:"service"`
	Action        string            `json:"action"`
	Args          map[string]string `json:"args"`
	Approval      bool              `json:"approval"`
	ExpiresAtMS   int64             `json:"expires_at_ms"`
}
type Receipt struct {
	ID            string `json:"id"`
	RequestDigest string `json:"request_digest"`
	State         State  `json:"state"`
	DecisionID    string `json:"decision_id,omitempty"`
	// Returned is a protocol outcome, never verification of a product effect.
	Result                string `json:"result,omitempty"`
	CancellationRequested bool   `json:"cancellation_requested,omitempty"`
	ResolutionID          string `json:"resolution_id,omitempty"`
	ResolutionStopDigest  string `json:"resolution_stop_digest,omitempty"`
}
type record struct {
	Version int     `json:"version"`
	Request Request `json:"request"`
	Receipt Receipt `json:"receipt"`
	Claim   string  `json:"claim,omitempty"`
}
type Ledger struct {
	dir    string
	now    func() time.Time
	mu     sync.Mutex
	active map[string]ownedCall
}
type ownedCall struct {
	root   string
	cancel context.CancelFunc
}

var hashShape = regexp.MustCompile(`^[a-f0-9]{64}$`)
var nameShape = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

func refused() error {
	return errors.New("managed broker invocation is unavailable or conflicts with its owner")
}
func fingerprint(value any) string {
	sum := sha256.Sum256(canonicalBytes(value))
	return hex.EncodeToString(sum[:])
}
func requestID(r Request) string {
	return fingerprint([]string{"stk.managed-mcp.v1", r.RootDigest, r.InvocationID})
}
func copyRequest(r Request) Request { r.Args = maps.Clone(r.Args); return r }
func validRequest(r Request) bool {
	if r.Version != 1 || !hashShape.MatchString(r.RootDigest) || !hashShape.MatchString(r.ProfileDigest) || !nameShape.MatchString(r.InvocationID) || !nameShape.MatchString(r.Service) || !nameShape.MatchString(r.Action) || r.Args == nil || len(r.Args) > 64 || (r.ExpiresAtMS <= 0 || r.ExpiresAtMS > 9007199254740991) {
		return false
	}
	for key, value := range r.Args {
		if !nameShape.MatchString(key) || !utf8.ValidString(value) || len(value) > 16384 {
			return false
		}
	}
	return len(canonicalBytes(r)) <= 65536
}

func Open(root string) (*Ledger, error) {
	if !filepath.IsAbs(root) {
		return nil, refused()
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, refused()
	}
	if err = privateDirectory(resolved); err != nil {
		return nil, err
	}
	dir := filepath.Join(resolved, "managed-mcp-v1")
	if err = os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, refused()
	}
	if err = privateDirectory(dir); err != nil {
		return nil, err
	}
	return &Ledger{dir: dir, now: time.Now, active: map[string]ownedCall{}}, nil
}
func (l *Ledger) locked(do func() error) error {
	if err := privateDirectory(l.dir); err != nil {
		return err
	}
	unlock, err := lockPrivateFile(filepath.Join(l.dir, "writer.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return do()
}
func (l *Ledger) path(id string) string { return filepath.Join(l.dir, id+".invocation") }
func (l *Ledger) read(id string) (record, error) {
	var r record
	if !hashShape.MatchString(id) {
		return r, refused()
	}
	body, err := readPrivateFile(l.path(id), 1<<20)
	if err != nil {
		return r, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || decoder.Decode(new(any)) != io.EOF || r.Version != 1 || !validRequest(r.Request) || requestID(r.Request) != id || r.Receipt.ID != id || fingerprint(r.Request) != r.Receipt.RequestDigest {
		return r, refused()
	}
	switch r.Receipt.State {
	case Prepared, AwaitingDecision, Approved, Denied, Claiming, Dispatching, Returned, OutcomeUnknown, OutcomeAcknowledged, Cancelled:
	default:
		return r, refused()
	}
	if len(r.Receipt.Result) > 256*1024 || (r.Receipt.State == Returned && r.Receipt.Result == "") || (r.Receipt.State != Returned && r.Receipt.Result != "") {
		return r, refused()
	}
	if r.Receipt.State == OutcomeAcknowledged {
		if !nameShape.MatchString(r.Receipt.ResolutionID) || !hashShape.MatchString(r.Receipt.ResolutionStopDigest) || r.Receipt.Result != "" {
			return r, refused()
		}
	} else if r.Receipt.ResolutionID != "" || r.Receipt.ResolutionStopDigest != "" {
		return r, refused()
	}
	return r, nil
}
func (l *Ledger) save(r record) error { return atomicJSON(l.path(r.Receipt.ID), r) }
func (l *Ledger) revoked(root string) (bool, error) {
	body, err := readPrivateFile(filepath.Join(l.dir, root+".revoked"), 1024)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, refused()
	}
	if string(body) != "\""+root+"\"" {
		return false, refused()
	}
	return true, nil
}
func (l *Ledger) Prepare(request Request) (Receipt, error) {
	r := copyRequest(request)

	var out Receipt
	if !validRequest(r) {
		return out, refused()
	}
	err := l.locked(func() error {
		id := requestID(r)
		old, err := l.read(id)
		if err == nil {
			if old.Receipt.RequestDigest != fingerprint(r) {
				return refused()
			}
			out = old.Receipt
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return refused()
		}
		revoked, err := l.revoked(r.RootDigest)
		if err != nil {
			return err
		}
		if revoked || l.now().UnixMilli() >= r.ExpiresAtMS || r.ExpiresAtMS > l.now().Add(5*time.Minute).UnixMilli() {
			return refused()
		}
		state := Prepared
		if r.Approval {
			state = AwaitingDecision
		}
		out = Receipt{ID: id, RequestDigest: fingerprint(r), State: state}
		return l.save(record{Version: 1, Request: r, Receipt: out})
	})
	return out, err
}
func (l *Ledger) Decide(id, decisionID string, allow bool) (Receipt, error) {
	var out Receipt
	if !nameShape.MatchString(decisionID) {
		return out, refused()
	}
	err := l.locked(func() error {
		r, err := l.read(id)
		if err != nil {
			return err
		}
		if r.Receipt.DecisionID == decisionID && ((allow && r.Receipt.State == Approved) || (!allow && r.Receipt.State == Denied)) {
			out = r.Receipt
			return nil
		}
		revoked, err := l.revoked(r.Request.RootDigest)
		if err != nil {
			return err
		}
		if r.Receipt.State != AwaitingDecision || revoked || l.now().UnixMilli() >= r.Request.ExpiresAtMS {
			return refused()
		}
		r.Receipt.DecisionID = decisionID
		r.Receipt.State = Denied
		if allow {
			r.Receipt.State = Approved
		}
		out = r.Receipt
		return l.save(r)
	})
	return out, err
}
func terminal(s State) bool {
	return s == Returned || s == OutcomeUnknown || s == OutcomeAcknowledged || s == Cancelled || s == Denied
}

func (l *Ledger) rootHasUnresolved(root, exceptID string) (bool, error) {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return false, refused()
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".invocation") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".invocation")
		if id == exceptID {
			continue
		}
		r, err := l.read(id)
		if err != nil {
			return false, err
		}
		if r.Request.RootDigest == root && (r.Receipt.State == Claiming || r.Receipt.State == Dispatching || r.Receipt.State == OutcomeUnknown) {
			return true, nil
		}
	}
	return false, nil
}

// Execute has one effect owner: the supervised broker caller. A human decision
// only answers the gate. Saved requests and uncertain markers precede fresh grants.
// The authorize callback MUST check fresh execution authority and durably consume
// the parent operation grant; a RootDigest or approved record is not authority.
func (l *Ledger) Execute(ctx context.Context, id, digest string, authorize func(context.Context, Request) error, execute func(context.Context, Request) (string, error)) (Receipt, error) {
	var r record
	var out Receipt
	claimed := false
	claim := rand.Text()
	err := l.locked(func() error {
		var err error
		r, err = l.read(id)
		if err != nil {
			return err
		}
		if digest != r.Receipt.RequestDigest {
			return refused()
		}
		out = r.Receipt
		if terminal(out.State) || out.State == Claiming || out.State == Dispatching {
			return nil
		}
		revoked, err := l.revoked(r.Request.RootDigest)
		if err != nil {
			return err
		}
		if revoked || ctx.Err() != nil || l.now().UnixMilli() >= r.Request.ExpiresAtMS {
			r.Receipt.State = Cancelled
			out = r.Receipt
			return l.save(r)
		}
		if out.State == AwaitingDecision {
			return nil
		}
		unresolved, err := l.rootHasUnresolved(r.Request.RootDigest, id)
		if err != nil {
			return err
		}
		if unresolved {
			return refused()
		}
		if authorize == nil || execute == nil {
			return refused()
		}
		r.Receipt.State = Claiming
		r.Claim = claim
		out = r.Receipt
		if err = l.save(r); err != nil {
			return err
		}
		claimed = true
		return nil
	})
	if err != nil || !claimed {
		return out, err
	}
	owned, cancel := context.WithDeadline(ctx, time.UnixMilli(r.Request.ExpiresAtMS))
	l.mu.Lock()
	l.active[id] = ownedCall{root: r.Request.RootDigest, cancel: cancel}
	l.mu.Unlock()
	defer func() { cancel(); l.mu.Lock(); delete(l.active, id); l.mu.Unlock() }()
	grantErr := authorize(owned, copyRequest(r.Request))
	dispatched := false
	err = l.locked(func() error {
		current, err := l.read(id)
		if err != nil {
			return err
		}
		out = current.Receipt
		if current.Claim != claim || current.Receipt.State != Claiming {
			return nil
		}
		revoked, err := l.revoked(current.Request.RootDigest)
		if err != nil {
			return err
		}
		if revoked || owned.Err() != nil || l.now().UnixMilli() >= current.Request.ExpiresAtMS {
			current.Receipt.State = Cancelled
		} else if grantErr != nil {
			current.Receipt.State = Denied
		} else {
			current.Receipt.State = Dispatching
		}
		out = current.Receipt
		if err = l.save(current); err != nil {
			return err
		}
		dispatched = current.Receipt.State == Dispatching
		return nil
	})
	if err != nil || !dispatched {
		return out, err
	}
	result, callErr := execute(owned, copyRequest(r.Request))
	err = l.locked(func() error {
		current, err := l.read(id)
		if err != nil {
			return err
		}
		if current.Claim != claim {
			return refused()
		}
		if callErr != nil || len(result) > 256*1024 || result == "" {
			current.Receipt.State = OutcomeUnknown
			current.Receipt.Result = ""
		} else {
			current.Receipt.State = Returned
			current.Receipt.Result = result
		}
		out = current.Receipt
		return l.save(current)
	})
	return out, err
}
func cancelRecord(r *record) {
	if terminal(r.Receipt.State) {
		return
	}
	r.Receipt.CancellationRequested = true
	if r.Receipt.State == Dispatching {
		r.Receipt.State = OutcomeUnknown
	} else {
		r.Receipt.State = Cancelled
	}
}
func (l *Ledger) Cancel(id, digest string) (Receipt, error) {
	var out Receipt
	err := l.locked(func() error {
		r, err := l.read(id)
		if err != nil {
			return err
		}
		if digest != r.Receipt.RequestDigest {
			return refused()
		}
		cancelRecord(&r)
		out = r.Receipt
		return l.save(r)
	})
	if err == nil {
		l.mu.Lock()
		call, ok := l.active[id]
		l.mu.Unlock()
		if ok {
			call.cancel()
		}
	}
	return out, err
}

// FenceInterrupted is called only after the supervisor observes its old owned
// process stopped. It preserves uncertainty; it is not a process-stop receipt.
// No grant or executor is called while recovering an interrupted marker.
func (l *Ledger) FenceInterrupted(id, digest string) (Receipt, error) {
	var out Receipt
	err := l.locked(func() error {
		r, err := l.read(id)
		if err != nil {
			return err
		}
		if r.Receipt.RequestDigest != digest {
			return refused()
		}
		if r.Receipt.State == Claiming || r.Receipt.State == Dispatching {
			r.Receipt.State = OutcomeUnknown
			if err = l.save(r); err != nil {
				return err
			}
		}
		out = r.Receipt
		return nil
	})
	return out, err
}
func (l *Ledger) RevokeRoot(root string) error {
	if !hashShape.MatchString(root) {
		return refused()
	}
	err := l.locked(func() error {
		if err := atomicJSON(filepath.Join(l.dir, root+".revoked"), root); err != nil {
			return err
		}
		entries, err := os.ReadDir(l.dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".invocation") {
				continue
			}
			id := strings.TrimSuffix(entry.Name(), ".invocation")
			r, err := l.read(id)
			if err != nil {
				return err
			}
			if r.Request.RootDigest == root {
				cancelRecord(&r)
				if err = l.save(r); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err == nil {
		l.mu.Lock()
		for _, call := range l.active {
			if call.root == root {
				call.cancel()
			}
		}
		l.mu.Unlock()
	}
	return err
}

func atomicJSON(path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return refused()
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".managed-write-")
	if err != nil {
		return refused()
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(body); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return refused()
	}
	if err = os.Rename(tmp, path); err != nil {
		return refused()
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return refused()
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return refused()
	}
	return nil
}
