package approval

// Hosted approvals: SuperPipeline decides, stk checks again and performs.
//
// When the policy names an approvals board, an effect at `approval` is also
// created as an approval request on that board, with a `stk-capability/v1`
// subject binding the request digest. A workspace owner or admin answers it
// there (or in chat, which carries the answer to SuperPipeline). stk reads the
// decision back with its own credential, checks the subject, the digest and the
// expiry itself, records who decided from SuperPipeline's answer, and only then
// performs. A hosted effect refuses every local decision: there is no fallback
// to `stk approvals allow`, so a SuperPipeline that cannot be reached means the
// effect waits and then expires — it fails closed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unicode/utf16"
)

func (q *Queue) hostedPath(id string) string { return filepath.Join(q.dir, id+".hosted") }
func (q *Queue) aprPath(id string) string    { return filepath.Join(q.dir, id+".apr") }

// hostedMarker is written before the request record exists and never changes.
type hostedMarker struct {
	Board string `json:"board"`
}

// hostedRequest is SuperPipeline's id for the approval request, written once.
type hostedRequest struct {
	ApprovalRequestID string `json:"approval_request_id"`
}

func (q *Queue) writeHostedMarker(id, board string) error {
	body, err := json.Marshal(hostedMarker{Board: board})
	if err != nil {
		return err
	}
	return writeNew(q.hostedPath(id), body)
}

func (q *Queue) readHostedMarker(id string) (hostedMarker, error) {
	var m hostedMarker
	raw, err := os.ReadFile(q.hostedPath(id))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.Board == "" {
		// A marker that exists but cannot be read still marks the effect
		// hosted (DecideAndPerform checks existence), it just names no board.
		return m, errors.New("unreadable hosted marker")
	}
	return m, nil
}

func (q *Queue) readHostedRequest(id string) (hostedRequest, error) {
	var r hostedRequest
	raw, err := os.ReadFile(q.aprPath(id))
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(raw, &r)
	return r, err
}

// Preview bounds, as SuperPipeline counts them (UTF-16 code units, the length
// of a JavaScript string). A block over its bound is cut and the preview is
// marked incomplete, so a client withholds approval until the person has seen
// the whole request on the board.
const (
	PreviewTextMax   = 4000
	PreviewFieldMax  = 200
	PreviewBlocksMax = 20
	questionMax      = 1000
)

// PreviewBlock is a gate.v2 preview block: {type:"field", label, value} or
// {type:"text", label?, text}.
type PreviewBlock struct {
	Type  string `json:"type"`
	Label string `json:"label,omitempty"`
	Value string `json:"value,omitempty"`
	Text  string `json:"text,omitempty"`
}

// ApprovalSubject is the `stk-capability/v1` subject an approval request binds.
type ApprovalSubject struct {
	Schema          string         `json:"schema"`
	ID              string         `json:"id"`
	Digest          string         `json:"digest"`
	Revision        int            `json:"revision"`
	ExpiresAt       string         `json:"expires_at"`
	Preview         []PreviewBlock `json:"preview"`
	PreviewComplete bool           `json:"preview_complete"`
}

// ApprovalRequest is the body of POST /v1/boards/:board/approval-requests.
type ApprovalRequest struct {
	RequestID string          `json:"requestId"`
	Question  string          `json:"question"`
	Subject   ApprovalSubject `json:"subject"`
}

// ApprovalCreated is SuperPipeline's answer to a create.
type ApprovalCreated struct {
	ApprovalRequestID string `json:"approvalRequestId"`
	State             string `json:"state"`
}

// ApprovalReadBack is SuperPipeline's record of the decision.
type ApprovalReadBack struct {
	ApprovalRequestID string  `json:"approvalRequestId"`
	RequestID         string  `json:"requestId"`
	State             string  `json:"state"`
	Option            *string `json:"option"`
	DecidedBy         *struct {
		PrincipalID string `json:"principalId"`
		Label       string `json:"label"`
	} `json:"decidedBy"`
	DecidedAt *string `json:"decidedAt"`
	Subject   struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
	} `json:"subject"`
	ExpiresAt string `json:"expiresAt"`
}

// ApprovalRequestClient reaches SuperPipeline with stk's own credentials. The
// credentials are applied inside the implementation and never returned.
type ApprovalRequestClient interface {
	CreateApprovalRequest(ctx context.Context, board string, body ApprovalRequest) (ApprovalCreated, error)
	ReadApprovalRequest(ctx context.Context, board, approvalRequestID string) (ApprovalReadBack, error)
}

// Host hosts approvals on one SuperPipeline board.
type Host struct {
	Queue  *Queue
	Client ApprovalRequestClient
	Board  string
	// Station names this host in the preview.
	Station string
}

func utf16Len(s string) int { return len(utf16.Encode([]rune(s))) }

// cut keeps s within max UTF-16 units, ending in "…" when it had to cut.
func cut(s string, max int) (string, bool) {
	if utf16Len(s) <= max {
		return s, false
	}
	out, n := []rune{}, 0
	for _, r := range s {
		w := utf16.RuneLen(r)
		if w < 1 {
			w = 1
		}
		if n+w > max-1 {
			break
		}
		out = append(out, r)
		n += w
	}
	return string(out) + "…", true
}

// Request is the approval request for an effect: the question, and a subject
// whose preview shows the service, capability, target, every argument in full,
// the station, the requesting agent and the expiry. Anything cut to fit makes
// preview_complete false.
func (h *Host) Request(e *Effect) ApprovalRequest {
	complete := true
	var blocks []PreviewBlock
	field := func(label, value string) {
		v, c := cut(value, PreviewFieldMax)
		complete = complete && !c
		blocks = append(blocks, PreviewBlock{Type: "field", Label: label, Value: v})
	}
	text := func(label, value string) {
		l, c1 := cut(label, PreviewFieldMax)
		v, c2 := cut(value, PreviewTextMax)
		complete = complete && !c1 && !c2
		blocks = append(blocks, PreviewBlock{Type: "text", Label: l, Text: v})
	}
	field("Service", e.Service)
	field("Capability", e.Capability)
	text("Target", e.Target)
	field("Station", h.Station)
	field("Requested by", e.Requester)
	field("Profile", orNone(e.Profile))
	field("Expires", e.Expires.UTC().Format(time.RFC3339))
	field("Request digest", e.RequestDigest)
	keys := make([]string, 0, len(e.Args))
	for k := range e.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	shown := keys
	if room := PreviewBlocksMax - len(blocks); len(keys) > room {
		// One block is kept to say how many arguments did not fit.
		shown = keys[:room-1]
	}
	for _, k := range shown {
		text("Argument "+k, e.Args[k])
	}
	if hidden := len(keys) - len(shown); hidden > 0 {
		complete = false
		text("More arguments", fmt.Sprintf("%d more not shown", hidden))
	}
	if len(keys) == 0 {
		text("Arguments", "(none)")
	}
	q, _ := cut(fmt.Sprintf("Allow %s on %s to %s/%s: %s?", orNone(e.Requester), orNone(h.Station),
		e.Service, e.Capability, e.Summary), questionMax)
	return ApprovalRequest{
		RequestID: e.ID,
		Question:  q,
		Subject: ApprovalSubject{
			Schema: DigestSchema, ID: e.ID, Digest: e.RequestDigest, Revision: 1,
			ExpiresAt: e.Expires.UTC().Format(time.RFC3339), Preview: blocks, PreviewComplete: complete,
		},
	}
}

func orNone(s string) string {
	if s == "" {
		return "(unnamed)"
	}
	return s
}

// Publish creates the approval request on the board and records its id. It is
// idempotent: SuperPipeline returns the same record for the same requestId
// from the same principal, so a retry after a lost answer is safe.
func (h *Host) Publish(ctx context.Context, e *Effect) (string, error) {
	if e.ApprovalRequestID != "" {
		return e.ApprovalRequestID, nil
	}
	created, err := h.Client.CreateApprovalRequest(ctx, h.Board, h.Request(e))
	if err != nil {
		return "", err
	}
	if created.ApprovalRequestID == "" {
		return "", errors.New("SuperPipeline returned no approval request id")
	}
	body, _ := json.Marshal(hostedRequest{ApprovalRequestID: created.ApprovalRequestID})
	if err := writeNew(h.Queue.aprPath(e.ID), body); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if r, err := h.Queue.readHostedRequest(e.ID); err == nil {
		return r.ApprovalRequestID, nil
	}
	return created.ApprovalRequestID, nil
}

// Resolve takes one hosted effect one step: create its request if that has not
// happened, read the decision back, and act on a final one. It returns the
// effect as it now stands. perform carries out an approved effect; it is the
// same one a local decider uses, so it re-checks the request digest too.
func (h *Host) Resolve(ctx context.Context, id string, perform func(*Effect) (string, error)) (*Effect, error) {
	e, ok := h.Queue.Get(id)
	if !ok {
		return nil, fmt.Errorf("no effect %q is waiting", id)
	}
	if e.HostedBoard == "" {
		return e, fmt.Errorf("effect %q is not hosted", id)
	}
	if e.State != Pending {
		return e, nil
	}
	if e.HostedBoard != h.Board {
		// The board was changed under a waiting effect. Its request lives on
		// the board it was created on; never read another board's answer.
		return e, fmt.Errorf("effect %q is hosted on %s, not %s", id, e.HostedBoard, h.Board)
	}
	aprID, err := h.Publish(ctx, e)
	if err != nil {
		return e, fmt.Errorf("creating the approval request on SuperPipeline: %w", err)
	}
	rb, err := h.Client.ReadApprovalRequest(ctx, h.Board, aprID)
	if err != nil {
		return e, fmt.Errorf("reading the approval request from SuperPipeline: %w", err)
	}
	decider := "superpipeline"
	if rb.DecidedBy != nil {
		decider = fmt.Sprintf("superpipeline: %s (%s)", rb.DecidedBy.Label, rb.DecidedBy.PrincipalID)
	}
	switch rb.State {
	case "pending":
		return e, nil
	case "denied":
		return h.Queue.decide(id, false, decider, false)
	case "expired":
		return h.Queue.decide(id, false, "superpipeline: expired undecided", false)
	case "approved":
	default:
		return e, fmt.Errorf("SuperPipeline reported state %q for %s", rb.State, aprID)
	}
	// Approved on SuperPipeline. Check it again here before acting: the
	// option, the subject it bound and the digest. The expiry is checked by
	// the claim itself: decide refuses an effect that has expired by then.
	if reason := h.mismatch(e, aprID, rb); reason != "" {
		claimed, err := h.Queue.decide(id, false, "supertoolkit: "+reason, false)
		if err != nil {
			return claimed, err
		}
		_ = h.Queue.RecordOutcome(id, "refused", errors.New(reason))
		claimed.Outcome, claimed.Error = "refused", reason
		return claimed, errors.New(reason)
	}
	claimed, err := h.Queue.decide(id, true, decider, true)
	if err != nil {
		return claimed, err
	}
	status, perr := perform(claimed)
	if perr != nil && outcomeMayBeUnknown(perr) {
		status = "outcome_unknown"
	}
	if rerr := h.Queue.RecordOutcome(id, status, perr); rerr != nil {
		return claimed, rerr
	}
	claimed.Outcome = status
	if perr != nil {
		claimed.Error = perr.Error()
	}
	return claimed, perr
}

// mismatch says why an approval read back from SuperPipeline must not be acted
// on, or "" when it may.
func (h *Host) mismatch(e *Effect, aprID string, rb ApprovalReadBack) string {
	switch {
	case rb.ApprovalRequestID != aprID:
		return fmt.Sprintf("SuperPipeline answered for %s, not %s", rb.ApprovalRequestID, aprID)
	case rb.Option == nil || *rb.Option != "allow_once":
		return "SuperPipeline's approval is not allow_once"
	case rb.Subject.ID != e.ID:
		return fmt.Sprintf("the approval binds subject %q, not this effect %q", rb.Subject.ID, e.ID)
	case e.RequestDigest == "" || rb.Subject.Digest != e.RequestDigest:
		return fmt.Sprintf("the approval binds digest %s, not this request's %s", rb.Subject.Digest, e.RequestDigest)
	case rb.DecidedBy == nil || rb.DecidedBy.PrincipalID == "":
		return "SuperPipeline's approval names no decider"
	}
	return ""
}

// Watch resolves every pending hosted effect until ctx ends. current is asked
// for the host on every pass, so a policy reload that changes or removes the
// board reaches the watcher; nil means nothing is hosted now (an effect hosted
// earlier still refuses local decisions and simply expires). Each effect is
// read every interval while it waits; one that errors (SuperPipeline
// unreachable, a create refused) backs off, doubling up to maxBackoff, and is
// retried until it expires. Several processes may watch one queue: deciding is
// a file created with O_EXCL, so exactly one of them performs.
func Watch(ctx context.Context, current func() *Host, interval, maxBackoff time.Duration, perform func(*Effect) (string, error), report func(id string, err error)) {
	type wait struct {
		next  time.Time
		delay time.Duration
	}
	waits := map[string]*wait{}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		seen := map[string]bool{}
		h := current()
		var pending []*Effect
		if h != nil {
			pending = h.Queue.Pending()
		}
		for _, e := range pending {
			if e.HostedBoard == "" {
				continue
			}
			seen[e.ID] = true
			w := waits[e.ID]
			if w == nil {
				w = &wait{delay: interval}
				waits[e.ID] = w
			}
			if h.Queue.now().Before(w.next) {
				continue
			}
			if _, err := h.Resolve(ctx, e.ID, perform); err != nil {
				if report != nil {
					report(e.ID, err)
				}
				w.delay *= 2
				if w.delay > maxBackoff {
					w.delay = maxBackoff
				}
				w.next = h.Queue.now().Add(w.delay)
			} else {
				w.delay, w.next = interval, time.Time{}
			}
		}
		for id := range waits {
			if !seen[id] {
				delete(waits, id)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
