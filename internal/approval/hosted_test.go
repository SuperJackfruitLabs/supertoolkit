package approval

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testBoard = "brd_fixture"

// fakeBoard stands in for SuperPipeline: it stores what was created and
// answers read-backs with whatever the test sets.
type fakeBoard struct {
	mu        sync.Mutex
	creates   int
	createErr error
	readErr   error
	created   map[string]ApprovalRequest // by requestId
	answer    func(req ApprovalRequest) ApprovalReadBack
}

func newFakeBoard() *fakeBoard { return &fakeBoard{created: map[string]ApprovalRequest{}} }

func (f *fakeBoard) CreateApprovalRequest(_ context.Context, board string, body ApprovalRequest) (ApprovalCreated, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates++
	if f.createErr != nil {
		return ApprovalCreated{}, f.createErr
	}
	f.created[body.RequestID] = body
	return ApprovalCreated{ApprovalRequestID: "apr_" + body.RequestID, State: "pending"}, nil
}

func (f *fakeBoard) ReadApprovalRequest(_ context.Context, board, id string) (ApprovalReadBack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return ApprovalReadBack{}, f.readErr
	}
	req := f.created[strings.TrimPrefix(id, "apr_")]
	rb := ApprovalReadBack{ApprovalRequestID: id, RequestID: req.RequestID, State: "pending"}
	rb.Subject.ID, rb.Subject.Digest = req.Subject.ID, req.Subject.Digest
	if f.answer != nil {
		rb = f.answer(req)
		if rb.ApprovalRequestID == "" {
			rb.ApprovalRequestID = id
		}
	}
	return rb, nil
}

func (f *fakeBoard) set(answer func(ApprovalRequest) ApprovalReadBack) {
	f.mu.Lock()
	f.answer = answer
	f.mu.Unlock()
}

func approvedBy(label string, mutate ...func(*ApprovalReadBack)) func(ApprovalRequest) ApprovalReadBack {
	return func(req ApprovalRequest) ApprovalReadBack {
		opt := "allow_once"
		rb := ApprovalReadBack{RequestID: req.RequestID, State: "approved", Option: &opt}
		rb.DecidedBy = &struct {
			PrincipalID string `json:"principalId"`
			Label       string `json:"label"`
		}{PrincipalID: "prn_admin", Label: label}
		rb.Subject.ID, rb.Subject.Digest = req.Subject.ID, req.Subject.Digest
		for _, m := range mutate {
			m(&rb)
		}
		return rb
	}
}

func hostedRig(t *testing.T) (*Host, *fakeBoard, *Effect) {
	t.Helper()
	q := mustOpen(t, 30*time.Minute)
	board := newFakeBoard()
	h := &Host{Queue: q, Client: board, Board: testBoard, Station: "station-1"}
	req := baseRequest()
	e := q.SubmitRequest(Submission{Service: req.Service, Capability: req.Capability, Summary: "Open an issue",
		Args: req.Args, Profile: req.Profile, Requester: "agent (uid 1001)", Target: req.Method + " " + req.URL,
		Digest: req.Digest(), HostedBoard: testBoard})
	if e.State != Pending {
		t.Fatalf("submit state = %q", e.State)
	}
	return h, board, e
}

func counter() (*int32, func(*Effect) (string, error)) {
	var n int32
	return &n, func(*Effect) (string, error) { atomic.AddInt32(&n, 1); return "201 Created", nil }
}

// Regression guarded: a hosted approval must never be decided locally, or an
// operator shell (or a compromised local UI) could bypass the workspace
// owners and admins SuperPipeline restricts it to.
func TestHostedEffectRefusesEveryLocalDecision(t *testing.T) {
	h, _, e := hostedRig(t)
	sends, perform := counter()
	for _, allow := range []bool{true, false} {
		if _, err := h.Queue.DecideAndPerform(e.ID, allow, "root (uid 0)", perform); err == nil {
			t.Fatalf("DecideAndPerform(allow=%v) accepted a local decision on a hosted effect", allow)
		}
		if _, err := h.Queue.Decide(e.ID, allow, "root (uid 0)"); err == nil {
			t.Fatalf("Decide(allow=%v) accepted a local decision on a hosted effect", allow)
		}
	}
	got, _ := h.Queue.Get(e.ID)
	if got.State != Pending || *sends != 0 || got.HostedBoard != testBoard {
		t.Fatalf("after local attempts: state=%q sends=%d board=%q", got.State, *sends, got.HostedBoard)
	}
}

func TestHostedApprovalIsCheckedRecordedAndPerformedOnce(t *testing.T) {
	h, board, e := hostedRig(t)
	sends, perform := counter()
	if got, err := h.Resolve(context.Background(), e.ID, perform); err != nil || got.State != Pending {
		t.Fatalf("undecided: state=%v err=%v", got.State, err)
	}
	if board.creates != 1 || *sends != 0 {
		t.Fatalf("creates=%d sends=%d before any decision", board.creates, *sends)
	}
	board.set(approvedBy("Rakesh"))
	got, err := h.Resolve(context.Background(), e.ID, perform)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != Approved || got.Outcome != "201 Created" || *sends != 1 {
		t.Fatalf("approved: state=%q outcome=%q sends=%d", got.State, got.Outcome, *sends)
	}
	if got.DecidedBy != "superpipeline: Rakesh (prn_admin)" {
		t.Fatalf("decided by %q; want SuperPipeline's decider", got.DecidedBy)
	}
	// Reading again, or a second watcher, performs nothing more.
	_, _ = h.Resolve(context.Background(), e.ID, perform)
	other := &Host{Queue: h.Queue, Client: board, Board: testBoard}
	_, _ = other.Resolve(context.Background(), e.ID, perform)
	if *sends != 1 || board.creates != 1 {
		t.Fatalf("sends=%d creates=%d after re-reads; want 1 and 1", *sends, board.creates)
	}
}

func TestConcurrentWatchersPerformOnce(t *testing.T) {
	h, board, e := hostedRig(t)
	board.set(approvedBy("Rakesh"))
	sends, perform := counter()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := &Host{Queue: h.Queue, Client: board, Board: testBoard}
			_, _ = w.Resolve(context.Background(), e.ID, perform)
		}()
	}
	wg.Wait()
	if *sends != 1 {
		t.Fatalf("8 watchers performed %d times; want exactly 1", *sends)
	}
}

// Each of these is an approval SuperPipeline reported that stk must still
// refuse, recording why, without sending anything.
func TestHostedApprovalThatDoesNotCheckOutIsRefused(t *testing.T) {
	cases := map[string]func(*ApprovalReadBack){
		"digest":     func(rb *ApprovalReadBack) { rb.Subject.Digest = "sha256:other" },
		"subject":    func(rb *ApprovalReadBack) { rb.Subject.ID = "someone-else" },
		"option":     func(rb *ApprovalReadBack) { d := "deny"; rb.Option = &d },
		"no option":  func(rb *ApprovalReadBack) { rb.Option = nil },
		"no decider": func(rb *ApprovalReadBack) { rb.DecidedBy = nil },
		"request id": func(rb *ApprovalReadBack) { rb.ApprovalRequestID = "apr_other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h, board, e := hostedRig(t)
			board.set(approvedBy("Rakesh", mutate))
			sends, perform := counter()
			got, err := h.Resolve(context.Background(), e.ID, perform)
			if err == nil || *sends != 0 {
				t.Fatalf("err=%v sends=%d; want a refusal and no send", err, *sends)
			}
			if got.State != Refused || got.Outcome != "refused" || got.Error == "" {
				t.Fatalf("recorded state=%q outcome=%q error=%q", got.State, got.Outcome, got.Error)
			}
		})
	}
}

func TestHostedApprovalAfterExpiryIsNotPerformed(t *testing.T) {
	h, board, e := hostedRig(t)
	_, _ = h.Resolve(context.Background(), e.ID, nil) // created while live
	board.set(approvedBy("Rakesh"))
	// The effect is still pending when it is read, and expires before the
	// approval is claimed: the claim must refuse it.
	var calls int32
	h.Queue.now = func() time.Time {
		if atomic.AddInt32(&calls, 1) == 1 {
			return e.Expires.Add(-time.Second)
		}
		return e.Expires.Add(time.Second)
	}
	sends, perform := counter()
	_, _ = h.Resolve(context.Background(), e.ID, perform)
	got, _ := h.Queue.Get(e.ID)
	if *sends != 0 || got.State != Expired {
		t.Fatalf("late approval: sends=%d state=%q; want nothing sent and the effect expired", *sends, got.State)
	}
}

func TestHostedDenialAndExpiryRefuse(t *testing.T) {
	for _, state := range []string{"denied", "expired"} {
		t.Run(state, func(t *testing.T) {
			h, board, e := hostedRig(t)
			board.set(func(req ApprovalRequest) ApprovalReadBack {
				rb := ApprovalReadBack{State: state}
				if state == "denied" {
					rb.DecidedBy = &struct {
						PrincipalID string `json:"principalId"`
						Label       string `json:"label"`
					}{"prn_member", "Asha"}
				}
				return rb
			})
			sends, perform := counter()
			got, err := h.Resolve(context.Background(), e.ID, perform)
			if err != nil || got.State != Refused || *sends != 0 {
				t.Fatalf("state=%q sends=%d err=%v", got.State, *sends, err)
			}
			if state == "denied" && got.DecidedBy != "superpipeline: Asha (prn_member)" {
				t.Fatalf("decided by %q", got.DecidedBy)
			}
		})
	}
}

// SuperPipeline unreachable: the effect stays pending and hosted, nothing
// falls back to a local decision, and the create is retried with the same
// requestId once SuperPipeline answers.
func TestHostedCreateFailureFailsClosedAndRetries(t *testing.T) {
	h, board, e := hostedRig(t)
	board.createErr = errors.New("dial tcp: connection refused")
	sends, perform := counter()
	if _, err := h.Resolve(context.Background(), e.ID, perform); err == nil {
		t.Fatal("a failed create reported success")
	}
	if _, err := h.Queue.DecideAndPerform(e.ID, true, "root (uid 0)", perform); err == nil {
		t.Fatal("an unreachable SuperPipeline let a local decision through")
	}
	got, _ := h.Queue.Get(e.ID)
	if got.State != Pending || got.ApprovalRequestID != "" || *sends != 0 {
		t.Fatalf("after failure: state=%q apr=%q sends=%d", got.State, got.ApprovalRequestID, *sends)
	}
	board.createErr = nil
	board.set(approvedBy("Rakesh"))
	if got, err := h.Resolve(context.Background(), e.ID, perform); err != nil || got.State != Approved || *sends != 1 {
		t.Fatalf("after recovery: state=%v sends=%d err=%v", got.State, *sends, err)
	}
	if _, ok := board.created[e.ID]; !ok {
		t.Fatal("the create was not keyed by the effect id")
	}
}

func TestPreviewShowsTheWholeRequest(t *testing.T) {
	h, _, e := hostedRig(t)
	r := h.Request(e)
	if r.RequestID != e.ID || r.Subject.ID != e.ID || r.Subject.Digest != e.RequestDigest ||
		r.Subject.Schema != "stk-capability/v1" || r.Subject.Revision != 1 {
		t.Fatalf("binding = %+v", r.Subject)
	}
	if exp, err := time.Parse(time.RFC3339, r.Subject.ExpiresAt); err != nil || !exp.Equal(e.Expires.Truncate(time.Second)) {
		t.Fatalf("expires_at %q (%v); want the effect's expiry", r.Subject.ExpiresAt, err)
	}
	raw, _ := json.Marshal(r)
	for _, want := range []string{"github", "create_issue", "POST https://api.github.com/repos/o/r/issues",
		"station-1", "agent (uid 1001)", "Argument owner", "Argument repo", "Argument title", e.RequestDigest} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("preview lacks %q: %s", want, raw)
		}
	}
	if !r.Subject.PreviewComplete || len(r.Subject.Preview) > PreviewBlocksMax {
		t.Fatalf("complete=%v blocks=%d", r.Subject.PreviewComplete, len(r.Subject.Preview))
	}
	if !strings.HasPrefix(r.Question, "Allow agent (uid 1001) on station-1 to github/create_issue") {
		t.Fatalf("question = %q", r.Question)
	}
}

func TestPreviewCutToBoundsIsMarkedIncomplete(t *testing.T) {
	h, _, e := hostedRig(t)
	long := *e
	long.Args = map[string]string{"body": strings.Repeat("é", PreviewTextMax+1)}
	r := h.Request(&long)
	if r.Subject.PreviewComplete {
		t.Fatal("a cut argument left the preview marked complete")
	}
	for _, b := range r.Subject.Preview {
		if utf16Len(b.Text) > PreviewTextMax || utf16Len(b.Value) > PreviewFieldMax || utf16Len(b.Label) > PreviewFieldMax {
			t.Fatalf("block over its bound: %d/%d", utf16Len(b.Text), utf16Len(b.Value))
		}
	}
	many := *e
	many.Args = map[string]string{}
	for i := 0; i < 30; i++ {
		many.Args[string(rune('a'+i%26))+strings.Repeat("x", i/26)] = "v"
	}
	r = h.Request(&many)
	if len(r.Subject.Preview) != PreviewBlocksMax || r.Subject.PreviewComplete {
		t.Fatalf("30 arguments: %d blocks, complete=%v; want %d and false", len(r.Subject.Preview), r.Subject.PreviewComplete, PreviewBlocksMax)
	}
	q := *e
	q.Summary = strings.Repeat("s", 2000)
	if utf16Len(h.Request(&q).Question) > 1000 {
		t.Fatal("question over 1000")
	}
}

func TestWatchResolvesHostedEffects(t *testing.T) {
	h, board, e := hostedRig(t)
	board.set(approvedBy("Rakesh"))
	sends, perform := counter()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Watch(ctx, func() *Host { return h }, 10*time.Millisecond, 50*time.Millisecond, perform, nil)
		close(done)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(sends) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	got, _ := h.Queue.Get(e.ID)
	if *sends != 1 || got.State != Approved {
		t.Fatalf("watch: sends=%d state=%q", *sends, got.State)
	}
}

// The HTTP client sends the create on the write credential and the read on
// the read credential, to the documented routes, with the documented fields.
func TestSuperPipelineClientRoutesAndCredentials(t *testing.T) {
	var calls []string
	var body map[string]any
	write := canned{cred: "write", status: 201, out: `{"approvalRequestId":"apr_1","state":"pending"}`, calls: &calls, body: &body}
	read := canned{cred: "read", status: 200, calls: &calls, body: &body,
		out: `{"approvalRequestId":"apr_1","state":"approved","option":"allow_once","decidedBy":{"principalId":"prn_a","label":"A"},"subject":{"id":"e1","digest":"d"}}`}
	c := &SuperPipelineHTTPClient{BaseURL: "https://app.superpipeline.dev", DeliveryDo: write.Do, ApprovalDo: read.Do}
	h, _, e := hostedRig(t)
	created, err := c.CreateApprovalRequest(context.Background(), testBoard, h.Request(e))
	if err != nil || created.ApprovalRequestID != "apr_1" {
		t.Fatalf("create: %+v %v", created, err)
	}
	subject, _ := body["subject"].(map[string]any)
	for _, k := range []string{"requestId", "question", "subject"} {
		if _, ok := body[k]; !ok {
			t.Errorf("create body lacks %q", k)
		}
	}
	for _, k := range []string{"schema", "id", "digest", "revision", "expires_at", "preview", "preview_complete"} {
		if _, ok := subject[k]; !ok {
			t.Errorf("subject lacks %q", k)
		}
	}
	if len(subject) != 7 || len(body) != 3 {
		t.Errorf("unknown fields sent (SuperPipeline refuses them): body=%d subject=%d", len(body), len(subject))
	}
	rb, err := c.ReadApprovalRequest(context.Background(), testBoard, "apr_1")
	if err != nil || rb.State != "approved" || *rb.Option != "allow_once" || rb.DecidedBy.Label != "A" {
		t.Fatalf("read: %+v %v", rb, err)
	}
	want := []string{"write POST /v1/boards/brd_fixture/approval-requests", "read GET /v1/boards/brd_fixture/approval-requests/apr_1"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %v; want %v", calls, want)
	}
}

// canned answers one credential's requests with a fixed response and records
// what was sent.
type canned struct {
	cred   string
	status int
	out    string
	calls  *[]string
	body   *map[string]any
}

func (c canned) Do(_ context.Context, r *http.Request) (*http.Response, error) {
	*c.calls = append(*c.calls, c.cred+" "+r.Method+" "+r.URL.Path)
	if r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, c.body)
	}
	return &http.Response{StatusCode: c.status, Body: io.NopCloser(strings.NewReader(c.out))}, nil
}
