package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type gateStub struct {
	confirmation GateConfirmation
	err          error
	confirms     int
	recorded     []string
}

func (g *gateStub) Confirm(_ context.Context, _, _, _ string) (GateConfirmation, error) {
	g.confirms++
	out := g.confirmation
	if out.Approved && out.ExpiresAt == "" {
		out.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	}
	return out, g.err
}
func (g *gateStub) RecordDelivered(_ context.Context, _, _, _, liveURL string) error {
	g.recorded = append(g.recorded, liveURL)
	return nil
}

type xStub struct {
	sends     []SendResult
	sendErrs  []error
	reads     []ReadBackResult
	readErrs  []error
	sendCalls int
	readCalls int
	digests   []string
}

func (x *xStub) Send(_ context.Context, req GatedRequest) (SendResult, error) {
	i := x.sendCalls
	x.sendCalls++
	x.digests = append(x.digests, req.Digest())
	var result SendResult
	var err error
	if i < len(x.sends) {
		result = x.sends[i]
	}
	if i < len(x.sendErrs) {
		err = x.sendErrs[i]
	}
	return result, err
}
func (x *xStub) ReadBack(_ context.Context, _ GatedRequest, _ SendResult) (ReadBackResult, error) {
	i := x.readCalls
	x.readCalls++
	var result ReadBackResult
	var err error
	if i < len(x.reads) {
		result = x.reads[i]
	}
	if i < len(x.readErrs) {
		err = x.readErrs[i]
	}
	return result, err
}

func gatedFixture(t *testing.T) (*Queue, *Effect, GatedRequest) {
	t.Helper()
	q := mustOpen(t, time.Minute)
	req := GatedRequest{
		BoardID: "brd_0123456789abcdef", SubjectID: "aps_0123456789abcdef",
		Method: "POST", URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"frozen copy"}`),
		Media: [][]byte{[]byte("first"), []byte("second")},
	}
	e, err := q.SubmitGated(req, "Publish frozen copy")
	if err != nil {
		t.Fatal(err)
	}
	return q, e, req
}

func TestHTTPClientsJoinSuperPipelineGateToXAndCardRecord(t *testing.T) {
	var verifyCalls, sends, reads, cardWrites int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/verify"):
			verifyCalls++
			if r.Header.Get("Authorization") != "Bearer approvals-read" {
				t.Errorf("verify credential = %q", r.Header.Get("Authorization"))
			}
			var body struct {
				ExpectedDigest string `json:"expectedDigest"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			_ = json.NewEncoder(w).Encode(GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: body.ExpectedDigest, GateID: "gate_http", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
		case strings.HasSuffix(r.URL.Path, "/delivery"):
			cardWrites++
			if r.Header.Get("Authorization") != "Bearer approvals-write" {
				t.Errorf("delivery credential = %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodPost && r.URL.Path == "/2/tweets":
			sends++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"123"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/2/tweets/123":
			reads++
			_, _ = w.Write([]byte(`{"data":{"id":"123","text":"http fixture"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	q := mustOpen(t, time.Minute)
	req := GatedRequest{BoardID: "brd_0123456789abcdef", SubjectID: "aps_0123456789abcdef", Method: http.MethodPost, URL: server.URL + "/2/tweets", Body: []byte(`{"text":"http fixture"}`)}
	e := q.Submit("x", "post_tweet", "http fixture", map[string]string{"_approval_authority": "superpipeline", "_approval_board": req.BoardID, "_approval_subject": req.SubjectID})
	client := &SuperPipelineHTTPClient{BaseURL: server.URL, HTTP: server.Client(), ApprovalToken: func(context.Context) (string, error) { return "approvals-read", nil }, DeliveryToken: func(context.Context) (string, error) { return "approvals-write", nil }}
	gate := &SubjectBoundGate{SuperPipelineHTTPClient: client, SubjectID: req.SubjectID}
	x := &XHTTPProvider{Username: "fixture", Do: func(ctx context.Context, request *http.Request) (*http.Response, error) {
		return server.Client().Do(request.WithContext(ctx))
	}}
	got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
	if err != nil || got.Outcome != "delivered" || got.LiveURL != "https://x.com/fixture/status/123" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if verifyCalls != 1 || sends != 1 || reads != 1 || cardWrites != 1 {
		t.Fatalf("verify/send/read/card = %d/%d/%d/%d", verifyCalls, sends, reads, cardWrites)
	}
}

func TestAutomaticXPublishingEndToEndRecordsVerifiedLiveURL(t *testing.T) {
	q, e, req := gatedFixture(t)
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture"}}
	x := &xStub{sends: []SendResult{{StatusCode: 201}}, reads: []ReadBackResult{{Status: ReadBackFound, LiveURL: "https://x.com/fixture/status/123"}}}

	got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "delivered" || got.LiveURL != "https://x.com/fixture/status/123" {
		t.Fatalf("effect = %+v, want delivered canonical URL", got)
	}
	if gate.confirms != 1 || x.sendCalls != 1 || x.readCalls != 1 {
		t.Fatalf("confirm/send/read = %d/%d/%d, want 1/1/1", gate.confirms, x.sendCalls, x.readCalls)
	}
	if fmt.Sprint(gate.recorded) != "[https://x.com/fixture/status/123]" {
		t.Fatalf("card URLs = %v", gate.recorded)
	}
}

func TestCompleteRequestDigestBindsMethodURLBodyAndOrderedMedia(t *testing.T) {
	_, _, base := gatedFixture(t)
	clone := func(in GatedRequest) GatedRequest {
		out := in
		out.Body = append([]byte(nil), in.Body...)
		out.Media = make([][]byte, len(in.Media))
		for i := range in.Media {
			out.Media[i] = append([]byte(nil), in.Media[i]...)
		}
		return out
	}
	variants := []GatedRequest{clone(base), clone(base), clone(base), clone(base), clone(base)}
	variants[0].Method = "PUT"
	variants[1].URL += "?changed=1"
	variants[2].Body = []byte(`{"text":"changed"}`)
	variants[3].Media = [][]byte{[]byte("second"), []byte("first")}
	variants[4].Media[0] = []byte("changed")
	for i, changed := range variants {
		if changed.Digest() == base.Digest() {
			t.Errorf("variant %d did not change digest", i)
		}
	}
}

func TestDigestMismatchRefusesAndDurablyRecordsBothDigests(t *testing.T) {
	q, e, req := gatedFixture(t)
	approved := req.Digest()
	req.Body = append(req.Body, ' ')
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: approved, GateID: "gate_fixture"}}
	x := &xStub{}
	got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
	if err == nil {
		t.Fatal("digest mismatch succeeded")
	}
	if got.State != Refused || got.ApprovedDigest != approved || got.RequestDigest != req.Digest() {
		t.Fatalf("record = %+v, want refused with both digests", got)
	}
	stored, _ := q.Get(e.ID)
	if stored.ApprovedDigest != approved || stored.RequestDigest != req.Digest() {
		t.Fatalf("durable record lost digests: %+v", stored)
	}
	if x.sendCalls != 0 {
		t.Fatal("mismatched request was sent")
	}
}

func TestHTTPGateDigestMismatchRefusesAndDurablyRecordsBothDigests(t *testing.T) {
	q, e, req := gatedFixture(t)
	approved := req.Digest()
	req.Body = append(req.Body, ' ')
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/verify") {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(GateConfirmation{
			Approved: false, DeliveryMode: "automatic", Digest: approved, GateID: "gate_fixture",
		})
	}))
	defer server.Close()
	client := &SuperPipelineHTTPClient{
		BaseURL: server.URL,
		HTTP:    server.Client(),
		ApprovalToken: func(context.Context) (string, error) {
			return "approvals-read", nil
		},
	}
	x := &xStub{}
	got, err := (&Publisher{Queue: q, Gate: client, X: x}).Perform(context.Background(), e.ID, req)
	if err == nil || got.State != Refused {
		t.Fatalf("got %+v, %v; want refused", got, err)
	}
	if got.ApprovedDigest != approved || got.RequestDigest != req.Digest() {
		t.Fatalf("record = %+v, want approved %s and request %s", got, approved, req.Digest())
	}
	stored, _ := q.Get(e.ID)
	if stored.ApprovedDigest != approved || stored.RequestDigest != req.Digest() {
		t.Fatalf("durable record lost digests: %+v", stored)
	}
	if x.sendCalls != 0 {
		t.Fatal("mismatched request was sent")
	}
}

func TestNonAutomaticGateOutcomesNeverSend(t *testing.T) {
	for _, outcome := range []string{"manual", "rejected", "changes_requested", "expired"} {
		t.Run(outcome, func(t *testing.T) {
			q, e, req := gatedFixture(t)
			gate := &gateStub{confirmation: GateConfirmation{Approved: false, DeliveryMode: outcome, Digest: req.Digest(), GateID: "gate_fixture"}}
			x := &xStub{}
			got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
			if err == nil || got.State != Refused {
				t.Fatalf("got %+v, %v", got, err)
			}
			if x.sendCalls != 0 {
				t.Fatalf("%s gate sent %d times", outcome, x.sendCalls)
			}
		})
	}
}

func TestTransientGateErrorLeavesEffectPending(t *testing.T) {
	q, e, req := gatedFixture(t)
	gate := &gateStub{err: errors.New("temporary SuperPipeline outage")}
	got, err := (&Publisher{Queue: q, Gate: gate, X: &xStub{}}).Perform(context.Background(), e.ID, req)
	if err == nil || got.State != Pending || got.Outcome != "" {
		t.Fatalf("got %+v, %v; want untouched pending effect", got, err)
	}
}

func TestProvider4xxAnd5xxAreTrueFailuresWithoutReadBack(t *testing.T) {
	for _, status := range []int{400, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			q, e, req := gatedFixture(t)
			gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture"}}
			x := &xStub{sends: []SendResult{{StatusCode: status}}}
			got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
			if err == nil || got.Outcome != "provider_error" {
				t.Fatalf("got %+v, %v", got, err)
			}
			if x.readCalls != 0 {
				t.Fatal("confirmed provider error triggered read-back")
			}
		})
	}
}

func TestUnknownOutcomeReadBackFoundDeliversWithoutRetry(t *testing.T) {
	for _, transport := range []string{"timeout", "drop"} {
		t.Run(transport, func(t *testing.T) {
			q, e, req := gatedFixture(t)
			gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture"}}
			x := &xStub{sendErrs: []error{UnknownOutcome(errors.New(transport))}, reads: []ReadBackResult{{Status: ReadBackFound, LiveURL: "https://x.com/a/status/9"}}}
			got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
			if err != nil || got.Outcome != "delivered" || x.sendCalls != 1 {
				t.Fatalf("got %+v, %v", got, err)
			}
		})
	}
}

func TestNegativeReadBackRemainsFencedWithoutRetry(t *testing.T) {
	q, e, req := gatedFixture(t)
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture"}}
	x := &xStub{
		sends:    []SendResult{{}, {StatusCode: 201}},
		sendErrs: []error{UnknownOutcome(errors.New("connection dropped")), nil},
		reads:    []ReadBackResult{{Status: ReadBackNotFound}, {Status: ReadBackFound, LiveURL: "https://x.com/a/status/10"}},
	}
	got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
	if err == nil || got.Outcome != "outcome_unknown" || got.Attempts != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if x.sendCalls != 1 || gate.confirms != 1 {
		t.Fatalf("send/confirm = %d/%d, want 1/1", x.sendCalls, gate.confirms)
	}
}

type concurrentRecoveryGate struct {
	digest   string
	confirms atomic.Int32
}

func (g *concurrentRecoveryGate) Confirm(_ context.Context, _, _, _ string) (GateConfirmation, error) {
	g.confirms.Add(1)
	return GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: g.digest, GateID: "gate_fixture", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}, nil
}

func (*concurrentRecoveryGate) RecordDelivered(context.Context, string, string, string, string) error {
	return nil
}

type concurrentRecoveryX struct {
	sends atomic.Int32
}

type slowInFlightX struct {
	sends      atomic.Int32
	released   atomic.Bool
	entered    chan struct{}
	release    chan struct{}
	secondSend chan struct{}
	enterOnce  sync.Once
	secondOnce sync.Once
}

func (x *slowInFlightX) Send(context.Context, GatedRequest) (SendResult, error) {
	call := x.sends.Add(1)
	if call == 1 {
		x.enterOnce.Do(func() { close(x.entered) })
		<-x.release
	} else {
		x.secondOnce.Do(func() { close(x.secondSend) })
	}
	return SendResult{StatusCode: http.StatusCreated, PostID: fmt.Sprintf("post-%d", call)}, nil
}

func (x *slowInFlightX) ReadBack(context.Context, GatedRequest, SendResult) (ReadBackResult, error) {
	if !x.released.Load() {
		return ReadBackResult{Status: ReadBackNotFound}, nil
	}
	return ReadBackResult{Status: ReadBackFound, LiveURL: "https://x.com/fixture/status/slow"}, nil
}

func (*concurrentRecoveryX) ReadBack(context.Context, GatedRequest, SendResult) (ReadBackResult, error) {
	return ReadBackResult{Status: ReadBackNotFound}, nil
}

func (x *concurrentRecoveryX) Send(context.Context, GatedRequest) (SendResult, error) {
	x.sends.Add(1)
	return SendResult{StatusCode: http.StatusServiceUnavailable}, nil
}

// Regression guarded: a search miss is inconclusive, so even concurrent
// recovery processes must keep the fence and perform no retry.
func TestConcurrentRecoveriesKeepNegativeReadBackFenced(t *testing.T) {
	dir := t.TempDir()
	q1, err := Open(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := GatedRequest{BoardID: "brd_0123456789abcdef", SubjectID: "aps_0123456789abcdef", Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"one retry"}`)}
	e, err := q1.SubmitGated(req, "concurrent recovery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q1.decide(e.ID, true, "superpipeline:gate_fixture", true); err != nil {
		t.Fatal(err)
	}
	if err := q1.writePublication(e.ID, publicationRecord{
		Outcome: "outcome_unknown", ApprovedDigest: req.Digest(), RequestDigest: req.Digest(), GateID: "gate_fixture", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}

	x := &concurrentRecoveryX{}
	gate := &concurrentRecoveryGate{digest: req.Digest()}
	publishers := []*Publisher{{Queue: q1, Gate: gate, X: x}, {Queue: q2, Gate: gate, X: x}}
	start := make(chan struct{})
	errs := make(chan error, len(publishers))
	var wg sync.WaitGroup
	for _, publisher := range publishers {
		wg.Add(1)
		go func(p *Publisher) {
			defer wg.Done()
			<-start
			_, runErr := p.Perform(context.Background(), e.ID, req)
			errs <- runErr
		}(publisher)
	}
	close(start)
	wg.Wait()
	close(errs)
	for runErr := range errs {
		if runErr == nil {
			t.Error("recovery unexpectedly succeeded against fixture 503")
		}
	}
	if got := x.sends.Load(); got != 0 {
		t.Fatalf("provider retries = %d, want 0", got)
	}
	stored, _ := q1.Get(e.ID)
	if stored.Attempts != 1 {
		t.Fatalf("durable attempts = %d, want 1", stored.Attempts)
	}
}

// Regression guarded: a recovery process that observes the durable sending
// marker while the original provider call is still in flight must not interpret
// that marker as an abandoned publisher and issue a duplicate post.
func TestRecoveryDuringSlowSendDoesNotPostAgain(t *testing.T) {
	dir := t.TempDir()
	q1, err := Open(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	q2, err := Open(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := GatedRequest{BoardID: "brd_0123456789abcdef", SubjectID: "aps_0123456789abcdef", Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"slow send"}`)}
	e := q1.Submit("x", "post_tweet", "slow in-flight send", map[string]string{
		"_approval_authority": "superpipeline", "_approval_board": req.BoardID, "_approval_subject": req.SubjectID,
	})

	x := &slowInFlightX{
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
		secondSend: make(chan struct{}),
	}
	gate := &concurrentRecoveryGate{digest: req.Digest()}
	firstDone := make(chan error, 1)
	go func() {
		_, runErr := (&Publisher{Queue: q1, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
		firstDone <- runErr
	}()
	select {
	case <-x.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first publisher never entered the provider send")
	}

	recoveryDone := make(chan error, 1)
	go func() {
		_, runErr := (&Publisher{Queue: q2, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
		recoveryDone <- runErr
	}()

	duplicate := false
	select {
	case <-x.secondSend:
		duplicate = true
	case <-time.After(200 * time.Millisecond):
	}
	x.released.Store(true)
	close(x.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first publisher: %v", err)
	}
	if err := <-recoveryDone; err != nil {
		t.Fatalf("recovery publisher: %v", err)
	}

	if duplicate || x.sends.Load() != 1 {
		t.Fatalf("provider sends while the original send was in flight = %d; want 1", x.sends.Load())
	}
}

func TestAcknowledgedPostIDIsNeverRetriedWhenExactReadBackIsNotFound(t *testing.T) {
	q, e, req := gatedFixture(t)
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture"}}
	x := &xStub{
		sends: []SendResult{{StatusCode: http.StatusCreated, PostID: "acknowledged-post"}},
		reads: []ReadBackResult{{Status: ReadBackNotFound}, {Status: ReadBackNotFound}},
	}
	publisher := &Publisher{Queue: q, Gate: gate, X: x}
	if got, err := publisher.Perform(context.Background(), e.ID, req); err == nil || got.Outcome != "outcome_unknown" {
		t.Fatalf("first read-back = %+v, %v", got, err)
	}
	got, err := publisher.Perform(context.Background(), e.ID, req)
	if err == nil || got.Outcome != "outcome_unknown" || x.sendCalls != 1 || got.PostID != "acknowledged-post" || !strings.Contains(got.Error, "retry remains fenced") {
		t.Fatalf("recovery = %+v, %v; sends=%d", got, err, x.sendCalls)
	}
}

func TestInconclusiveReadBackRemainsFenced(t *testing.T) {
	q, e, req := gatedFixture(t)
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture"}}
	x := &xStub{sendErrs: []error{UnknownOutcome(errors.New("timeout"))}, reads: []ReadBackResult{{Status: ReadBackInconclusive}, {Status: ReadBackInconclusive}}}
	p := &Publisher{Queue: q, Gate: gate, X: x}
	got, err := p.Perform(context.Background(), e.ID, req)
	if err == nil || got.Outcome != "outcome_unknown" {
		t.Fatalf("got %+v, %v", got, err)
	}
	got, err = p.Perform(context.Background(), e.ID, req)
	if err == nil || got.Outcome != "outcome_unknown" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if x.sendCalls != 1 {
		t.Fatalf("inconclusive read-back allowed %d sends", x.sendCalls)
	}
}

func TestChangedRequestAfterUnknownOutcomeIsRefusedBeforeReadBackOrRetry(t *testing.T) {
	q, e, req := gatedFixture(t)
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture"}}
	x := &xStub{
		sendErrs: []error{UnknownOutcome(errors.New("timeout"))},
		reads:    []ReadBackResult{{Status: ReadBackInconclusive}},
	}
	p := &Publisher{Queue: q, Gate: gate, X: x}
	if got, err := p.Perform(context.Background(), e.ID, req); err == nil || got.Outcome != "outcome_unknown" {
		t.Fatalf("first attempt = %+v, %v", got, err)
	}
	approved := req.Digest()
	req.Body = append(req.Body, ' ')
	got, err := p.Perform(context.Background(), e.ID, req)
	if err == nil || got.Outcome != "outcome_unknown" {
		t.Fatalf("changed request = %+v, %v; want preserved outcome_unknown fence", got, err)
	}
	if got.ApprovedDigest != approved || got.RequestDigest != approved {
		t.Fatalf("record was overwritten: %+v", got)
	}
	if x.sendCalls != 1 || x.readCalls != 1 {
		t.Fatalf("changed request caused send/read-back: %d/%d", x.sendCalls, x.readCalls)
	}
}

func TestXHTTPProviderSendsExactBytesAndReadsCanonicalURL(t *testing.T) {
	request := GatedRequest{Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"Exact approved fixture text."}`)}
	provider := &XHTTPProvider{Username: "fixture", Do: func(_ context.Context, got *http.Request) (*http.Response, error) {
		if got.Method == http.MethodPost {
			body, _ := io.ReadAll(got.Body)
			if string(body) != string(request.Body) || got.URL.String() != request.URL {
				t.Fatalf("write changed request: %s %s", got.URL, body)
			}
			return &http.Response{StatusCode: 201, Body: io.NopCloser(strings.NewReader(`{"data":{"id":"123"}}`))}, nil
		}
		if got.Method != http.MethodGet || got.URL.Path != "/2/tweets/123" {
			t.Fatalf("unexpected read-back request: %s %s", got.Method, got.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":{"id":"123","text":"Exact approved fixture text."}}`))}, nil
	}}
	if result, err := provider.Send(context.Background(), request); err != nil || result.StatusCode != 201 {
		t.Fatalf("send = %+v, %v", result, err)
	}
	if request.Digest() != "sha256:1c9763d267117f796b38ee41266eb01ebc2ece548dc13ef9b96ac6ffd8aed7ca" {
		t.Fatalf("cross-product digest = %s", request.Digest())
	}
	read, err := provider.ReadBack(context.Background(), request, SendResult{PostID: "123"})
	if err != nil || read.Status != ReadBackFound || read.LiveURL != "https://x.com/fixture/status/123" {
		t.Fatalf("read-back = %+v, %v", read, err)
	}
}

func TestXHTTPProviderVerifiesTheCreatedPostIDNotAnOlderIdenticalPost(t *testing.T) {
	request := GatedRequest{Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"repeated copy"}`)}
	provider := &XHTTPProvider{Username: "fixture", Do: func(_ context.Context, got *http.Request) (*http.Response, error) {
		switch {
		case got.Method == http.MethodPost && got.URL.Path == "/2/tweets":
			return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{"data":{"id":"new-post"}}`))}, nil
		case got.Method == http.MethodGet && got.URL.Path == "/2/tweets/new-post":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":{"id":"new-post","text":"repeated copy"}}`))}, nil
		case got.Method == http.MethodGet && got.URL.Path == "/2/tweets/search/recent":
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":[{"id":"older-post","text":"repeated copy"}]}`))}, nil
		default:
			t.Fatalf("unexpected X request: %s %s", got.Method, got.URL)
			return nil, nil
		}
	}}

	q, e, gated := gatedFixture(t)
	gated.Method, gated.URL, gated.Body, gated.Media = request.Method, request.URL, request.Body, nil
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: gated.Digest(), GateID: "gate_fixture"}}
	got, err := (&Publisher{Queue: q, Gate: gate, X: provider}).Perform(context.Background(), e.ID, gated)
	if err != nil {
		t.Fatal(err)
	}
	if got.LiveURL != "https://x.com/fixture/status/new-post" || got.PostID != "new-post" {
		t.Fatalf("recorded live URL = %q, want the id returned by create", got.LiveURL)
	}
}

func TestXHTTPProviderDoesNotCorrelateUnknownSendFromIdenticalTextAlone(t *testing.T) {
	request := GatedRequest{Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"repeated copy"}`)}
	provider := &XHTTPProvider{Username: "fixture", Do: func(_ context.Context, got *http.Request) (*http.Response, error) {
		if got.Method != http.MethodGet || got.URL.Path != "/2/tweets/search/recent" {
			t.Fatalf("unexpected X request: %s %s", got.Method, got.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":[{"id":"older-post","text":"repeated copy"}]}`))}, nil
	}}
	read, err := provider.ReadBack(context.Background(), request, SendResult{})
	if err == nil || read.Status != ReadBackInconclusive {
		t.Fatalf("read-back = %+v, %v; identical text without create id must stay fenced", read, err)
	}
}

func TestAutomaticXPublishingUploadsFrozenMediaInOrderAndVerifiesIt(t *testing.T) {
	media := [][]byte{
		append([]byte("\x89PNG\r\n\x1a\n"), []byte("first-image")...),
		append([]byte("\x89PNG\r\n\x1a\n"), []byte("second-image")...),
	}
	var initialized, appended, finalized, posts, reads int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/2/media/upload/initialize":
			initialized++
			var body struct {
				MediaType     string `json:"media_type"`
				TotalBytes    int    `json:"total_bytes"`
				MediaCategory string `json:"media_category"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.MediaType != "image/png" || body.TotalBytes != len(media[initialized-1]) || body.MediaCategory != "tweet_image" {
				t.Fatalf("initialize %d = %+v, %v", initialized, body, err)
			}
			_, _ = fmt.Fprintf(w, `{"data":{"id":"media-%d"}}`, initialized)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/append"):
			appended++
			if err := r.ParseMultipartForm(6 << 20); err != nil {
				t.Fatal(err)
			}
			if r.FormValue("segment_index") != "0" {
				t.Fatalf("segment index = %q", r.FormValue("segment_index"))
			}
			file, _, err := r.FormFile("media")
			if err != nil {
				t.Fatal(err)
			}
			got, _ := io.ReadAll(file)
			_ = file.Close()
			if string(got) != string(media[appended-1]) {
				t.Fatalf("append %d changed frozen bytes", appended)
			}
			_, _ = w.Write([]byte(`{"data":{"expires_at":1}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/finalize"):
			finalized++
			_, _ = fmt.Fprintf(w, `{"data":{"id":"media-%d"}}`, finalized)
		case r.Method == http.MethodPost && r.URL.Path == "/2/tweets":
			posts++
			var body struct {
				Text  string `json:"text"`
				Media struct {
					IDs []string `json:"media_ids"`
				} `json:"media"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Text != "media fixture" || fmt.Sprint(body.Media.IDs) != "[media-1 media-2]" {
				t.Fatalf("post body = %+v", body)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"post-media"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/2/tweets/post-media":
			reads++
			_, _ = w.Write([]byte(`{"data":{"id":"post-media","text":"media fixture","attachments":{"media_keys":["3_media-1","3_media-2"]}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	q, e, req := gatedFixture(t)
	req.URL, req.Body, req.Media = server.URL+"/2/tweets", []byte(`{"text":"media fixture"}`), media
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_media"}}
	x := &XHTTPProvider{Username: "fixture", Do: func(ctx context.Context, request *http.Request) (*http.Response, error) {
		return server.Client().Do(request.WithContext(ctx))
	}}
	got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
	if err != nil || got.Outcome != "delivered" || got.LiveURL != "https://x.com/fixture/status/post-media" || got.PostID != "post-media" || fmt.Sprint(got.MediaIDs) != "[media-1 media-2]" {
		t.Fatalf("effect = %+v, %v", got, err)
	}
	if initialized != 2 || appended != 2 || finalized != 2 || posts != 1 || reads != 1 {
		t.Fatalf("init/append/finalize/post/read = %d/%d/%d/%d/%d", initialized, appended, finalized, posts, reads)
	}
}

func TestAutomaticXPublishingMediaFailuresNeverCreateAPost(t *testing.T) {
	for _, failPath := range []string{"initialize", "append", "finalize"} {
		t.Run(failPath, func(t *testing.T) {
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, failPath) {
					http.Error(w, "fixture failure", http.StatusBadGateway)
					return
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/initialize"):
					_, _ = w.Write([]byte(`{"data":{"id":"media-1"}}`))
				case strings.HasSuffix(r.URL.Path, "/append"):
					_, _ = w.Write([]byte(`{"data":{"expires_at":1}}`))
				case strings.HasSuffix(r.URL.Path, "/finalize"):
					_, _ = w.Write([]byte(`{"data":{"id":"media-1"}}`))
				case r.URL.Path == "/2/tweets":
					posts++
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"data":{"id":"must-not-exist"}}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			q, e, req := gatedFixture(t)
			req.URL = server.URL + "/2/tweets"
			req.Body = []byte(`{"text":"media failure"}`)
			req.Media = [][]byte{append([]byte("\x89PNG\r\n\x1a\n"), []byte("image")...)}
			gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_media"}}
			x := &XHTTPProvider{Username: "fixture", Do: func(ctx context.Context, request *http.Request) (*http.Response, error) {
				return server.Client().Do(request.WithContext(ctx))
			}}
			got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
			if err == nil || got.Outcome != "provider_error" || posts != 0 || !strings.Contains(got.Error, failPath) {
				t.Fatalf("effect = %+v, err=%v, posts=%d", got, err, posts)
			}
		})
	}
}

func TestGatedEffectUsesGateExpiryAndKeepsUnknownFenceDuringCleanup(t *testing.T) {
	q, e, req := gatedFixture(t)
	originalNow := q.now()
	q.now = func() time.Time { return originalNow.Add(2 * time.Minute) }
	gate := &gateStub{confirmation: GateConfirmation{
		Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture",
		ExpiresAt: originalNow.Add(time.Hour).UTC().Format(time.RFC3339),
	}}
	x := &xStub{sends: []SendResult{{StatusCode: http.StatusCreated, PostID: "late"}}, reads: []ReadBackResult{{Status: ReadBackFound, LiveURL: "https://x.com/fixture/status/late"}}}
	if got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req); err != nil || got.Outcome != "delivered" {
		t.Fatalf("late approved gate = %+v, %v", got, err)
	}

	q2, fenced, req2 := gatedFixture(t)
	if _, err := q2.decide(fenced.ID, true, "superpipeline:gate_fixture", true); err != nil {
		t.Fatal(err)
	}
	if err := q2.writePublication(fenced.ID, publicationRecord{Outcome: "outcome_unknown", RequestDigest: req2.Digest(), ApprovedDigest: req2.Digest(), Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	q2.now = func() time.Time { return fenced.Submitted.Add(48 * time.Hour) }
	if got := q2.List(); len(got) != 1 || got[0].Outcome != "outcome_unknown" {
		t.Fatalf("cleanup removed unknown-outcome fence: %+v", got)
	}

	q3, abandoned, _ := gatedFixture(t)
	q3.now = func() time.Time { return abandoned.Submitted.Add(gatedBackstopTTL + time.Second) }
	if got, ok := q3.Get(abandoned.ID); !ok || got.State != Expired {
		t.Fatalf("unconfirmed gated backstop = %+v, %v; want expired", got, ok)
	}

	q4, legacy, _ := gatedFixture(t)
	legacy.Expires = legacy.Submitted.Add(q4.ttl)
	body, _ := json.Marshal(legacy)
	if err := os.WriteFile(q4.reqPath(legacy.ID), body, 0o600); err != nil {
		t.Fatal(err)
	}
	q4.now = func() time.Time { return legacy.Submitted.Add(time.Hour) }
	if got, ok := q4.Get(legacy.ID); !ok || got.State != Pending || !got.Expires.Equal(legacy.Submitted.Add(gatedBackstopTTL)) {
		t.Fatalf("legacy gated expiry migration = %+v, %v", got, ok)
	}
}

func TestExpiredUnconfirmedGateBecomesTerminalAndCannotSendLater(t *testing.T) {
	q, e, req := gatedFixture(t)
	q.now = func() time.Time { return e.Submitted.Add(gatedBackstopTTL + time.Second) }
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "late"}}
	x := &xStub{}
	publisher := &Publisher{Queue: q, Gate: gate, X: x}
	got, err := publisher.Perform(context.Background(), e.ID, req)
	if err == nil || got.State != Expired || x.sendCalls != 0 || gate.confirms != 0 {
		t.Fatalf("expired gate = %+v, %v; sends=%d confirms=%d", got, err, x.sendCalls, gate.confirms)
	}
	rec, readErr := q.readPublication(e.ID)
	if readErr != nil || rec.Outcome != "refused" {
		t.Fatalf("terminal publication = %+v, %v", rec, readErr)
	}
	if _, err := publisher.Perform(context.Background(), e.ID, req); err == nil || x.sendCalls != 0 || gate.confirms != 0 {
		t.Fatalf("late approval re-enabled expired gate: err=%v sends=%d confirms=%d", err, x.sendCalls, gate.confirms)
	}
}

func TestXReadBackNormalizesLinksWithAndWithoutKnownPostID(t *testing.T) {
	request := GatedRequest{Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"read https://example.com/story"}`)}
	for _, tc := range []struct {
		name       string
		sent       SendResult
		path       string
		body       string
		wantStatus ReadBackStatus
	}{
		{name: "known id", sent: SendResult{PostID: "known"}, path: "/2/tweets/known", body: `{"data":{"id":"known","text":"read https://t.co/a","entities":{"urls":[{"url":"https://t.co/a","expanded_url":"https://example.com/story"}]}}}`, wantStatus: ReadBackFound},
		{name: "recent search", path: "/2/tweets/search/recent", body: `{"data":[{"id":"searched","text":"read https://t.co/a","entities":{"urls":[{"url":"https://t.co/a","expanded_url":"https://example.com/story"}]}}]}`, wantStatus: ReadBackInconclusive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &XHTTPProvider{Username: "fixture", Do: func(_ context.Context, got *http.Request) (*http.Response, error) {
				if got.URL.Path != tc.path {
					t.Fatalf("path = %s, want %s", got.URL.Path, tc.path)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}}
			result, err := provider.ReadBack(context.Background(), request, tc.sent)
			if result.Status != tc.wantStatus || (tc.wantStatus == ReadBackFound && (err != nil || !strings.Contains(result.LiveURL, "/status/"))) {
				t.Fatalf("read-back = %+v, %v", result, err)
			}
		})
	}
}

func TestAutomaticXPublishingMediaReadBackMismatchStaysFenced(t *testing.T) {
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/initialize"):
			_, _ = w.Write([]byte(`{"data":{"id":"media-1"}}`))
		case strings.HasSuffix(r.URL.Path, "/append"):
			_, _ = w.Write([]byte(`{"data":{"expires_at":1}}`))
		case strings.HasSuffix(r.URL.Path, "/finalize"):
			_, _ = w.Write([]byte(`{"data":{"id":"media-1"}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/2/tweets":
			posts++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"data":{"id":"post-media"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/2/tweets/post-media":
			_, _ = w.Write([]byte(`{"data":{"id":"post-media","text":"media mismatch","attachments":{"media_keys":["3_other-media"]}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	q, e, req := gatedFixture(t)
	req.URL = server.URL + "/2/tweets"
	req.Body = []byte(`{"text":"media mismatch"}`)
	req.Media = [][]byte{append([]byte("\x89PNG\r\n\x1a\n"), []byte("image")...)}
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_media"}}
	x := &XHTTPProvider{Username: "fixture", Do: func(ctx context.Context, request *http.Request) (*http.Response, error) {
		return server.Client().Do(request.WithContext(ctx))
	}}
	got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
	if err == nil || got.Outcome != "outcome_unknown" || posts != 1 || len(gate.recorded) != 0 || !strings.Contains(got.Error, "media") {
		t.Fatalf("effect = %+v, err=%v, posts=%d, card=%v", got, err, posts, gate.recorded)
	}
}

func TestPublisherPathStillRefusesLocalApproval(t *testing.T) {
	q, e, _ := gatedFixture(t)
	sends := 0
	got, err := q.DecideAndPerform(e.ID, true, "shell-agent", func(*Effect) (string, error) { sends++; return "201 Created", nil })
	if sends != 0 || err == nil || (got != nil && got.State != Pending) {
		t.Fatalf("got %+v, err %v, sends %d", got, err, sends)
	}
	if !strings.Contains(err.Error(), "direct SuperPipeline") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRecentSearchMissRemainsInconclusive(t *testing.T) {
	request := GatedRequest{Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"approved text"}`)}
	provider := &XHTTPProvider{Username: "fixture", Do: func(context.Context, *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":[]}`))}, nil
	}}
	result, err := provider.ReadBack(context.Background(), request, SendResult{})
	if result.Status != ReadBackInconclusive || err == nil || !strings.Contains(err.Error(), "not indexed") {
		t.Fatalf("read-back = %+v, %v; search miss must stay fenced", result, err)
	}
}

func TestKnownPostIDStillRequiresApprovedContent(t *testing.T) {
	request := GatedRequest{Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"approved text"}`)}
	provider := &XHTTPProvider{Username: "fixture", Do: func(_ context.Context, got *http.Request) (*http.Response, error) {
		if got.URL.Query().Get("tweet.fields") != "attachments,entities,note_tweet" {
			t.Fatalf("tweet.fields = %q", got.URL.Query().Get("tweet.fields"))
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":{"id":"planted","text":"someone else's post"}}`))}, nil
	}}
	result, err := provider.ReadBack(context.Background(), request, SendResult{PostID: "planted"})
	if result.Status != ReadBackInconclusive || err == nil || !strings.Contains(err.Error(), "content") {
		t.Fatalf("read-back = %+v, %v", result, err)
	}
}

func TestKnownPostIDNormalizesXRepresentations(t *testing.T) {
	for _, tc := range []struct{ name, approved, body string }{
		{"media suffix", "with image", `{"data":{"id":"known","text":"with image https://t.co/media","entities":{"urls":[{"url":"https://t.co/media","expanded_url":"https://x.com/fixture/status/1/photo/1","media_key":"3_fixture"}]}}}`},
		{"html escaped", "fish & chips", `{"data":{"id":"known","text":"fish &amp; chips"}}`},
		{"scheme-less link", "visit example.com/story", `{"data":{"id":"known","text":"visit https://t.co/a","entities":{"urls":[{"url":"https://t.co/a","expanded_url":"http://example.com/story"}]}}}`},
		{"long note", strings.Repeat("long form ", 40), `{"data":{"id":"known","text":"long form…","note_tweet":{"text":"` + strings.Repeat("long form ", 40) + `"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := GatedRequest{Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":` + strconv.Quote(tc.approved) + `}`)}
			provider := &XHTTPProvider{Username: "fixture", Do: func(_ context.Context, got *http.Request) (*http.Response, error) {
				if !strings.Contains(got.URL.Query().Get("tweet.fields"), "note_tweet") {
					t.Fatalf("tweet.fields = %q", got.URL.Query().Get("tweet.fields"))
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			}}
			result, err := provider.ReadBack(context.Background(), request, SendResult{PostID: "known"})
			if err != nil || result.Status != ReadBackFound {
				t.Fatalf("read-back = %+v, %v", result, err)
			}
		})
	}
}

func TestMissingApprovalExpiryNeverSends(t *testing.T) {
	q, e, req := gatedFixture(t)
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture", ExpiresAt: "invalid"}}
	x := &xStub{}
	got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
	if err == nil || got.State != Refused || x.sendCalls != 0 {
		t.Fatalf("got %+v, %v; sends=%d", got, err, x.sendCalls)
	}
}

func TestManualRecoveryStatesAreSurfacedWithoutSending(t *testing.T) {
	for _, outcome := range []string{"retry_allowed", ""} {
		t.Run(outcome, func(t *testing.T) {
			q, e, req := gatedFixture(t)
			if _, err := q.decide(e.ID, true, "superpipeline:gate_fixture", true); err != nil {
				t.Fatal(err)
			}
			if outcome != "" {
				if err := q.writePublication(e.ID, publicationRecord{Outcome: outcome, ApprovedDigest: req.Digest(), RequestDigest: req.Digest(), GateID: "gate_fixture"}); err != nil {
					t.Fatal(err)
				}
			}
			x := &xStub{}
			got, err := (&Publisher{Queue: q, Gate: &gateStub{}, X: x}).Perform(context.Background(), e.ID, req)
			if err == nil || got.State != Approved || x.sendCalls != 0 || !strings.Contains(err.Error(), "manual recovery") {
				t.Fatalf("got %+v, %v; sends=%d", got, err, x.sendCalls)
			}
		})
	}
}
