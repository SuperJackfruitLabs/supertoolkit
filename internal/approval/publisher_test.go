package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	return g.confirmation, g.err
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
func (x *xStub) ReadBack(_ context.Context, _ GatedRequest) (ReadBackResult, error) {
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
	e := q.Submit("x", "post_tweet", "Publish frozen copy", map[string]string{
		"_approval_authority": "superpipeline",
		"_approval_board":     req.BoardID,
		"_approval_subject":   req.SubjectID,
	})
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
			_ = json.NewEncoder(w).Encode(GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: body.ExpectedDigest, GateID: "gate_http"})
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
		case r.Method == http.MethodGet && r.URL.Path == "/2/tweets/search/recent":
			reads++
			_, _ = w.Write([]byte(`{"data":[{"id":"123","text":"http fixture"}]}`))
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
			gate := &gateStub{err: fmt.Errorf("gate %s", outcome)}
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

func TestNegativeReadBackAllowsExactlyOneUnchangedRetry(t *testing.T) {
	q, e, req := gatedFixture(t)
	gate := &gateStub{confirmation: GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: req.Digest(), GateID: "gate_fixture"}}
	x := &xStub{
		sends:    []SendResult{{}, {StatusCode: 201}},
		sendErrs: []error{UnknownOutcome(errors.New("connection dropped")), nil},
		reads:    []ReadBackResult{{Status: ReadBackNotFound}, {Status: ReadBackFound, LiveURL: "https://x.com/a/status/10"}},
	}
	got, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req)
	if err != nil || got.Outcome != "delivered" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if x.sendCalls != 2 || gate.confirms != 2 {
		t.Fatalf("send/confirm = %d/%d, want 2/2", x.sendCalls, gate.confirms)
	}
	if x.digests[0] != x.digests[1] || x.digests[0] != req.Digest() {
		t.Fatalf("retry digests = %v", x.digests)
	}
	if got.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", got.Attempts)
	}
	if _, err := (&Publisher{Queue: q, Gate: gate, X: x}).Perform(context.Background(), e.ID, req); err != nil {
		t.Fatal(err)
	}
	if x.sendCalls != 2 {
		t.Fatalf("delivered effect sent %d times", x.sendCalls)
	}
}

type concurrentRecoveryGate struct {
	digest   string
	confirms atomic.Int32
}

func (g *concurrentRecoveryGate) Confirm(_ context.Context, _, _, _ string) (GateConfirmation, error) {
	g.confirms.Add(1)
	return GateConfirmation{Approved: true, DeliveryMode: "automatic", Digest: g.digest, GateID: "gate_fixture"}, nil
}

func (*concurrentRecoveryGate) RecordDelivered(context.Context, string, string, string, string) error {
	return nil
}

type concurrentRecoveryX struct {
	readers  atomic.Int32
	sends    atomic.Int32
	bothRead chan struct{}
	once     sync.Once
}

func (x *concurrentRecoveryX) ReadBack(context.Context, GatedRequest) (ReadBackResult, error) {
	if x.readers.Add(1) == 2 {
		x.once.Do(func() { close(x.bothRead) })
	}
	<-x.bothRead
	return ReadBackResult{Status: ReadBackNotFound}, nil
}

func (x *concurrentRecoveryX) Send(context.Context, GatedRequest) (SendResult, error) {
	x.sends.Add(1)
	return SendResult{StatusCode: http.StatusServiceUnavailable}, nil
}

// Regression guarded: two recovery processes must not both turn the same
// negative read-back into the one permitted retry. Separate Queue values model
// separate processes; the claim therefore has to live in the filesystem, not a
// process-local mutex or a rename-based last-writer-wins record update.
func TestConcurrentRecoveriesClaimTheSingleRetryOnce(t *testing.T) {
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
	e := q1.Submit("x", "post_tweet", "concurrent recovery", map[string]string{
		"_approval_authority": "superpipeline", "_approval_board": req.BoardID, "_approval_subject": req.SubjectID,
	})
	if _, err := q1.decide(e.ID, true, "superpipeline:gate_fixture", true); err != nil {
		t.Fatal(err)
	}
	if err := q1.writePublication(e.ID, publicationRecord{
		Outcome: "outcome_unknown", ApprovedDigest: req.Digest(), RequestDigest: req.Digest(), GateID: "gate_fixture", Attempts: 1,
	}); err != nil {
		t.Fatal(err)
	}

	x := &concurrentRecoveryX{bothRead: make(chan struct{})}
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
	if got := x.sends.Load(); got != 1 {
		t.Fatalf("provider retries = %d, want exactly 1", got)
	}
	stored, _ := q1.Get(e.ID)
	if stored.Attempts != 2 {
		t.Fatalf("durable attempts = %d, want 2", stored.Attempts)
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
	if err == nil || got.Outcome != "refused" {
		t.Fatalf("changed request = %+v, %v; want refused", got, err)
	}
	if got.ApprovedDigest != approved || got.RequestDigest != req.Digest() {
		t.Fatalf("record = %+v, want both digests", got)
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
		if got.Method != http.MethodGet || got.URL.Path != "/2/tweets/search/recent" {
			t.Fatalf("unexpected read-back request: %s %s", got.Method, got.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":[{"id":"123","text":"Exact approved fixture text."}]}`))}, nil
	}}
	if result, err := provider.Send(context.Background(), request); err != nil || result.StatusCode != 201 {
		t.Fatalf("send = %+v, %v", result, err)
	}
	if request.Digest() != "sha256:1c9763d267117f796b38ee41266eb01ebc2ece548dc13ef9b96ac6ffd8aed7ca" {
		t.Fatalf("cross-product digest = %s", request.Digest())
	}
	read, err := provider.ReadBack(context.Background(), request)
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
	if got.LiveURL != "https://x.com/fixture/status/new-post" {
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
	read, err := provider.ReadBack(context.Background(), request)
	if err == nil || read.Status != ReadBackInconclusive {
		t.Fatalf("read-back = %+v, %v; identical text without create id must stay fenced", read, err)
	}
}

func TestPublisherPathStillRefusesLocalApproval(t *testing.T) {
	q, e, _ := gatedFixture(t)
	sends := 0
	got, err := q.DecideAndPerform(e.ID, true, "shell-agent", func(*Effect) (string, error) { sends++; return "201 Created", nil })
	if sends != 0 || err == nil || (got != nil && got.State != Refused) {
		t.Fatalf("got %+v, err %v, sends %d", got, err, sends)
	}
	if !strings.Contains(err.Error(), "direct SuperPipeline") {
		t.Fatalf("unexpected error: %v", err)
	}
}
