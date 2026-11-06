package publishcmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
)

type commandGate struct {
	confirmation approval.GateConfirmation
	recorded     []string
}

func (g *commandGate) Confirm(_ context.Context, _, _, digest string) (approval.GateConfirmation, error) {
	out := g.confirmation
	if out.Digest == "" {
		out.Digest = digest
	}
	if out.Approved && out.ExpiresAt == "" {
		out.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	}
	return out, nil
}

func (g *commandGate) RecordDelivered(_ context.Context, _, _, _, liveURL string) error {
	g.recorded = append(g.recorded, liveURL)
	return nil
}

type commandX struct {
	sends      int
	reads      int
	requests   []approval.GatedRequest
	successful bool
}

func (x *commandX) Send(_ context.Context, req approval.GatedRequest) (approval.SendResult, error) {
	x.sends++
	x.requests = append(x.requests, req)
	if x.sends == 1 && !x.successful {
		return approval.SendResult{}, approval.UnknownOutcome(errors.New("fixture connection dropped"))
	}
	return approval.SendResult{StatusCode: http.StatusCreated}, nil
}

func (x *commandX) ReadBack(_ context.Context, _ approval.GatedRequest, _ approval.SendResult) (approval.ReadBackResult, error) {
	x.reads++
	if x.successful {
		return approval.ReadBackResult{Status: approval.ReadBackFound, LiveURL: "https://x.com/fixture/status/42"}, nil
	}
	if x.reads == 1 {
		return approval.ReadBackResult{Status: approval.ReadBackInconclusive}, nil
	}
	return approval.ReadBackResult{Status: approval.ReadBackFound, LiveURL: "https://x.com/fixture/status/42"}, nil
}

// Regression guarded: the shipped command path must own durable ingress,
// execution and recovery. A publisher reachable only by directly constructing
// approval.Publisher in tests is dead production code.
func TestCommandDrivesDurableIngressExecutionAndRecovery(t *testing.T) {
	q, err := approval.Open(t.TempDir(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	gate := &commandGate{confirmation: approval.GateConfirmation{Approved: true, DeliveryMode: "automatic", GateID: "gate_fixture"}}
	x := &commandX{}
	runtime := Runtime{Queue: q, Publisher: func(context.Context, approval.GatedRequest) (*approval.Publisher, error) {
		return &approval.Publisher{Queue: q, Gate: gate, X: x}, nil
	}}

	frozenMedia := append([]byte("\x89PNG\r\n\x1a\n"), []byte("command-image")...)
	payload, _ := json.Marshal(map[string]any{
		"boardId":     "brd_0123456789abcdef",
		"subjectId":   "aps_0123456789abcdef",
		"method":      http.MethodPost,
		"url":         "https://api.x.com/2/tweets",
		"bodyBase64":  base64.StdEncoding.EncodeToString([]byte(`{"text":"frozen command path"}`)),
		"mediaBase64": []string{base64.StdEncoding.EncodeToString(frozenMedia)},
		"summary":     "Publish the frozen command-path fixture",
	})
	var submitted bytes.Buffer
	if err := Run(context.Background(), []string{"submit"}, bytes.NewReader(payload), &submitted, runtime); err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		ID     string `json:"id"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(submitted.Bytes(), &receipt); err != nil || receipt.ID == "" || !strings.HasPrefix(receipt.Digest, "sha256:") {
		t.Fatalf("submission receipt = %q, %v", submitted.String(), err)
	}

	// The first executor run loses the provider outcome and leaves durable state.
	if err := Run(context.Background(), []string{"perform", receipt.ID}, strings.NewReader(""), &bytes.Buffer{}, runtime); err == nil {
		t.Fatal("ambiguous first send unexpectedly succeeded")
	}
	stored, ok := q.Get(receipt.ID)
	if !ok || stored.Outcome != "outcome_unknown" || stored.Attempts != 1 {
		t.Fatalf("stored first outcome = %+v, ok=%v", stored, ok)
	}

	// A later process can recover solely from the queue's durable request bytes.
	var recovered bytes.Buffer
	if err := Run(context.Background(), []string{"recover"}, strings.NewReader(""), &recovered, runtime); err != nil {
		t.Fatal(err)
	}
	stored, _ = q.Get(receipt.ID)
	if stored.Outcome != "delivered" || stored.LiveURL != "https://x.com/fixture/status/42" || x.sends != 1 {
		t.Fatalf("recovered effect = %+v; sends=%d reads=%d", stored, x.sends, x.reads)
	}
	if len(gate.recorded) != 1 || gate.recorded[0] != stored.LiveURL {
		t.Fatalf("card records = %v", gate.recorded)
	}
	if len(x.requests) != 1 || len(x.requests[0].Media) != 1 || string(x.requests[0].Media[0]) != string(frozenMedia) {
		t.Fatalf("durable frozen media was not preserved across retry: %+v", x.requests)
	}
}

func TestRecoverSkipsUndecidedGateAndLaterApprovalPostsOnce(t *testing.T) {
	q, err := approval.Open(t.TempDir(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := approval.GatedRequest{BoardID: "brd_0123456789abcdef", SubjectID: "aps_0123456789abcdef", Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"wait for review"}`)}
	e, err := q.SubmitGated(req, "wait for review")
	if err != nil {
		t.Fatal(err)
	}
	gate := &commandGate{confirmation: approval.GateConfirmation{DeliveryMode: "none", GateStatus: "pending", GateID: "gate_fixture", Digest: req.Digest()}}
	x := &commandX{successful: true}
	factories := 0
	runtime := Runtime{Queue: q, Publisher: func(context.Context, approval.GatedRequest) (*approval.Publisher, error) {
		factories++
		return &approval.Publisher{Queue: q, Gate: gate, X: x}, nil
	}}
	recoverErr := recover(context.Background(), &bytes.Buffer{}, runtime)
	if got, _ := q.Get(e.ID); got.State != approval.Pending || x.sends != 0 || factories != 0 {
		t.Fatalf("recover changed or performed undecided effect: %+v; sends=%d factories=%d", got, x.sends, factories)
	}
	if recoverErr != nil {
		t.Fatal(recoverErr)
	}
	if _, err := perform(context.Background(), e.ID, runtime); err == nil {
		t.Fatal("undecided gate was accepted")
	}
	if got, _ := q.Get(e.ID); got.State != approval.Pending || got.Outcome != "" {
		t.Fatalf("undecided perform changed state: %+v", got)
	}
	gate.confirmation = approval.GateConfirmation{Approved: true, DeliveryMode: "automatic", GateID: "gate_fixture", Digest: req.Digest(), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if _, err := perform(context.Background(), e.ID, runtime); err != nil {
		t.Fatal(err)
	}
	if x.sends != 1 {
		t.Fatalf("provider sends = %d, want 1", x.sends)
	}
}

func TestRecoverSurfacesRetryAllowedWithoutSendingAgain(t *testing.T) {
	dir := t.TempDir()
	q, err := approval.Open(dir, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := approval.GatedRequest{BoardID: "brd_0123456789abcdef", SubjectID: "aps_0123456789abcdef", Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"recover"}`)}
	e, err := q.SubmitGated(req, "recover")
	if err != nil {
		t.Fatal(err)
	}
	gate := &commandGate{confirmation: approval.GateConfirmation{Approved: true, DeliveryMode: "automatic", GateID: "gate_fixture", Digest: req.Digest()}}
	x := &commandX{}
	runtime := Runtime{Queue: q, Publisher: func(context.Context, approval.GatedRequest) (*approval.Publisher, error) {
		return &approval.Publisher{Queue: q, Gate: gate, X: x}, nil
	}}
	if _, err := perform(context.Background(), e.ID, runtime); err == nil {
		t.Fatal("fixture did not create the unknown-outcome fence")
	}
	retry := []byte(`{"outcome":"retry_allowed","approved_digest":"` + req.Digest() + `","request_digest":"` + req.Digest() + `","gate_id":"gate_fixture","attempts":1}`)
	if err := os.WriteFile(filepath.Join(dir, "approvals", e.ID+".pub"), retry, 0o600); err != nil {
		t.Fatal(err)
	}
	err = recover(context.Background(), &bytes.Buffer{}, runtime)
	if err == nil || !strings.Contains(err.Error(), "manual recovery") || x.sends != 1 {
		t.Fatalf("recover err=%v sends=%d; want surfaced retry_allowed and no second send", err, x.sends)
	}
}

func TestPerformReportsAwaitingDecisionState(t *testing.T) {
	q, err := approval.Open(t.TempDir(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := approval.GatedRequest{BoardID: "brd_0123456789abcdef", SubjectID: "aps_0123456789abcdef", Method: http.MethodPost, URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"wait"}`)}
	e, err := q.SubmitGated(req, "wait")
	if err != nil {
		t.Fatal(err)
	}
	gate := &commandGate{confirmation: approval.GateConfirmation{DeliveryMode: "none", GateStatus: "open", Digest: req.Digest()}}
	runtime := Runtime{Queue: q, Publisher: func(context.Context, approval.GatedRequest) (*approval.Publisher, error) {
		return &approval.Publisher{Queue: q, Gate: gate, X: &commandX{successful: true}}, nil
	}}
	var out bytes.Buffer
	err = Run(context.Background(), []string{"perform", e.ID}, strings.NewReader(""), &out, runtime)
	if !approval.IsAwaitingDecision(err) || !strings.Contains(out.String(), `"state":"awaiting_decision"`) {
		t.Fatalf("perform = %q, %v; want typed awaiting_decision", out.String(), err)
	}
	if got, _ := q.Get(e.ID); got.State != approval.Pending || got.Outcome != "" {
		t.Fatalf("awaiting gate changed durable state: %+v", got)
	}
}
