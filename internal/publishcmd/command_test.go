package publishcmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
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
	return out, nil
}

func (g *commandGate) RecordDelivered(_ context.Context, _, _, _, liveURL string) error {
	g.recorded = append(g.recorded, liveURL)
	return nil
}

type commandX struct {
	sends int
	reads int
}

func (x *commandX) Send(_ context.Context, _ approval.GatedRequest) (approval.SendResult, error) {
	x.sends++
	if x.sends == 1 {
		return approval.SendResult{}, approval.UnknownOutcome(errors.New("fixture connection dropped"))
	}
	return approval.SendResult{StatusCode: http.StatusCreated}, nil
}

func (x *commandX) ReadBack(_ context.Context, _ approval.GatedRequest) (approval.ReadBackResult, error) {
	x.reads++
	if x.reads == 1 {
		return approval.ReadBackResult{Status: approval.ReadBackInconclusive}, nil
	}
	if x.reads == 2 {
		return approval.ReadBackResult{Status: approval.ReadBackNotFound}, nil
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

	payload, _ := json.Marshal(map[string]any{
		"boardId":     "brd_0123456789abcdef",
		"subjectId":   "aps_0123456789abcdef",
		"method":      http.MethodPost,
		"url":         "https://api.x.com/2/tweets",
		"bodyBase64":  base64.StdEncoding.EncodeToString([]byte(`{"text":"frozen command path"}`)),
		"mediaBase64": []string{},
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
	if stored.Outcome != "delivered" || stored.LiveURL != "https://x.com/fixture/status/42" || x.sends != 2 {
		t.Fatalf("recovered effect = %+v; sends=%d reads=%d", stored, x.sends, x.reads)
	}
	if len(gate.recorded) != 1 || gate.recorded[0] != stored.LiveURL {
		t.Fatalf("card records = %v", gate.recorded)
	}
}
