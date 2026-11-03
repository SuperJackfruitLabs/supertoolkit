package approval

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Regression guarded: if a SuperPipeline-bound effect can still be claimed by
// the local approval queue, an agent with shell access can run `stk approvals
// allow` and publish without SuperPipeline ever approving the frozen digest for
// automatic delivery.
func TestSuperPipelineGatedEffectRefusesLocalApproval(t *testing.T) {
	q := mustOpen(t, time.Minute)
	e := q.Submit("x", "post_tweet", "Publish the frozen X post.", map[string]string{
		"text":                     "frozen copy",
		"_approval_authority":      "superpipeline",
		"_approval_gate":           "gate-fixture",
		"_approval_subject_digest": strings.Repeat("a", 64),
	})

	sends := 0
	got, err := q.DecideAndPerform(e.ID, true, "shell-agent", func(*Effect) (string, error) {
		sends++
		return "201 Created", nil
	})
	if sends != 0 {
		t.Errorf("local approval performed the SuperPipeline-gated effect %d time(s); want 0", sends)
	}
	if err == nil {
		t.Error("local approval was accepted; want stk approvals allow to be refused for a SuperPipeline-gated effect")
	}
	if got != nil && got.State != Refused {
		t.Errorf("recorded state = %q; want %q", got.State, Refused)
	}
}

// Regression guarded: if a timeout or dropped connection is recorded as an
// ordinary failure, a retry can duplicate an X post that the provider accepted
// before its response was lost. The durable outcome must instead fence retries
// as unknown until provider read-back resolves it.
func TestConnectionLossIsRecordedAsOutcomeUnknown(t *testing.T) {
	q := mustOpen(t, time.Minute)
	e := q.Submit("x", "post_tweet", "Publish the frozen X post.", map[string]string{
		"text": "frozen copy",
	})

	sends := 0
	_, _ = q.DecideAndPerform(e.ID, true, "automatic-gate", func(*Effect) (string, error) {
		sends++
		return "", errors.New("connection reset after request write")
	})
	got, ok := q.Get(e.ID)
	if !ok {
		t.Fatal("outcome record disappeared")
	}
	if got.Outcome != "outcome_unknown" {
		t.Fatalf("outcome = %q, error = %q; want outcome_unknown pending provider read-back", got.Outcome, got.Error)
	}

	_, _ = q.DecideAndPerform(e.ID, true, "retry", func(*Effect) (string, error) {
		sends++
		return "201 Created", nil
	})
	if sends != 1 {
		t.Fatalf("provider send count = %d; want exactly 1 before read-back permits a retry", sends)
	}
}
