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
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "allow", false: "deny"}[allow], func(t *testing.T) {
			q := mustOpen(t, time.Minute)
			req := GatedRequest{BoardID: "brd_fixture", SubjectID: "aps_fixture", Method: "POST", URL: "https://api.x.com/2/tweets", Body: []byte(`{"text":"frozen copy"}`)}
			e, err := q.SubmitGated(req, "Publish the frozen X post.")
			if err != nil {
				t.Fatal(err)
			}
			sends := 0
			got, err := q.DecideAndPerform(e.ID, allow, "shell-agent", func(*Effect) (string, error) {
				sends++
				return "201 Created", nil
			})
			if sends != 0 || err == nil {
				t.Fatalf("local decision: sends=%d, err=%v; want refusal without a send", sends, err)
			}
			if got != nil && got.State != Pending {
				t.Errorf("recorded state = %q; want unchanged %q", got.State, Pending)
			}
		})
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

	_, retryErr := q.DecideAndPerform(e.ID, true, "retry", func(*Effect) (string, error) {
		sends++
		return "201 Created", nil
	})
	if retryErr == nil || !strings.Contains(retryErr.Error(), "fenced by outcome_unknown") {
		t.Fatalf("retry error = %v; want durable outcome fence", retryErr)
	}
	stored, ok := q.Get(e.ID)
	if !ok || stored.Outcome != "outcome_unknown" {
		t.Fatalf("stored outcome after retry = %+v; want outcome_unknown", stored)
	}
	if sends != 1 {
		t.Fatalf("provider send count = %d; want exactly 1 before read-back permits a retry", sends)
	}
}
