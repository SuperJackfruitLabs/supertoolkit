package controlplane

import (
	"context"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
)

const hostedToolPolicy = hostedPolicy + "servers:\n  faker:\n    command: /bin/true\n    host: fake.example\n    env_var: FAKE_API_TOKEN\n"

type toolChild struct{ calls []map[string]string }

func (c *toolChild) ListTools(context.Context) ([]mcphost.Tool, error) { return nil, nil }
func (c *toolChild) Tool(context.Context, string) (mcphost.Tool, bool, error) {
	return mcphost.Tool{}, false, nil
}
func (c *toolChild) CallTool(_ context.Context, _ string, args map[string]string) (string, bool, error) {
	c.calls = append(c.calls, args)
	return "ok", false, nil
}

// approvingBoard approves whatever it was asked, binding the subject it got.
type approvingBoard struct{ req approval.ApprovalRequest }

func (b *approvingBoard) CreateApprovalRequest(_ context.Context, _ string, body approval.ApprovalRequest) (approval.ApprovalCreated, error) {
	b.req = body
	return approval.ApprovalCreated{ApprovalRequestID: "apr_1", State: "pending"}, nil
}

func (b *approvingBoard) ReadApprovalRequest(context.Context, string, string) (approval.ApprovalReadBack, error) {
	opt := "allow_once"
	rb := approval.ApprovalReadBack{ApprovalRequestID: "apr_1", State: "approved", Option: &opt}
	rb.DecidedBy = &struct {
		PrincipalID string `json:"principalId"`
		Label       string `json:"label"`
	}{"prn_admin", "Rakesh"}
	rb.Subject.ID, rb.Subject.Digest = b.req.Subject.ID, b.req.Subject.Digest
	return rb, nil
}

func hostedToolEffect(svc *Service, digest string) *approval.Effect {
	args := map[string]string{"path": "/a"}
	if digest == "" {
		digest = approval.ToolCapabilityRequest("faker", "write_thing", "", args).Digest()
	}
	return svc.Queue.SubmitRequest(approval.Submission{Service: "faker", Capability: "write_thing", Summary: "Write a thing",
		Args: args, Target: "mcp://faker/write_thing", Digest: digest, HostedBoard: "brd_fixture"})
}

// A hosted tool approval has no agent session waiting on it: once
// SuperPipeline approves, this process runs the tool, exactly once.
func TestHostedToolApprovalIsPerformedHere(t *testing.T) {
	svc := newTestService(t, hostedToolPolicy)
	child := &toolChild{}
	svc.fronted = func(string) (mcp.FrontedServer, error) { return child, nil }
	e := hostedToolEffect(svc, "")
	h := svc.Hosting()
	h.Client = &approvingBoard{}
	got, err := h.Resolve(context.Background(), e.ID, func(e *approval.Effect) (string, error) { return svc.performApproved(context.Background(), e) })
	if err != nil || got.State != approval.Approved || len(child.calls) != 1 || child.calls[0]["path"] != "/a" {
		t.Fatalf("state=%v calls=%v err=%v", got.State, child.calls, err)
	}
}

func TestHostedToolApprovalForAnotherCallIsRefused(t *testing.T) {
	svc := newTestService(t, hostedToolPolicy)
	child := &toolChild{}
	svc.fronted = func(string) (mcp.FrontedServer, error) { return child, nil }
	// SuperPipeline approves the digest stored on the effect, but the call
	// the effect would make is a different one.
	e := hostedToolEffect(svc, "sha256:something-else")
	h := svc.Hosting()
	h.Client = &approvingBoard{}
	_, err := h.Resolve(context.Background(), e.ID, func(e *approval.Effect) (string, error) { return svc.performApproved(context.Background(), e) })
	if err == nil || len(child.calls) != 0 {
		t.Fatalf("calls=%v err=%v; want a refusal and no call", child.calls, err)
	}
}

// Regression guarded: an effect queued before a reload added the board had no
// hosted marker, so it stayed locally decidable until it expired.
func TestBoardConfiguredRefusesEveryLocalDecide(t *testing.T) {
	svc := newTestService(t, hostedPolicy)
	e := svc.Queue.Submit("github", "create_issue", "Open an issue", map[string]string{"owner": "o"})
	sends := countingPerform(svc)
	if _, err := svc.DecideAndPerform(e.ID, true, "root (uid 0)"); err == nil || !strings.Contains(err.Error(), "SuperPipeline") {
		t.Fatalf("local decide with a board configured: err=%v", err)
	}
	if got, _ := svc.Queue.Get(e.ID); got.State != approval.Pending || *sends != 0 {
		t.Fatalf("state=%q sends=%d", got.State, *sends)
	}
}
