// Package mcpserve serves one fronted MCP server's own tools, under their own
// names, with supertoolkit deciding and recording every call.
//
// The child is never asked whether it may act. Each tools/call is decided by a
// Gate — in process from the local policy, or by the broker daemon over its
// socket — and recorded, allowed or denied, with the id of the rule that
// decided it, before the child sees it.
package mcpserve

import (
	"context"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// Decision is the answer for one tool call.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Policy  string `json:"policy"` // agent, approval, deny
	Rule    string `json:"rule"`
	Reason  string `json:"reason,omitempty"`
}

// Decide answers whether profile may call tool on server. It reads policy only;
// recording is the caller's.
func Decide(cfg *policy.Config, prof *policy.Profile, server, tool string, hint policy.ToolHint) Decision {
	srv, ok := cfg.Server(server)
	if !ok {
		return Decision{Policy: "deny", Rule: "server:" + server + "/unknown", Reason: "no such server in policy"}
	}
	if prof != nil && !prof.AllowsAction(server, tool) {
		name := prof.Name
		if name == "" {
			name = "default"
		}
		return Decision{Policy: "deny", Rule: "profile:" + name, Reason: "this profile does not include " + server + "/" + tool}
	}
	act, rule := srv.Decide(tool, hint)
	d := Decision{Policy: act.String(), Rule: rule}
	switch act {
	case policy.ActionAgent:
		d.Allowed = true
	case policy.ActionDeny:
		d.Reason = "denied by policy"
	default:
		d.Reason = "needs a person's approval; stk mcp serve does not hold a call open for one — use the meta-tools (stk mcp) for approval-gated tools"
	}
	return d
}

// DecisionEntry is the audit row for a decision.
func DecisionEntry(server, tool, caller string, d Decision) ledger.Entry {
	e := ledger.Entry{
		When: time.Now().UTC(), Service: server, Capability: tool, Method: "tools/call", Path: tool,
		Policy: d.Policy, Caller: caller, Credential: "none", Rule: d.Rule, Outcome: "allowed",
	}
	if !d.Allowed {
		e.Outcome = "403 denied: " + d.Rule
	}
	return e
}

// DoneEntry is the audit row for what an allowed call came to.
func DoneEntry(server, tool, caller, rule, outcome string) ledger.Entry {
	return ledger.Entry{
		When: time.Now().UTC(), Service: server, Capability: tool, Method: "tools/call", Path: tool,
		Policy: "agent", Caller: caller, Credential: "none", Rule: rule, Outcome: outcome,
	}
}

// Gate decides and records. Implementations: Local (in process) and the
// daemon client in internal/mcpcmd.
type Gate interface {
	// Decide decides one call and records the decision.
	Decide(ctx context.Context, tool string, hint policy.ToolHint) (Decision, error)
	// Done records what an allowed call came to.
	Done(ctx context.Context, tool, rule, outcome string) error
	// Visible reports whether a tool should be listed. It records nothing.
	Visible(ctx context.Context, tool string, hint policy.ToolHint) bool
}

// Appender is the slice of the ledger a Local gate needs.
type Appender interface{ Append(ledger.Entry) error }

// Local is a Gate over an in-process policy and ledger.
type Local struct {
	Config  func() *policy.Config
	Profile string
	Server  string
	Caller  string
	Ledger  Appender
}

func (l *Local) decide(tool string, hint policy.ToolHint) Decision {
	cfg := l.Config()
	prof, ok := cfg.Profile(l.Profile)
	if !ok {
		return Decision{Policy: "deny", Rule: "profile:" + l.Profile, Reason: "unknown profile"}
	}
	return Decide(cfg, prof, l.Server, tool, hint)
}

func (l *Local) Decide(_ context.Context, tool string, hint policy.ToolHint) (Decision, error) {
	d := l.decide(tool, hint)
	// A decision that cannot be recorded is not acted on.
	if err := l.Ledger.Append(DecisionEntry(l.Server, tool, l.Caller, d)); err != nil {
		return Decision{Policy: "deny", Rule: "audit:unwritable", Reason: err.Error()}, nil
	}
	return d, nil
}

func (l *Local) Done(_ context.Context, tool, rule, outcome string) error {
	return l.Ledger.Append(DoneEntry(l.Server, tool, l.Caller, rule, outcome))
}

func (l *Local) Visible(_ context.Context, tool string, hint policy.ToolHint) bool {
	return l.decide(tool, hint).Allowed
}
