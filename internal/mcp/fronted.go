package mcp

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// frontedTool is one tool of a server we did not write, with the policy we
// resolved for it.
type frontedTool struct {
	tool   mcphost.Tool
	action policy.Action
}

// serverTools lists the tools of a fronted server that this profile may see,
// sorted. A failure to reach the child yields nothing rather than an error,
// because discovery should degrade to "no actions here" instead of breaking an
// agent's whole turn.
func (s *Server) serverTools(name string) []frontedTool {
	srv, ok := s.cfg.Server(name)
	if !ok || s.servers == nil {
		return nil
	}
	host, err := s.servers(name)
	if err != nil {
		return nil
	}
	tools, err := host.ListTools(context.Background())
	if err != nil {
		return nil
	}
	var out []frontedTool
	for _, t := range tools {
		if !s.profile.AllowsAction(name, t.Name) {
			continue
		}
		act := srv.Policy(t.Name, hintOf(t))
		if act == policy.ActionDeny {
			continue
		}
		out = append(out, frontedTool{tool: t, action: act})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].tool.Name < out[j].tool.Name })
	return out
}

// hintOf converts a child's own annotations into the hint policy reasons about.
// Absence is carried through as "not annotated", because it is not evidence of
// safety.
func hintOf(t mcphost.Tool) policy.ToolHint {
	ro, annotated := t.ReadOnly()
	return policy.ToolHint{ReadOnly: ro, Destructive: t.Destructive(), Known: annotated}
}

// frontedTool finds one visible tool of a fronted server.
func (s *Server) frontedTool(server, action string) (frontedTool, bool) {
	for _, ft := range s.serverTools(server) {
		if ft.tool.Name == action {
			return ft, true
		}
	}
	return frontedTool{}, false
}

// executeFronted runs one tool of a server we did not write.
//
// Policy is checked here, at the same single point native capabilities use, so
// there is one place to audit. The child is never consulted about whether it
// should be allowed to act.
func (s *Server) executeFronted(ctx context.Context, server, action, rawArgs string) toolResult {
	ft, ok := s.frontedTool(server, action)
	if !ok {
		return errText("no action %q is available to you in %q", action, server)
	}
	args := map[string]string{}
	if strings.TrimSpace(rawArgs) != "" {
		if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
			return errText("`args` must be a JSON object: %v", err)
		}
	}

	switch ft.action {
	case policy.ActionDeny:
		return errText("%s/%s is denied on this workspace", server, action)
	case policy.ActionApproval:
		summary := ft.tool.Description
		if summary == "" {
			summary = server + "/" + action
		}
		e := s.queue.Submit(server, action, describeArgs(summary, args), args)
		if s.waitFor <= 0 {
			return obj(map[string]any{
				"state": "pending", "id": e.ID,
				"note": "a human must approve this before it happens; nothing has been done yet",
			})
		}
		wctx, cancel := context.WithTimeout(ctx, s.waitFor)
		defer cancel()
		d, err := s.queue.Await(wctx, e.ID)
		if err != nil || !d.Allowed() {
			state := "pending"
			if err == nil {
				state = string(d.State)
			}
			return obj(map[string]any{"state": state, "id": e.ID, "note": "not approved, so nothing was done"})
		}
	}

	host, err := s.servers(server)
	if err != nil {
		return errText("%s is not available: %v", server, err)
	}
	text, isErr, err := host.CallTool(ctx, action, args)
	if err != nil {
		return errText("%s/%s failed: %v", server, action, err)
	}
	if isErr {
		return errText("%s", text)
	}
	return text2(text)
}

// describeArgs builds the line a human reads before approving.
func describeArgs(summary string, args map[string]string) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+args[k])
	}
	if len(parts) == 0 {
		return summary
	}
	return summary + " (" + strings.Join(parts, ", ") + ")"
}

func text2(s string) toolResult {
	return toolResult{Content: []contentItem{{Type: "text", Text: s}}}
}
