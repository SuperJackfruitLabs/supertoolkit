// Package mcp speaks the Model Context Protocol over stdio, exposing brokered
// capabilities through exactly four meta-tools.
//
// **Four, never N.** Ten services at ten actions each would put a hundred tool
// schemas in every agent's context on every turn. Discovery is progressive
// instead: categories, then actions, then one action's schema, and the full
// parameter detail arrives only when the agent asks for it.
//
// A single `execute_action` is also the only place policy is enforced, so there
// is one thing to audit and no second path to forget.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// ToolNames is the complete, closed set. A test asserts tools/list returns
// exactly these, because the whole point is that the catalogue never leaks into
// the context window.
var ToolNames = []string{
	"discover_server_categories",
	"get_category_actions",
	"get_action_details",
	"execute_action",
}

// Executor performs an approved effect. The broker supplies it; this package
// never sees a credential.
type Executor func(ctx context.Context, service string, req *http.Request) (*http.Response, error)

// FrontedServer is one MCP server we did not write, already running with a
// placeholder instead of a credential.
type FrontedServer interface {
	ListTools(ctx context.Context) ([]mcphost.Tool, error)
	Tool(ctx context.Context, name string) (mcphost.Tool, bool, error)
	CallTool(ctx context.Context, name string, args map[string]string) (string, bool, error)
}

// Server answers MCP over a reader and writer.
type Server struct {
	cfg     *policy.Config
	profile *policy.Profile
	queue   *approval.Queue
	exec    Executor
	servers func(name string) (FrontedServer, error)
	waitFor time.Duration
	mu      sync.Mutex
}

// Options configure a server.
type Options struct {
	Config  *policy.Config
	Profile *policy.Profile
	Queue   *approval.Queue
	Exec    Executor
	// Servers resolves a fronted MCP server by name. Optional: without it a
	// configured server reports as having no actions rather than failing oddly.
	Servers func(name string) (FrontedServer, error)
	// ApprovalWait is how long execute_action blocks for a decision before
	// returning `pending`. Zero returns immediately.
	ApprovalWait time.Duration
}

// NewServer builds a server.
func NewServer(o Options) (*Server, error) {
	if o.Config == nil || o.Profile == nil || o.Queue == nil || o.Exec == nil {
		return nil, fmt.Errorf("mcp: Config, Profile, Queue and Exec are all required")
	}
	return &Server{cfg: o.Config, profile: o.Profile, queue: o.Queue, exec: o.Exec,
		servers: o.Servers, waitFor: o.ApprovalWait}, nil
}

// --- JSON-RPC 2.0 ---

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type toolDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []contentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

func text(format string, a ...any) toolResult {
	return toolResult{Content: []contentItem{{Type: "text", Text: fmt.Sprintf(format, a...)}}}
}

func errText(format string, a ...any) toolResult {
	r := text(format, a...)
	r.IsError = true
	return r
}

func obj(v any) toolResult {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errText("could not encode the result: %v", err)
	}
	return text("%s", string(b))
}

// Serve reads requests until the reader ends.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)
	for {
		var req rpcRequest
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		resp := s.dispatch(ctx, req)
		if resp == nil {
			continue // a notification needs no reply
		}
		s.mu.Lock()
		err := enc.Encode(resp)
		s.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (s *Server) dispatch(ctx context.Context, req rpcRequest) *rpcResponse {
	reply := func(result any) *rpcResponse {
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
	}
	switch req.Method {
	case "initialize":
		return reply(map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "supertoolkit", "version": "0.0.1"},
		})
	case "notifications/initialized", "notifications/cancelled":
		return nil
	case "ping":
		return reply(map[string]any{})
	case "tools/list":
		return reply(map[string]any{"tools": s.tools()})
	case "tools/call":
		var p struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return reply(errText("could not read the arguments: %v", err))
		}
		return reply(s.call(ctx, p.Name, p.Arguments))
	default:
		return &rpcResponse{JSONRPC: "2.0", ID: req.ID,
			Error: &rpcError{Code: -32601, Message: "unknown method " + req.Method}}
	}
}

func (s *Server) tools() []toolDef {
	str := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}
	schema := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	return []toolDef{
		{
			Name:        "discover_server_categories",
			Description: "List the service categories available to you. Start here.",
			InputSchema: schema(map[string]any{}),
		},
		{
			Name:        "get_category_actions",
			Description: "List the actions in one category, with a one-line summary and whether each needs human approval.",
			InputSchema: schema(map[string]any{"category": str("A category from discover_server_categories.")}, "category"),
		},
		{
			Name:        "get_action_details",
			Description: "The full parameter schema for one action. Call this before execute_action.",
			InputSchema: schema(map[string]any{
				"category": str("The category."),
				"action":   str("The action."),
			}, "category", "action"),
		},
		{
			Name:        "execute_action",
			Description: "Run an action. Arguments are passed as a JSON object in `args`. Actions that change the world may require a human decision first.",
			InputSchema: schema(map[string]any{
				"category": str("The category."),
				"action":   str("The action."),
				"args":     str("A JSON object of the action's parameters."),
			}, "category", "action"),
		},
	}
}

// CallTool invokes one meta-tool directly, for callers that are not speaking
// JSON-RPC — the daemon reuses this so there is one implementation of the four
// tools and one enforcement point, rather than a second path that could drift.
func (s *Server) CallTool(ctx context.Context, name string, args map[string]string) any {
	return s.call(ctx, name, args)
}

func (s *Server) call(ctx context.Context, name string, args map[string]string) toolResult {
	switch name {
	case "discover_server_categories":
		return s.discover()
	case "get_category_actions":
		return s.actions(args["category"])
	case "get_action_details":
		return s.details(args["category"], args["action"])
	case "execute_action":
		return s.execute(ctx, args["category"], args["action"], args["args"])
	}
	return errText("unknown tool %q; this server exposes %s", name, strings.Join(ToolNames, ", "))
}

func (s *Server) discover() toolResult {
	type cat struct {
		Category string `json:"category"`
		Host     string `json:"host"`
		Actions  int    `json:"actions"`
		// Kind tells an agent whether it is using a capability we modelled or a
		// server someone else wrote, which affects how literally the action
		// descriptions should be read.
		Kind string `json:"kind"`
	}
	var out []cat
	for _, name := range s.profile.Services() {
		svc, _ := s.cfg.Service(name)
		out = append(out, cat{Category: name, Host: svc.Entry().Host,
			Actions: len(s.profile.Capabilities(name)), Kind: "service"})
	}
	for _, name := range s.cfg.Servers() {
		tools := s.serverTools(name)
		if len(tools) == 0 {
			continue
		}
		srv, _ := s.cfg.Server(name)
		out = append(out, cat{Category: name, Host: srv.Host, Actions: len(tools), Kind: "fronted server"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	if len(out) == 0 {
		return text("No categories are available to this profile.")
	}
	return obj(map[string]any{"categories": out})
}

func (s *Server) actions(category string) toolResult {
	if s.cfg.IsServer(category) {
		tools := s.serverTools(category)
		if len(tools) == 0 {
			return errText("no category %q is available to you", category)
		}
		type act struct {
			Action  string `json:"action"`
			Summary string `json:"summary"`
			Policy  string `json:"policy"`
		}
		out := make([]act, 0, len(tools))
		for _, ft := range tools {
			out = append(out, act{Action: ft.tool.Name, Summary: ft.tool.Description, Policy: ft.action.String()})
		}
		return obj(map[string]any{"category": category, "kind": "fronted server", "actions": out})
	}
	svc, ok := s.cfg.Service(category)
	if !ok || len(s.profile.Capabilities(category)) == 0 {
		return errText("no category %q is available to you", category)
	}
	type act struct {
		Action  string `json:"action"`
		Summary string `json:"summary"`
		Policy  string `json:"policy"`
	}
	var out []act
	for _, capName := range s.profile.Capabilities(category) {
		c, _ := svc.Entry().Capability(capName)
		out = append(out, act{Action: c.Name, Summary: c.Summary, Policy: s.profile.Resolve(category, capName).String()})
	}
	return obj(map[string]any{"category": category, "actions": out})
}

func (s *Server) details(category, action string) toolResult {
	if s.cfg.IsServer(category) {
		ft, ok := s.frontedTool(category, action)
		if !ok {
			return errText("no action %q is available to you in %q", action, category)
		}
		return obj(map[string]any{
			"category": category, "action": ft.tool.Name, "kind": "fronted server",
			"summary": ft.tool.Description, "policy": ft.action.String(),
			// The child's own schema, passed through rather than reinterpreted.
			"input_schema": ft.tool.InputSchema,
		})
	}
	// A capability outside the profile is refused as unavailable, not described.
	// Describing it would tell the agent that something it may not use exists.
	if !s.profile.Visible(category, action) {
		return errText("no action %q is available to you in %q", action, category)
	}
	svc, _ := s.cfg.Service(category)
	c, _ := svc.Entry().Capability(action)
	type param struct {
		Name     string `json:"name"`
		Required bool   `json:"required"`
		Summary  string `json:"summary,omitempty"`
	}
	ps := make([]param, 0, len(c.Params))
	for _, p := range c.Params {
		ps = append(ps, param{Name: p.Name, Required: p.Required, Summary: p.Summary})
	}
	return obj(map[string]any{
		"category": category, "action": c.Name, "summary": c.Summary,
		"policy": s.profile.Resolve(category, action).String(),
		"params": ps,
	})
}

func (s *Server) execute(ctx context.Context, category, action, rawArgs string) toolResult {
	if s.cfg.IsServer(category) {
		return s.executeFronted(ctx, category, action, rawArgs)
	}
	if !s.profile.Visible(category, action) {
		return errText("no action %q is available to you in %q", action, category)
	}
	args := map[string]string{}
	if strings.TrimSpace(rawArgs) != "" {
		if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
			return errText("`args` must be a JSON object: %v", err)
		}
	}
	svc, _ := s.cfg.Service(category)
	c, _ := svc.Entry().Capability(action)

	// The one enforcement point.
	switch s.profile.Resolve(category, action) {
	case policy.ActionDeny:
		return errText("%s/%s is denied on this workspace", category, action)
	case policy.ActionApproval:
		e := s.queue.Submit(category, action, describe(c, args), args)
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
			return obj(map[string]any{
				"state": state, "id": e.ID,
				"note": "not approved, so nothing was done",
			})
		}
	}
	return s.perform(ctx, category, svc, action, args)
}

func (s *Server) perform(ctx context.Context, category string, svc *policy.Service, action string, args map[string]string) toolResult {
	req, err := svc.Entry().Request(action, args)
	if err != nil {
		return errText("%v", err)
	}
	resp, err := s.exec(ctx, category, req.WithContext(ctx))
	if err != nil {
		return errText("the request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	return obj(map[string]any{"status": resp.StatusCode, "body": string(body)})
}

func describe(c catalog.Capability, args map[string]string) string {
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
		return c.Summary
	}
	return c.Summary + " (" + strings.Join(parts, ", ") + ")"
}
