package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/managedmcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
)

// A NEW command is deliberate. Older stk mcp ignores unknown flags; an old
// binary rejects this command instead of launching an unbound legacy broker.
func cmdManagedMCP(args []string) error {
	if len(args) != 4 || args[0] != "--manifest" || args[2] != "--sha256" {
		return managedUnavailable()
	}
	admission, err := managedmcp.Admit(args[1], args[3])
	if err != nil {
		return managedUnavailable()
	}
	release, err := managedmcp.OwnProcess(admission.Manifest.StateDir)
	if err != nil {
		return managedUnavailable()
	}
	defer release()
	engine, err := newManagedNative(admission)
	if err != nil {
		return managedUnavailable()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_ = os.Stdin.Close()
		case <-finished:
		}
	}()
	return (&managedStdio{engine: engine}).serve(ctx, os.Stdin, os.Stdout)
}

type managedRPC struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}
type managedToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	Meta      struct {
		Owner struct {
			Version      int    `json:"version"`
			InvocationID string `json:"invocation_id"`
			ExpiresAtMS  int64  `json:"expires_at_ms"`
		} `json:"salaam.dev/toolkit"`
	} `json:"_meta,omitempty"`
}
type managedActive struct {
	request managedmcp.Request
	cancel  context.CancelFunc
}
type managedStdio struct {
	engine   *managedNative
	mu       sync.Mutex
	active   *managedActive
	activeID string
	writes   sync.Mutex
	wg       sync.WaitGroup
}

func closedJSON(data []byte, value any) bool {
	if !managedmcp.ValidJSON(data) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(value) == nil && d.Decode(new(any)) == io.EOF
}
func rpcID(id json.RawMessage) bool {
	if len(id) == 0 || len(id) > 132 {
		return false
	}
	var text string
	if json.Unmarshal(id, &text) == nil {
		return len(text) > 0 && len(text) <= 128
	}
	var n int64
	return json.Unmarshal(id, &n) == nil && n >= 0 && n <= 9007199254740991
}
func (s *managedStdio) write(out io.Writer, id json.RawMessage, result any) error {
	s.writes.Lock()
	defer s.writes.Unlock()
	return json.NewEncoder(out).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}
func toolReply(value any, isError bool) any {
	body, err := json.Marshal(value)
	if err != nil {
		body = []byte(`{"error":"managed_toolkit_unavailable"}`)
		isError = true
	}
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(body)}}, "isError": isError}
}
func (s *managedStdio) cancel(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || (id != "" && id != s.activeID) {
		return
	}
	// Create/answer the cancellation marker before context abort, including a
	// notification racing the executor's first Prepare call.
	if v, err := s.engine.ledger.Prepare(s.active.request); err == nil {
		_, _ = s.engine.ledger.Cancel(v.ID, v.RequestDigest)
	}
	s.active.cancel()
}
func (s *managedStdio) serve(ctx context.Context, in io.Reader, out io.Writer) error {
	defer func() { s.cancel(""); s.wg.Wait() }()
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), 131072)
	initialized := false
	seen := map[string]bool{}
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		var rpc managedRPC
		if !closedJSON(scanner.Bytes(), &rpc) || rpc.JSONRPC != "2.0" {
			return managedUnavailable()
		}
		if len(rpc.ID) == 0 {
			switch rpc.Method {
			case "notifications/initialized":
				if !initialized {
					return managedUnavailable()
				}
			case "notifications/cancelled":
				var params struct {
					RequestID json.RawMessage `json:"requestId"`
					Reason    string          `json:"reason,omitempty"`
				}
				if !closedJSON(rpc.Params, &params) || !rpcID(params.RequestID) {
					return managedUnavailable()
				}
				s.cancel(string(params.RequestID))
			default:
				return managedUnavailable()
			}
			continue
		}
		if !rpcID(rpc.ID) || seen[string(rpc.ID)] || len(seen) >= 1024 {
			return managedUnavailable()
		}
		seen[string(rpc.ID)] = true
		var result any
		switch rpc.Method {
		case "initialize":
			if initialized {
				return managedUnavailable()
			}
			initialized = true
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "supertoolkit-managed", "version": version}}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			if !initialized || s.engine.admission.Check() != nil {
				return managedUnavailable()
			}
			result = map[string]any{"tools": managedTools()}
		case "tools/call":
			if !initialized {
				return managedUnavailable()
			}
			var call managedToolCall
			if !closedJSON(rpc.Params, &call) {
				return managedUnavailable()
			}
			if call.Name != "execute_action" {
				value, ok := s.discover(call)
				result = toolReply(value, !ok)
				break
			}
			var args struct {
				Category string          `json:"category"`
				Action   string          `json:"action"`
				Args     json.RawMessage `json:"args"`
			}
			if !closedJSON(call.Arguments, &args) || call.Meta.Owner.Version != 1 {
				return managedUnavailable()
			}
			parameters, err := managedmcp.DecodeArguments(args.Args)
			if err != nil {
				return managedUnavailable()
			}
			r, err := s.engine.request(call.Meta.Owner.InvocationID, args.Category, args.Action, parameters, call.Meta.Owner.ExpiresAtMS)
			if err != nil {
				result = toolReply(map[string]any{"error": "managed_toolkit_unavailable"}, true)
				break
			}
			s.mu.Lock()
			if s.active != nil {
				s.mu.Unlock()
				result = toolReply(map[string]any{"error": "managed_toolkit_busy"}, true)
				break
			}
			owned, cancel := context.WithCancel(ctx)
			s.active = &managedActive{r, cancel}
			s.activeID = string(rpc.ID)
			s.mu.Unlock()
			id := append(json.RawMessage(nil), rpc.ID...)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer cancel()
				v, err := s.engine.invoke(owned, r)
				bad := err != nil || v.State != managedmcp.Returned
				if v.State == managedmcp.Returned {
					var outcome managedResult
					valid := closedJSON([]byte(v.Result), &outcome) && outcome.ProtocolResult == "returned" && outcome.Status >= 100 && outcome.Status <= 599 && outcome.IsError == (outcome.Status < 200 || outcome.Status >= 300)
					bad = !valid || outcome.IsError
					if !valid {
						v.Result = ""
					}
				}
				var response any = v
				if err != nil {
					response = map[string]any{"error": "managed_toolkit_unavailable", "receipt": v}
				}
				s.mu.Lock()
				s.active = nil
				s.activeID = ""
				s.mu.Unlock()
				if s.write(out, id, toolReply(response, bad)) != nil {
					s.cancel(string(id))
				}
			}()
			continue
		default:
			return managedUnavailable()
		}
		if err := s.write(out, rpc.ID, result); err != nil {
			return managedUnavailable()
		}
	}
	if scanner.Err() != nil {
		return managedUnavailable()
	}
	return nil
}

func managedTools() []any {
	out := []any{}
	for _, name := range mcp.ToolNames {
		props := map[string]any{}
		required := []string{}
		if name != "discover_server_categories" {
			props["category"] = map[string]any{"type": "string"}
			required = append(required, "category")
		}
		if name == "get_action_details" || name == "execute_action" {
			props["action"] = map[string]any{"type": "string"}
			required = append(required, "action")
		}
		if name == "execute_action" {
			props["args"] = map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}}
			required = append(required, "args")
		}
		out = append(out, map[string]any{"name": name, "description": "Progressive discovery of reviewed native Toolkit actions; execution remains subject to the owning run and human decisions.", "inputSchema": map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}})
	}
	return out
}
func (s *managedStdio) discover(call managedToolCall) (any, bool) {
	if s.engine.admission.Check() != nil {
		return map[string]any{"error": "managed_toolkit_unavailable"}, false
	}
	var args map[string]string
	if !closedJSON(call.Arguments, &args) || args == nil {
		return map[string]any{"error": "invalid_arguments"}, false
	}
	switch call.Name {
	case "discover_server_categories":
		if len(args) != 0 {
			break
		}
		out := []any{}
		for _, service := range s.engine.profile.Services() {
			out = append(out, map[string]any{"category": service, "actions": len(s.engine.profile.Capabilities(service)), "kind": "native"})
		}
		return map[string]any{"categories": out}, true
	case "get_category_actions":
		if len(args) != 1 || args["category"] == "" {
			break
		}
		out := []any{}
		for _, action := range s.engine.profile.Capabilities(args["category"]) {
			out = append(out, map[string]any{"action": action, "policy": s.engine.profile.Resolve(args["category"], action).String()})
		}
		return map[string]any{"actions": out}, true
	case "get_action_details":
		if len(args) != 2 || !s.engine.profile.Visible(args["category"], args["action"]) {
			break
		}
		svc, _ := s.engine.cfg.Service(args["category"])
		capability, _ := svc.Entry().Capability(args["action"])
		return map[string]any{"category": args["category"], "action": args["action"], "summary": capability.Summary, "params": capability.Params, "policy": s.engine.profile.Resolve(args["category"], args["action"]).String()}, true
	}
	return map[string]any{"error": "managed_toolkit_unavailable"}, false
}
