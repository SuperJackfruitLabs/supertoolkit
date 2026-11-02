package mcpserve

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// Child is the fronted server, as mcphost.Host provides it.
type Child interface {
	ToolsRaw(ctx context.Context) ([]mcphost.Tool, []json.RawMessage, error)
	CallToolRaw(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error)
}

// Server speaks MCP for one fronted server.
type Server struct {
	Name    string
	Version string
	Child   Child
	Gate    Gate

	wmu sync.Mutex
	out io.Writer
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// protocols are the MCP revisions this server answers in, newest first.
var protocols = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// Serve answers requests from in until it closes. Each request is handled on
// its own goroutine, so a slow tool call does not block a ping.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.out = out
	dec := json.NewDecoder(bufio.NewReader(in))
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		var req request
		if err := dec.Decode(&req); err != nil {
			if err == io.EOF {
				return nil
			}
			s.write(nil, nil, &rpcError{Code: -32700, Message: "parse error: " + err.Error()})
			return err
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			continue // a notification needs no answer
		}
		wg.Add(1)
		go func(req request) {
			defer wg.Done()
			res, rerr := s.handle(ctx, req)
			s.write(req.ID, res, rerr)
		}(req)
	}
}

func (s *Server) write(id json.RawMessage, result any, rerr *rpcError) {
	msg := map[string]any{"jsonrpc": "2.0", "id": id}
	if id == nil {
		msg["id"] = nil
	}
	if rerr != nil {
		msg["error"] = rerr
	} else {
		msg["result"] = result
	}
	b, _ := json.Marshal(msg)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	// A client that stopped reading has gone; there is nobody left to tell.
	_, _ = s.out.Write(append(b, '\n'))
}

func (s *Server) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		// Unreadable params leave the version empty, which picks protocols[0] below.
		_ = json.Unmarshal(req.Params, &p)
		v := protocols[0]
		for _, x := range protocols {
			if x == p.ProtocolVersion {
				v = x
			}
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "stk/" + s.Name, "version": s.Version},
			"instructions": "The tools of " + s.Name + ", served by supertoolkit. Every call is decided " +
				"by the workspace policy and recorded; a refusal names the rule that refused it.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		tools, raws, err := s.Child.ToolsRaw(ctx)
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: s.Name + " is not available: " + err.Error()}
		}
		list := []json.RawMessage{}
		for i, t := range tools {
			if i < len(raws) && s.Gate.Visible(ctx, t.Name, hintOf(t)) {
				list = append(list, raws[i])
			}
		}
		return map[string]any{"tools": list}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
			return nil, &rpcError{Code: -32602, Message: "tools/call needs a name"}
		}
		return s.call(ctx, p.Name, p.Arguments), nil
	}
	return nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method}
}

// call decides, records, and only then asks the child.
func (s *Server) call(ctx context.Context, name string, args json.RawMessage) any {
	// The hint comes from the child's own list. A name it never listed has no
	// hint, which decides as unannotated: never more permissive.
	var hint policy.ToolHint
	if tools, _, err := s.Child.ToolsRaw(ctx); err == nil {
		for _, t := range tools {
			if t.Name == name {
				hint = hintOf(t)
			}
		}
	}
	d, err := s.Gate.Decide(ctx, name, hint)
	if err != nil {
		return toolError("supertoolkit could not decide this call, so nothing was done: %v", err)
	}
	if !d.Allowed {
		return toolError("supertoolkit denied %s/%s: rule %s (%s). Nothing was done.", s.Name, name, d.Rule, d.Reason)
	}
	raw, err := s.Child.CallToolRaw(ctx, name, args)
	if err != nil {
		// The call failed either way; the decision was recorded before it ran.
		_ = s.Gate.Done(ctx, name, d.Rule, "failed: "+err.Error())
		return toolError("%s/%s failed: %v", s.Name, name, err)
	}
	var res struct {
		IsError bool `json:"isError"`
	}
	// A result that is not an object has no isError, so it counts as completed.
	_ = json.Unmarshal(raw, &res)
	outcome := "completed"
	if res.IsError {
		outcome = "completed with a tool error"
	}
	// The result is returned either way; the decision was recorded before the call ran.
	_ = s.Gate.Done(ctx, name, d.Rule, outcome)
	return raw
}

func toolError(format string, a ...any) map[string]any {
	return map[string]any{
		"content": []map[string]string{{"type": "text", "text": fmt.Sprintf(format, a...)}},
		"isError": true,
	}
}

func hintOf(t mcphost.Tool) policy.ToolHint {
	ro, annotated := t.ReadOnly()
	return policy.ToolHint{ReadOnly: ro, Destructive: t.Destructive(), Known: annotated}
}
