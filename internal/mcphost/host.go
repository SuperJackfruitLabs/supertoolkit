// Package mcphost runs an MCP server we did not write, as a child process with
// no credential in its environment.
//
// The child is started with a **placeholder** in the variable it expects and
// HTTPS_PROXY pointing at the broker, so it behaves exactly as it would with a
// real credential while holding something worthless off this machine. Nothing
// here requires the child to cooperate: it builds its own HTTP client and sets
// its own headers, as real servers do.
package mcphost

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Tool is one of the child's tools, as it describes itself.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations struct {
		ReadOnlyHint    *bool `json:"readOnlyHint"`
		DestructiveHint *bool `json:"destructiveHint"`
	} `json:"annotations"`
}

// ReadOnly reports the child's own annotation, and whether it made one at all.
// Absence is not evidence of safety, so the caller needs both facts.
func (t Tool) ReadOnly() (readOnly, annotated bool) {
	if t.Annotations.ReadOnlyHint == nil {
		return false, false
	}
	return *t.Annotations.ReadOnlyHint, true
}

// Destructive reports the child's destructive annotation.
func (t Tool) Destructive() bool {
	return t.Annotations.DestructiveHint != nil && *t.Annotations.DestructiveHint
}

// Spec is how to start a child.
type Spec struct {
	Name    string
	Command string
	Args    []string
	// Env is the complete environment for the child. It is built elsewhere so
	// that the placeholder, the proxy and the CA come from one implementation
	// shared with `stk run`.
	Env []string
	Dir string
	// Build, when set, makes the command instead of Command and Args: how a
	// confined child is started inside its namespace. Env and Dir still apply.
	Build func() *exec.Cmd
	// OnStart is told the child's pid once it runs, so it can be watched.
	OnStart func(pid int)
	// Stderr receives the child's diagnostics; nil discards them.
	Stderr io.Writer
}

// Host owns one child process.
type Host struct {
	spec Spec

	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	dec     *json.Decoder
	nextID  int
	started bool
	dead    error
	// killed is set by Kill; a killed host is never restarted. procMu guards
	// it and proc, and is never held across a call, so Kill is immediate.
	procMu sync.Mutex
	killed error
	proc   *os.Process

	// tools is cached: a child's list does not change while it runs, and
	// re-asking on every discovery would spend a round trip per agent turn.
	tools      []Tool
	rawTools   []json.RawMessage
	toolsValid bool
}

// New creates a host without starting the child.
func New(spec Spec) *Host { return &Host{spec: spec} }

// Start launches the child and performs the MCP handshake.
func (h *Host) Start(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.startLocked(ctx)
}

func (h *Host) startLocked(ctx context.Context) error {
	h.procMu.Lock()
	killed := h.killed
	h.procMu.Unlock()
	if killed != nil {
		return killed
	}
	if h.started && h.dead == nil {
		return nil
	}
	cmd := exec.Command(h.spec.Command, h.spec.Args...)
	if h.spec.Build != nil {
		cmd = h.spec.Build()
	}
	cmd.Env = h.spec.Env
	cmd.Dir = h.spec.Dir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	// The child's stderr is its own diagnostics and may be noisy; it is not
	// protocol, so it is discarded rather than mixed into stdout.
	cmd.Stderr = io.Discard
	if h.spec.Stderr != nil {
		cmd.Stderr = h.spec.Stderr
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", h.spec.Name, err)
	}
	h.procMu.Lock()
	h.proc = cmd.Process
	h.procMu.Unlock()
	if h.spec.OnStart != nil {
		h.spec.OnStart(cmd.Process.Pid)
	}
	h.cmd, h.stdin = cmd, stdin
	h.dec = json.NewDecoder(bufio.NewReader(stdout))
	h.started, h.dead = true, nil
	h.toolsValid = false

	// Reap the child so a crash becomes an error rather than a hang.
	go func() {
		err := cmd.Wait()
		h.mu.Lock()
		if h.dead == nil {
			h.dead = fmt.Errorf("%s exited: %v", h.spec.Name, err)
		}
		h.mu.Unlock()
	}()

	if _, err := h.callLocked(ctx, "initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "supertoolkit", "version": "0.0.1"},
	}); err != nil {
		return fmt.Errorf("%s did not complete the handshake: %w", h.spec.Name, err)
	}
	// A notification needs no reply, so it is written directly.
	notice, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	// A child that cannot read this fails the next request, which reports it.
	_, _ = h.stdin.Write(append(notice, '\n'))
	return nil
}

type rpcResp struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (h *Host) callLocked(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if h.dead != nil {
		return nil, h.dead
	}
	h.nextID++
	req, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": h.nextID, "method": method, "params": params,
	})
	if err != nil {
		return nil, err
	}
	if _, err := h.stdin.Write(append(req, '\n')); err != nil {
		return nil, fmt.Errorf("%s: writing %s: %w", h.spec.Name, method, err)
	}

	type outcome struct {
		raw json.RawMessage
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		for {
			var r rpcResp
			if err := h.dec.Decode(&r); err != nil {
				done <- outcome{err: fmt.Errorf("%s: reading the reply to %s: %w", h.spec.Name, method, err)}
				return
			}
			// A notification or an out-of-order reply is skipped rather than
			// treated as the answer, so a chatty child cannot wedge the host.
			if len(r.ID) == 0 || string(r.ID) == "null" {
				continue
			}
			if r.Error != nil {
				done <- outcome{err: fmt.Errorf("%s: %s", h.spec.Name, r.Error.Message)}
				return
			}
			done <- outcome{raw: r.Result}
			return
		}
	}()

	select {
	case o := <-done:
		return o.raw, o.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("%s did not answer %s within 30s", h.spec.Name, method)
	}
}

// ListTools returns the child's tools, asking it once.
func (h *Host) ListTools(ctx context.Context) ([]Tool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.startLocked(ctx); err != nil {
		return nil, err
	}
	if h.toolsValid {
		return h.tools, nil
	}
	raw, err := h.callLocked(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s: could not read its tool list: %w", h.spec.Name, err)
	}
	var rawOut struct {
		Tools []json.RawMessage `json:"tools"`
	}
	// raw already decoded into out above, so this second view of the same bytes decodes too.
	_ = json.Unmarshal(raw, &rawOut)
	h.tools, h.rawTools, h.toolsValid = out.Tools, rawOut.Tools, true
	return h.tools, nil
}

// ToolsRaw is ListTools with each tool exactly as the child described it, for
// serving the list on unchanged: a field we do not model must not vanish.
func (h *Host) ToolsRaw(ctx context.Context) ([]Tool, []json.RawMessage, error) {
	tools, err := h.ListTools(ctx)
	if err != nil {
		return nil, nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return tools, h.rawTools, nil
}

// CallToolRaw invokes a tool with the caller's own JSON arguments and returns
// the child's result unchanged.
func (h *Host) CallToolRaw(ctx context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.startLocked(ctx); err != nil {
		return nil, err
	}
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	return h.callLocked(ctx, "tools/call", map[string]any{"name": name, "arguments": args})
}

// Kill stops the child at once, as Close does, and makes every later call fail
// with why rather than restarting it.
//
// It does not wait for a call in flight: that call fails when the child dies.
func (h *Host) Kill(why error) {
	h.procMu.Lock()
	defer h.procMu.Unlock()
	h.killed = why
	if h.proc != nil {
		// Already exited is the outcome Kill wants.
		_ = h.proc.Kill()
	}
}

// Tool finds one of the child's tools by name.
func (h *Host) Tool(ctx context.Context, name string) (Tool, bool, error) {
	tools, err := h.ListTools(ctx)
	if err != nil {
		return Tool{}, false, err
	}
	for _, t := range tools {
		if t.Name == name {
			return t, true, nil
		}
	}
	return Tool{}, false, nil
}

// CallTool invokes one of the child's tools and returns its text content.
func (h *Host) CallTool(ctx context.Context, name string, args map[string]string) (string, bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.startLocked(ctx); err != nil {
		return "", false, err
	}
	// Arguments arrive as strings from our meta-tool; pass them through as the
	// child's schema expects.
	anyArgs := make(map[string]any, len(args))
	for k, v := range args {
		anyArgs[k] = v
	}
	raw, err := h.callLocked(ctx, "tools/call", map[string]any{"name": name, "arguments": anyArgs})
	if err != nil {
		return "", false, err
	}
	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", false, fmt.Errorf("%s: could not read its result: %w", h.spec.Name, err)
	}
	var text string
	for _, c := range out.Content {
		text += c.Text
	}
	return text, out.IsError, nil
}

// Close stops the child and reaps it.
func (h *Host) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.started {
		return nil
	}
	if h.stdin != nil {
		h.stdin.Close()
	}
	if h.cmd != nil && h.cmd.Process != nil {
		// Already exited is the outcome Kill wants.
		_ = h.cmd.Process.Kill()
	}
	h.started = false
	h.toolsValid = false
	return nil
}
