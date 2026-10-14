package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// fakeFronted stands in for a running child, so these tests exercise the
// meta-tool wiring without spawning a process.
type fakeFronted struct {
	tools  []mcphost.Tool
	called []string
	answer string
	fail   error
}

func (f *fakeFronted) ListTools(context.Context) ([]mcphost.Tool, error) {
	return f.tools, f.fail
}

func (f *fakeFronted) Tool(ctx context.Context, name string) (mcphost.Tool, bool, error) {
	for _, t := range f.tools {
		if t.Name == name {
			return t, true, nil
		}
	}
	return mcphost.Tool{}, false, nil
}

func (f *fakeFronted) CallTool(ctx context.Context, name string, args map[string]string) (string, bool, error) {
	f.called = append(f.called, name)
	if f.fail != nil {
		return "", false, f.fail
	}
	return f.answer, false, nil
}

func boolp(b bool) *bool { return &b }

func frontedRig(t *testing.T, profile string, wait time.Duration) (*Server, *fakeFronted, *approval.Queue) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	os.WriteFile(p, []byte(`
workspace: test
services:
  github:
    scopes: []
servers:
  faker:
    command: /bin/true
    host: fake.example
    env_var: FAKE_API_TOKEN
    capabilities:
      wipe_everything: deny
profiles:
  looker:
    faker: [read_thing]
`), 0o600)
	cfg, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	prof, ok := cfg.Profile(profile)
	if !ok {
		t.Fatalf("profile %q not found", profile)
	}
	child := &fakeFronted{
		answer: "the child's answer",
		tools: []mcphost.Tool{
			{Name: "read_thing", Description: "Read a thing.",
				Annotations: struct {
					ReadOnlyHint    *bool `json:"readOnlyHint"`
					DestructiveHint *bool `json:"destructiveHint"`
				}{ReadOnlyHint: boolp(true)}},
			{Name: "write_thing", Description: "Write a thing."},
			{Name: "wipe_everything", Description: "Wipe it all."},
		},
	}
	q, qerr := approval.Open(t.TempDir(), time.Minute)
	if qerr != nil {
		t.Fatal(qerr)
	}
	srv, err := NewServer(Options{
		Config: cfg, Profile: prof, Queue: q, ApprovalWait: wait,
		Exec:    func(context.Context, string, *http.Request) (*http.Response, error) { return nil, nil },
		Servers: func(string) (FrontedServer, error) { return child, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv, child, q
}

func callT(t *testing.T, s *Server, name string, args map[string]string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	var out bytes.Buffer
	if err := s.Serve(context.Background(), bytes.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	json.Unmarshal(out.Bytes(), &resp)
	res := resp["result"].(map[string]any)
	txt := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if isErr, _ := res["isError"].(bool); isErr {
		return "ERROR: " + txt
	}
	return txt
}

// The constraint that must survive a fronted server with fifty tools.
func TestToolsListIsStillFourWithServersConfigured(t *testing.T) {
	srv, _, _ := frontedRig(t, "", 0)
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	var out bytes.Buffer
	srv.Serve(context.Background(), bytes.NewReader(body), &out)
	var resp map[string]any
	json.Unmarshal(out.Bytes(), &resp)
	tools := resp["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("tools/list returned %d, want 4 — a child's tools must not reach the context window", len(tools))
	}
}

func TestDiscoveryMarksFrontedServers(t *testing.T) {
	srv, _, _ := frontedRig(t, "", 0)
	got := callT(t, srv, "discover_server_categories", nil)
	if !strings.Contains(got, "faker") {
		t.Fatalf("the fronted server is missing from discovery: %s", got)
	}
	if !strings.Contains(got, "fronted server") {
		t.Errorf("discovery does not say which categories are not ours: %s", got)
	}
	if !strings.Contains(got, "service") {
		t.Errorf("the native service is missing: %s", got)
	}
}

// The child's annotation may promote a tool; absence of one may not.
func TestFrontedPolicyFollowsAnnotationsAndDefaultsToApproval(t *testing.T) {
	srv, _, _ := frontedRig(t, "", 0)
	got := callT(t, srv, "get_category_actions", map[string]string{"category": "faker"})

	var parsed struct {
		Actions []struct {
			Action string `json:"action"`
			Policy string `json:"policy"`
		} `json:"actions"`
	}
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("could not parse %q: %v", got, err)
	}
	policies := map[string]string{}
	for _, a := range parsed.Actions {
		policies[a.Action] = a.Policy
	}
	if policies["read_thing"] != "agent" {
		t.Errorf("a read-only-annotated tool = %q, want agent", policies["read_thing"])
	}
	if policies["write_thing"] != "approval" {
		t.Errorf("an unannotated tool = %q, want approval — absence of a hint is not evidence of safety", policies["write_thing"])
	}
	if _, present := policies["wipe_everything"]; present {
		t.Error("an explicitly denied tool should not be listed at all")
	}
}

func TestFrontedExecuteCallsTheChild(t *testing.T) {
	srv, child, _ := frontedRig(t, "", 0)
	got := callT(t, srv, "execute_action", map[string]string{"category": "faker", "action": "read_thing"})
	if got != "the child's answer" {
		t.Fatalf("execute_action = %q, want the child's answer", got)
	}
	if len(child.called) != 1 || child.called[0] != "read_thing" {
		t.Fatalf("the child was called with %v", child.called)
	}
}

func TestFrontedWriteQueuesForApproval(t *testing.T) {
	srv, child, q := frontedRig(t, "", 0)
	got := callT(t, srv, "execute_action", map[string]string{
		"category": "faker", "action": "write_thing", "args": `{"text":"hello"}`,
	})
	if !strings.Contains(got, "pending") {
		t.Fatalf("an unannotated tool was not queued: %s", got)
	}
	if len(child.called) != 0 {
		t.Fatalf("the child was called before approval: %v", child.called)
	}
	if len(q.Pending()) != 1 {
		t.Fatalf("Pending() = %d, want 1", len(q.Pending()))
	}
	if !strings.Contains(q.Pending()[0].Summary, "hello") {
		t.Errorf("the approval summary should show what would happen: %q", q.Pending()[0].Summary)
	}
}

func TestFrontedDeniedToolIsRefusedAndNotCalled(t *testing.T) {
	srv, child, _ := frontedRig(t, "", 0)
	got := callT(t, srv, "execute_action", map[string]string{"category": "faker", "action": "wipe_everything"})
	if !strings.HasPrefix(got, "ERROR") {
		t.Fatalf("a denied tool was not refused: %s", got)
	}
	if len(child.called) != 0 {
		t.Fatalf("the child was called for a denied tool: %v", child.called)
	}
}

// A profile narrows a fronted server exactly as it narrows a native service.
func TestProfileNarrowsAFrontedServer(t *testing.T) {
	srv, child, _ := frontedRig(t, "looker", 0)
	actions := callT(t, srv, "get_category_actions", map[string]string{"category": "faker"})
	if strings.Contains(actions, "write_thing") {
		t.Errorf("the looker profile was told write_thing exists: %s", actions)
	}
	details := callT(t, srv, "get_action_details", map[string]string{"category": "faker", "action": "write_thing"})
	if !strings.HasPrefix(details, "ERROR") {
		t.Errorf("the looker profile could describe write_thing: %s", details)
	}
	exec := callT(t, srv, "execute_action", map[string]string{"category": "faker", "action": "write_thing"})
	if !strings.HasPrefix(exec, "ERROR") {
		t.Errorf("the looker profile executed write_thing: %s", exec)
	}
	if len(child.called) != 0 {
		t.Fatalf("the child was called outside the profile: %v", child.called)
	}
}

// A child that cannot be reached should make its category disappear rather than
// break an agent's whole turn.
func TestUnreachableChildDegradesToNoActions(t *testing.T) {
	srv, child, _ := frontedRig(t, "", 0)
	child.fail = fmt.Errorf("child is not running")
	got := callT(t, srv, "discover_server_categories", nil)
	if strings.Contains(got, "faker") {
		t.Errorf("an unreachable server was still offered: %s", got)
	}
	if !strings.Contains(got, "github") {
		t.Errorf("the native service should still be offered: %s", got)
	}
}
