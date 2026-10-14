package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

const theSecret = "ghp_the_real_credential_mcp"

const cfgBody = `
workspace: test
services:
  github:
    scopes: [repo:read]
    capabilities:
      delete_repo: deny
profiles:
  reader:
    github: [get_user]
`

type rig struct {
	srv  *Server
	q    *approval.Queue
	sent chan *http.Request
}

func newRig(t *testing.T, profile string, wait time.Duration) *rig {
	t.Helper()
	p := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	os.WriteFile(p, []byte(cfgBody), 0o600)
	cfg, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	prof, ok := cfg.Profile(profile)
	if !ok {
		t.Fatalf("profile %q not found", profile)
	}
	q := approval.New(time.Minute)
	sent := make(chan *http.Request, 8)
	srv, err := NewServer(Options{
		Config: cfg, Profile: prof, Queue: q, ApprovalWait: wait,
		Exec: func(ctx context.Context, service string, req *http.Request) (*http.Response, error) {
			// The executor is where a credential would be added. The MCP layer
			// never sees one, so the test records only the request.
			sent <- req
			return &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(strings.NewReader(`{"login":"brokered"}`)),
				Header:     http.Header{},
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{srv: srv, q: q, sent: sent}
}

// rpc drives the server exactly as an agent would, over the wire.
func (r *rig) rpc(t *testing.T, method string, params any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	var out bytes.Buffer
	if err := r.srv.Serve(context.Background(), bytes.NewReader(body), &out); err != nil {
		t.Fatalf("Serve() = %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %q: %v", out.String(), err)
	}
	return resp
}

func (r *rig) callTool(t *testing.T, name string, args map[string]string) string {
	t.Helper()
	resp := r.rpc(t, "tools/call", map[string]any{"name": name, "arguments": args})
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", resp)
	}
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %v", result)
	}
	first, _ := content[0].(map[string]any)
	txt, _ := first["text"].(string)
	if isErr, _ := result["isError"].(bool); isErr {
		return "ERROR: " + txt
	}
	return txt
}

// The constraint that gives this phase its shape.
func TestToolsListReturnsExactlyFour(t *testing.T) {
	r := newRig(t, "", 0)
	resp := r.rpc(t, "tools/list", nil)
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("tools/list returned %d tools, want exactly 4 — the catalogue must not reach the context window", len(tools))
	}
	var got []string
	for _, tr := range tools {
		got = append(got, tr.(map[string]any)["name"].(string))
	}
	for i, want := range ToolNames {
		if got[i] != want {
			t.Errorf("tool %d = %q, want %q", i, got[i], want)
		}
	}
}

func TestInitializeAnnouncesTools(t *testing.T) {
	r := newRig(t, "", 0)
	resp := r.rpc(t, "initialize", map[string]any{})
	result := resp["result"].(map[string]any)
	caps := result["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("initialize did not announce tools: %v", result)
	}
}

func TestDiscoveryAnswersFromTheProfile(t *testing.T) {
	full := newRig(t, "", 0).callTool(t, "discover_server_categories", nil)
	if !strings.Contains(full, "github") {
		t.Fatalf("default profile saw no github: %s", full)
	}

	reader := newRig(t, "reader", 0)
	actions := reader.callTool(t, "get_category_actions", map[string]string{"category": "github"})
	if !strings.Contains(actions, "get_user") {
		t.Errorf("reader cannot see get_user: %s", actions)
	}
	// Absent, not refused.
	if strings.Contains(actions, "create_issue") {
		t.Errorf("reader was told create_issue exists: %s", actions)
	}
	if strings.Contains(actions, "delete_repo") {
		t.Errorf("reader was told about a denied capability: %s", actions)
	}
}

func TestDetailsRefusesWhatTheProfileCannotSee(t *testing.T) {
	r := newRig(t, "reader", 0)
	got := r.callTool(t, "get_action_details", map[string]string{"category": "github", "action": "create_issue"})
	if !strings.HasPrefix(got, "ERROR:") {
		t.Fatalf("get_action_details described a capability outside the profile: %s", got)
	}
	// And it must not leak the summary of what it refused.
	if strings.Contains(got, "Open an issue") {
		t.Errorf("the refusal described the action anyway: %s", got)
	}
}

func TestAgentCapabilityExecutesImmediately(t *testing.T) {
	r := newRig(t, "", 0)
	got := r.callTool(t, "execute_action", map[string]string{"category": "github", "action": "get_user"})
	if strings.HasPrefix(got, "ERROR:") {
		t.Fatalf("execute_action failed: %s", got)
	}
	select {
	case req := <-r.sent:
		if req.URL.String() != "https://api.github.com/user" {
			t.Errorf("request URL = %q", req.URL.String())
		}
	default:
		t.Fatal("no request was performed")
	}
}

// A write returns pending and performs nothing.
func TestApprovalCapabilityPerformsNothingYet(t *testing.T) {
	r := newRig(t, "", 0)
	got := r.callTool(t, "execute_action", map[string]string{
		"category": "github", "action": "create_issue",
		"args": `{"owner":"o","repo":"r","title":"t"}`,
	})
	if !strings.Contains(got, "pending") {
		t.Fatalf("want a pending result, got: %s", got)
	}
	select {
	case req := <-r.sent:
		t.Fatalf("the effect happened before approval: %s", req.URL)
	default:
	}
	if len(r.q.Pending()) != 1 {
		t.Fatalf("Pending() = %d, want 1", len(r.q.Pending()))
	}
	// The queued summary is for a human, so it must not carry a credential.
	if strings.Contains(r.q.Pending()[0].Summary, theSecret) {
		t.Error("the approval summary contains a credential")
	}
}

func TestApprovedEffectHappensExactlyOnce(t *testing.T) {
	r := newRig(t, "", 2*time.Second)
	done := make(chan string, 1)
	go func() {
		done <- r.callTool(t, "execute_action", map[string]string{
			"category": "github", "action": "create_issue",
			"args": `{"owner":"o","repo":"r","title":"t"}`,
		})
	}()
	// Wait for it to be queued, then approve.
	deadline := time.Now().Add(2 * time.Second)
	for len(r.q.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	pend := r.q.Pending()
	if len(pend) != 1 {
		t.Fatalf("nothing queued")
	}
	if err := r.q.Decide(pend[0].ID, true, "operator"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if strings.HasPrefix(got, "ERROR:") {
			t.Fatalf("approved effect failed: %s", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("execute_action never returned after approval")
	}
	if n := len(r.sent); n != 1 {
		t.Fatalf("the effect ran %d times, want exactly 1", n)
	}
}

func TestDeniedCapabilityIsRefused(t *testing.T) {
	r := newRig(t, "", 0)
	got := r.callTool(t, "execute_action", map[string]string{
		"category": "github", "action": "delete_repo", "args": `{"owner":"o","repo":"r"}`,
	})
	if !strings.HasPrefix(got, "ERROR:") {
		t.Fatalf("a denied capability was not refused: %s", got)
	}
	if len(r.sent) != 0 {
		t.Fatal("a denied capability performed a request")
	}
}

// Parameter validation must survive the MCP layer, since args come from a model.
func TestPathTraversalIsRefusedThroughMCP(t *testing.T) {
	r := newRig(t, "", 0)
	got := r.callTool(t, "execute_action", map[string]string{
		"category": "github", "action": "read_file",
		"args": `{"owner":"../../orgs/x","repo":"r","path":"a"}`,
	})
	if !strings.HasPrefix(got, "ERROR:") {
		t.Fatalf("a traversal argument was accepted: %s", got)
	}
	if len(r.sent) != 0 {
		t.Fatal("a request was performed with a traversal argument")
	}
}

// No response from any tool, on any path including errors, may carry a credential.
func TestNoResponseCarriesACredential(t *testing.T) {
	r := newRig(t, "", 0)
	calls := []struct {
		tool string
		args map[string]string
	}{
		{"discover_server_categories", nil},
		{"get_category_actions", map[string]string{"category": "github"}},
		{"get_action_details", map[string]string{"category": "github", "action": "get_user"}},
		{"execute_action", map[string]string{"category": "github", "action": "get_user"}},
		{"get_category_actions", map[string]string{"category": "nonexistent"}},
		{"execute_action", map[string]string{"category": "github", "action": "delete_repo"}},
		{"nonexistent_tool", nil},
	}
	for _, c := range calls {
		out := r.callTool(t, c.tool, c.args)
		if strings.Contains(out, theSecret) {
			t.Fatalf("%s leaked a credential: %s", c.tool, out)
		}
	}
}

func TestUnknownMethodIsAnRPCError(t *testing.T) {
	r := newRig(t, "", 0)
	resp := r.rpc(t, "no/such/method", nil)
	if _, ok := resp["error"]; !ok {
		t.Fatalf("want a JSON-RPC error, got %v", resp)
	}
}

var _ = fmt.Sprintf
