package e2e

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

const mcpSecret = "ghp_mcp_e2e_real_credential"

const mcpCfg = `
workspace: e2e
services:
  github:
    scopes: [repo:read]
    capabilities:
      delete_repo: deny
profiles:
  reader:
    github: [get_user]
`

// agent drives the MCP server over a pipe, as a host would over stdio.
type agent struct {
	in   io.WriteCloser
	out  *bufio.Reader
	id   int
	seen chan string // Authorization the provider received
	q    *approval.Queue
}

func newAgent(t *testing.T, profile string, wait time.Duration) *agent {
	t.Helper()

	// A provider that records what credential it was given.
	seen := make(chan string, 8)
	provCA, err := broker.NewCA("mcp e2e provider CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := provCA.LeafForTest("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]string{"path": r.URL.Path, "ok": "yes"})
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}}}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	os.WriteFile(cfgPath, []byte(mcpCfg), 0o600)
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(filepath.Join(dir, "state"), "e2e key")
	if err != nil {
		t.Fatal(err)
	}
	store.Put("github", mcpSecret)

	prof, ok := cfg.Profile(profile)
	if !ok {
		t.Fatalf("profile %q not found", profile)
	}
	q, qerr := approval.Open(t.TempDir(), time.Minute)
	if qerr != nil {
		t.Fatal(qerr)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: provCA.Pool()},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if strings.HasPrefix(addr, "api.github.com:") {
					addr = ln.Addr().String()
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	}
	srvMCP, err := mcp.NewServer(mcp.Options{
		Config: cfg, Profile: prof, Queue: q, ApprovalWait: wait,
		Exec: func(ctx context.Context, name string, req *http.Request) (*http.Response, error) {
			secret, err := store.Get(name)
			if err != nil {
				return nil, err
			}
			e, _ := cfg.Service(name)
			req.Header.Set("Authorization", "Bearer "+broker.Placeholder(name))
			credential.Inject(req, broker.Placeholder(name), secret, e.Entry().Placement, e.Entry().Field)
			return client.Do(req)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go srvMCP.Serve(context.Background(), inR, outW)
	t.Cleanup(func() { inW.Close() })
	return &agent{in: inW, out: bufio.NewReader(outR), seen: seen, q: q}
}

func (a *agent) rpc(t *testing.T, method string, params any) map[string]any {
	t.Helper()
	a.id++
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": a.id, "method": method, "params": params})
	if _, err := a.in.Write(append(req, '\n')); err != nil {
		t.Fatal(err)
	}
	var resp map[string]any
	if err := json.NewDecoder(a.out).Decode(&resp); err != nil {
		t.Fatalf("decoding the reply to %s: %v", method, err)
	}
	return resp
}

func (a *agent) tool(t *testing.T, name string, args map[string]string) string {
	t.Helper()
	resp := a.rpc(t, "tools/call", map[string]any{"name": name, "arguments": args})
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", resp)
	}
	content := res["content"].([]any)
	txt := content[0].(map[string]any)["text"].(string)
	if isErr, _ := res["isError"].(bool); isErr {
		return "ERROR: " + txt
	}
	return txt
}

// The whole Phase 1 path, in the order an agent actually walks it.
func TestAgentDiscoversThenExecutes(t *testing.T) {
	a := newAgent(t, "", 0)

	init := a.rpc(t, "initialize", map[string]any{})
	if _, ok := init["result"]; !ok {
		t.Fatalf("initialize failed: %v", init)
	}

	list := a.rpc(t, "tools/list", nil)
	tools := list["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("an agent sees %d tools, want 4", len(tools))
	}

	if got := a.tool(t, "discover_server_categories", nil); !strings.Contains(got, "github") {
		t.Fatalf("discovery did not offer github: %s", got)
	}
	if got := a.tool(t, "get_category_actions", map[string]string{"category": "github"}); !strings.Contains(got, "get_user") {
		t.Fatalf("actions did not include get_user: %s", got)
	}
	if got := a.tool(t, "get_action_details", map[string]string{"category": "github", "action": "get_user"}); !strings.Contains(got, "authenticated user") {
		t.Fatalf("details were unhelpful: %s", got)
	}

	out := a.tool(t, "execute_action", map[string]string{"category": "github", "action": "get_user"})
	if strings.HasPrefix(out, "ERROR") {
		t.Fatalf("execute_action failed: %s", out)
	}

	select {
	case authz := <-a.seen:
		if authz != "Bearer "+mcpSecret {
			t.Fatalf("the provider received %q, want the real credential", authz)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the provider was never reached")
	}
	// And the agent was never shown it.
	if strings.Contains(out, mcpSecret) {
		t.Fatal("execute_action returned the credential to the agent")
	}
}

func TestApprovalBlocksUntilDecidedThenRunsOnce(t *testing.T) {
	a := newAgent(t, "", 3*time.Second)
	done := make(chan string, 1)
	go func() {
		done <- a.tool(t, "execute_action", map[string]string{
			"category": "github", "action": "create_issue",
			"args": `{"owner":"o","repo":"r","title":"t"}`,
		})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for len(a.q.Pending()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	pend := a.q.Pending()
	if len(pend) != 1 {
		t.Fatal("nothing was queued for approval")
	}
	// Nothing has happened yet.
	select {
	case authz := <-a.seen:
		t.Fatalf("the effect happened before approval: %q", authz)
	default:
	}

	if _, err := a.q.Decide(pend[0].ID, true, "operator"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if strings.HasPrefix(got, "ERROR") {
			t.Fatalf("the approved effect failed: %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("execute_action never returned after approval")
	}
	if n := len(a.seen); n != 1 {
		t.Fatalf("the effect reached the provider %d times, want exactly 1", n)
	}
}

func TestRestrictedProfileCannotSeeDescribeOrExecute(t *testing.T) {
	a := newAgent(t, "reader", 0)

	actions := a.tool(t, "get_category_actions", map[string]string{"category": "github"})
	if strings.Contains(actions, "create_issue") {
		t.Errorf("the reader profile was told create_issue exists: %s", actions)
	}

	details := a.tool(t, "get_action_details", map[string]string{"category": "github", "action": "create_issue"})
	if !strings.HasPrefix(details, "ERROR") {
		t.Errorf("the reader profile could describe create_issue: %s", details)
	}

	exec := a.tool(t, "execute_action", map[string]string{
		"category": "github", "action": "create_issue", "args": `{"owner":"o","repo":"r","title":"t"}`,
	})
	if !strings.HasPrefix(exec, "ERROR") {
		t.Errorf("the reader profile executed create_issue: %s", exec)
	}
	select {
	case authz := <-a.seen:
		t.Fatalf("a request was made outside the profile: %q", authz)
	default:
	}
}

func TestDeniedCapabilityIsUnreachableEvenForTheDefaultProfile(t *testing.T) {
	a := newAgent(t, "", 0)
	out := a.tool(t, "execute_action", map[string]string{
		"category": "github", "action": "delete_repo", "args": `{"owner":"o","repo":"r"}`,
	})
	if !strings.HasPrefix(out, "ERROR") {
		t.Fatalf("a denied capability executed: %s", out)
	}
	if len(a.q.Pending()) != 0 {
		t.Fatal("a denied capability was queued for approval instead of refused")
	}
}
