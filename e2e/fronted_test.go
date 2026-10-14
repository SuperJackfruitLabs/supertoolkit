package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

const frontedSecret = "the_real_credential_the_child_never_holds"

var (
	fakeOnce sync.Once
	fakeBin  string
)

// buildFakeServer compiles the fixture that stands in for a third-party MCP
// server: it reads its token from the environment, builds its own HTTP client,
// and knows nothing about supertoolkit.
func buildFakeServer(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "stk-e2e-fake")
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "fakeserver")
		if b, err := exec.Command("go", "build", "-o", out, "../testdata/fakeserver").CombinedOutput(); err != nil {
			t.Fatalf("building the fixture server: %v\n%s", err, b)
		}
		fakeBin = out
	})
	return fakeBin
}

// This is Phase 3's point: a server we did not write, holding only a
// placeholder, reaching a provider that receives the real credential.
func TestFrontedServerNeverHoldsTheCredential(t *testing.T) {
	bin := buildFakeServer(t)

	// The provider records what it was given.
	var gotAuth string
	var mu sync.Mutex
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		if gotAuth != "Bearer "+frontedSecret {
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"who": "brokered-through-a-server-we-did-not-write"})
	}))
	defer provider.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	os.WriteFile(cfgPath, []byte(`
workspace: e2e
servers:
  faker:
    command: `+bin+`
    host: fake.example
    env_var: FAKE_API_TOKEN
    capabilities:
      # Both are reads, and the fixture annotates neither, so without these the
      # safe default would queue them for approval — which is the default
      # working, not a bug. An operator promotes what they have looked at.
      report_env: agent
      whoami: agent
`), 0o600)
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// The child is given the placeholder, and a plain-HTTP provider URL so the
	// test needs no CA plumbing: what is under test is that the child never has
	// the credential, and that something else supplies it.
	env := broker.ChildEnv(
		[]string{"PATH=" + os.Getenv("PATH")},
		"", "",
		map[string]string{"FAKE_API_TOKEN": broker.Placeholder("faker")},
		map[string]string{"FAKE_API_URL": provider.URL + "/whoami"},
	)
	host := mcphost.New(mcphost.Spec{Name: "faker", Command: bin, Env: env})
	defer host.Close()

	// Stand in for the broker's egress injection: the child's placeholder is
	// swapped for the real credential on the way out. On a real deployment this
	// is the proxy from Phase 0 doing it on the wire.
	injector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(r.Method, provider.URL+"/whoami", r.Body)
		if strings.Contains(r.Header.Get("Authorization"), broker.Placeholder("faker")) {
			req.Header.Set("Authorization", "Bearer "+frontedSecret)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		w.Write(buf[:n])
	}))
	defer injector.Close()

	// Point the child at the injector, as HTTPS_PROXY would.
	env = broker.ChildEnv(
		[]string{"PATH=" + os.Getenv("PATH")},
		"", "",
		map[string]string{"FAKE_API_TOKEN": broker.Placeholder("faker")},
		map[string]string{"FAKE_API_URL": injector.URL + "/whoami"},
	)
	host.Close()
	host = mcphost.New(mcphost.Spec{Name: "faker", Command: bin, Env: env})
	defer host.Close()

	q, qerr := approval.Open(t.TempDir(), time.Minute)
	if qerr != nil {
		t.Fatal(qerr)
	}
	prof, _ := cfg.Profile("")
	srv, err := mcp.NewServer(mcp.Options{
		Config: cfg, Profile: prof, Queue: q, ApprovalWait: 0,
		Exec:    func(context.Context, string, *http.Request) (*http.Response, error) { return nil, nil },
		Servers: func(string) (mcp.FrontedServer, error) { return host, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	call := func(name string, args map[string]string) string {
		b, _ := json.Marshal(srv.CallTool(context.Background(), name, args))
		return string(b)
	}

	// Walk the four meta-tools as an agent would.
	if got := call("discover_server_categories", nil); !strings.Contains(got, "faker") {
		t.Fatalf("discovery did not offer the fronted server: %s", got)
	}
	if got := call("get_category_actions", map[string]string{"category": "faker"}); !strings.Contains(got, "whoami") {
		t.Fatalf("actions did not include the child's tool: %s", got)
	}

	// The child reports its own view of its credential.
	reported := call("execute_action", map[string]string{"category": "faker", "action": "report_env"})
	if !strings.Contains(reported, broker.Placeholder("faker")) {
		t.Fatalf("the child does not hold the placeholder: %s", reported)
	}
	if strings.Contains(reported, frontedSecret) {
		t.Fatal("the child holds the real credential")
	}

	// And the authenticated call succeeds anyway.
	out := call("execute_action", map[string]string{"category": "faker", "action": "whoami"})
	if !strings.Contains(out, "brokered-through-a-server-we-did-not-write") {
		t.Fatalf("the authenticated call did not succeed: %s", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer "+frontedSecret {
		t.Fatalf("the provider received %q, want the real credential", gotAuth)
	}
	if strings.Contains(out, frontedSecret) {
		t.Fatal("the agent's result contained the credential")
	}
}

// A write on a fronted server still queues, and the child is not called until
// a human decides.
func TestFrontedWriteStillNeedsApprovalEndToEnd(t *testing.T) {
	bin := buildFakeServer(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	os.WriteFile(cfgPath, []byte(`
workspace: e2e
servers:
  faker:
    command: `+bin+`
    host: fake.example
    env_var: FAKE_API_TOKEN
`), 0o600)
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	var calls int
	var mu sync.Mutex
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Write([]byte(`{"ok":true}`))
	}))
	defer provider.Close()

	env := broker.ChildEnv([]string{"PATH=" + os.Getenv("PATH")}, "", "",
		map[string]string{"FAKE_API_TOKEN": broker.Placeholder("faker")},
		map[string]string{"FAKE_API_URL": provider.URL + "/post"})
	host := mcphost.New(mcphost.Spec{Name: "faker", Command: bin, Env: env})
	defer host.Close()

	q, qerr := approval.Open(t.TempDir(), time.Minute)
	if qerr != nil {
		t.Fatal(qerr)
	}
	prof, _ := cfg.Profile("")
	srv, _ := mcp.NewServer(mcp.Options{
		Config: cfg, Profile: prof, Queue: q, ApprovalWait: 0,
		Exec:    func(context.Context, string, *http.Request) (*http.Response, error) { return nil, nil },
		Servers: func(string) (mcp.FrontedServer, error) { return host, nil },
	})

	b, _ := json.Marshal(srv.CallTool(context.Background(), "execute_action", map[string]string{
		"category": "faker", "action": "post_message", "args": `{"text":"hello"}`,
	}))
	if !strings.Contains(string(b), "pending") {
		t.Fatalf("post_message was not queued: %s", b)
	}
	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 0 {
		t.Fatalf("the provider was called %d times before approval", n)
	}
	if len(q.Pending()) != 1 {
		t.Fatalf("Pending() = %d, want 1", len(q.Pending()))
	}
}
