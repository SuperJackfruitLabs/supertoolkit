// A forge defined in configuration, end to end: the host exists nowhere in the
// compiled-in catalogue, yet a child holding only a placeholder reaches it with
// the real credential, in whichever Authorization scheme the forge speaks.
package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

const forgeSecret = "forge_e2e_real_credential_0123"

// hit is one request the fake forge actually received.
type hit struct {
	Method, Path, Auth, ContentType, Body string
}

// forgeSeen is what the fake forge saw; a denied request must never appear.
type forgeSeen struct {
	mu   sync.Mutex
	hits []hit
}

func (f *forgeSeen) add(h hit)  { f.mu.Lock(); f.hits = append(f.hits, h); f.mu.Unlock() }
func (f *forgeSeen) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.hits) }
func (f *forgeSeen) last() hit {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.hits) == 0 {
		return hit{}
	}
	return f.hits[len(f.hits)-1]
}

func forgeRig(t *testing.T, scheme string) (*rig, string) {
	r, cfgPath, _ := forgeRigWith(t, scheme, "    preset: read\n", nil)
	return r, cfgPath
}

// forgeRigWith takes the rule-bearing tail of the service block (indented four
// spaces, ending in a newline) and an optional audit observer, and also returns
// what the fake forge received.
func forgeRigWith(t *testing.T, scheme, tail string, mk func(*policy.Config) broker.Observer) (*rig, string, *forgeSeen) {
	t.Helper()
	provCA, err := broker.NewCA("e2e forge CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 8)
	got := &forgeSeen{}
	// A plain handler, not a ServeMux: the mux would clean paths and redirect,
	// hiding exactly what the broker forwarded.
	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.add(hit{r.Method, r.URL.EscapedPath(), r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(body)})
		select {
		case seen <- r.Header.Get("Authorization"):
		default:
		}
		json.NewEncoder(w).Encode(map[string]string{"login": "chotu"})
	})
	provLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustLeaf(t, provCA, "forge.example.test")
	provSrv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{leaf}}}
	go provSrv.ServeTLS(provLn, "", "")
	t.Cleanup(func() { provSrv.Close() })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	yaml := "workspace: e2e\nservices:\n  forge-main:\n    kind: forge\n    provider: forgejo\n" +
		"    host: forge.example.test\n    scheme: " + scheme + "\n    env_var: FORGEJO_TOKEN\n" +
		"    repositories: [o/r]\n" + tail
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(filepath.Join(dir, "state"), "e2e passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put("forge-main", forgeSecret); err != nil {
		t.Fatal(err)
	}
	ca, err := broker.NewCA("e2e broker CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPath, err := ca.WriteCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	var obs broker.Observer
	if mk != nil {
		obs = mk(cfg)
	}
	b, err := broker.New(broker.Options{
		Config: cfg, CA: ca, Secrets: store.Get, Observer: obs,
		Upstream: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: provCA.Pool()},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if strings.HasPrefix(addr, "forge.example.test:") {
					addr = provLn.Addr().String()
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(proxyLn)
	t.Cleanup(func() { proxyLn.Close() })
	return &rig{proxyURL: "http://" + proxyLn.Addr().String(), caPath: caPath, broker: b, seen: seen}, cfgPath, got
}

func TestForgeServiceInjectsThroughTheProxy(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	for _, c := range []struct{ scheme, sent, want string }{
		{"bearer", "Bearer ", "Bearer "},
		{"token", "token ", "token "},
	} {
		t.Run(c.scheme, func(t *testing.T) {
			r, _ := forgeRig(t, c.scheme)
			env := append(r.childEnv(), "FORGEJO_TOKEN="+broker.Placeholder("forge-main"))
			cmd := exec.Command("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}",
				"-H", "Authorization: "+c.sent+broker.Placeholder("forge-main"),
				"https://forge.example.test/api/v1/user")
			cmd.Env = env
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("child failed: %v (output %q)", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != "200" {
				t.Fatalf("child saw http %s, want 200", got)
			}
			select {
			case authz := <-r.seen:
				if authz != c.want+forgeSecret {
					t.Fatalf("provider received %q, want %q", authz, c.want+forgeSecret)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the provider never saw a request")
			}
			for _, kv := range env {
				if strings.Contains(kv, forgeSecret) {
					t.Fatalf("the child's environment contained the credential: %s", strings.SplitN(kv, "=", 2)[0])
				}
			}
			if st := r.broker.Stats(); st.Swap != 1 {
				t.Fatalf("Stats() = %+v, want exactly one swap", st)
			}
		})
	}
}

// curlForge runs a real curl through the proxy as the child would, with the
// placeholder as its credential, and returns the http status.
func curlForge(t *testing.T, r *rig, method, url, body string, extra ...string) string {
	t.Helper()
	args := []string{"-s", "-m", "20", "--path-as-is", "-o", "/dev/null", "-w", "%{http_code}", "-X", method,
		"-H", "Authorization: Bearer " + broker.Placeholder("forge-main")}
	if body != "" {
		args = append(args, "-H", "Content-Type: application/json", "--data-binary", body)
	}
	args = append(args, extra...)
	args = append(args, url)
	cmd := exec.Command("curl", args...)
	cmd.Env = r.childEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("curl %s %s failed: %v (%q)", method, url, err, out)
	}
	return strings.TrimSpace(string(out))
}

func needCurl(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
}

const forgeBase = "https://forge.example.test/api/v1"

func TestForgeRulesAllowThenDeny(t *testing.T) {
	needCurl(t)
	r, _, got := forgeRigWith(t, "bearer", "    preset: issues\n", nil)

	if c := curlForge(t, r, "POST", forgeBase+"/repos/o/r/issues", `{"title":"x"}`); c != "200" {
		t.Fatalf("allowed POST returned %s, want 200", c)
	}
	if got.count() != 1 {
		t.Fatalf("provider hits = %d, want 1", got.count())
	}
	if h := got.last(); h.Auth != "Bearer "+forgeSecret || h.Method != "POST" || h.Path != "/api/v1/repos/o/r/issues" {
		t.Fatalf("provider saw %+v, want the substituted Bearer credential", h)
	}

	if c := curlForge(t, r, "DELETE", forgeBase+"/repos/o/r/issues/1", ""); c != "403" {
		t.Fatalf("DELETE returned %s, want 403", c)
	}
	if got.count() != 1 {
		t.Fatalf("provider hits = %d after a denied DELETE, want still 1", got.count())
	}
}

func TestForgeRulesRefuseTraversalThroughCurl(t *testing.T) {
	needCurl(t)
	r, _, got := forgeRigWith(t, "bearer", "    preset: issues\n", nil)
	for _, p := range []string{
		"/repos/o/r/../../admin/users",
		"/repos/o/r/%2e%2e/%2e%2e/admin/users",
		"/repos/o/r/%2E%2E/%2E%2E/admin/users",
		"/repos/o/r/.%2e/.%2e/admin/users",
		"/repos//o/r/issues",
		"/repos/o/r/issues//1",
		"/repos/o/r/issues%2f1",
		"/repos/o/r/issues%2F..%2F..%2Fadmin",
	} {
		if c := curlForge(t, r, "GET", forgeBase+p, ""); c != "403" {
			t.Errorf("GET %s returned %s, want 403", p, c)
		}
	}
	if got.count() != 0 {
		t.Fatalf("provider received %d requests, want 0: %+v", got.count(), got.hits)
	}
}

func TestForgeBodyConditionThroughCurl(t *testing.T) {
	needCurl(t)
	tail := "    preset: read\n    rules:\n" +
		"      - allow: \"PATCH /repos/{owner}/{repo}/issues/*\"\n        when: {state: absent}\n"
	r, _, got := forgeRigWith(t, "bearer", tail, nil)
	url := forgeBase + "/repos/o/r/issues/1"

	if c := curlForge(t, r, "PATCH", url, `{"title":"x"}`); c != "200" {
		t.Fatalf("title-only PATCH returned %s, want 200", c)
	}
	if got.count() != 1 {
		t.Fatalf("provider hits = %d, want 1", got.count())
	}
	if h := got.last(); h.ContentType != "application/json" || h.Body != `{"title":"x"}` || h.Auth != "Bearer "+forgeSecret {
		t.Fatalf("provider saw %+v", h)
	}
	for _, body := range []string{`{"state":"closed"}`, `{"State":"closed"}`} {
		if c := curlForge(t, r, "PATCH", url, body); c != "403" {
			t.Errorf("PATCH %s returned %s, want 403", body, c)
		}
	}
	if got.count() != 1 {
		t.Fatalf("provider hits = %d after denied bodies, want still 1", got.count())
	}
}

func TestForgeGraphQLDeniedByDefault(t *testing.T) {
	needCurl(t)
	tail := "    preset: none\n    rules:\n      - allow: \"POST /**\"\n"
	r, _, got := forgeRigWith(t, "bearer", tail, nil)
	if c := curlForge(t, r, "POST", forgeBase+"/graphql", `{"query":"{viewer{login}}"}`); c != "403" {
		t.Fatalf("graphql returned %s, want 403", c)
	}
	if got.count() != 0 {
		t.Fatalf("provider hits = %d, want 0", got.count())
	}

	r2, _, got2 := forgeRigWith(t, "bearer", tail+"    allow_graphql: true\n", nil)
	if c := curlForge(t, r2, "POST", forgeBase+"/graphql", `{"query":"{viewer{login}}"}`); c != "200" {
		t.Fatalf("graphql with allow_graphql returned %s, want 200", c)
	}
	if got2.count() != 1 {
		t.Fatalf("provider hits = %d, want 1", got2.count())
	}
}

func TestForgeDeniedRequestLandsInTheLedgerWithRuleNotSecret(t *testing.T) {
	needCurl(t)
	led, err := ledger.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, _, _ := forgeRigWith(t, "bearer", "    preset: issues\n", func(*policy.Config) broker.Observer {
		return ruleObserver{led}
	})
	if c := curlForge(t, r, "DELETE", forgeBase+"/repos/o/r/issues/1", ""); c != "403" {
		t.Fatalf("DELETE returned %s, want 403", c)
	}
	entries, err := led.Read(10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("ledger entries = %v, err %v; want exactly one", entries, err)
	}
	if e := entries[0]; e.Rule != "builtin:default-deny" || !strings.HasPrefix(e.Outcome, "403") || e.Service != "forge-main" {
		t.Fatalf("entry = %+v, want a 403 naming builtin:default-deny", e)
	}
	raw, err := os.ReadFile(led.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), forgeSecret) {
		t.Error("the ledger contains the credential")
	}
}

type ruleObserver struct{ led *ledger.Ledger }

func (o ruleObserver) Observe(r broker.Record) {
	o.led.Append(ledger.Entry{
		When: r.When.UTC(), Service: r.Service, Host: r.Host, Method: r.Method,
		Path: r.Path, Outcome: r.Status, Rule: r.Rule, Caller: "e2e",
	})
}
