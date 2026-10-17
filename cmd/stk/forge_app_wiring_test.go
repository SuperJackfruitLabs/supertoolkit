package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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

// fakeGHE is a GitHub Enterprise at example.com (the httptest certificate's
// name): it issues numbered installation tokens and records what it was sent.
type fakeGHE struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies []string
	jwts   []string
	api    []string
}

func newFakeGHE(t *testing.T) *fakeGHE {
	f := &fakeGHE{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == "POST" && r.URL.Path == "/api/v3/app/installations/987/access_tokens" {
			f.bodies = append(f.bodies, string(b))
			f.jwts = append(f.jwts, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{
				"token":      fmt.Sprintf("ghs_wired_install_%d", len(f.bodies)),
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
			return
		}
		f.api = append(f.api, r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(map[string]string{"full_name": "Corp/r"})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// transport reaches the fake for any address.
func (f *fakeGHE) transport() *http.Transport {
	tr := f.srv.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.srv.Listener.Addr().String())
	}
	return tr
}

func (f *fakeGHE) exchanges() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.bodies...)
}

func testAppKeyPEM(t *testing.T) string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

func appConfig(t *testing.T, repos string) *policy.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	os.WriteFile(p, []byte("services:\n  ghe-app:\n    kind: forge\n    provider: github\n"+
		"    host: example.com\n    auth: app\n    env_var: GH_TOKEN\n    repositories: ["+repos+"]\n"), 0o600)
	cfg, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func appStore(t *testing.T) (*credential.Store, string) {
	s, err := credential.OpenStore(t.TempDir(), "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	key := testAppKeyPEM(t)
	s.PutMaterial("ghe-app", credential.Material{
		credential.FieldAppID: "4242", credential.FieldPrivateKey: key, credential.FieldInstallationID: "987",
	})
	return s, key
}

// A changed repository list must not be served a token minted for the old one,
// however fresh it is: each config builds new acquirers, as a restart does,
// over the same on-disk cache.
func TestAppForgeCacheFollowsRepositoryScope(t *testing.T) {
	f := newFakeGHE(t)
	store, _ := appStore(t)
	client := &http.Client{Transport: f.transport()}
	token := func(repos string) string {
		cfg := appConfig(t, repos)
		tok, err := secretSource(cfg, store, newAcquirers(cfg, store, client))("ghe-app")
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	token("Corp/a, Corp/b")
	token("Corp/a, Corp/b")
	if got := f.exchanges(); len(got) != 1 {
		t.Fatalf("unchanged config: %d exchanges, want 1 (the cache reused)", len(got))
	}
	if tok := token("Corp/a"); tok != "ghs_wired_install_2" {
		t.Errorf("narrowed: got %q, want a fresh token", tok)
	}
	token("Corp/a, Corp/b, Corp/c")
	want := []string{`{"repositories":["a","b"]}`, `{"repositories":["a"]}`, `{"repositories":["a","b","c"]}`}
	if got := f.exchanges(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("exchange bodies = %q, want %q", got, want)
	}
}

func TestBuiltinGitHubAppCacheKeyUnchanged(t *testing.T) {
	store, _ := appStore(t)
	acqs := newAcquirers(appConfig(t, "Corp/a"), store, http.DefaultClient)
	if s, ok := acqs.githubApp.Shared.(*credential.Store); !ok || s != store {
		t.Fatalf("built-in github-app Shared = %T, want the store itself (key = service name)", acqs.githubApp.Shared)
	}
}

// The whole path through production wiring: newAcquirers + secretSource feed
// the proxy, a child curl holds a placeholder, the API sees only the
// installation token, and no log or ledger line carries the key, JWT or token.
func TestAppForgeInjectsInstallationTokenThroughProxy(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	f := newFakeGHE(t)
	store, keyPEM := appStore(t)
	cfg := appConfig(t, "Corp/r, Corp/s")
	up := f.transport()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	led, err := ledger.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca, err := broker.NewCA("wired CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPath, err := ca.WriteCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := broker.New(broker.Options{
		Config: cfg, CA: ca, Upstream: up, Observer: ledgerObs{led},
		Logger:  slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Secrets: secretSource(cfg, store, newAcquirers(cfg, store, &http.Client{Transport: up})),
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	proxy := "http://" + ln.Addr().String()
	cmd := exec.Command("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}",
		"-H", "Authorization: Bearer "+broker.Placeholder("ghe-app"),
		"https://example.com/api/v3/repos/Corp/r")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HTTPS_PROXY=" + proxy, "https_proxy=" + proxy,
		"CURL_CA_BUNDLE=" + caPath, "SSL_CERT_FILE=" + caPath}
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "200" {
		t.Fatalf("child: %v, http %q", err, out)
	}

	f.mu.Lock()
	api, jwts, bodies := append([]string(nil), f.api...), append([]string(nil), f.jwts...), append([]string(nil), f.bodies...)
	f.mu.Unlock()
	if len(api) != 1 || api[0] != "Bearer ghs_wired_install_1" {
		t.Fatalf("API saw %q, want one Bearer installation token", api)
	}
	if len(jwts) != 1 || len(bodies) != 1 || bodies[0] != `{"repositories":["r","s"]}` {
		t.Fatalf("exchanges: jwts %d, bodies %q", len(jwts), bodies)
	}
	parts := strings.Split(jwts[0], ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		t.Fatalf("the token endpoint was not sent a JWT: %q", jwts[0])
	}
	if entries, err := led.Read(10); err != nil || len(entries) != 1 {
		t.Fatalf("ledger = %+v, %v; want one entry", entries, err)
	}
	raw, err := os.ReadFile(led.Path())
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"JWT": jwts[0], "JWT signature": parts[2], "installation token": "ghs_wired_install_1"}
	for i, line := range strings.Split(strings.TrimSpace(keyPEM), "\n") {
		if !strings.HasPrefix(line, "-----") {
			secrets[fmt.Sprintf("private key line %d", i)] = line
		}
	}
	for where, data := range map[string]string{"ledger": string(raw), "log": logs.String()} {
		for what, s := range secrets {
			if strings.Contains(data, s) {
				t.Errorf("the %s contains the %s", where, what)
			}
		}
	}
}

type ledgerObs struct{ led *ledger.Ledger }

func (o ledgerObs) Observe(r broker.Record) {
	o.led.Append(ledger.Entry{When: r.When.UTC(), Service: r.Service, Host: r.Host, Method: r.Method,
		Path: r.Path, Outcome: r.Status, Rule: r.Rule, Caller: "test"})
}
