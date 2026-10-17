package broker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/rules"
)

const theSecret = "ghp_the_real_credential"

// fixture stands up a local provider pretending to be api.github.com, a broker
// in front of it, and a client that trusts the broker.
type fixture struct {
	broker     *Broker
	proxyURL   *url.URL
	clientCA   *tls.Config
	provider   string // host:port of the local provider
	tunnelHits *int64
	// providerHits counts every request the provider received; secretCalls
	// counts every call to the secret source.
	providerHits *atomic.Int64
	secretCalls  *atomic.Int64
	// lastBody is the body of the provider's most recent catch-all request.
	lastBody chan []byte
	// logs holds everything the broker logged, at debug level.
	logs *lockedBuf
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newFixture(t *testing.T, cfgBody string) *fixture {
	t.Helper()
	return newFixtureKey(t, cfgBody, "")
}

func newFixtureKey(t *testing.T, cfgBody, proxyKey string) *fixture {
	t.Helper()

	// The provider's own CA, so the broker verifies it like a real upstream.
	providerCA, err := NewCA("test provider CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := providerCA.leafFor("api.github.com")
	if err != nil {
		t.Fatal(err)
	}

	var providerHits, secretCalls atomic.Int64
	lastBody := make(chan []byte, 16)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case lastBody <- body:
		default:
		}
		json.NewEncoder(w).Encode(map[string]string{"authorization": r.Header.Get("Authorization"), "path": r.URL.EscapedPath()})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		decoded := ""
		if enc, ok := strings.CutPrefix(authz, "Basic "); ok {
			if raw, err := base64.StdEncoding.DecodeString(enc); err == nil {
				decoded = string(raw)
			}
		}
		json.NewEncoder(w).Encode(map[string]string{
			"authorization": authz, "basic_decoded": decoded, "proto": r.Proto,
		})
	})
	mux.HandleFunc("/trailers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(200)
		w.Write([]byte("payload"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		w.Header().Set("Grpc-Status", "0")
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		f, _ := w.(http.Flusher)
		for i := 0; i < 5; i++ {
			w.Write([]byte("chunk\n"))
			if f != nil {
				f.Flush()
			}
		}
	})

	provSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			providerHits.Add(1)
			mux.ServeHTTP(w, r)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}, NextProtos: []string{"h2", "http/1.1"}},
	}
	if err := http2.ConfigureServer(provSrv, &http2.Server{}); err != nil {
		t.Fatal(err)
	}
	provLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go provSrv.ServeTLS(provLn, "", "")
	t.Cleanup(func() { provSrv.Close() })
	provAddr := provLn.Addr().String()

	// Config.
	cfgPath := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// The broker's upstream: trusts the provider's CA, and resolves the
	// service's hostname to the local provider.
	upstream := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: providerCA.Pool(), MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "api.github.com:") {
				addr = provAddr
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}

	var tunnelHits int64
	logs := &lockedBuf{}
	brokerCA, err := NewCA("test broker CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Options{
		Config: cfg, CA: brokerCA, ProxyKey: proxyKey,
		Logger:   slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Secrets:  func(string) (string, error) { secretCalls.Add(1); return theSecret, nil },
		Upstream: upstream,
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			tunnelHits++
			// Tunnel targets go to the provider too, so the test needs no internet.
			return (&net.Dialer{}).DialContext(ctx, network, provAddr)
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

	pu, _ := url.Parse("http://" + proxyLn.Addr().String())
	return &fixture{
		broker: b, proxyURL: pu, provider: provAddr, tunnelHits: &tunnelHits,
		providerHits: &providerHits, secretCalls: &secretCalls, lastBody: lastBody,
		logs:     logs,
		clientCA: &tls.Config{RootCAs: brokerCA.Pool()},
	}
}

func (f *fixture) client(forceH1 bool) *http.Client {
	tr := &http.Transport{
		Proxy:             http.ProxyURL(f.proxyURL),
		TLSClientConfig:   f.clientCA,
		ForceAttemptHTTP2: !forceH1,
	}
	if forceH1 {
		tr.TLSClientConfig = f.clientCA.Clone()
		tr.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
	return &http.Client{Transport: tr, Timeout: 20 * time.Second}
}

const githubOnly = `
workspace: test
services:
  github:
    scopes: [repo:read]
`

func TestInterceptsAndInjects(t *testing.T) {
	f := newFixture(t, githubOnly)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+Placeholder("github"))

	resp, err := f.client(false).Do(req)
	if err != nil {
		t.Fatalf("request through the broker failed: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]string
	json.NewDecoder(resp.Body).Decode(&out)

	if got := out["authorization"]; got != "Bearer "+theSecret {
		t.Fatalf("provider saw %q, want the real credential", got)
	}
	st := f.broker.Stats()
	if st.Intercept != 1 || st.Swap != 1 {
		t.Fatalf("Stats() = %+v, want one interception and one swap", st)
	}
}

// A host outside policy must be tunnelled, not decrypted. This is what keeps
// interception's blast radius equal to the configured service list.
func TestOutOfPolicyHostIsTunnelledNotOpened(t *testing.T) {
	f := newFixture(t, githubOnly)
	// elsewhere.example is not in the config, so the broker must not terminate
	// its TLS — the client will fail to verify the provider cert, which proves
	// the bytes were passed through rather than re-signed by our CA.
	req, _ := http.NewRequest("GET", "https://elsewhere.example/user", nil)
	_, err := f.client(false).Do(req)
	if err == nil {
		t.Fatal("expected certificate verification to fail, which proves no interception")
	}
	st := f.broker.Stats()
	if st.Tunnel != 1 {
		t.Fatalf("Stats() = %+v, want one tunnel", st)
	}
	if st.Intercept != 0 || st.Swap != 0 {
		t.Fatalf("Stats() = %+v, want no interception and no swap for an out-of-policy host", st)
	}
}

// gRPC carries its status in a trailer. The control request, straight to the
// provider, is what separates "the broker dropped it" from "the provider never
// sent one" — without it a missing trailer is ambiguous.
func TestTrailersSurviveInterception(t *testing.T) {
	f := newFixture(t, githubOnly)

	control := &http.Client{Transport: &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}}
	cr, err := control.Get("https://" + f.provider + "/trailers")
	if err != nil {
		t.Fatalf("control request failed: %v", err)
	}
	io.Copy(io.Discard, cr.Body)
	cr.Body.Close()
	if got := cr.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("control: provider trailer = %q, want %q — the test fixture is broken, not the broker", got, "0")
	}

	resp, err := f.client(false).Get("https://api.github.com/trailers")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("through the broker: Grpc-Status trailer = %q, want %q — gRPC would break", got, "0")
	}
}

// Each leg negotiates its own protocol version. A client speaking HTTP/1.1 is
// bridged to an upstream speaking h2, which is why the provider's view of the
// protocol is not the client's. The assertion therefore checks the client leg
// and the broker's own counter, and records the bridging as intended.
func TestBothProtocolVersionsCarry(t *testing.T) {
	for _, tc := range []struct {
		name       string
		forceH1    bool
		wantClient string
	}{
		{"http1", true, "HTTP/1.1"},
		{"h2", false, "HTTP/2.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, githubOnly)
			req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
			req.Header.Set("Authorization", "Bearer "+Placeholder("github"))
			resp, err := f.client(tc.forceH1).Do(req)
			if err != nil {
				t.Fatalf("%s failed: %v", tc.name, err)
			}
			defer resp.Body.Close()
			var out map[string]string
			json.NewDecoder(resp.Body).Decode(&out)

			if resp.Proto != tc.wantClient {
				t.Errorf("client leg spoke %q, want %q", resp.Proto, tc.wantClient)
			}
			if out["authorization"] != "Bearer "+theSecret {
				t.Errorf("credential was not injected over %s", tc.name)
			}
			st := f.broker.Stats()
			if tc.forceH1 && st.H1 != 1 {
				t.Errorf("Stats() = %+v, want one http/1.1 connection", st)
			}
			if !tc.forceH1 && st.H2 != 1 {
				t.Errorf("Stats() = %+v, want one h2 connection", st)
			}
			// The upstream leg is independent, and is expected to use h2
			// regardless of what the client chose.
			if out["proto"] != "HTTP/2.0" {
				t.Errorf("upstream leg spoke %q, want HTTP/2.0 — the broker should bridge versions", out["proto"])
			}
		})
	}
}

func TestStreamingIsNotBuffered(t *testing.T) {
	f := newFixture(t, githubOnly)
	resp, err := f.client(false).Get("https://api.github.com/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if n := strings.Count(string(body), "chunk"); n != 5 {
		t.Fatalf("got %d chunks, want 5: %q", n, string(body))
	}
}

// The audit record is the operator's evidence, and it must never become a place
// a credential leaks to.
func TestAuditNeverContainsTheSecret(t *testing.T) {
	f := newFixture(t, githubOnly)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+Placeholder("github"))
	resp, err := f.client(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	records := f.broker.Audit()
	if len(records) == 0 {
		t.Fatal("no audit records written")
	}
	for _, r := range records {
		blob := r.Host + r.Method + r.Path + r.Proto + r.Injected + r.AuthzFP + r.Status
		if strings.Contains(blob, theSecret) {
			t.Fatalf("audit record contains the secret: %+v", r)
		}
	}
	if !strings.HasPrefix(records[0].AuthzFP, "sha256:") {
		t.Errorf("AuthzFP = %q, want a fingerprint", records[0].AuthzFP)
	}
}

// There is deliberately no endpoint on the broker that could hand back a
// credential. A plain GET must be refused rather than served.
func TestBrokerIsNotAnAPI(t *testing.T) {
	f := newFixture(t, githubOnly)
	plain := &http.Client{Timeout: 5 * time.Second}
	resp, err := plain.Get("http://" + f.proxyURL.Host + "/credentials")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("GET /credentials = %d, want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), theSecret) {
		t.Fatal("the refusal body contained the secret")
	}
}

// A WebSocket handshake through the round-trip path has no way to hand the raw
// connection back, so it would appear to succeed and then hang — which reads as
// the provider's fault. It must fail loudly, naming the host and the way out.
func TestProtocolUpgradeIsRefusedWithAnExplanation(t *testing.T) {
	f := newFixture(t, githubOnly)

	req, _ := http.NewRequest("GET", "https://api.github.com/live", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Authorization", "Bearer "+Placeholder("github"))

	resp, err := f.client(true).Do(req)
	if err != nil {
		t.Fatalf("the request failed instead of being answered: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	for _, want := range []string{"websocket", "api.github.com", "Nothing was sent", "Tunnel the host"} {
		if !strings.Contains(text, want) {
			t.Errorf("the explanation does not mention %q:\n%s", want, text)
		}
	}
	// Nothing was sent upstream, and the credential was not substituted.
	if st := f.broker.Stats(); st.Swap != 0 {
		t.Errorf("Stats() = %+v, want no substitution for a refused upgrade", st)
	}
	// It is still recorded: an operator wants to see the attempt.
	audit := f.broker.Audit()
	if len(audit) == 0 || !strings.Contains(audit[len(audit)-1].Status, "501") {
		t.Errorf("the refused upgrade was not audited: %+v", audit)
	}
}

// An Upgrade header without Connection: Upgrade is not an upgrade request, and
// must pass through normally rather than being refused.
func TestUpgradeHeaderAloneIsNotAnUpgrade(t *testing.T) {
	f := newFixture(t, githubOnly)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Upgrade", "websocket") // no Connection: Upgrade
	req.Header.Set("Authorization", "Bearer "+Placeholder("github"))

	resp, err := f.client(true).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotImplemented {
		t.Fatal("a request that is not an upgrade was refused as one")
	}
}

// forgeAt is a forge service on the fixture's provider host. Provider github
// has no API prefix, so paths are matched as sent.
func forgeAt(extra string) string {
	return `
services:
  forge-main:
    kind: forge
    provider: github
    host: api.github.com
    auth: token
    scheme: bearer
    env_var: FORGE_TOKEN
    repositories: [acme/widgets]
    preset: read
` + extra
}

func (f *fixture) do(t *testing.T, forceH1 bool, method, path string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "https://api.github.com"+path, body)
	req.Header.Set("Authorization", "Bearer "+Placeholder("forge-main"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.client(forceH1).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func assertDenied(t *testing.T, f *fixture, resp *http.Response, body, ruleID string) {
	t.Helper()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body %q", resp.StatusCode, body)
	}
	if !strings.Contains(body, "rule "+ruleID+" (") || !strings.Contains(body, "Nothing was sent.") {
		t.Errorf("deny body = %q, want it to name rule %s", body, ruleID)
	}
	if n := f.providerHits.Load(); n != 0 {
		t.Errorf("provider received %d requests, want 0", n)
	}
	if n := f.secretCalls.Load(); n != 0 {
		t.Errorf("secret source called %d times, want 0", n)
	}
	if st := f.broker.Stats(); st.Denied != 1 || st.Swap != 0 {
		t.Errorf("Stats() = %+v, want Denied 1 and no swap", st)
	}
	recs := f.broker.Audit()
	if len(recs) != 1 || recs[0].Rule != ruleID || recs[0].Status != "403 denied: "+ruleID {
		t.Errorf("audit = %+v, want one denied record for %s", recs, ruleID)
	}
}

func TestDeniedRequestNeverReachesTheProvider(t *testing.T) {
	f := newFixture(t, forgeAt(""))
	resp, body := f.do(t, false, "DELETE", "/repos/acme/widgets", nil)
	assertDenied(t, f, resp, body, "builtin:default-deny")
}

func TestDeniedRequestNeverFetchesTheSecret(t *testing.T) {
	f := newFixture(t, forgeAt(`    rules:
      - deny: "GET /repos/{owner}/{repo}/issues"
`))
	resp, body := f.do(t, true, "GET", "/repos/acme/widgets/issues", nil)
	assertDenied(t, f, resp, body, "user#1")
}

func TestAllowedRequestStillGetsTheCredential(t *testing.T) {
	f := newFixture(t, forgeAt(""))
	resp, body := f.do(t, false, "GET", "/repos/acme/widgets/issues", nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "Bearer "+theSecret) {
		t.Fatalf("allowed request: %d %q, want the credential injected", resp.StatusCode, body)
	}
	if f.broker.Stats().Denied != 0 || f.providerHits.Load() != 1 || f.secretCalls.Load() != 1 {
		t.Errorf("Stats() = %+v hits %d secrets %d", f.broker.Stats(), f.providerHits.Load(), f.secretCalls.Load())
	}
}

// A request outside the read preset is allowed for a built-in, which has no
// rules: built-ins are untouched by enforcement.
func TestBuiltinServiceIsUntouched(t *testing.T) {
	f := newFixture(t, githubOnly)
	req, _ := http.NewRequest("DELETE", "https://api.github.com/graphql", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+Placeholder("github"))
	resp, err := f.client(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), theSecret) {
		t.Fatalf("built-in: %d %q", resp.StatusCode, b)
	}
	if st := f.broker.Stats(); st.Denied != 0 || st.Swap != 1 {
		t.Errorf("Stats() = %+v", st)
	}
	if recs := f.broker.Audit(); len(recs) != 1 || recs[0].Rule != "" {
		t.Errorf("audit = %+v", recs)
	}
}

func TestGraphQLDeniedByDefault(t *testing.T) {
	for _, p := range []string{"/graphql", "/GraphQL", "/graphql/", "/graphql/x", "/%67raphql", "/GRAPHQL/"} {
		t.Run(p, func(t *testing.T) {
			// An allow-everything rule must not reopen GraphQL.
			f := newFixture(t, forgeAt(`    rules:
      - allow: "POST /**"
      - allow: "GET /**"
`))
			resp, body := f.do(t, false, "POST", p, strings.NewReader(`{"query":"{viewer{login}}"}`))
			assertDenied(t, f, resp, body, "builtin:graphql")
		})
	}
	// Dot segments are refused by the normaliser: still a deny, never a pass.
	for _, p := range []string{"/./graphql", "/x/../graphql"} {
		t.Run(p, func(t *testing.T) {
			f := newFixture(t, forgeAt(`    rules:
      - allow: "POST /**"
`))
			resp, body := f.do(t, false, "POST", p, strings.NewReader(`{}`))
			assertDenied(t, f, resp, body, "builtin:bad-path")
		})
	}
	t.Run("allow_graphql", func(t *testing.T) {
		f := newFixture(t, forgeAt(`    allow_graphql: true
    rules:
      - allow: "POST /graphql"
`))
		resp, body := f.do(t, false, "POST", "/graphql", strings.NewReader(`{}`))
		if resp.StatusCode != 200 || f.providerHits.Load() != 1 {
			t.Fatalf("allow_graphql: %d %q", resp.StatusCode, body)
		}
	})
}

func TestDeniedOverHTTP2(t *testing.T) {
	f := newFixture(t, forgeAt(""))
	resp, body := f.do(t, false, "POST", "/repos/acme/widgets/issues", strings.NewReader(`{"title":"x"}`))
	if resp.Proto != "HTTP/2.0" {
		t.Fatalf("client leg spoke %q, want HTTP/2.0", resp.Proto)
	}
	assertDenied(t, f, resp, body, "builtin:default-deny")
}

// chunked hides its length, so the request carries no Content-Length.
type chunked struct{ r io.Reader }

func (c chunked) Read(p []byte) (int, error) { return c.r.Read(p) }

func TestBodyIsForwardedIntactAfterEvaluation(t *testing.T) {
	small := []byte(`{"title":"hello","body":"world"}`)
	big := make([]byte, rules.MaxBody*3+17)
	for i := range big {
		big[i] = byte(i * 7)
	}
	for _, tc := range []struct {
		name    string
		forceH1 bool
		body    io.Reader
		want    []byte
	}{
		{"small-h2", false, bytes.NewReader(small), small},
		{"small-h1", true, bytes.NewReader(small), small},
		{"chunked-over-max-h2", false, chunked{bytes.NewReader(big)}, big},
		{"chunked-over-max-h1", true, chunked{bytes.NewReader(big)}, big},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, forgeAt(`    rules:
      - allow: "POST /repos/{owner}/{repo}/labels"
`))
			resp, body := f.do(t, tc.forceH1, "POST", "/repos/acme/widgets/labels", tc.body)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d %q", resp.StatusCode, body)
			}
			got := <-f.lastBody
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("provider got %d bytes, want %d identical bytes", len(got), len(tc.want))
			}
		})
	}
}

func TestOversizeBodyFailsClosedWhenARuleNeedsIt(t *testing.T) {
	f := newFixture(t, forgeAt(`    rules:
      - allow: "PATCH /repos/{owner}/{repo}/issues/{n}"
        when: {state: closed}
`))
	pad := strings.Repeat("x", rules.MaxBody)
	resp, body := f.do(t, false, "PATCH", "/repos/acme/widgets/issues/1",
		chunked{strings.NewReader(`{"state":"closed","pad":"` + pad + `"}`)})
	assertDenied(t, f, resp, body, "builtin:default-deny")

	// Control: the same rule allows the small body, so the deny above is the
	// size and not the rule.
	g := newFixture(t, forgeAt(`    rules:
      - allow: "PATCH /repos/{owner}/{repo}/issues/{n}"
        when: {state: closed}
`))
	resp, body = g.do(t, false, "PATCH", "/repos/acme/widgets/issues/1", strings.NewReader(`{"state":"closed"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("control: %d %q", resp.StatusCode, body)
	}
}

func TestGraphQLDeniedUnderAnAPIPrefix(t *testing.T) {
	f := newFixture(t, `
services:
  forge-main:
    kind: forge
    provider: gitea
    host: api.github.com
    auth: token
    scheme: bearer
    env_var: FORGE_TOKEN
    repositories: [acme/widgets]
    preset: read
    rules:
      - allow: "POST /**"
`)
	resp, body := f.do(t, false, "POST", "/api/v1/graphql", strings.NewReader(`{}`))
	assertDenied(t, f, resp, body, "builtin:graphql")
}

func TestMethodOverrideIsDeniedAtTheBroker(t *testing.T) {
	f := newFixture(t, forgeAt(""))
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/acme/widgets/issues", nil)
	req.Header.Set("Authorization", "Bearer "+Placeholder("forge-main"))
	req.Header.Set("X-HTTP-Method-Override", "DELETE")
	resp, err := f.client(false).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assertDenied(t, f, resp, string(b), "builtin:method-override")
}

// Exactly MaxBody bytes is not truncated: the body condition is evaluated and
// holds, and the provider receives identical bytes.
func TestBodyOfExactlyMaxBodyIsEvaluatedAndForwarded(t *testing.T) {
	f := newFixture(t, forgeAt(`    rules:
      - allow: "PATCH /repos/{owner}/{repo}/issues/{n}"
        when: {state: closed}
`))
	head, tail := `{"state":"closed","pad":"`, `"}`
	body := []byte(head + strings.Repeat("x", rules.MaxBody-len(head)-len(tail)) + tail)
	if len(body) != rules.MaxBody {
		t.Fatalf("fixture body is %d bytes", len(body))
	}
	resp, rb := f.do(t, true, "PATCH", "/repos/acme/widgets/issues/1", chunked{bytes.NewReader(body)})
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %q", resp.StatusCode, rb)
	}
	if got := <-f.lastBody; !bytes.Equal(got, body) {
		t.Fatalf("provider got %d bytes, want %d identical", len(got), len(body))
	}
}
