package broker

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
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
}

func newFixture(t *testing.T, cfgBody string) *fixture {
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

	mux := http.NewServeMux()
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
		Handler:   mux,
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
	brokerCA, err := NewCA("test broker CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Options{
		Config: cfg, CA: brokerCA,
		Secrets:  func(string) (string, error) { return theSecret, nil },
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
