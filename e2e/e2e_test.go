// Package e2e holds the test that is the point of Phase 0: a real child process
// reaches a provider with a real credential it never possessed.
package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

const theSecret = "ghp_phase_zero_real_credential"

type rig struct {
	proxyURL string
	caPath   string
	broker   *broker.Broker
	seen     chan string // what Authorization the provider received
}

func newRig(t *testing.T) *rig { return newRigWithObserver(t, nil) }

// newRigWithObserver is newRig with a durable audit sink. The observer needs the
// loaded config, which the rig builds, so it arrives as a function of it.
func newRigWithObserver(t *testing.T, mk func(*policy.Config) broker.Observer) *rig {
	t.Helper()

	provCA, err := broker.NewCA("e2e provider CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 8)
	mux := http.NewServeMux()
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]string{"login": "brokered"})
	})
	provLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	leaf := mustLeaf(t, provCA, "api.github.com")
	provSrv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{leaf}}}
	go provSrv.ServeTLS(provLn, "", "")
	t.Cleanup(func() { provSrv.Close() })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	os.WriteFile(cfgPath, []byte("workspace: e2e\nservices:\n  github:\n    scopes: []\n"), 0o600)
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	store, err := credential.OpenStore(filepath.Join(dir, "state"), "e2e passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put("github", theSecret); err != nil {
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
				if strings.HasPrefix(addr, "api.github.com:") {
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

	return &rig{proxyURL: "http://" + proxyLn.Addr().String(), caPath: caPath, broker: b, seen: seen}
}

func mustLeaf(t *testing.T, ca *broker.CA, host string) tls.Certificate {
	t.Helper()
	// The CA mints leaves internally; reach it through a TLS handshake config
	// by asking for the host's certificate via the exported helper used by the
	// broker itself.
	c, err := ca.LeafForTest(host)
	if err != nil {
		t.Fatal(err)
	}
	return *c
}

// childEnv mirrors what `stk run` hands a child: the placeholder, the proxy,
// the CA, Node's proxy opt-in, and NO_PROXY deliberately absent.
func (r *rig) childEnv() []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"HTTPS_PROXY=" + r.proxyURL,
		"https_proxy=" + r.proxyURL,
		"SSL_CERT_FILE=" + r.caPath,
		"CURL_CA_BUNDLE=" + r.caPath,
		"NODE_USE_ENV_PROXY=1",
		"GH_TOKEN=" + broker.Placeholder("github"),
	}
}

// This is Phase 0's one provable sentence.
func TestChildReachesProviderWithACredentialItNeverHeld(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	r := newRig(t)

	env := r.childEnv()
	cmd := exec.Command("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}",
		"-H", "Authorization: Bearer "+broker.Placeholder("github"),
		"https://api.github.com/user")
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
		if authz != "Bearer "+theSecret {
			t.Fatalf("provider received %q, want the real credential", authz)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the provider never saw a request")
	}

	// The other half of the promise: the credential was never in the child's reach.
	for _, kv := range env {
		if strings.Contains(kv, theSecret) {
			t.Fatalf("the child's environment contained the credential: %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
	if st := r.broker.Stats(); st.Swap != 1 {
		t.Fatalf("Stats() = %+v, want exactly one swap", st)
	}
}

// With the broker unreachable the child must fail, not reach the provider
// directly. A silent fall back to a direct connection is the worst outcome
// available, because it looks like success.
func TestChildFailsClosedWhenTheBrokerIsDown(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	r := newRig(t)

	env := r.childEnv()
	for i, kv := range env {
		if strings.HasPrefix(kv, "HTTPS_PROXY=") {
			env[i] = "HTTPS_PROXY=http://127.0.0.1:1" // nothing listening
		}
		if strings.HasPrefix(kv, "https_proxy=") {
			env[i] = "https_proxy=http://127.0.0.1:1"
		}
	}
	cmd := exec.Command("curl", "-s", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}",
		"https://api.github.com/user")
	cmd.Env = env
	out, _ := cmd.Output()
	if got := strings.TrimSpace(string(out)); got != "000" {
		t.Fatalf("child got http %s with the broker down, want 000 — it must not reach the provider directly", got)
	}
	select {
	case authz := <-r.seen:
		t.Fatalf("the provider was reached despite the broker being down: %q", authz)
	default:
	}
}
