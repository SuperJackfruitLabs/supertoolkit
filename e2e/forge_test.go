// A forge defined in configuration, end to end: the host exists nowhere in the
// compiled-in catalogue, yet a child holding only a placeholder reaches it with
// the real credential, in whichever Authorization scheme the forge speaks.
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

const forgeSecret = "forge_e2e_real_credential_0123"

func forgeRig(t *testing.T, scheme string) (*rig, string) {
	t.Helper()
	provCA, err := broker.NewCA("e2e forge CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan string, 8)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
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
		"    repositories: [o/r]\n    preset: read\n"
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
	b, err := broker.New(broker.Options{
		Config: cfg, CA: ca, Secrets: store.Get,
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
	return &rig{proxyURL: "http://" + proxyLn.Addr().String(), caPath: caPath, broker: b, seen: seen}, cfgPath
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
