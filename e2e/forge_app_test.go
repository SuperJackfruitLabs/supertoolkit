// A GitHub App forge end to end: the broker holds the App's private key, mints a
// JWT, trades it for an installation token restricted to the configured
// repositories, and only that token reaches the API.
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

const appInstallToken = "ghs_e2e_installation_token_0123"

func TestAppForgeInjectsInstallationTokenThroughProxy(t *testing.T) {
	needCurl(t)
	provCA, err := broker.NewCA("e2e ghe CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var jwt, exchangeBody string
	var apiAuth []string
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" && r.URL.Path == "/api/v3/app/installations/987/access_tokens" {
			jwt = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			exchangeBody = string(b)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{
				"token": appInstallToken, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
			return
		}
		apiAuth = append(apiAuth, r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(map[string]string{"full_name": "Corp/r"})
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, TLSConfig: &tls.Config{Certificates: []tls.Certificate{mustLeaf(t, provCA, "ghe.example.test")}}}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	upstream := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: provCA.Pool()},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "ghe.example.test:") {
				addr = ln.Addr().String()
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	os.WriteFile(cfgPath, []byte("workspace: e2e\nservices:\n  ghe-app:\n    kind: forge\n    provider: github\n"+
		"    host: ghe.example.test\n    api_prefix: /api/v3\n    auth: app\n    env_var: GH_TOKEN\n"+
		"    repositories: [Corp/r, Corp/s]\n    preset: read\n"), 0o600)
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := cfg.Service("ghe-app")
	fi := svc.Entry().Forge
	store, err := credential.OpenStore(filepath.Join(dir, "state"), "e2e passphrase")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := rsaKeyPEM(t)
	store.PutMaterial("ghe-app", credential.Material{
		credential.FieldAppID: "4242", credential.FieldPrivateKey: keyPEM, credential.FieldInstallationID: "987",
	})
	acq := &credential.Acquirer{
		Material: store.Material,
		Exchange: credential.ExchangeGitHubApp(fi.APIBase, &http.Client{Transport: upstream},
			func(string) []string { return fi.RepositoryNames }),
	}
	led, err := ledger.Open(t.TempDir())
	if err != nil {
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
		Config: cfg, CA: ca, Observer: ruleObserver{led}, Upstream: upstream,
		Secrets: func(s string) (string, error) { return acq.Token(context.Background(), s) },
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
	r := &rig{proxyURL: "http://" + proxyLn.Addr().String(), caPath: caPath, broker: b}

	cmd := exec.Command("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}",
		"-H", "Authorization: Bearer "+broker.Placeholder("ghe-app"),
		"https://ghe.example.test/api/v3/repos/Corp/r")
	cmd.Env = r.childEnv()
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) != "200" {
		t.Fatalf("child: %v, http %q", err, out)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(apiAuth) != 1 || apiAuth[0] != "Bearer "+appInstallToken {
		t.Fatalf("API saw %q, want one Bearer installation token", apiAuth)
	}
	if strings.Count(jwt, ".") != 2 {
		t.Fatalf("the token endpoint was not sent a JWT: %q", jwt)
	}
	if exchangeBody != `{"repositories":["r","s"]}` {
		t.Errorf("exchange body = %q, want the configured repository names", exchangeBody)
	}
	entries, err := led.Read(10)
	if err != nil || len(entries) != 1 || entries[0].Service != "ghe-app" {
		t.Fatalf("ledger = %+v, %v; want one ghe-app entry", entries, err)
	}
	raw, err := os.ReadFile(led.Path())
	if err != nil {
		t.Fatal(err)
	}
	keyBody := strings.Split(keyPEM, "\n")[1]
	for what, secret := range map[string]string{"private key": keyBody, "JWT": jwt, "installation token": appInstallToken} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the ledger contains the %s", what)
		}
	}
}
