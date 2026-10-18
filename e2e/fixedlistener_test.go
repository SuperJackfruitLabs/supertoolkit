// The fixed, keyed listener end to end: the settings come from the real
// `stk env`, and a client without the key is turned away before the provider
// is ever reached.
package e2e

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func TestCurlThroughFixedListenerWithKey(t *testing.T) {
	needCurl(t)
	stk := filepath.Join(t.TempDir(), "stk")
	if b, err := exec.Command("go", "build", "-o", stk, "../cmd/stk").CombinedOutput(); err != nil {
		t.Fatalf("building stk: %v\n%s", err, b)
	}

	// The fake provider, counting what actually reaches it.
	provCA, err := broker.NewCA("e2e provider CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	var lastAuth atomic.Value
	provLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	prov := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			lastAuth.Store(r.Header.Get("Authorization"))
			json.NewEncoder(w).Encode(map[string]string{"login": "chotu"})
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{mustLeaf(t, provCA, "forge.example.test")}},
	}
	go prov.ServeTLS(provLn, "", "")
	t.Cleanup(func() { prov.Close() })

	// State dir and config shared by this process and the stk binary.
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "home")
	os.MkdirAll(stateDir, 0o700)
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	yaml := "workspace: e2e\nservices:\n  forge-main:\n    kind: forge\n    provider: forgejo\n" +
		"    host: forge.example.test\n    scheme: bearer\n    env_var: FORGEJO_TOKEN\n" +
		"    repositories: [o/r]\n    preset: read\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(stateDir, "e2e passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put("forge-main", forgeSecret); err != nil {
		t.Fatal(err)
	}

	// A fixed loopback port. Listening first and recording the address is what
	// `stk serve --proxy-listen` does before `stk env` can answer.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxyLn.Close() })
	// `stk env` only reads the key and verifies the listener, so the key file
	// and CA exist, and the broker is serving, before it runs.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	proxyKey := base64.RawURLEncoding.EncodeToString(raw)
	if err := os.WriteFile(filepath.Join(stateDir, "proxy.key"), []byte(proxyKey), 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := broker.LoadOrCreateCA(stateDir, "supertoolkit local CA", 365*24*time.Hour) // the lifetime stk uses, or env would renew it
	if err != nil {
		t.Fatal(err)
	}
	b, err := broker.New(broker.Options{
		Config: cfg, CA: ca, Secrets: store.Get, ProxyKey: proxyKey,
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
	go b.Serve(proxyLn)
	// proxy.addr in the format serve writes: address, then a live pid.
	addrLine := fmt.Sprintf("%s\n%d\n", proxyLn.Addr().String(), os.Getpid())
	if err := os.WriteFile(filepath.Join(stateDir, "proxy.addr"), []byte(addrLine), 0o600); err != nil {
		t.Fatal(err)
	}

	envCmd := exec.Command(stk, "env", "--json")
	envCmd.Env = append(os.Environ(), "STK_CONFIG="+cfgPath, "STK_HOME="+stateDir)
	out, err := envCmd.Output()
	if err != nil {
		t.Fatalf("stk env: %v", err)
	}
	var got struct {
		ProxyURL string            `json:"proxy_url"`
		CAPath   string            `json:"ca_path"`
		Env      map[string]string `json:"env"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), forgeSecret) {
		t.Fatal("stk env printed the service credential")
	}

	curl := func(env []string) string {
		cmd := exec.Command("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}",
			"-H", "Authorization: Bearer "+broker.Placeholder("forge-main"),
			"https://forge.example.test/api/v1/user")
		cmd.Env = env
		o, _ := cmd.Output() // a refused tunnel makes curl exit non-zero; the code is what we assert
		return strings.TrimSpace(string(o))
	}

	// With the key, from the `stk env` output alone.
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	for k, v := range got.Env {
		env = append(env, k+"="+v)
	}
	if c := curl(env); c != "200" {
		t.Fatalf("with the key curl got %q, want 200", c)
	}
	if hits.Load() != 1 || lastAuth.Load() != "Bearer "+forgeSecret {
		t.Fatalf("provider hits=%d auth=%v, want 1 hit with the real credential", hits.Load(), lastAuth.Load())
	}

	// Without the key: same address, no userinfo.
	bare := "http://" + proxyLn.Addr().String()
	noKey := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"HTTPS_PROXY=" + bare, "https_proxy=" + bare, "CURL_CA_BUNDLE=" + got.CAPath, "SSL_CERT_FILE=" + got.CAPath}
	if c := curl(noKey); c == "200" {
		t.Fatalf("without the key curl got %q, want a refusal", c)
	}
	// Curl reports a refused CONNECT as 000 (the proxy's 407 is not a response to
	// the origin request), so the load-bearing assertions are the provider's
	// own counter and the broker's refusal.
	if hits.Load() != 1 {
		t.Fatalf("provider hits = %d after a keyless request, want still 1", hits.Load())
	}
	// A wrong key is refused the same way.
	wrong := strings.Replace(got.ProxyURL, "stk:", "stk:x", 1)
	badEnv := append(append([]string{}, noKey...), "HTTPS_PROXY="+wrong, "https_proxy="+wrong)
	curl(badEnv)
	if hits.Load() != 1 {
		t.Fatalf("provider hits = %d after a wrong-key request, want still 1", hits.Load())
	}
	// The 407 itself, read directly off the wire.
	conn, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("CONNECT forge.example.test:443 HTTP/1.1\r\nHost: forge.example.test:443\r\n\r\n"))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 407") {
		t.Fatalf("keyless CONNECT answered %q, want 407", buf[:n])
	}
	if hits.Load() != 1 {
		t.Fatalf("provider hits = %d, want 1", hits.Load())
	}
}
