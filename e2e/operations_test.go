package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

const (
	awsAccess = "AKIAIOSFODNN7EXAMPLE"
	awsSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)

// opsRig stands up providers for every scheme and an MCP server in front.
type opsRig struct {
	authSeen  map[string]chan string // service -> what Authorization it received
	exchanges *int
	q         *approval.Queue
	tool      func(t *testing.T, name string, args map[string]string) string
	keyPEM    string
}

func rsaKeyPEM(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

func newOpsRig(t *testing.T) *opsRig {
	t.Helper()
	provCA, err := broker.NewCA("ops provider CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]chan string{
		"aws-sts":    make(chan string, 8),
		"github-app": make(chan string, 8),
	}
	exchanges := 0

	mux := http.NewServeMux()
	// The AWS-shaped provider.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/access_tokens"):
			exchanges++
			seen["github-app"] <- "exchange:" + r.Header.Get("Authorization")
			json.NewEncoder(w).Encode(map[string]any{
				"token":      "ghs_installation_token",
				"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339),
			})
		case strings.HasPrefix(r.URL.Path, "/installation") || strings.HasPrefix(r.URL.Path, "/repos"):
			seen["github-app"] <- r.Header.Get("Authorization")
			json.NewEncoder(w).Encode(map[string]string{"ok": "yes"})
		default:
			seen["aws-sts"] <- r.Header.Get("Authorization")
			w.Write([]byte(`{"Arn":"arn:aws:iam::123456789012:user/brokered"}`))
		}
	})

	hosts := []string{"sts.amazonaws.com", "api.github.com"}
	certs := make([]tls.Certificate, 0, len(hosts))
	for _, h := range hosts {
		leaf, err := provCA.LeafForTest(h)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, *leaf)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: certs}}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	os.WriteFile(cfgPath, []byte(`
workspace: ops
services:
  aws-sts:
    scopes: []
  github-app:
    scopes: []
`), 0o600)
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(filepath.Join(dir, "state"), "ops key")
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := rsaKeyPEM(t)
	store.PutMaterial("aws-sts", credential.Material{
		credential.FieldAccessKeyID: awsAccess, credential.FieldSecretAccessKey: awsSecret,
	})
	store.PutMaterial("github-app", credential.Material{
		credential.FieldAppID: "123456", credential.FieldPrivateKey: keyPEM,
		credential.FieldInstallationID: "987",
	})

	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: provCA.Pool()},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			for _, h := range hosts {
				if strings.HasPrefix(addr, h+":") {
					addr = ln.Addr().String()
				}
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	acq := &credential.Acquirer{
		Material: store.Material,
		Exchange: credential.ExchangeGitHubApp("https://api.github.com", client),
	}

	q := approval.New(time.Minute)
	prof, _ := cfg.Profile("")
	srvMCP, err := mcp.NewServer(mcp.Options{
		Config: cfg, Profile: prof, Queue: q, ApprovalWait: 0,
		Exec: func(ctx context.Context, name string, req *http.Request) (*http.Response, error) {
			svc, _ := cfg.Service(name)
			e := svc.Entry()
			switch e.Auth {
			case catalog.AuthSigV4:
				m, err := store.Material(name)
				if err != nil {
					return nil, err
				}
				if err := credential.SignSigV4(req, m, e.Region, e.AWSService, time.Now()); err != nil {
					return nil, err
				}
			case catalog.AuthGitHubApp:
				tok, err := acq.Token(ctx, name)
				if err != nil {
					return nil, err
				}
				req.Header.Set("Authorization", "Bearer "+tok)
			}
			return client.Do(req)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := &opsRig{authSeen: seen, exchanges: &exchanges, q: q, keyPEM: keyPEM}
	r.tool = func(t *testing.T, name string, args map[string]string) string {
		t.Helper()
		res := srvMCP.CallTool(context.Background(), name, args)
		b, _ := json.Marshal(res)
		return string(b)
	}
	return r
}

// Signing: the provider receives a SigV4 Authorization and never the secret.
func TestSigV4ServiceWorksEndToEnd(t *testing.T) {
	r := newOpsRig(t)
	out := r.tool(t, "execute_action", map[string]string{"category": "aws-sts", "action": "whoami"})
	if strings.Contains(out, "isError") {
		t.Fatalf("execute_action failed: %s", out)
	}
	if !strings.Contains(out, "brokered") {
		t.Errorf("the provider's answer did not come through: %s", out)
	}

	select {
	case authz := <-r.authSeen["aws-sts"]:
		if !strings.HasPrefix(authz, "AWS4-HMAC-SHA256 ") {
			t.Fatalf("Authorization = %q, want a SigV4 signature", authz)
		}
		if !strings.Contains(authz, awsAccess) {
			t.Error("the access key id should be present; it is public")
		}
		if strings.Contains(authz, awsSecret) {
			t.Fatal("the secret access key was sent to the provider")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the AWS provider was never reached")
	}
	if strings.Contains(out, awsSecret) {
		t.Fatal("the agent's result contained the secret access key")
	}
}

// Acquiring: a JWT is exchanged for an installation token, and the provider
// sees the installation token rather than the private key.
func TestGitHubAppServiceWorksEndToEnd(t *testing.T) {
	r := newOpsRig(t)
	out := r.tool(t, "execute_action", map[string]string{
		"category": "github-app", "action": "list_installation_repos",
	})
	if strings.Contains(out, "isError") {
		t.Fatalf("execute_action failed: %s", out)
	}

	var sawExchange, sawCall string
	deadline := time.After(3 * time.Second)
	for sawExchange == "" || sawCall == "" {
		select {
		case v := <-r.authSeen["github-app"]:
			if strings.HasPrefix(v, "exchange:") {
				sawExchange = v
			} else {
				sawCall = v
			}
		case <-deadline:
			t.Fatalf("missing traffic: exchange=%q call=%q", sawExchange, sawCall)
		}
	}
	// A JWT went to the token endpoint, not the key.
	if strings.Count(sawExchange, ".") != 2 {
		t.Errorf("the exchange did not present a JWT: %q", sawExchange)
	}
	if strings.Contains(sawExchange, "PRIVATE KEY") {
		t.Fatal("the private key was sent to the provider")
	}
	// And the API call used the short-lived installation token.
	if sawCall != "Bearer ghs_installation_token" {
		t.Fatalf("the API call used %q, want the installation token", sawCall)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatal("the agent's result contained the private key")
	}
}

// Single-flight has to survive the whole stack, not just the unit.
func TestAcquisitionIsSingleFlightThroughTheStack(t *testing.T) {
	r := newOpsRig(t)
	for i := 0; i < 5; i++ {
		out := r.tool(t, "execute_action", map[string]string{
			"category": "github-app", "action": "list_installation_repos",
		})
		if strings.Contains(out, "isError") {
			t.Fatalf("call %d failed: %s", i, out)
		}
	}
	// Drain, then check how many exchanges happened.
	time.Sleep(100 * time.Millisecond)
	if *r.exchanges != 1 {
		t.Fatalf("the token endpoint was called %d times for five actions, want 1", *r.exchanges)
	}
}

// No stored material may appear in any agent-visible output, on any path.
func TestNoStoredMaterialReachesTheAgent(t *testing.T) {
	r := newOpsRig(t)
	secrets := []string{awsSecret, r.keyPEM, "-----BEGIN RSA PRIVATE KEY-----"}
	calls := []struct {
		tool string
		args map[string]string
	}{
		{"discover_server_categories", nil},
		{"get_category_actions", map[string]string{"category": "aws-sts"}},
		{"get_category_actions", map[string]string{"category": "github-app"}},
		{"get_action_details", map[string]string{"category": "aws-sts", "action": "whoami"}},
		{"execute_action", map[string]string{"category": "aws-sts", "action": "whoami"}},
		{"execute_action", map[string]string{"category": "github-app", "action": "list_installation_repos"}},
		// Error paths too.
		{"execute_action", map[string]string{"category": "aws-sts", "action": "nope"}},
		{"get_action_details", map[string]string{"category": "nope", "action": "nope"}},
	}
	for _, c := range calls {
		out := r.tool(t, c.tool, c.args)
		for _, s := range secrets {
			if s != "" && strings.Contains(out, s) {
				t.Fatalf("%s leaked stored material", c.tool)
			}
		}
	}
}

// A write on an acquiring service still goes through approval.
func TestWriteOnAnAcquiringServiceStillNeedsApproval(t *testing.T) {
	r := newOpsRig(t)
	out := r.tool(t, "execute_action", map[string]string{
		"category": "github-app", "action": "create_issue",
		"args": `{"owner":"o","repo":"r","title":"t"}`,
	})
	if !strings.Contains(out, "pending") {
		t.Fatalf("a write was not queued: %s", out)
	}
	if len(r.q.Pending()) != 1 {
		t.Fatalf("Pending() = %d, want 1", len(r.q.Pending()))
	}
	// Nothing was exchanged, because nothing was performed.
	if *r.exchanges != 0 {
		t.Fatalf("a token was exchanged for an unapproved effect (%d exchanges)", *r.exchanges)
	}
}
