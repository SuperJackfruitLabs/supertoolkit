package clitest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/localstate"
)

// WithStdin runs fn with os.Stdin reading `in`, and returns what fn wrote to
// os.Stdout.
func WithStdin(t *testing.T, in string, fn func()) string {
	t.Helper()
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	go func() { inW.WriteString(in); inW.Close() }()
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	done := make(chan string)
	go func() { b, _ := io.ReadAll(outR); done <- string(b) }()
	fn()
	outW.Close()
	return <-done
}

func OpenTestStore(t *testing.T, home string) *credential.Store {
	t.Helper()
	s, err := credential.OpenStore(home, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ForgeEnv points the CLI at a temp home and a policy file holding one forge.
func ForgeEnv(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	cfg := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	if err := os.WriteFile(cfg, []byte(ForgeConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STK_HOME", home)
	t.Setenv("STK_CONFIG", cfg)
	t.Setenv("STK_PASSPHRASE", "test-passphrase")
	return home
}

const ForgeConfig = `
services:
  forge-main:
    kind: forge
    provider: forgejo
    host: forge.superjackfruit.com
    env_var: FORGEJO_TOKEN
    repositories: [SuperJackfruitLabs/supertoolkit]
    preset: issues
`

func TestResolveEntryPrefersConfig(t *testing.T) {
	ForgeEnv(t)
	e, err := localstate.ResolveEntry("forge-main")
	if err != nil || e.Forge == nil {
		t.Fatalf("resolveEntry(forge-main) = %v, %v", e, err)
	}
	if b, err := localstate.ResolveEntry("github"); err != nil || b.Forge != nil {
		t.Errorf("a built-in must still resolve with a config present: %v, %v", b, err)
	}
}

// CaptureStdout runs f with os.Stdout redirected, so a command that prints can
// be asserted on without changing its signature.
func CaptureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		io.Copy(&b, r)
		done <- b.String()
	}()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}

func ReadLedger(t *testing.T, dir string) []ledger.Entry {
	t.Helper()
	led, _ := ledger.Open(dir)
	es, err := led.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func DeniedRecord(rule string) broker.Record {
	return broker.Record{
		When: time.Now(), Service: "github", Host: "api.github.com",
		Method: "DELETE", Path: "/repos/o/r", Status: "403 denied: " + rule, Rule: rule,
	}
}

// Rig points stk's config and home at a temporary directory.
func Rig(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "supertoolkit.yaml")
	if err := os.WriteFile(cfg, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STK_CONFIG", cfg)
	t.Setenv("STK_HOME", filepath.Join(dir, "home"))
	t.Setenv("STK_PASSPHRASE", "test-passphrase")
	return dir
}

const EnvConfig = "workspace: test\nservices:\n  github:\n    scopes: []\n"

func TestAppKeyPEM(t *testing.T) string {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

type RoundTripFunc func(*http.Request) (*http.Response, error)

func (fn RoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
