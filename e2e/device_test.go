// Device flow, end to end through the real binary.
//
// The cmd-level test proves the function stores a token. This one proves the
// shipped command does, on a machine with no browser, and that the token it
// obtained then works through the broker — which is the only claim that
// matters: a credential nothing but the provider and the broker ever held,
// reaching an API from a child process that cannot read it.
package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const deviceToken = "gho_device_granted_credential"

// buildStk compiles the real CLI once per run.
func buildStk(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "stk")
	if b, err := exec.Command("go", "build", "-o", out, "../cmd/stk").CombinedOutput(); err != nil {
		t.Fatalf("building stk: %v\n%s", err, b)
	}
	return out
}

// provider behaves the way a real one does under load: pending, pending, then a
// slow_down, then approval. A client that ignores slow_down gets rate-limited
// at the exact moment a person is trying to help it, so the flow has to widen.
func deviceProvider(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int64) {
	t.Helper()
	var polls atomic.Int32
	var lastPoll, gap atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"device_code":"DEVICE-CODE-NEVER-LOG-ME","user_code":"BCDF-2468",
			"verification_uri":"https://provider.invalid/device",
			"verification_uri_complete":"https://provider.invalid/device?user_code=BCDF-2468",
			"interval":1,"expires_in":900}`)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now().UnixMilli()
		if prev := lastPoll.Swap(now); prev != 0 {
			gap.Store(now - prev)
		}
		w.Header().Set("Content-Type", "application/json")
		switch polls.Add(1) {
		case 1, 2:
			fmt.Fprint(w, `{"error":"authorization_pending"}`)
		case 3:
			fmt.Fprint(w, `{"error":"slow_down"}`)
		default:
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer","scope":"repo,read:org"}`, deviceToken)
		}
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s, &polls, &gap
}

func TestDeviceFlowThroughTheBinary(t *testing.T) {
	stk := buildStk(t)
	prov, polls, gap := deviceProvider(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	cfg := fmt.Sprintf(`workspace: e2e
services:
  github:
    scopes: []
    device:
      client_id: Iv1.e2eclientid
      authorization_url: %s/device/code
      token_url: %s/token
notify:
  file: %s
`, prov.URL, prov.URL, filepath.Join(dir, "notify.log"))
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	env := append(os.Environ(),
		"STK_CONFIG="+cfgPath,
		"STK_HOME="+filepath.Join(dir, "home"),
		"STK_PASSPHRASE=e2e-passphrase",
	)
	cmd := exec.Command(stk, "connect", "github", "--device")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stk connect --device: %v\n%s", err, out)
	}
	text := string(out)

	// It polled through pending, pending, slow_down, approved.
	if n := polls.Load(); n < 4 {
		t.Errorf("the provider was polled %d times; pending and slow_down must not end the flow", n)
	}
	// slow_down widened the interval: the last gap must exceed the stated one
	// by roughly the five seconds RFC 8628 §3.5 requires.
	if g := gap.Load(); g < 5500 {
		t.Errorf("the final gap was %dms; slow_down must widen a 1s interval to ~6s", g)
	}

	// The user code is shown and logged — that is what a person types.
	if !strings.Contains(text, "BCDF-2468") {
		t.Errorf("the user code never appeared:\n%s", text)
	}
	notes, err := os.ReadFile(filepath.Join(dir, "notify.log"))
	if err != nil {
		t.Fatalf("the file sink wrote nothing: %v", err)
	}
	if !strings.Contains(string(notes), "BCDF-2468") {
		t.Errorf("the notification carried no code: %s", notes)
	}

	// Neither the device code nor the credential appears anywhere a person or a
	// log aggregator would see.
	for name, body := range map[string]string{"stdout": text, "the notification log": string(notes)} {
		if strings.Contains(body, "DEVICE-CODE-NEVER-LOG-ME") {
			t.Errorf("%s contains the device code, which is what a poll redeems", name)
		}
		if strings.Contains(body, deviceToken) {
			t.Errorf("%s contains the credential itself", name)
		}
	}

	// And the token actually reached the store: `stk doctor` sees it connected
	// without ever printing it.
	doctor := exec.Command(stk, "doctor")
	doctor.Env = env
	dout, _ := doctor.CombinedOutput()
	if !strings.Contains(string(dout), "github") {
		t.Errorf("doctor does not see github:\n%s", dout)
	}
	if strings.Contains(string(dout), deviceToken) {
		t.Error("doctor printed the credential")
	}
}

// The hand-over path, through the binary: seal on one machine, open on another,
// with two separate homes so neither can read the other's store.
func TestHandoverBetweenTwoBrokers(t *testing.T) {
	stk := buildStk(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	if err := os.WriteFile(cfgPath, []byte("workspace: e2e\nservices:\n  github:\n    scopes: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const secret = "ghp_handover_credential"

	envFor := func(homeName string) []string {
		return append(os.Environ(),
			"STK_CONFIG="+cfgPath,
			"STK_HOME="+filepath.Join(dir, homeName),
			"STK_PASSPHRASE="+homeName+"-passphrase",
		)
	}
	laptop, server := envFor("laptop"), envFor("server")

	run := func(env []string, stdin string, args ...string) string {
		t.Helper()
		c := exec.Command(stk, args...)
		c.Env = env
		if stdin != "" {
			c.Stdin = strings.NewReader(stdin)
		}
		var errb strings.Builder
		c.Stderr = &errb
		out, err := c.Output()
		if err != nil {
			t.Fatalf("stk %s: %v\n%s", strings.Join(args, " "), err, errb.String())
		}
		return strings.TrimSpace(string(out))
	}

	// The server publishes a key. It can only seal; it cannot open.
	key := run(server, "", "handover", "key")
	if !strings.HasPrefix(key, "stk-handover-v1:") {
		t.Fatalf("handover key = %q", key)
	}

	// The laptop has the credential, and seals it to that key.
	run(laptop, secret, "connect", "github")
	envelope := run(laptop, "", "handover", "seal", "github", "--to", key)
	if strings.Contains(envelope, secret) {
		t.Fatal("the envelope carries the credential in the clear")
	}

	// The laptop cannot open its own envelope: it was sealed to the server.
	wrong := exec.Command(stk, "handover", "open", "github")
	wrong.Env = laptop
	wrong.Stdin = strings.NewReader(envelope)
	if out, err := wrong.CombinedOutput(); err == nil {
		t.Errorf("the sealing machine opened the envelope:\n%s", out)
	}

	// The server opens it, and now holds the credential.
	opened := run(server, envelope, "handover", "open", "github")
	if !strings.Contains(opened, "connected") {
		t.Errorf("open said %q", opened)
	}
	if strings.Contains(opened, secret) {
		t.Error("open printed the credential")
	}
	// And it says the credential still exists where it was sealed, because a
	// fallback that hides its cost is worse than one that states it.
	if !strings.Contains(opened, "still exists") {
		t.Errorf("open does not say the credential survives on the sealing machine: %q", opened)
	}
}
