package main

// Characterization of what stk prints and how it exits, pinned before the commands move out of
// package main (docs/code-quality.md). The test binary re-runs itself as stk (TestMain in
// main_test.go), so each case is the real main() in a child process, with a state directory,
// a policy file and a PATH of its own. Nothing here reads a real store or reaches the network:
// the clients the probe and doctor run are fakes on that PATH, and the device grant talks to a
// local stand-in for the provider.
//
// The goldens hold the Linux output, which is what CI runs. On another platform the few lines
// that differ by design (where a Go program finds its CA) are mapped to their Linux form before
// the comparison, so the same file passes on a Mac.
//
// Regenerate the golden files with:
//
//	go test ./cmd/stk -run 'TestCLICharacterization' -update-cli-golden

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var updateCLIGolden = flag.Bool("update-cli-golden", false, "rewrite testdata/cli-*.golden.txt")

// cliCharacterizationEnv carries the child's arguments, separated by \x1f.
const cliCharacterizationEnv = "STK_CLI_CHARACTERIZATION_ARGS"

// runAsCharacterizedStk runs main() as stk when the test binary was started as one of the
// characterization's children. It reports false otherwise.
func runAsCharacterizedStk() bool {
	args, ok := os.LookupEnv(cliCharacterizationEnv)
	if !ok {
		return false
	}
	os.Args = []string{"stk"}
	if args != "" {
		os.Args = append(os.Args, strings.Split(args, "\x1f")...)
	}
	main()
	return true
}

// cliRig is one isolated stk installation: state, policy file, working directory and PATH, all
// under a short root (a Unix socket path must fit in 104 bytes on macOS).
type cliRig struct {
	t     *testing.T
	root  string
	bin   string // fake clients: curl, python3, node
	empty string // a PATH with only `true` on it
	path  string // the PATH children get
	extra []string
	// replace holds values discovered while running (a key, a port) and what they print as.
	mu      sync.Mutex
	replace [][2]string
}

func newCLIRig(t *testing.T) *cliRig {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "stkc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	r := &cliRig{t: t, root: root, bin: filepath.Join(root, "bin"), empty: filepath.Join(root, "nobin")}
	for _, d := range []string{"state", "work", "user", "tmp", "bin", "nobin"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r.script(r.empty, "true", "exit 0")
	r.script(r.bin, "true", "exit 0")
	r.path = r.empty
	return r
}

// script writes an executable shell script.
func (r *cliRig) script(dir, name, body string) {
	r.t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil { //nolint:gosec // a test fixture that must be executable
		r.t.Fatal(err)
	}
}

func (r *cliRig) env(args []string) []string {
	env := []string{
		cliCharacterizationEnv + "=" + strings.Join(args, "\x1f"),
		"PATH=" + r.path,
		"HOME=" + filepath.Join(r.root, "user"),
		"STK_HOME=" + filepath.Join(r.root, "state"),
		"STK_CONFIG=" + filepath.Join(r.root, "work", "supertoolkit.yaml"),
		"STK_PASSPHRASE=characterization-passphrase",
		"TMPDIR=" + filepath.Join(r.root, "tmp"),
		"TZ=UTC",
		"USER=operator",
	}
	return append(env, r.extra...)
}

func (r *cliRig) command(stdin string, args ...string) *exec.Cmd {
	self, err := os.Executable()
	if err != nil {
		r.t.Fatal(err)
	}
	cmd := exec.CommandContext(context.Background(), self)
	cmd.Env = r.env(args)
	cmd.Dir = filepath.Join(r.root, "work")
	cmd.Stdin = strings.NewReader(stdin)
	return cmd
}

// run runs stk with args and stdin to completion and returns its transcript and stdout.
func (r *cliRig) run(stdin string, args ...string) (string, string) {
	r.t.Helper()
	cmd := r.command(stdin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := exitCode(r.t, cmd.Run(), args)
	return r.transcript(args, stdin, code, stdout.String(), stderr.String()), stdout.String()
}

func exitCode(t *testing.T, err error, args []string) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("stk %v: %v", args, err)
	}
	return exit.ExitCode()
}

func (r *cliRig) transcript(args []string, stdin string, code int, stdout, stderr string) string {
	head := "$ stk " + strings.Join(args, " ")
	if stdin != "" {
		head += "  <<< " + strconv.Quote(stdin)
	}
	return r.normalise(fmt.Sprintf("%s\nexit %d\n--- stdout\n%s--- stderr\n%s\n", head, code, stdout, stderr))
}

func (r *cliRig) learn(value, as string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.replace = append(r.replace, [2]string{value, as})
}

var (
	clock    = regexp.MustCompile(`\b\d\d:\d\d UTC\b`)
	date     = regexp.MustCompile(`\b\d{4}-\d\d-\d\d \d\d:\d\d UTC\b`)
	uiURL    = regexp.MustCompile(`http://127\.0\.0\.1:\d+/\?token=[A-Za-z0-9_-]+`)
	proxyKey = regexp.MustCompile(`stk:[A-Za-z0-9_-]{43}@`)
	envelope = regexp.MustCompile(`stk-handover-v1:[A-Za-z0-9_-]+`)
	expires  = regexp.MustCompile(`expires in \d+m\d+s`)
)

// linuxForms maps output that differs by platform on purpose to its Linux form.
var linuxForms = map[string][][2]string{
	"darwin": {
		{"  ! CA trust for Go binaries  macOS Go programs ignore SSL_CERT_FILE and read the keychain; add the CA there for tools like gh",
			"  ✓ CA trust  SSL_CERT_FILE covers Go, curl, Python and Node here"},
		{`      "name": "CA trust for Go binaries",
      "ok": true,
      "warn": true,
      "detail": "macOS Go programs ignore SSL_CERT_FILE and read the keychain; add the CA there for tools like gh"`,
			`      "name": "CA trust",
      "ok": true,
      "detail": "SSL_CERT_FILE covers Go, curl, Python and Node here"`},
		{"    `stk run` sets the CA for curl, Python and Node automatically.\n" +
			"    On macOS, Go programs ignore SSL_CERT_FILE and use the system\n" +
			"    keychain, so tools like `gh` need the CA added there:\n" +
			"      sudo security add-trusted-cert -d -k /Library/Keychains/System.keychain $ROOT/state/ca.pem\n",
			"    `stk run` sets SSL_CERT_FILE and friends, which covers Go, curl,\n" +
				"    Python and Node on this platform. No system change needed.\n"},
	},
}

func (r *cliRig) normalise(s string) string {
	r.mu.Lock()
	for _, kv := range r.replace {
		s = strings.ReplaceAll(s, kv[0], kv[1])
	}
	r.mu.Unlock()
	if self, err := os.Executable(); err == nil {
		s = strings.ReplaceAll(s, self, "$STK")
	}
	if real, err := filepath.EvalSymlinks(r.root); err == nil {
		s = strings.ReplaceAll(s, real, "$ROOT")
	}
	s = strings.ReplaceAll(s, r.root, "$ROOT")
	s = strings.ReplaceAll(s, fmt.Sprintf("owner uid %d", os.Getuid()), "owner uid $UID")
	s = uiURL.ReplaceAllString(s, "$$UI_URL")
	s = proxyKey.ReplaceAllString(s, "stk:$$PROXY_KEY@")
	s = envelope.ReplaceAllString(s, "$$SEALED_ENVELOPE")
	s = expires.ReplaceAllString(s, "expires in $$MINUTES")
	s = date.ReplaceAllString(s, "YYYY-MM-DD HH:MM UTC")
	s = clock.ReplaceAllString(s, "HH:MM UTC")
	for _, kv := range linuxForms[runtime.GOOS] {
		s = strings.ReplaceAll(s, kv[0], kv[1])
	}
	return s
}

func compareGolden(t *testing.T, name, got string) {
	t.Helper()
	golden := filepath.Join("testdata", name)
	if *updateCLIGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil { //nolint:gosec // a committed directory
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil { //nolint:gosec // a committed file
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update-cli-golden to create it)", err)
	}
	if string(want) != got {
		t.Errorf("stk's output changed (%s). A diff of the first difference:\n%s", golden, firstDifference(string(want), got))
	}
}

// firstDifference shows the lines around the first line that differs.
func firstDifference(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			from := max(0, i-6)
			ctx := strings.Join(g[from:min(len(g), i)], "\n")
			return fmt.Sprintf("line %d\n%s\n- want: %s\n+ got:  %s", i+1, ctx, wl, gl)
		}
	}
	return "(none)"
}

// TestCLICharacterization pins help, usage, error text, exit codes and machine output for every
// command that runs to completion, in the order a person meets them: before init, after init,
// with a service added and connected, then withdrawn.
func TestCLICharacterization(t *testing.T) {
	r := newCLIRig(t)
	var b strings.Builder
	write := func(stdin string, args ...string) string {
		out, stdout := r.run(stdin, args...)
		b.WriteString(out + "\n")
		return stdout
	}

	// Help, version and dispatch.
	write("")
	for _, a := range []string{"help", "-h", "--help", "version", "--version", "-v", "bogus", "stk-netjail-bogus"} {
		write("", a)
	}

	// Before `stk init`: every command that needs the policy file says so.
	for _, args := range [][]string{
		{"add"}, {"add", "github"}, {"connect"}, {"connect", "github", "gitlab"},
		{"connect", "github", "--device", "--browser"}, {"connect", "github", "--device"},
		{"connect", "github", "--browser"}, {"run"}, {"run", "--"}, {"run", "--", "true"},
		{"serve", "--bogus"}, {"serve", "--proxy-listen"}, {"serve", "--proxy-listen", "0.0.0.0:8899"},
		{"serve", "--proxy-listen", "127.0.0.1:0"}, {"serve", "--proxy-listen=localhost:x"},
		{"serve", "--allow-uid"}, {"serve", "--allow-uid", "-1"}, {"serve", "--allow-uid=x"},
		{"serve", "--socket-mode", "0644"}, {"serve", "--socket-mode=0777"}, {"serve", "--socket-mode"},
		{"serve", "--local-commands-socket", "relative.sock"}, {"serve", "--local-commands-socket"},
		{"serve", "--local-commands-mode", "0700"}, {"serve", "--local-commands-mode"},
		{"serve"}, {"reload", "--bogus"}, {"reload"}, {"reload", "--json"},
		{"env", "--bogus"}, {"env"}, {"env", "--json"},
		{"mcp", "--profile"}, {"mcp"}, {"mcp", "install"}, {"mcp", "install", "claude-code"},
		{"mcp", "--profile", "reader", "install", "cursor"}, {"mcp", "serve"}, {"mcp", "serve", "--bogus"},
		{"mcp", "serve", "a", "b"}, {"mcp", "serve", "fetch", "--profile"}, {"mcp", "serve", "fetch", "--standalone"},
		{"mcp", "serve", "fetch"},
		{"managed-mcp-v1"}, {"managed-mcp-v1", "--manifest", "m.json", "--sha256", "00"},
		{"managed-control-v1"}, {"managed-control-v1", "--manifest", "m.json", "--sha256", "00"},
		{"managed-evidence-v1"}, {"managed-evidence-v1", "--manifest", "m.json", "--sha256", "00"},
		{"verify"}, {"verify", "a", "b"}, {"verify", "github", "--expect-login"}, {"verify", "nosuch"},
		{"revoke"}, {"revoke", "a", "b"}, {"revoke", "nosuch"}, {"forget"},
		{"audit", "--bogus"}, {"audit", "--limit"}, {"audit", "--limit", "0"}, {"audit", "-n", "x"},
		{"audit"}, {"audit", "--json"},
		{"approvals"}, {"approval", "bogus"},
		{"ui"}, {"ui", "--bind"},
		{"doctor", "--bogus"}, {"doctor", "--agent-uid"}, {"doctor", "--agent-uid", "x"}, {"doctor", "--agent-uid=-3"},
		{"doctor"}, {"doctor", "--json"},
		{"handover"}, {"handover", "bogus"}, {"handover", "seal"}, {"handover", "seal", "github"},
		{"handover", "open"}, {"handover", "open", "github", "extra"},
	} {
		write("", args...)
	}

	// init, twice: the second keeps the file.
	write("", "init")
	write("", "init")
	write("", "add")
	write("", "add", "nosuch")
	write("", "add", "github", "slack")
	write("", "add", "github")
	if err := os.WriteFile(filepath.Join(r.root, "work", "supertoolkit.yaml"), []byte(`# characterization policy
workspace: characterization
services:
  github:
    scopes: []
  slack:
    scopes: []
servers:
  fetch:
    command: /nonexistent/fetch-server
    egress: { preset: public-only }
    network: host
profiles:
  reader:
    github: [get_user, list_repos]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// The hand-over key is random, so it prints as a name.
	_, key := r.run("", "handover", "key")
	r.learn(strings.TrimSpace(key), "$HANDOVER_KEY")
	write("", "handover", "key")
	write("", "handover", "key", "--json")
	write("", "handover", "seal", "github", "--to")
	write("", "handover", "seal", "github", "--to", "not-a-key")
	write("", "handover", "seal", "github", "--to", strings.TrimSpace(key))
	write("ghp_characterization_fixture", "handover", "seal", "github", "--stdin", "--to", strings.TrimSpace(key))
	write("not an envelope", "handover", "open", "github")
	write("", "handover", "open", "nosuch")

	// Connecting, from stdin.
	write("", "connect", "github")
	write("token=a\nnot-a-field", "connect", "slack")
	write("ghp_characterization_fixture", "connect", "github")
	write("", "connect", "nosuch")
	write("", "verify", "slack")
	write("", "verify", "slack", "--json")
	write("", "env")

	// Running a command through the broker; it makes no request, which stk says.
	write("", "run", "--", "true")
	write("", "run", "nosuchcommand")
	write("", "audit")
	write("", "audit", "--json", "--limit", "5")

	// MCP on stdio: initialise, list the four meta-tools, and discover.
	write(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"characterization","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"discover_server_categories","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_category_actions","arguments":{"category":"github"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"execute_action","arguments":{"category":"github","action":"create_issue","args":"{}"}}}
`, "mcp", "--profile", "reader")
	write("", "mcp", "--profile", "nosuch")
	write("", "mcp", "serve", "nosuch", "--standalone")
	write("", "mcp", "serve", "fetch", "--standalone", "--profile", "nosuch")
	write("", "mcp", "serve", "fetch", "--socket", filepath.Join(r.root, "absent.sock"))
	write("", "approvals")
	write("", "approvals", "allow")
	write("", "approvals", "refuse")

	// doctor: no curl on PATH, so no live probe; then a fake curl that never reaches the broker.
	write("", "doctor")
	write("", "doctor", "--json")
	r.path = r.bin
	r.script(r.bin, "curl", "exit 0")
	write("", "doctor")
	r.path = r.empty

	// Withdrawing: --local never reaches a provider.
	write("", "revoke", "github", "--local")
	write("", "revoke", "github")
	write("", "verify", "github")
	compareGolden(t, "cli-commands.golden.txt", b.String())
}

// TestCLICharacterizationProbe pins `stk doctor --probe` over fake clients: one honoured, one
// bypassed, one refusing the CA, and no Go toolchain.
func TestCLICharacterizationProbe(t *testing.T) {
	r := newCLIRig(t)
	r.path = r.bin
	r.script(r.bin, "curl", `echo "stk-probe-substituted-value"`)
	r.script(r.bin, "python3", `echo "<urlopen error [Errno -2] Name or service not known>"`)
	r.script(r.bin, "node", `echo "Error: self-signed certificate in certificate chain"`)
	var b strings.Builder
	write := func(args ...string) {
		out, _ := r.run("", args...)
		b.WriteString(out + "\n")
	}
	write("doctor", "--probe")
	write("doctor", "--probe", "--json")
	write("doctor", "--probe", "--with-proxy-key")

	// Every client honoured: the pass is earned.
	r.script(r.bin, "python3", `echo "stk-probe-substituted-value"`)
	r.script(r.bin, "node", `echo "stk-probe-substituted-value"`)
	write("doctor", "--probe")
	// A keyed broker, and a client that dropped the key.
	r.script(r.bin, "curl", `echo "curl: (56) Received HTTP code 407 from proxy after CONNECT"`)
	write("doctor", "--probe", "--with-proxy-key", "--json")
	// No client at all: nothing is proven, and that fails.
	r.path = r.empty
	write("doctor", "--probe")
	compareGolden(t, "cli-probe.golden.txt", b.String())
}

// TestCLICharacterizationDevice pins `stk connect --device` against a local stand-in for the
// provider: pending once, then approved with a refresh token.
func TestCLICharacterizationDevice(t *testing.T) {
	r := newCLIRig(t)
	polls := 0
	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"device_code":"DEVICE-CODE","user_code":"WXYZ-1234","verification_uri":"https://example.invalid/device","interval":1,"expires_in":900}`)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		polls++
		n := polls
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = fmt.Fprint(w, `{"error":"authorization_pending"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"access_token":"gho_characterization","refresh_token":"ghr_characterization","token_type":"bearer","scope":"repo","expires_in":28800}`)
	})
	prov := httptest.NewServer(mux)
	t.Cleanup(prov.Close)
	r.learn(prov.URL, "$PROVIDER")

	policy := func(device string) {
		body := "workspace: characterization\nservices:\n  github:\n    scopes: []\n" + device +
			"  x:\n    scopes: []\n"
		if err := os.WriteFile(filepath.Join(r.root, "work", "supertoolkit.yaml"), []byte(body), 0o644); err != nil { //nolint:gosec // a policy file is world-readable by design
			t.Fatal(err)
		}
	}
	var b strings.Builder
	write := func(args ...string) {
		out, _ := r.run("", args...)
		b.WriteString(out + "\n")
	}
	policy("")
	write("connect", "github", "--device")
	write("connect", "nosuch", "--device")
	write("connect", "x", "--browser")
	write("connect", "github", "--browser")
	policy(fmt.Sprintf("    device:\n      client_id: Iv1.characterization\n      authorization_url: %s/device/code\n      token_url: %s/token\n      scopes: [repo]\n", prov.URL, prov.URL))
	write("connect", "github", "--device")
	write("doctor")
	compareGolden(t, "cli-device.golden.txt", b.String())
}

// syncBuffer is a bytes.Buffer safe to read while a child writes to it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// background is a long-running stk: serve or ui.
type background struct {
	r              *cliRig
	args           []string
	cmd            *exec.Cmd
	stdout, stderr syncBuffer
}

func (r *cliRig) start(args ...string) *background {
	r.t.Helper()
	bg := &background{r: r, args: args, cmd: r.command("", args...)}
	bg.cmd.Stdout, bg.cmd.Stderr = &bg.stdout, &bg.stderr
	if err := bg.cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { _ = bg.cmd.Process.Kill(); _ = bg.cmd.Wait() })
	return bg
}

// waitFor waits until the child's stdout holds want.
func (bg *background) waitFor(want string) {
	bg.r.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(bg.stdout.String(), want) {
		if time.Now().After(deadline) {
			bg.r.t.Fatalf("stk %v never printed %q; stdout:\n%s\nstderr:\n%s", bg.args, want, bg.stdout.String(), bg.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// stop sends SIGTERM and returns the transcript.
func (bg *background) stop() string {
	bg.r.t.Helper()
	if err := bg.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		bg.r.t.Fatal(err)
	}
	code := exitCode(bg.r.t, bg.cmd.Wait(), bg.args)
	return bg.r.transcript(bg.args, "", code, bg.stdout.String(), bg.stderr.String())
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestCLICharacterizationServe pins `stk serve` and the commands that talk to it: what serve
// prints as it starts, reloads on SIGHUP and stops, and what reload, approvals, env and
// mcp serve print against it. Also `stk ui`, which serves until it is stopped.
func TestCLICharacterizationServe(t *testing.T) {
	r := newCLIRig(t)
	var b strings.Builder
	write := func(stdin string, args ...string) {
		out, _ := r.run(stdin, args...)
		b.WriteString(out + "\n")
	}
	write("", "init")
	write("", "add", "github")
	write("ghp_characterization_fixture", "connect", "github")

	addr := freePort(t)
	r.learn(addr, "$PROXY_ADDR")
	serve := r.start("serve", "--proxy-listen", addr)
	serve.waitFor("ctrl-C to stop")
	write("", "reload")
	write("", "reload", "--json")
	write("", "approvals")
	write("", "approvals", "allow", "nosuch")
	write("", "env")
	write("", "env", "--json")
	write("", "mcp", "serve", "nosuch")
	write("", "serve")
	if err := serve.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	serve.waitFor("SIGHUP:")
	b.WriteString(serve.stop() + "\n")
	write("", "env")

	ui := r.start("ui", "--no-open", "--bind", "127.0.0.1:0")
	ui.waitFor("ctrl-C to stop")
	b.WriteString(ui.stop() + "\n")
	compareGolden(t, "cli-serve.golden.txt", b.String())
}

// recordingRunner records the commands an install would run, and runs none.
type recordingRunner struct{ calls []string }

func (r *recordingRunner) Run(name string, args ...string) error {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return nil
}

// TestCLICharacterizationInstall pins `stk install` for both answers to "is this Linux": the
// command is Linux/systemd only, so it is run in-process with the platform named rather than
// in a child, which would only ever see the host's.
func TestCLICharacterizationInstall(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(self)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, goos := range []string{"linux", "darwin"} {
		for _, args := range [][]string{
			{}, {"--user"}, {"--user", "stk", "--bogus"}, {"--user", "stk", "--agent-uid", "x"},
			{"--user", "stk", "--proxy-port", "x"}, {"--group", "agents"},
			{"--user", "stk", "--unit-name", "bad.service", "--agent-uid", "1000", "--dry-run"},
			{"--user", "stk", "--group=agents", "--agent-uid", "1000", "--agent-uid=1001", "--proxy-port", "9000", "--dry-run"},
			{"--user", "stk", "--agent-uid", "1000", "--unit-name", "stk-two", "--state-dir", "/srv/stk", "--dry-run"},
		} {
			root := t.TempDir()
			r := &recordingRunner{}
			var out bytes.Buffer
			err := runInstall(args, goos, root, r, &out)
			res := "ok"
			if err != nil {
				res = "error: " + err.Error()
			}
			text := fmt.Sprintf("$ [%s] stk install %s\n%s\n--- output\n%s--- runs\n%s\n\n", goos, strings.Join(args, " "), res, out.String(), strings.Join(r.calls, "\n"))
			text = strings.ReplaceAll(text, root, "$ROOT")
			b.WriteString(strings.ReplaceAll(text, real, "$STK"))
		}
	}
	compareGolden(t, "cli-install.golden.txt", b.String())
}
