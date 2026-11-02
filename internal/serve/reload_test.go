package serve

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/audit"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/clitest"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/controlplane"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/livepolicy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/localstate"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/session"
)

func forgeSvc(name, host, extra string) string {
	return "  " + name + `:
    kind: forge
    provider: forgejo
    host: ` + host + `
    auth: token
    scheme: bearer
    env_var: ` + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + `_TOKEN
    repositories: [acme/widgets]
    preset: read
` + extra
}

func reloadConfig(svcs ...string) string {
	return "workspace: test\nservices:\n  github:\n    scopes: []\n" + strings.Join(svcs, "")
}

type reloadFixture struct {
	dir   string
	live  *livepolicy.Config
	sess  *session.Session
	rl    *livepolicy.Reloader
	store *credential.Store
}

func newReloadFixture(t *testing.T, config string) *reloadFixture {
	t.Helper()
	clitest.Rig(t, config)
	cfg, store, dir, err := localstate.LoadForRun()
	if err != nil {
		t.Fatal(err)
	}
	live := livepolicy.New(cfg, store, &http.Client{Timeout: 5 * time.Second})
	sess, err := session.StartWith(cfg, store, dir, session.Options{Live: live})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Stop)
	return &reloadFixture{dir: dir, live: live, sess: sess, store: store,
		rl: livepolicy.NewReloader(localstate.ConfigPath(), live, sess.Broker, store)}
}

func writeConfig(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(localstate.ConfigPath(), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReloadWithABadFileKeepsTheOldPolicy(t *testing.T) {
	f := newReloadFixture(t, reloadConfig(forgeSvc("forge-a", "forge.example.com", "")))
	old := f.live.Config()
	for name, body := range map[string]string{
		"unknown rule key": reloadConfig(forgeSvc("forge-a", "forge.example.com", "    rules:\n      - allow: \"GET /x\"\n        whn: {}\n")),
		"bad label":        reloadConfig(forgeSvc("forge-a", "forge.example.com", "    labels: {station: \"a\\x1bb\"}\n")),
		"same host":        reloadConfig(forgeSvc("forge-a", "forge.example.com", ""), forgeSvc("forge-b", "forge.example.com", "")),
		"not yaml":         "services: [\n",
	} {
		writeConfig(t, body)
		res := f.rl.Reload()
		if res.OK || res.Error == "" {
			t.Errorf("%s: reload = %+v, want a failure with a reason", name, res)
		}
		if f.live.Config() != old || f.sess.Broker.Config() != old {
			t.Fatalf("%s: a failed reload changed the policy in force", name)
		}
	}
	os.Remove(localstate.ConfigPath())
	if res := f.rl.Reload(); res.OK || !strings.Contains(res.Error, "no such file") {
		t.Errorf("missing file: reload = %+v", res)
	}
	if f.live.Config() != old || f.sess.Broker.Config() != old {
		t.Fatal("a missing file changed the policy in force")
	}
	// Control: a good file does apply, to both holders at once.
	writeConfig(t, reloadConfig())
	if res := f.rl.Reload(); !res.OK {
		t.Fatalf("good file: %+v", res)
	}
	if f.live.Config() == old || f.sess.Broker.Config() != f.live.Config() {
		t.Fatal("a good reload did not reach both the broker and the daemon path")
	}
}

func TestReloadResultListsChangedServices(t *testing.T) {
	base := func(a string) string {
		return reloadConfig(forgeSvc("forge-a", "a.example.com", a), forgeSvc("forge-c", "c.example.com", ""))
	}
	f := newReloadFixture(t, base(""))
	if res := f.rl.Reload(); !res.OK || len(res.Added)+len(res.Removed)+len(res.Changed) != 0 {
		t.Fatalf("identical reload = %+v, want nothing listed", res)
	}
	for name, a := range map[string]string{
		"rules":         "    rules:\n      - deny: \"GET /x\"\n",
		"allow_graphql": "    allow_graphql: true\n",
		"labels":        "    labels: {station: s}\n",
	} {
		writeConfig(t, base(a))
		res := f.rl.Reload()
		if !res.OK || !reflect.DeepEqual(res.Changed, []string{"forge-a"}) || len(res.Added)+len(res.Removed) != 0 {
			t.Errorf("%s: %+v, want forge-a changed", name, res)
		}
		writeConfig(t, base(""))
		if res := f.rl.Reload(); !reflect.DeepEqual(res.Changed, []string{"forge-a"}) {
			t.Errorf("%s back: %+v", name, res)
		}
	}
	for name, body := range map[string]string{
		"host":   strings.Replace(base(""), "a.example.com", "a2.example.com", 1),
		"repos":  strings.Replace(base(""), "repositories: [acme/widgets]", "repositories: [acme/gadgets]", 1),
		"preset": strings.Replace(base(""), "preset: read", "preset: none", 1),
	} {
		writeConfig(t, body)
		if res := f.rl.Reload(); !res.OK || !reflect.DeepEqual(res.Changed, []string{"forge-a"}) {
			t.Errorf("%s: %+v, want forge-a changed", name, res)
		}
		writeConfig(t, base(""))
		f.rl.Reload()
	}

	if err := f.store.Put("forge-c", "tok"); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, reloadConfig(forgeSvc("forge-a", "a.example.com", ""), forgeSvc("forge-d", "d.example.com", "")))
	res := f.rl.Reload()
	if !res.OK || !reflect.DeepEqual(res.Removed, []string{"forge-c"}) || !reflect.DeepEqual(res.Added, []string{"forge-d"}) || len(res.Changed) != 0 {
		t.Fatalf("reload = %+v", res)
	}
	if !reflect.DeepEqual(res.KeptCredentials, []string{"forge-c"}) {
		t.Errorf("KeptCredentials = %v, want forge-c (its credential is still stored)", res.KeptCredentials)
	}
	if !f.store.Has("forge-c") {
		t.Error("reload deleted a credential")
	}
	if !strings.Contains(res.Summary(), "forge-c") || !strings.Contains(res.Summary(), "credential") {
		t.Errorf("summary does not mention the kept credential: %q", res.Summary())
	}
}

// shortSock is a socket path short enough for macOS.
func shortSock(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "stk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	p := filepath.Join(d, "s")
	t.Setenv("STK_SOCKET", p)
	return p
}

func serveReload(t *testing.T, f *reloadFixture, opts daemon.Options) *daemon.Server {
	t.Helper()
	svc, err := controlplane.NewWith(f.live, f.store, f.dir, "serve", "test")
	if err != nil {
		t.Fatal(err)
	}
	svc.Reload = f.rl.Reload
	d, err := daemon.ListenWith(shortSock(t), svc.Handle, opts)
	if err != nil {
		t.Fatal(err)
	}
	go d.Serve()
	t.Cleanup(func() { d.Close() })
	return d
}

func TestReloadCommandJSON(t *testing.T) {
	f := newReloadFixture(t, reloadConfig(forgeSvc("forge-a", "a.example.com", "")))
	d := serveReload(t, f, daemon.Options{})

	writeConfig(t, reloadConfig(forgeSvc("forge-b", "b.example.com", "")))
	var out bytes.Buffer
	if err := livepolicy.RunReload(&out, []string{"--json"}); err != nil {
		t.Fatalf("reload: %v\n%s", err, out.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("not json: %v\n%s", err, out.String())
	}
	if got["ok"] != true || !reflect.DeepEqual(got["removed"], []any{"forge-a"}) ||
		!reflect.DeepEqual(got["added"], []any{"forge-b"}) || !reflect.DeepEqual(got["changed"], []any{}) {
		t.Fatalf("reload --json = %s", out.String())
	}
	if _, ok := f.live.Config().Service("forge-b"); !ok {
		t.Fatal("the daemon reported ok but the policy did not change")
	}

	writeConfig(t, "services: [\n")
	out.Reset()
	if err := livepolicy.RunReload(&out, []string{"--json"}); err == nil {
		t.Fatal("a failed reload exited zero")
	}
	got = nil
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got["ok"] != false || got["error"] == "" {
		t.Fatalf("failed reload --json = %s (%v)", out.String(), err)
	}

	writeConfig(t, reloadConfig())
	out.Reset()
	if err := livepolicy.RunReload(&out, nil); err != nil || !strings.Contains(out.String(), "forge-b") {
		t.Fatalf("text reload: %v %q", err, out.String())
	}

	d.Close()
	out.Reset()
	err := livepolicy.RunReload(&out, []string{"--json"})
	if err == nil {
		t.Fatal("no daemon: exited zero")
	}
	got = nil
	if json.Unmarshal(out.Bytes(), &got) != nil || got["ok"] != false || !strings.Contains(got["error"].(string), "stk serve") {
		t.Fatalf("no daemon --json = %s", out.String())
	}
}

func TestReloadUnlistedUIDRefused(t *testing.T) {
	for _, tc := range []struct {
		allow []int
		want  int64
	}{{[]int{1}, 0}, {[]int{4242}, 1}} {
		f := newReloadFixture(t, reloadConfig(forgeSvc("forge-a", "a.example.com", "")))
		var calls atomic.Int64
		svc, err := controlplane.NewWith(f.live, f.store, f.dir, "serve", "test")
		if err != nil {
			t.Fatal(err)
		}
		svc.Reload = func() livepolicy.Result { calls.Add(1); return f.rl.Reload() }
		d, err := daemon.ListenWith(shortSock(t), svc.Handle, daemon.Options{
			AllowUIDs: tc.allow, PeerUID: func(net.Conn) (int, error) { return 4242, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		go d.Serve()
		old := f.live.Config()
		writeConfig(t, reloadConfig())
		var out bytes.Buffer
		err = livepolicy.RunReload(&out, []string{"--json"})
		d.Close()
		if calls.Load() != tc.want {
			t.Fatalf("allow %v: reload ran %d time(s), want %d", tc.allow, calls.Load(), tc.want)
		}
		if tc.want == 0 && (err == nil || f.live.Config() != old) {
			t.Fatalf("unlisted uid: err %v, policy changed %v", err, f.live.Config() != old)
		}
	}
}

// The real binary: SIGHUP re-reads the file and the daemon path sees it.
func TestSIGHUPReloads(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "stk")
	if b, err := exec.Command("go", "build", "-o", bin, "../../cmd/stk").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	sock := shortSock(t)
	cfg := filepath.Join(dir, "supertoolkit.yaml")
	os.WriteFile(cfg, []byte(reloadConfig()), 0o600)
	srv := exec.Command(bin, "serve")
	srv.Env = append(os.Environ(), "STK_HOME="+filepath.Join(dir, "home"), "STK_CONFIG="+cfg,
		"STK_PASSPHRASE=test-passphrase", "STK_SOCKET="+sock)
	logs := &syncBuf{}
	srv.Stdout, srv.Stderr = logs, logs
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- srv.Wait() }()
	defer srv.Process.Kill()

	services := func() []string {
		c, err := daemon.Dial(sock)
		if err != nil {
			return nil
		}
		defer c.Close()
		resp, err := c.Call(daemon.Request{Method: "status"})
		if err != nil {
			return nil
		}
		var st struct{ Services []string }
		json.Unmarshal(resp.Result, &st)
		return st.Services
	}
	poll := func(what string, ok func([]string) bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !ok(services()) {
			select {
			case err := <-exited:
				t.Fatalf("serve exited: %v\n%s", err, logs.String())
			case <-time.After(20 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s never happened\n%s", what, logs.String())
			}
		}
	}
	poll("startup", func(s []string) bool { return reflect.DeepEqual(s, []string{"github"}) })

	os.WriteFile(cfg, []byte(reloadConfig(forgeSvc("forge-a", "a.example.com", ""))), 0o600)
	// Control: a changed file alone changes nothing.
	if s := services(); !reflect.DeepEqual(s, []string{"github"}) {
		t.Fatalf("policy changed without a reload: %v", s)
	}
	srv.Process.Signal(syscall.SIGHUP)
	poll("the SIGHUP reload", func(s []string) bool { return reflect.DeepEqual(s, []string{"forge-a", "github"}) })

	// A bad file on SIGHUP keeps the old policy and the daemon keeps running.
	os.WriteFile(cfg, []byte("services: [\n"), 0o600)
	srv.Process.Signal(syscall.SIGHUP)
	poll("the failure report", func([]string) bool { return strings.Contains(logs.String(), "reload failed") })
	if s := services(); !reflect.DeepEqual(s, []string{"forge-a", "github"}) {
		t.Fatalf("a bad SIGHUP reload changed the policy: %v", s)
	}
	srv.Process.Signal(syscall.SIGTERM)
	<-exited
}

const labelledForge = `workspace: test
services:
  forge-main:
    kind: forge
    provider: forgejo
    host: forge.example.com
    auth: token
    scheme: bearer
    env_var: FORGE_TOKEN
    repositories: [acme/widgets]
    preset: read
    labels: {station: st-1, principal: lyra, grant: g-7}
`

func TestLabelsCopiedToAuditRows(t *testing.T) {
	clitest.Rig(t, labelledForge)
	dir, _ := localstate.Home()
	cfg, err := policy.Load(localstate.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	obs, err := audit.NewObserver(cfg, dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"station": "st-1", "principal": "lyra", "grant": "g-7"}
	obs.Observe(broker.Record{When: time.Now(), Service: "forge-main", Method: "GET", Path: "/api/v1/repos/acme/widgets", Status: "200 OK", Injected: "h", AuthzFP: "sha256:x"})
	obs.Observe(broker.Record{When: time.Now(), Service: "forge-main", Method: "DELETE", Path: "/api/v1/repos/acme/widgets", Status: "403 denied: builtin:default-deny", Rule: "builtin:default-deny"})
	// A record that carries its own labels (from the broker's snapshot) keeps them.
	obs.Observe(broker.Record{When: time.Now(), Service: "forge-main", Method: "GET", Path: "/", Status: "200 OK", Labels: map[string]string{"station": "from-snapshot"}})
	obs.Observe(broker.Record{When: time.Now(), Service: "github", Method: "GET", Path: "/user", Status: "200 OK"})
	es := clitest.ReadLedger(t, dir)
	if len(es) != 4 {
		t.Fatalf("%d entries", len(es))
	}
	if es[0].Labels != nil {
		t.Errorf("built-in row has labels: %v", es[0].Labels)
	}
	if es[1].Labels["station"] != "from-snapshot" {
		t.Errorf("snapshot labels lost: %v", es[1].Labels)
	}
	for i, e := range es[2:] {
		if !reflect.DeepEqual(e.Labels, want) {
			t.Errorf("row %d (%s) labels = %v, want %v", i, e.Outcome, e.Labels, want)
		}
	}

	out := clitest.CaptureStdout(t, func() {
		if err := audit.Command([]string{"--json"}); err != nil {
			t.Error(err)
		}
	})
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatal(err)
	}
	if l, _ := rows[2]["labels"].(map[string]any); l["principal"] != "lyra" {
		t.Errorf("audit --json row lacks labels: %v", rows[2])
	}

	// The text view prints labels, escaped like every other field.
	led, _ := ledger.Open(dir)
	led.Append(ledger.Entry{Service: "forge-main", Labels: map[string]string{"station": "a\x1b[2Jb"}})
	text := clitest.CaptureStdout(t, func() { audit.Command(nil) })
	if strings.Contains(text, "\x1b") || !strings.Contains(text, `station=a\x1b[2Jb`) || !strings.Contains(text, "principal=lyra") {
		t.Errorf("text view labels not printed escaped:\n%s", text)
	}
}

// syncBuf is a buffer a subprocess writes while the test reads it.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
