package proxyenv

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/audit"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/clitest"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/localstate"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/session"
)

const envSecret = "ghp_DISTINCTIVE_service_secret_9f3a"

// envRig stores a real credential, starts a listener standing in for a fixed
// proxy and records its address as `serve --proxy-listen` would.
func envRig(t *testing.T, config string) (dir string) {
	t.Helper()
	clitest.Rig(t, config)
	dir, err := localstate.Home()
	if err != nil {
		t.Fatal(err)
	}
	pass, _, err := credential.StoreKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put("github", envSecret); err != nil {
		t.Fatal(err)
	}
	key, err := localstate.LoadOrCreateProxyKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	sess := liveBroker(t, dir, key)
	if err := localstate.WriteProxyAddr(dir, sess.Addr); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEnvJSONHasProxyURLWithUserinfoAndNoServiceSecret(t *testing.T) {
	dir := envRig(t, clitest.EnvConfig)
	var out, errb bytes.Buffer
	if err := runEnv(&out, &errb, []string{"--json"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String()+errb.String(), envSecret) {
		t.Fatal("the service credential appeared in stk env output")
	}
	var got struct {
		ProxyURL string            `json:"proxy_url"`
		CAPath   string            `json:"ca_path"`
		Env      map[string]string `json:"env"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("not json: %v\n%s", err, out.String())
	}
	key, err := localstate.LoadOrCreateProxyKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got.ProxyURL)
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := u.User.Password()
	if u.User.Username() != "stk" || pw != key {
		t.Fatalf("proxy_url userinfo = %q:%q, want stk:<proxy.key>", u.User.Username(), pw)
	}
	addr, _ := os.ReadFile(filepath.Join(dir, "proxy.addr"))
	if u.Host != strings.Fields(string(addr))[0] {
		t.Fatalf("proxy_url host %q != proxy.addr %q", u.Host, addr)
	}
	if got.CAPath == "" || got.Env["SSL_CERT_FILE"] != got.CAPath {
		t.Fatalf("ca_path %q, SSL_CERT_FILE %q", got.CAPath, got.Env["SSL_CERT_FILE"])
	}
	if _, err := os.Stat(got.CAPath); err != nil {
		t.Fatalf("ca_path does not exist: %v", err)
	}
	for k, want := range map[string]string{
		"HTTPS_PROXY": got.ProxyURL, "NODE_USE_ENV_PROXY": "1", "STK_BROKERED": "1",
	} {
		if got.Env[k] != want {
			t.Errorf("env[%s] = %q, want %q", k, got.Env[k], want)
		}
	}
	cfg, _, _, err := localstate.LoadForRun()
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := map[string]bool{}
	for _, kv := range session.ChildEnvFrom(nil, cfg, "", "") {
		k, _, _ := strings.Cut(kv, "=")
		wantKeys[k] = true
	}
	if len(got.Env) != len(wantKeys) {
		t.Errorf("env has %d entries, want exactly %d", len(got.Env), len(wantKeys))
	}
	for k := range got.Env {
		if !wantKeys[k] {
			t.Errorf("unexpected variable %s in env", k)
		}
	}
}

func TestEnvPlaceholdersMatchConfig(t *testing.T) {
	envRig(t, clitest.EnvConfig+"  forge-main:\n    kind: forge\n    provider: forgejo\n    host: forge.example.test\n"+
		"    scheme: bearer\n    env_var: FORGEJO_TOKEN\n    repositories: [o/r]\n    preset: read\n")
	var out, errb bytes.Buffer
	if err := runEnv(&out, &errb, []string{"--json"}); err != nil {
		t.Fatal(err)
	}
	var got struct{ Env map[string]string }
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	cfg, _, _, err := localstate.LoadForRun()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for _, name := range cfg.Services() {
		svc, _ := cfg.Service(name)
		if v := svc.Entry().EnvVar; v != "" {
			want[v] = broker.Placeholder(name)
		}
	}
	if want["FORGEJO_TOKEN"] == "" || len(want) < 2 {
		t.Fatalf("test bug: expected placeholders for both services, got %v", want)
	}
	for k, v := range want {
		if got.Env[k] != v {
			t.Errorf("env[%s] = %q, want %q", k, got.Env[k], v)
		}
	}
	// The plain-text form is shell-sourceable lines of the same variables.
	out.Reset()
	if err := runEnv(&out, &errb, nil); err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if !strings.Contains(out.String(), "export "+k+"='"+v+"'") {
			t.Errorf("text output lacks export of %s:\n%s", k, out.String())
		}
	}
	if strings.Contains(out.String(), envSecret) {
		t.Fatal("secret in text output")
	}
}

func TestEnvErrorsWhenNoFixedProxyIsRunning(t *testing.T) {
	clitest.Rig(t, clitest.EnvConfig)
	var out, errb bytes.Buffer
	err := runEnv(&out, &errb, nil)
	if err == nil || !strings.Contains(err.Error(), "no fixed proxy is running; start `stk serve --proxy-listen <addr>`") {
		t.Fatalf("err = %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("printed %q on failure", out.String())
	}
}

func TestProxyKeyNeverReachesAuditOrLogs(t *testing.T) {
	dir := envRig(t, clitest.EnvConfig)
	key, err := localstate.LoadOrCreateProxyKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if err := runEnv(&out, &errb, []string{"--json"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errb.String(), key) {
		t.Fatal("the key was written to stderr")
	}
	cfg, _, _, _ := localstate.LoadForRun()
	obs, _ := audit.NewObserver(cfg, dir, "test")
	obs.Observe(clitest.DeniedRecord("x"))
	if s := clitest.CaptureStdout(t, func() { audit.Command(nil) }); strings.Contains(s, key) {
		t.Fatal("the key appeared in stk audit output")
	}
	if s := clitest.CaptureStdout(t, func() { audit.Command([]string{"--json"}) }); strings.Contains(s, key) {
		t.Fatal("the key appeared in stk audit --json output")
	}
	// Nothing under the state dir other than proxy.key (and the env command's
	// own stdout) holds the key.
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || filepath.Base(p) == "proxy.key" {
			return nil
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), key) {
			t.Errorf("%s contains the proxy key", p)
		}
		return nil
	})
}

// liveBroker starts the real broker the way `stk serve --proxy-listen` does.
func liveBroker(t *testing.T, dir, key string) *session.Session {
	t.Helper()
	cfg, store, _, err := localstate.LoadForRun()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := session.StartWith(cfg, store, dir, session.Options{Listen: "127.0.0.1:0", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Stop)
	return sess
}
