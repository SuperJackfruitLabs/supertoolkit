package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func auditRig(t *testing.T) (observer, string) {
	t.Helper()
	rig(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	dir, err := home()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(os.Getenv("STK_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := newObserver(cfg, dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	return obs, dir
}

func deniedRecord(rule string) broker.Record {
	return broker.Record{
		When: time.Now(), Service: "github", Host: "api.github.com",
		Method: "DELETE", Path: "/repos/o/r", Status: "403 denied: " + rule, Rule: rule,
	}
}

func readAll(t *testing.T, dir string) []ledger.Entry {
	t.Helper()
	led, _ := ledger.Open(dir)
	es, err := led.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func TestObserveRecordsTheDenyingRule(t *testing.T) {
	obs, dir := auditRig(t)
	obs.Observe(deniedRecord("preset:issues#2"))
	es := readAll(t, dir)
	if len(es) != 1 {
		t.Fatalf("entries = %d", len(es))
	}
	e := es[0]
	if e.Rule != "preset:issues#2" || e.Capability != "(denied)" || e.Policy != "deny" {
		t.Errorf("entry = %+v", e)
	}
	if strings.Contains(e.Credential, "sha256:") {
		t.Errorf("a denied request has no credential fingerprint: %q", e.Credential)
	}
}

func TestAuditJSONIncludesRule(t *testing.T) {
	obs, _ := auditRig(t)
	obs.Observe(deniedRecord("builtin:default-deny"))
	out := captureStdout(t, func() {
		if err := cmdAudit([]string{"--json"}); err != nil {
			t.Error(err)
		}
	})
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(got) != 1 || got[0]["rule"] != "builtin:default-deny" {
		t.Errorf("json = %s", out)
	}
}

func TestAuditTextShowsTheRuleForDeniedRows(t *testing.T) {
	obs, _ := auditRig(t)
	obs.Observe(deniedRecord("user#1"))
	out := captureStdout(t, func() {
		if err := cmdAudit(nil); err != nil {
			t.Error(err)
		}
	})
	if !strings.Contains(out, "user#1") || !strings.Contains(out, "(denied)") {
		t.Errorf("text view lacks the rule:\n%s", out)
	}
}

func TestAuditNeverContainsTheSecretOnADeniedRequest(t *testing.T) {
	const secret = "forge_denied_real_secret_9f8e7d"
	rig(t, "workspace: test\n")
	dir, _ := home()
	cfgPath := filepath.Join(dir, "forge.yaml")
	yaml := "workspace: test\nservices:\n  forge-main:\n    kind: forge\n    provider: forgejo\n" +
		"    host: forge.example.test\n    scheme: bearer\n    env_var: FORGEJO_TOKEN\n" +
		"    repositories: [o/r]\n    preset: read\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := newObserver(cfg, dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	var fetched atomic.Int64
	ca, err := broker.NewCA("denied test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := broker.New(broker.Options{
		Config: cfg, CA: ca, Observer: obs,
		Secrets: func(string) (string, error) { fetched.Add(1); return secret, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(ln)
	defer ln.Close()
	proxy, _ := url.Parse("http://" + ln.Addr().String())
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxy),
		TLSClientConfig: &tls.Config{RootCAs: ca.Pool()},
	}}
	req, _ := http.NewRequest("DELETE", "https://forge.example.test/api/v1/repos/o/r", nil)
	req.Header.Set("Authorization", "Bearer "+broker.Placeholder("forge-main"))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if n := fetched.Load(); n != 0 {
		t.Fatalf("the secret source was called %d time(s) for a denied request", n)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), "sha256:") {
		t.Fatalf("ledger holds a secret or credential fingerprint:\n%s", raw)
	}
	es := readAll(t, dir)
	if len(es) != 1 {
		t.Fatalf("entries = %d, want 1", len(es))
	}
	if e := es[0]; e.Rule == "" || e.Capability != "(denied)" || e.Policy != "deny" || e.Outcome != "403 denied: "+e.Rule {
		t.Errorf("entry = %+v", e)
	}
}

func TestOldLedgerLinesWithoutRuleStillRead(t *testing.T) {
	dir := t.TempDir()
	line := `{"when":"2026-01-01T00:00:00Z","service":"github","capability":"read","method":"GET","path":"/user","host":"api.github.com","policy":"agent","outcome":"200"}` + "\n"
	if err := os.WriteFile(dir+"/audit.log", []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	led, _ := ledger.Open(dir)
	es, err := led.Read(5)
	if err != nil || len(es) != 1 || es[0].Rule != "" || es[0].Capability != "read" {
		t.Fatalf("es=%+v err=%v", es, err)
	}
}

const evilPath = "/repos/o/r/\x1b[2Jevil\nfake-line\u009b"

func TestObserveStoresNoControlBytesInPath(t *testing.T) {
	obs, dir := auditRig(t)
	rec := deniedRecord("user#1")
	rec.Path = evilPath
	obs.Observe(rec)
	led, _ := ledger.Open(dir)
	raw, err := os.ReadFile(led.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(string(raw), "\x1b\u009b") || strings.Count(string(raw), "\n") != 1 {
		t.Errorf("ledger holds raw control bytes: %q", raw)
	}
	if es := readAll(t, dir); len(es) != 1 || !strings.Contains(es[0].Path, `\x1b[2Jevil\x0afake-line`) {
		t.Errorf("path = %+v", es)
	}
}

func TestAuditTextEscapesControlCharsInEveryField(t *testing.T) {
	_, dir := auditRig(t)
	led, _ := ledger.Open(dir)
	bad := "a\x1b[2Jb\nc"
	if err := led.Append(ledger.Entry{When: time.Now(), Service: "github", Host: bad,
		Method: bad, Path: bad, Outcome: bad, Rule: bad, Capability: "x", Policy: "deny"}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t, func() {
		if err := cmdAudit(nil); err != nil {
			t.Error(err)
		}
	})
	if strings.ContainsRune(out, 0x1b) || strings.Contains(out, "\nc") {
		t.Errorf("raw control bytes reached the terminal: %q", out)
	}
	if strings.Count(out, `\x1b[2J`) < 4 {
		t.Errorf("fields not escaped: %q", out)
	}
}

func TestAuditJSONStaysValidWithEscapedPath(t *testing.T) {
	obs, _ := auditRig(t)
	rec := deniedRecord("user#1")
	rec.Path = evilPath
	obs.Observe(rec)
	out := captureStdout(t, func() { _ = cmdAudit([]string{"--json"}) })
	var got []map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got) != 1 {
		t.Fatalf("%v: %s", err, out)
	}
}

func TestEscapeControlLeavesNormalPathsAlone(t *testing.T) {
	for _, s := range []string{"/repos/o/r/issues?x=1", "/café/ü", ""} {
		if got := escapeControl(s); got != s {
			t.Errorf("escapeControl(%q) = %q", s, got)
		}
	}
}
