package main

import (
	"encoding/json"
	"os"
	"strings"
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
	const secret = "ghp_real_secret_value"
	obs, dir := auditRig(t)
	r := deniedRecord("builtin:outside-prefix")
	// The placeholder travelled; the secret was never fetched.
	r.Path = "/repos/o/r?t=" + broker.Placeholder("github")
	obs.Observe(r)
	raw, err := os.ReadFile(dir + "/audit.log")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("ledger contains the secret")
	}
	if e := readAll(t, dir)[0]; e.Credential != "" && strings.HasPrefix(e.Credential, "sha256:") {
		t.Errorf("credential = %q", e.Credential)
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
