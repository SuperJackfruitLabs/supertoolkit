package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A change made from a screen must survive a reload, or the UI is lying.
func TestSetPolicyPersistsAndReloads(t *testing.T) {
	p := writeCfg(t, `workspace: test
services:
  github:
    scopes: []
`)
	if err := setPolicyInFile(p, "github", "get_user", policy.ActionApproval); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(p)
	if err != nil {
		t.Fatalf("the file no longer parses: %v", err)
	}
	svc, _ := cfg.Service("github")
	if got := svc.Policy("get_user"); got != policy.ActionApproval {
		t.Fatalf("Policy(get_user) = %v, want %v", got, policy.ActionApproval)
	}
}

func TestSetPolicyReplacesAnExistingEntry(t *testing.T) {
	p := writeCfg(t, `workspace: test
services:
  github:
    scopes: []
    capabilities:
      get_user: deny
`)
	if err := setPolicyInFile(p, "github", "get_user", policy.ActionAgent); err != nil {
		t.Fatal(err)
	}
	cfg, _ := policy.Load(p)
	svc, _ := cfg.Service("github")
	if got := svc.Policy("get_user"); got != policy.ActionAgent {
		t.Fatalf("Policy(get_user) = %v, want %v", got, policy.ActionAgent)
	}
	raw, _ := os.ReadFile(p)
	if strings.Count(string(raw), "get_user:") != 1 {
		t.Fatalf("the action is listed more than once:\n%s", raw)
	}
}

// A config that gets reshuffled on every click is one people stop keeping in
// git, so comments and ordering have to survive.
func TestSetPolicyKeepsCommentsAndOrder(t *testing.T) {
	p := writeCfg(t, `# supertoolkit policy. Safe to commit.
workspace: test
services:
  # the one we use most
  github:
    scopes: [repo:read]
  aws-sts:
    scopes: []
`)
	if err := setPolicyInFile(p, "github", "create_issue", policy.ActionDeny); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	out := string(raw)
	for _, want := range []string{"# supertoolkit policy", "# the one we use most", "aws-sts:", "repo:read"} {
		if !strings.Contains(out, want) {
			t.Errorf("the rewrite lost %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "github:") > strings.Index(out, "aws-sts:") {
		t.Error("the services were reordered")
	}
	cfg, err := policy.Load(p)
	if err != nil {
		t.Fatalf("the file no longer parses: %v", err)
	}
	svc, _ := cfg.Service("github")
	if svc.Policy("create_issue") != policy.ActionDeny {
		t.Error("the change did not take effect")
	}
}

func TestSetPolicyRefusesAnUnknownService(t *testing.T) {
	p := writeCfg(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	if err := setPolicyInFile(p, "not-configured", "x", policy.ActionDeny); err == nil {
		t.Fatal("writing a policy for an unconfigured service succeeded")
	}
}
