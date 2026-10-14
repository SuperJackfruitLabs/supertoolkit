package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadResolvesPolicyPerCapability(t *testing.T) {
	p := write(t, `
workspace: marketing
services:
  github:
    scopes: [repo:read]
    capabilities:
      delete_repo: deny
`)
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Workspace != "marketing" {
		t.Errorf("Workspace = %q, want %q", cfg.Workspace, "marketing")
	}
	svc, ok := cfg.Service("github")
	if !ok {
		t.Fatal("Service(github) not found")
	}
	if got := svc.Scopes; len(got) != 1 || got[0] != "repo:read" {
		t.Errorf("Scopes = %v, want [repo:read]", got)
	}

	for _, tc := range []struct {
		capability string
		want       Action
		why        string
	}{
		{"list_repos", ActionAgent, "a read with no explicit policy"},
		{"create_issue", ActionApproval, "a write with no explicit policy"},
		{"delete_repo", ActionDeny, "explicitly denied in the file"},
		{"not_in_catalogue", ActionApproval, "an unknown capability must not be agent-callable"},
	} {
		if got := svc.Policy(tc.capability); got != tc.want {
			t.Errorf("Policy(%q) = %v, want %v — %s", tc.capability, got, tc.want, tc.why)
		}
	}
}

// Revert-proofing the safe default. Delete the rule that writes need approval
// and this test must go red, rather than quietly widening every agent's reach.
func TestWritesDefaultToApprovalWithNoCapabilitiesBlock(t *testing.T) {
	cfg, err := Load(write(t, `
workspace: w
services:
  github:
    scopes: [repo:read]
`))
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := cfg.Service("github")
	if got := svc.Policy("create_issue"); got != ActionApproval {
		t.Fatalf("a write with no capabilities block = %v, want %v", got, ActionApproval)
	}
	if got := svc.Policy("delete_repo"); got != ActionApproval {
		t.Fatalf("a destructive capability with no block = %v, want %v", got, ActionApproval)
	}
	if got := svc.Policy("list_repos"); got != ActionAgent {
		t.Fatalf("a read with no block = %v, want %v", got, ActionAgent)
	}
}

func TestUnknownServiceIsRefusedAtLoad(t *testing.T) {
	_, err := Load(write(t, `
workspace: w
services:
  not-a-real-service:
    scopes: []
`))
	if err == nil {
		t.Fatal("Load() error = nil, want a refusal naming the unknown service")
	}
}

func TestInterceptHostsComeFromTheCatalogue(t *testing.T) {
	cfg, err := Load(write(t, `
workspace: w
services:
  github:
    scopes: [repo:read]
`))
	if err != nil {
		t.Fatal(err)
	}
	hosts := cfg.InterceptHosts()
	if !hosts["api.github.com"] {
		t.Fatalf("InterceptHosts() = %v, want api.github.com present", hosts)
	}
	if len(hosts) != 1 {
		t.Fatalf("InterceptHosts() = %v, want exactly the configured service's host", hosts)
	}
}
