package policy

import (
	"strings"
	"testing"
)

const forgeYAML = `
services:
  forge-main:
    kind: forge
    provider: forgejo
    host: forge.superjackfruit.com
    auth: token
    scheme: bearer
    env_var: FORGEJO_TOKEN
    repositories: [SuperJackfruitLabs/supertoolkit]
    preset: issues
`

func TestLoadForgeService(t *testing.T) {
	cfg, err := Load(write(t, forgeYAML))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	svc, ok := cfg.Service("forge-main")
	if !ok {
		t.Fatal("Service(forge-main) not found")
	}
	f := svc.Entry().Forge
	if f == nil || len(f.Repositories) != 1 || f.Repositories[0] != "SuperJackfruitLabs/supertoolkit" {
		t.Errorf("Forge = %+v", f)
	}
	if !cfg.InterceptHosts()["forge.superjackfruit.com"] {
		t.Error("forge host is not in InterceptHosts")
	}
}

func TestLoadForgeRejectsSecondEntryOnSameHost(t *testing.T) {
	_, err := Load(write(t, forgeYAML+`
  forge-other:
    kind: forge
    provider: forgejo
    host: forge.superjackfruit.com
    repositories: [SuperJackfruitLabs/agentpod]
`))
	if err == nil || !strings.Contains(err.Error(), "forge.superjackfruit.com") {
		t.Errorf("error = %v, want a rejection naming the shared host", err)
	}
}

func TestLoadStillRejectsUnknownBuiltin(t *testing.T) {
	_, err := Load(write(t, "services:\n  forgejo:\n    scopes: []\n"))
	if err == nil || !strings.Contains(err.Error(), "unknown service") {
		t.Errorf("error = %v, want the unknown service message", err)
	}
}

func TestLoadRejectsUnknownKind(t *testing.T) {
	_, err := Load(write(t, "services:\n  x:\n    kind: widget\n"))
	if err == nil || !strings.Contains(err.Error(), "kind") {
		t.Errorf("error = %v, want a rejection of the kind", err)
	}
}

func TestForgeEntriesAreCopies(t *testing.T) {
	a, err := Load(write(t, forgeYAML))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(write(t, strings.Replace(forgeYAML, "forge.superjackfruit.com", "git.example.org", 1)))
	if err != nil {
		t.Fatal(err)
	}
	sa, _ := a.Service("forge-main")
	sb, _ := b.Service("forge-main")
	if sa.Entry() == sb.Entry() || sa.Entry().Host == sb.Entry().Host {
		t.Error("two loads shared one Entry")
	}
}

// The proxy maps a host to one service. A forge on a built-in's host would have
// one of the two silently win, so it is refused whichever order they load in.
func TestLoadRejectsAForgeOnABuiltinsHost(t *testing.T) {
	_, err := Load(write(t, `
services:
  github:
    scopes: []
  gh-enterprise-clone:
    kind: forge
    provider: github
    host: api.github.com
    repositories: [o/r]
`))
	if err == nil || !strings.Contains(err.Error(), "api.github.com") {
		t.Errorf("error = %v, want a rejection naming the shared host", err)
	}
}
