package policy

import "testing"

const withProfiles = `
workspace: test
services:
  github:
    scopes: [repo:read]
    capabilities:
      delete_repo: deny
profiles:
  reader:
    github: [get_user, list_repos]
  writer:
    github: [get_user, create_issue]
  sneaky:
    github: [delete_repo]
  everything:
    github: ["*"]
`

func TestProfileHidesWhatItDoesNotList(t *testing.T) {
	cfg, err := Load(write(t, withProfiles))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.Profile("reader")
	if !ok {
		t.Fatal("profile reader not found")
	}
	if !p.Visible("github", "get_user") {
		t.Error("get_user should be visible to reader")
	}
	if p.Visible("github", "create_issue") {
		t.Error("create_issue must be invisible to reader — absent, not refused")
	}
	if p.Visible("nope", "get_user") {
		t.Error("an unconfigured service must not be visible")
	}
}

// The ceiling. A profile selects a subset of what the service policy allows and
// can never promote a capability — listing a write does not make it agent-callable.
func TestProfileCannotPromoteAboveTheServicePolicy(t *testing.T) {
	cfg, _ := Load(write(t, withProfiles))
	p, _ := cfg.Profile("writer")

	if got := p.Resolve("github", "create_issue"); got != ActionApproval {
		t.Fatalf("Resolve(create_issue) = %v, want %v — a profile must not promote a write", got, ActionApproval)
	}
	if got := p.Resolve("github", "get_user"); got != ActionAgent {
		t.Fatalf("Resolve(get_user) = %v, want %v", got, ActionAgent)
	}
}

// A profile naming a denied capability gets nothing. Deny is the floor as well
// as the ceiling.
func TestProfileCannotRecoverADeniedCapability(t *testing.T) {
	cfg, _ := Load(write(t, withProfiles))
	p, _ := cfg.Profile("sneaky")
	if p.Visible("github", "delete_repo") {
		t.Error("a denied capability must not become visible by being listed in a profile")
	}
	if got := p.Resolve("github", "delete_repo"); got != ActionDeny {
		t.Fatalf("Resolve(delete_repo) = %v, want %v", got, ActionDeny)
	}
}

func TestWildcardProfileStillRespectsTheCeiling(t *testing.T) {
	cfg, _ := Load(write(t, withProfiles))
	p, _ := cfg.Profile("everything")
	if !p.Visible("github", "create_issue") {
		t.Error(`a "*" profile should see every non-denied capability`)
	}
	if p.Visible("github", "delete_repo") {
		t.Error(`"*" must not include a denied capability`)
	}
	if got := p.Resolve("github", "create_issue"); got != ActionApproval {
		t.Fatalf(`"*" promoted a write to %v, want %v`, got, ActionApproval)
	}
}

// With no profiles declared, there is nothing to narrow and every caller sees
// what the service policy allows.
func TestDefaultProfileWithNoneDeclared(t *testing.T) {
	cfg, err := Load(write(t, `
workspace: test
services:
  github:
    scopes: []
`))
	if err != nil {
		t.Fatal(err)
	}
	p, ok := cfg.Profile("")
	if !ok {
		t.Fatal("the default profile should always exist")
	}
	if !p.Visible("github", "create_issue") {
		t.Error("the default profile should see everything not denied")
	}
	if got := p.Resolve("github", "create_issue"); got != ActionApproval {
		t.Errorf("Resolve = %v, want the service policy %v", got, ActionApproval)
	}
}

func TestUnknownProfileIsNotSilentlyPermissive(t *testing.T) {
	cfg, _ := Load(write(t, withProfiles))
	if _, ok := cfg.Profile("does-not-exist"); ok {
		t.Fatal("an unknown profile must not resolve — it would otherwise fall back to full access")
	}
}

func TestProfileNamesAreListed(t *testing.T) {
	cfg, _ := Load(write(t, withProfiles))
	got := cfg.Profiles()
	if len(got) != 4 {
		t.Fatalf("Profiles() = %v, want four declared profiles", got)
	}
}
