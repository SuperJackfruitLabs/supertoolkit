package catalog

import (
	"strings"
	"testing"
)

func forgejoSpec() ForgeSpec {
	return ForgeSpec{
		Name: "forge-main", Provider: "forgejo", Host: "forge.superjackfruit.com",
		Auth: "token", Scheme: "bearer", EnvVar: "FORGEJO_TOKEN",
		Repositories: []string{"SuperJackfruitLabs/supertoolkit"}, Preset: "issues",
	}
}

func TestNewForgeEntryForgejo(t *testing.T) {
	e, err := NewForgeEntry(forgejoSpec())
	if err != nil {
		t.Fatalf("NewForgeEntry() error = %v", err)
	}
	if e.Name != "forge-main" || e.Host != "forge.superjackfruit.com" || e.EnvVar != "FORGEJO_TOKEN" {
		t.Errorf("entry = %+v", e)
	}
	if e.Auth != AuthToken || e.Placement != BearerHeader {
		t.Errorf("Auth/Placement = %v/%v, want AuthToken/BearerHeader", e.Auth, e.Placement)
	}
	if e.Forge == nil {
		t.Fatal("Forge info missing")
	}
	if e.Forge.APIPrefix != "/api/v1" || e.Forge.IdentityPath != "/user" || e.Forge.Preset != "issues" {
		t.Errorf("Forge = %+v", e.Forge)
	}
	if got := e.Hosts(); len(got) != 1 || got[0] != "forge.superjackfruit.com" {
		t.Errorf("Hosts() = %v", got)
	}
}

func TestNewForgeEntryRejects(t *testing.T) {
	cases := map[string]func(*ForgeSpec){
		"host with scheme":       func(s *ForgeSpec) { s.Host = "https://forge.example" },
		"host with path":         func(s *ForgeSpec) { s.Host = "forge.example/api" },
		"host with whitespace":   func(s *ForgeSpec) { s.Host = "forge .example" },
		"empty host":             func(s *ForgeSpec) { s.Host = "" },
		"unknown provider":       func(s *ForgeSpec) { s.Provider = "sourcehut" },
		"unknown scheme":         func(s *ForgeSpec) { s.Scheme = "digest" },
		"app auth on forgejo":    func(s *ForgeSpec) { s.Auth = "app" },
		"empty repositories":     func(s *ForgeSpec) { s.Repositories = nil },
		"repository no slash":    func(s *ForgeSpec) { s.Repositories = []string{"nobody"} },
		"repository two slashes": func(s *ForgeSpec) { s.Repositories = []string{"a/b/c"} },
		"repository empty part":  func(s *ForgeSpec) { s.Repositories = []string{"a/"} },
		"unknown preset":         func(s *ForgeSpec) { s.Preset = "root" },
		"empty name":             func(s *ForgeSpec) { s.Name = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := forgejoSpec()
			mutate(&s)
			if _, err := NewForgeEntry(s); err == nil {
				t.Errorf("NewForgeEntry(%s) accepted a bad spec", name)
			}
		})
	}
}

func githubAppSpec() ForgeSpec {
	return ForgeSpec{
		Name: "gh-app", Provider: "github", Host: "api.github.com", Auth: "app",
		EnvVar: "GH_TOKEN", Repositories: []string{"SuperJackfruitLabs/a", "SuperJackfruitLabs/b"},
	}
}

func TestNewForgeEntryAppOnlyForGitHub(t *testing.T) {
	e, err := NewForgeEntry(githubAppSpec())
	if err != nil {
		t.Fatalf("NewForgeEntry(github app) error = %v", err)
	}
	if e.Auth != AuthGitHubApp || e.Placement != BearerHeader {
		t.Errorf("auth/placement = %v/%v, want AuthGitHubApp/BearerHeader", e.Auth, e.Placement)
	}
	if e.Forge.APIBase != "https://api.github.com" {
		t.Errorf("APIBase = %q", e.Forge.APIBase)
	}
	if strings.Join(e.Forge.RepositoryNames, ",") != "a,b" || e.Forge.Owner != "SuperJackfruitLabs" {
		t.Errorf("RepositoryNames = %v, Owner = %q", e.Forge.RepositoryNames, e.Forge.Owner)
	}
	for _, p := range []string{"forgejo", "gitea", "bitbucket"} {
		s := githubAppSpec()
		s.Provider = p
		_, err := NewForgeEntry(s)
		if err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("provider %s with auth app: error = %v, want one naming the provider", p, err)
		}
	}
}

func TestAppEntryAPIBaseForEnterprise(t *testing.T) {
	s := githubAppSpec()
	s.Host = "github.example.com"
	e, err := NewForgeEntry(s)
	if err != nil {
		t.Fatal(err)
	}
	if e.Forge.APIBase != "https://github.example.com/api/v3" {
		t.Errorf("APIBase = %q, want https://github.example.com/api/v3", e.Forge.APIBase)
	}
}

func TestAppEntryMixedOwnersRejected(t *testing.T) {
	s := githubAppSpec()
	s.Repositories = []string{"one/a", "two/b"}
	_, err := NewForgeEntry(s)
	if err == nil || !strings.Contains(err.Error(), "one owner") {
		t.Errorf("error = %v, want a refusal of mixed owners", err)
	}
	// A token-auth forge may still span owners.
	s.Auth = "token"
	if _, err := NewForgeEntry(s); err != nil {
		t.Errorf("token forge with mixed owners: %v", err)
	}
}

func TestForgeProviders(t *testing.T) {
	want := []string{"forgejo", "gitea", "github", "bitbucket"}
	got := Providers()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Providers() = %v, want %v", got, want)
	}
}

func TestBuiltinEntriesHaveNoForgeInfo(t *testing.T) {
	e, _ := Lookup("github")
	if e.Forge != nil {
		t.Error("built-in github must not carry forge info")
	}
}

func TestNewForgeEntryTokenScheme(t *testing.T) {
	s := forgejoSpec()
	s.Scheme = "token"
	e, err := NewForgeEntry(s)
	if err != nil {
		t.Fatalf("NewForgeEntry() error = %v", err)
	}
	if e.Placement != SchemeHeader || e.Field != "token" {
		t.Errorf("Placement/Field = %v/%q, want SchemeHeader/token", e.Placement, e.Field)
	}
}

func TestGitHubEnterpriseDefaultsAPIPrefix(t *testing.T) {
	for _, auth := range []string{"token", "app"} {
		s := githubAppSpec()
		s.Auth = auth
		s.Host = "ghe.example.com"
		e, err := NewForgeEntry(s)
		if err != nil {
			t.Fatal(err)
		}
		if e.Forge.APIPrefix != "/api/v3" {
			t.Errorf("%s auth on GHE: APIPrefix = %q, want /api/v3", auth, e.Forge.APIPrefix)
		}
		s.Host = "api.github.com"
		if e, _ = NewForgeEntry(s); e.Forge.APIPrefix != "" {
			t.Errorf("%s auth on api.github.com: APIPrefix = %q, want empty", auth, e.Forge.APIPrefix)
		}
		s.Host, s.APIPrefix = "ghe.example.com", "/custom"
		if e, _ = NewForgeEntry(s); e.Forge.APIPrefix != "/custom" {
			t.Errorf("%s auth: explicit api_prefix lost: %q", auth, e.Forge.APIPrefix)
		}
	}
}

func TestAppAuthRefusesTokenScheme(t *testing.T) {
	s := githubAppSpec()
	s.Scheme = "token"
	_, err := NewForgeEntry(s)
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Errorf("error = %v, want a refusal of scheme token with auth app", err)
	}
}
