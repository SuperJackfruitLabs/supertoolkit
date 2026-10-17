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
		"app auth not yet":       func(s *ForgeSpec) { s.Auth = "app" },
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

func TestNewForgeEntryAppAuthMessage(t *testing.T) {
	s := forgejoSpec()
	s.Auth = "app"
	_, err := NewForgeEntry(s)
	if err == nil || !strings.Contains(err.Error(), "GitHub adapter") {
		t.Errorf("error = %v, want a mention of the GitHub adapter", err)
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
