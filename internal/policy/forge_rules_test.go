package policy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/rules"
)

func forgeWith(preset, extra string) string {
	return `
services:
  forge-main:
    kind: forge
    provider: forgejo
    host: forge.superjackfruit.com
    auth: token
    scheme: bearer
    env_var: FORGEJO_TOKEN
    repositories: [acme/widgets]
    preset: ` + preset + "\n" + extra
}

func eval(t *testing.T, s *Service, method, path string) rules.Decision {
	t.Helper()
	return s.Rules().Evaluate(s.APIPrefix(), rules.Request{Method: method, EscapedPath: path, Header: http.Header{}})
}

func loadForge(t *testing.T, y string) *Service {
	t.Helper()
	cfg, err := Load(write(t, y))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	svc, _ := cfg.Service("forge-main")
	return svc
}

func TestLoadForgeRulesExtendPreset(t *testing.T) {
	svc := loadForge(t, forgeWith("read", `    rules:
      - allow: "POST /repos/{owner}/{repo}/labels"
`))
	p := svc.APIPrefix()
	if p == "" {
		t.Fatal("APIPrefix empty for a forge")
	}
	if d := eval(t, svc, "POST", p+"/repos/acme/widgets/labels"); !d.Allowed || d.RuleID != "user#1" {
		t.Errorf("added allow: %+v", d)
	}
	if d := eval(t, svc, "GET", p+"/repos/acme/widgets/issues"); !d.Allowed {
		t.Errorf("preset read rule lost: %+v", d)
	}
}

func TestLoadForgeRuleDenySubtractsFromPreset(t *testing.T) {
	svc := loadForge(t, forgeWith("issues", `    rules:
      - deny: "POST /repos/{owner}/{repo}/issues"
`))
	p := svc.APIPrefix()
	d := eval(t, svc, "POST", p+"/repos/acme/widgets/issues")
	if d.Allowed || d.RuleID != "user#1" {
		t.Errorf("deny: %+v", d)
	}
}

func TestLoadRejectsRulesOnABuiltin(t *testing.T) {
	for _, body := range []string{
		"    rules:\n      - allow: \"GET /x\"\n",
		"    allow_graphql: true\n",
	} {
		_, err := Load(write(t, "services:\n  github:\n    scopes: []\n"+body))
		if err == nil || !strings.Contains(err.Error(), "github") {
			t.Errorf("error = %v, want rejection naming github", err)
		}
	}
}

func TestLoadRejectsABadRule(t *testing.T) {
	for _, line := range []string{`allow: "FETCH /repos/x"`, `allow: "GET /a/**/b"`, `allow: "GET"`} {
		_, err := Load(write(t, forgeWith("none", "    rules:\n      - "+line+"\n")))
		if err == nil || !strings.Contains(err.Error(), "forge-main") || !strings.Contains(err.Error(), "user#1") {
			t.Errorf("%s: error = %v, want service and rule named", line, err)
		}
	}
}

func TestLoadRejectsBodyConditionOnGraphQLPath(t *testing.T) {
	for _, pat := range []string{"/graphql", "/graphql/**"} {
		_, err := Load(write(t, forgeWith("none", "    rules:\n      - allow: \"POST "+pat+"\"\n        when: {query: present}\n")))
		if err == nil || !strings.Contains(err.Error(), "graphql") || !strings.Contains(err.Error(), "forge-main") {
			t.Errorf("%s: error = %v", pat, err)
		}
	}
}

func TestLoadRejectsSinglePlaceholderAllow(t *testing.T) {
	for _, pat := range []string{"/repos/{owner}/x/issues", "/repos/acme/{repo}/issues"} {
		_, err := Load(write(t, forgeWith("none", "    rules:\n      - allow: \"GET "+pat+"\"\n")))
		if err == nil || !strings.Contains(err.Error(), "forge-main") || !strings.Contains(err.Error(), "{owner}") || !strings.Contains(err.Error(), "{repo}") {
			t.Errorf("%s: error = %v", pat, err)
		}
	}
	// A deny with one placeholder is fine.
	loadForge(t, forgeWith("none", "    rules:\n      - deny: \"GET /repos/{owner}/x\"\n"))
}

func TestLoadForgeWhenValues(t *testing.T) {
	loadForge(t, forgeWith("none", `    rules:
      - allow: "PATCH /repos/{owner}/{repo}/issues/*"
        when: {state: closed, labels: [a, b], milestone: absent}
`))
	_, err := Load(write(t, forgeWith("none", `    rules:
      - allow: "PATCH /repos/{owner}/{repo}/issues/*"
        when: {state: {x: y}}
`)))
	if err == nil || !strings.Contains(err.Error(), "forge-main") {
		t.Errorf("map value: error = %v", err)
	}
}

func TestLoadForgePresetNoneStartsEmpty(t *testing.T) {
	svc := loadForge(t, forgeWith("none", ""))
	if d := eval(t, svc, "GET", svc.APIPrefix()+"/repos/acme/widgets/issues"); d.Allowed {
		t.Errorf("none preset allowed: %+v", d)
	}
}

func TestLoadForgeBitbucketPresetErrors(t *testing.T) {
	_, err := Load(write(t, `
services:
  bb:
    kind: forge
    provider: bitbucket
    host: api.bitbucket.org
    auth: token
    scheme: bearer
    env_var: BB_TOKEN
    repositories: [acme/widgets]
    preset: read
`))
	if err == nil || !strings.Contains(err.Error(), "bb") {
		t.Errorf("error = %v, want rejection naming bb", err)
	}
}

func TestAllowGraphQLDefaultsFalse(t *testing.T) {
	if loadForge(t, forgeWith("none", "")).AllowGraphQL() {
		t.Error("default true")
	}
	if !loadForge(t, forgeWith("none", "    allow_graphql: true\n")).AllowGraphQL() {
		t.Error("explicit true ignored")
	}
	cfg, _ := Load(write(t, "services:\n  github:\n    scopes: []\n"))
	g, _ := cfg.Service("github")
	if g.Rules() != nil || g.APIPrefix() != "" || g.AllowGraphQL() {
		t.Error("built-in not inert")
	}
}

func TestLoadRejectsUnknownRuleKey(t *testing.T) {
	for name, item := range map[string]string{
		"whn":       "allow: \"PATCH /repos/{owner}/{repo}/issues/*\"\n        whn: {state: closed}",
		"When":      "allow: \"PATCH /repos/{owner}/{repo}/issues/*\"\n        When: {state: closed}",
		"deny typo": "deny: \"PATCH /repos/{owner}/{repo}/issues/*\"\n        whn: {state: closed}",
	} {
		_, err := Load(write(t, forgeWith("none", "    rules:\n      - "+item+"\n")))
		if err == nil || !strings.Contains(err.Error(), "forge-main") || !strings.Contains(err.Error(), "user#1") || !strings.Contains(err.Error(), "unknown key") {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestLoadRejectsAllowAndDenyTogetherOrNeither(t *testing.T) {
	for _, item := range []string{
		"allow: \"GET /a\"\n        deny: \"GET /b\"",
		"when: {state: closed}",
	} {
		_, err := Load(write(t, forgeWith("none", "    rules:\n      - "+item+"\n")))
		if err == nil || !strings.Contains(err.Error(), "exactly one") {
			t.Errorf("%q: error = %v", item, err)
		}
	}
}

func TestLoadValidRuleWithWhenStillLoads(t *testing.T) {
	loadForge(t, forgeWith("none", "    rules:\n      - allow: \"PATCH /repos/{owner}/{repo}/issues/*\"\n        when: {state: closed}\n"))
}

func TestLoadRejectsGraphQLBodyConditionAnyCase(t *testing.T) {
	_, err := Load(write(t, forgeWith("none", "    rules:\n      - allow: \"POST /GraphQL\"\n        when: {query: present}\n")))
	if err == nil || !strings.Contains(err.Error(), "forge-main") {
		t.Errorf("error = %v", err)
	}
}

func TestLoadUserRuleIDsFollowPresetInOrder(t *testing.T) {
	svc := loadForge(t, forgeWith("read", `    rules:
      - allow: "POST /repos/{owner}/{repo}/labels"
      - deny: "POST /repos/{owner}/{repo}/labels"
`))
	// deny wins, and names the second user rule; the first allow is id user#1.
	if d := eval(t, svc, "POST", svc.APIPrefix()+"/repos/acme/widgets/labels"); d.Allowed || d.RuleID != "user#2" {
		t.Errorf("decision = %+v, want deny by user#2", d)
	}
	if d := eval(t, svc, "GET", svc.APIPrefix()+"/repos/acme/widgets/issues"); d.RuleID == "" || !strings.HasPrefix(d.RuleID, "preset:") {
		t.Errorf("preset rule id = %+v", d)
	}
}
