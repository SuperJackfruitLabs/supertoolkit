package rules

import (
	"net/http"
	"strings"
	"testing"
)

func mustRule(t *testing.T, id, line string, when map[string]any, allow bool) Rule {
	t.Helper()
	r, err := ParseRule(id, line, when, allow)
	if err != nil {
		t.Fatalf("ParseRule(%q): %v", line, err)
	}
	return r
}

func mustSet(t *testing.T, repos []string, rs ...Rule) *Set {
	t.Helper()
	s, err := NewSet(repos, rs)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	return s
}

func jsonReq(method, path, body string) Request {
	return Request{Method: method, EscapedPath: path, Header: http.Header{}, Body: []byte(body), ContentType: "application/json"}
}

func req(method, path string) Request {
	return Request{Method: method, EscapedPath: path, Header: http.Header{}}
}

func TestDenyWinsOverAllow(t *testing.T) {
	s := mustSet(t, []string{"acme/widgets"},
		mustRule(t, "allow-all-delete", "DELETE /repos/{owner}/{repo}/**", nil, true),
		mustRule(t, "no-delete", "DELETE /**", nil, false),
		mustRule(t, "read", "GET /repos/{owner}/{repo}", nil, true),
	)
	d := s.Evaluate("", req("DELETE", "/repos/acme/widgets/issues/1"))
	if d.Allowed || d.RuleID != "no-delete" {
		t.Fatalf("want deny by no-delete, got %+v", d)
	}
	if d := s.Evaluate("", req("GET", "/repos/acme/widgets")); !d.Allowed || d.RuleID != "read" {
		t.Fatalf("control: want allow by read, got %+v", d)
	}
}

func TestDenyIsCaseInsensitiveAndSlashTolerant(t *testing.T) {
	s := mustSet(t, []string{"acme/widgets"},
		mustRule(t, "any", "GET /repos/{owner}/{repo}/**", nil, true),
		mustRule(t, "any-root", "GET /repos/{owner}/{repo}/", nil, true),
		mustRule(t, "no-hooks", "GET /repos/{owner}/{repo}/hooks", nil, false),
	)
	for _, p := range []string{
		"/repos/acme/widgets/hooks", "/repos/acme/widgets/HOOKS", "/REPOS/acme/widgets/Hooks",
		"/repos/acme/widgets/hooks/",
	} {
		if d := s.Evaluate("", req("GET", p)); d.Allowed || d.RuleID != "no-hooks" {
			t.Errorf("%s: want deny by no-hooks, got %+v", p, d)
		}
	}
	// Lowercase method must not dodge a deny.
	s2 := mustSet(t, []string{"acme/widgets"}, mustRule(t, "no-del", "DELETE /**", nil, false))
	if d := s2.Evaluate("", req("delete", "/repos/acme/widgets")); d.Allowed || d.RuleID != "no-del" {
		t.Errorf("lowercase delete: %+v", d)
	}
	// Allow stays exact.
	s3 := mustSet(t, nil, mustRule(t, "user", "GET /user", nil, true))
	for _, p := range []string{"/USER", "/user/"} {
		if d := s3.Evaluate("", req("GET", p)); d.Allowed {
			t.Errorf("allow must be exact: %s allowed", p)
		}
	}
	if d := s3.Evaluate("", req("get", "/user")); d.Allowed {
		t.Errorf("allow method must be exact")
	}
}

func TestDefaultDeny(t *testing.T) {
	s := mustSet(t, []string{"acme/widgets"}, mustRule(t, "read", "GET /repos/{owner}/{repo}", nil, true))
	d := s.Evaluate("", req("POST", "/repos/acme/widgets"))
	if d.Allowed || d.Reason != "no-rule" || d.RuleID != "" {
		t.Fatalf("want no-rule deny, got %+v", d)
	}
	empty := mustSet(t, nil)
	if d := empty.Evaluate("", req("GET", "/")); d.Allowed || d.Reason != "no-rule" {
		t.Fatalf("empty set must deny, got %+v", d)
	}
	var nilSet *Set
	if d := nilSet.Evaluate("", req("GET", "/")); d.Allowed {
		t.Fatalf("nil set must deny")
	}
}

func TestOwnerRepoBindToGrantedRepositories(t *testing.T) {
	s := mustSet(t, []string{"acme/widgets", "Other/Thing"},
		mustRule(t, "issues", "POST /repos/{owner}/{repo}/issues", nil, true),
		mustRule(t, "owner-only", "GET /orgs/{owner}", nil, true),
		mustRule(t, "other-var", "GET /users/{user}", nil, true),
	)
	cases := []struct {
		path string
		ok   bool
	}{
		{"/repos/acme/widgets/issues", true},
		{"/repos/Acme/Widgets/issues", true},
		{"/repos/ACME/WIDGETS/issues", true},
		{"/repos/other/thing/issues", true},
		{"/repos/acme/widgets-evil/issues", false},
		{"/repos/acme/widgets/../x/issues", false},
		{"/repos/acme/thing/issues", false}, // cross-pair: owner of one, name of another
		{"/repos/evil/widgets/issues", false},
		{"/repos/nobody/nothing/issues", false},
		{"/repos/acme%2fwidgets/x/issues", false},
	}
	for _, c := range cases {
		d := s.Evaluate("", req("POST", c.path))
		if d.Allowed != c.ok {
			t.Errorf("%s: allowed=%v want %v (%+v)", c.path, d.Allowed, c.ok, d)
		}
	}
	if d := s.Evaluate("", req("GET", "/orgs/ACME")); !d.Allowed {
		t.Errorf("owner-only granted: %+v", d)
	}
	if d := s.Evaluate("", req("GET", "/orgs/evil")); d.Allowed {
		t.Errorf("owner-only ungranted allowed")
	}
	if d := s.Evaluate("", req("GET", "/users/anyone")); !d.Allowed {
		t.Errorf("other captures unrestricted: %+v", d)
	}
	none := mustSet(t, nil, mustRule(t, "issues", "POST /repos/{owner}/{repo}/issues", nil, true))
	if d := none.Evaluate("", req("POST", "/repos/acme/widgets/issues")); d.Allowed {
		t.Errorf("empty grant must not bind anything")
	}
	if _, err := NewSet([]string{"acme"}, nil); err == nil {
		t.Errorf("repo without owner must be rejected")
	}
	if _, err := NewSet([]string{"a/b/c"}, nil); err == nil {
		t.Errorf("repo with two slashes must be rejected")
	}
}

func TestRulesWithoutRepoPlaceholderMatchLiterally(t *testing.T) {
	s := mustSet(t, nil, mustRule(t, "me", "GET /user", nil, true))
	if d := s.Evaluate("", req("GET", "/user")); !d.Allowed || d.RuleID != "me" {
		t.Fatalf("want allow, got %+v", d)
	}
	for _, p := range []string{"/user/repos", "/users", "/"} {
		if d := s.Evaluate("", req("GET", p)); d.Allowed {
			t.Errorf("%s allowed", p)
		}
	}
}

func TestOutsideAPIPrefixDenied(t *testing.T) {
	s := mustSet(t, nil, mustRule(t, "me", "GET /user", nil, true), mustRule(t, "all", "GET /**", nil, true))
	if d := s.Evaluate("/api/v1", req("GET", "/api/v1/user")); !d.Allowed || d.RuleID != "me" {
		t.Fatalf("control: %+v", d)
	}
	for _, p := range []string{"/login", "/api/v10/user", "/api/user", "/acme/widgets.git/info/refs", "/api/v1/../../login"} {
		d := s.Evaluate("/api/v1", req("GET", p))
		if d.Allowed {
			t.Errorf("%s allowed", p)
		}
	}
	if d := s.Evaluate("/api/v1", req("GET", "/login")); d.Reason != "outside-api-prefix" {
		t.Errorf("reason = %q", d.Reason)
	}
	if d := s.Evaluate("/api/v1/", req("GET", "/api/v1/user")); !d.Allowed {
		t.Errorf("trailing slash on prefix: %+v", d)
	}
}

func TestMethodOverrideHeaderDenied(t *testing.T) {
	s := mustSet(t, []string{"acme/widgets"}, mustRule(t, "issues", "POST /repos/{owner}/{repo}/issues", nil, true))
	if d := s.Evaluate("", req("POST", "/repos/acme/widgets/issues")); !d.Allowed {
		t.Fatalf("control: %+v", d)
	}
	for _, h := range []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method", "x-http-method-override"} {
		r := req("POST", "/repos/acme/widgets/issues")
		r.Header = http.Header{h: {"DELETE"}} // raw map, not canonicalised
		d := s.Evaluate("", r)
		if d.Allowed || d.Reason != "method-override" {
			t.Errorf("%s: %+v", h, d)
		}
	}
}

func TestBodyConditionAbsent(t *testing.T) {
	s := mustSet(t, []string{"acme/widgets"},
		mustRule(t, "edit", "PATCH /repos/{owner}/{repo}/issues/*", map[string]any{"body.state": "absent"}, true))
	if d := s.Evaluate("", jsonReq("PATCH", "/repos/acme/widgets/issues/7", `{"title":"x"}`)); !d.Allowed {
		t.Fatalf("want allow, got %+v", d)
	}
	for _, b := range []string{`{"state":"closed"}`, `{"title":"x","state":null}`, `{"state":"closed"}`} {
		if d := s.Evaluate("", jsonReq("PATCH", "/repos/acme/widgets/issues/7", b)); d.Allowed {
			t.Errorf("%s allowed", b)
		}
	}
}

func TestBodyConditionEqualsAndOneOf(t *testing.T) {
	s := mustSet(t, []string{"acme/widgets"},
		mustRule(t, "close", "PATCH /repos/{owner}/{repo}/issues/*", map[string]any{"state": "closed"}, true),
		mustRule(t, "merge", "PUT /repos/{owner}/{repo}/pulls/*/merge", map[string]any{"merge_method": []any{"squash", "rebase"}}, true),
		mustRule(t, "nested", "POST /repos/{owner}/{repo}/x", map[string]any{"body.a.b": true}, true),
		mustRule(t, "no-force", "POST /repos/{owner}/{repo}/git/refs", map[string]any{"force": true}, false),
		mustRule(t, "refs", "POST /repos/{owner}/{repo}/git/refs", nil, true),
	)
	cases := []struct {
		m, p, body string
		ok         bool
	}{
		{"PATCH", "/repos/acme/widgets/issues/1", `{"state":"closed"}`, true},
		{"PATCH", "/repos/acme/widgets/issues/1", `{"state":"open"}`, false},
		{"PATCH", "/repos/acme/widgets/issues/1", `{}`, false},
		{"PATCH", "/repos/acme/widgets/issues/1", `{"state":["closed"]}`, false},
		{"PUT", "/repos/acme/widgets/pulls/3/merge", `{"merge_method":"squash"}`, true},
		{"PUT", "/repos/acme/widgets/pulls/3/merge", `{"merge_method":"rebase"}`, true},
		{"PUT", "/repos/acme/widgets/pulls/3/merge", `{"merge_method":"merge"}`, false},
		{"POST", "/repos/acme/widgets/x", `{"a":{"b":true}}`, true},
		{"POST", "/repos/acme/widgets/x", `{"a":{"b":false}}`, false},
		{"POST", "/repos/acme/widgets/x", `{"a":{"b":true,"b":false}}`, false},
		{"POST", "/repos/acme/widgets/x", `{"a":{"b":false,"b":true}}`, false},
		{"POST", "/repos/acme/widgets/x", `{"a.b":true}`, false},
		{"POST", "/repos/acme/widgets/git/refs", `{"ref":"x"}`, true},
		{"POST", "/repos/acme/widgets/git/refs", `{"force":true}`, false},
		{"POST", "/repos/acme/widgets/git/refs", `not json`, false}, // deny with When, unevaluable => matched
	}
	for _, c := range cases {
		d := s.Evaluate("", jsonReq(c.m, c.p, c.body))
		if d.Allowed != c.ok {
			t.Errorf("%s %s %s: allowed=%v want %v (%+v)", c.m, c.p, c.body, d.Allowed, c.ok, d)
		}
	}
}

func TestBodyConditionFailsClosed(t *testing.T) {
	s := mustSet(t, []string{"acme/widgets"},
		mustRule(t, "edit", "PATCH /repos/{owner}/{repo}/issues/*", map[string]any{"state": "absent"}, true))
	p := "/repos/acme/widgets/issues/7"
	if d := s.Evaluate("", jsonReq("PATCH", p, `{"title":"x"}`)); !d.Allowed {
		t.Fatalf("control: %+v", d)
	}
	bad := map[string]Request{
		"not json":       jsonReq("PATCH", p, `title=x`),
		"array":          jsonReq("PATCH", p, `[{"title":"x"}]`),
		"string":         jsonReq("PATCH", p, `"x"`),
		"trailing data":  jsonReq("PATCH", p, `{"title":"x"} {"state":"closed"}`),
		"empty body":     jsonReq("PATCH", p, ``),
		"duplicate key":  jsonReq("PATCH", p, `{"state":"open","state":"closed"}`),
		"truncated flag": func() Request { r := jsonReq("PATCH", p, `{"title":"x"}`); r.BodyTruncated = true; return r }(),
		"over limit":     jsonReq("PATCH", p, `{"title":"`+strings.Repeat("a", MaxBody)+`"}`),
		"text/plain":     func() Request { r := jsonReq("PATCH", p, `{"title":"x"}`); r.ContentType = "text/plain"; return r }(),
		"no ctype":       func() Request { r := jsonReq("PATCH", p, `{"title":"x"}`); r.ContentType = ""; return r }(),
		"bad ctype": func() Request {
			r := jsonReq("PATCH", p, `{"title":"x"}`)
			r.ContentType = "application/json;;"
			return r
		}(),
		"invalid utf8": jsonReq("PATCH", p, "{\"title\":\"\xff\"}"),
	}
	for name, r := range bad {
		if d := s.Evaluate("", r); d.Allowed {
			t.Errorf("%s: allowed", name)
		}
	}
	for _, ct := range []string{"application/json; charset=utf-8", "application/vnd.github+json", "APPLICATION/JSON"} {
		r := jsonReq("PATCH", p, `{"title":"x"}`)
		r.ContentType = ct
		if d := s.Evaluate("", r); !d.Allowed {
			t.Errorf("content type %q refused: %+v", ct, d)
		}
	}
	// Duplicate key counts as present for a deny-on-present rule too.
	sd := mustSet(t, []string{"acme/widgets"},
		mustRule(t, "no-state", "PATCH /repos/{owner}/{repo}/issues/*", map[string]any{"state": "present"}, false),
		mustRule(t, "edit", "PATCH /repos/{owner}/{repo}/issues/*", nil, true))
	if d := sd.Evaluate("", jsonReq("PATCH", p, `{"state":"open","state":"closed"}`)); d.Allowed || d.RuleID != "no-state" {
		t.Errorf("dup key on deny-present: %+v", d)
	}
	if d := sd.Evaluate("", jsonReq("PATCH", p, `{"title":"x"}`)); !d.Allowed {
		t.Errorf("control: %+v", d)
	}
}

func TestParseRuleRejects(t *testing.T) {
	bad := []struct {
		line string
		when map[string]any
	}{
		{"FETCH /user", nil},
		{"get /user", nil},
		{"GET", nil},
		{"GET ", nil},
		{"/user", nil},
		{"GET /a/**/b", nil},
		{"GET user", nil},
		{"GET /a//b", nil},
		{"GET /a/{}/b", nil},
		{"GET /a/{x/b", nil},
		{"GET /a/b extra", nil},
		{"GET /a", map[string]any{"state": map[string]any{"x": 1}}},
		{"GET /a", map[string]any{"state": []any{}}},
		{"GET /a", map[string]any{"state": []any{map[string]any{}}}},
		{"GET /a", map[string]any{"state": nil}},
		{"GET /a", map[string]any{"": "x"}},
		{"GET /a", map[string]any{"a..b": "x"}},
		{"GET /a", map[string]any{"body.": "x"}},
	}
	for _, b := range bad {
		if _, err := ParseRule("r", b.line, b.when, true); err == nil {
			t.Errorf("ParseRule(%q, %v) accepted", b.line, b.when)
		}
	}
	if _, err := ParseRule("", "GET /a", nil, true); err == nil {
		t.Errorf("empty id accepted")
	}
	r, err := ParseRule("r", "PATCH   /repos/{owner}/{repo}/issues/*", map[string]any{"body.state": "absent", "n": 3, "l": []any{"a", "b"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "PATCH" || r.Pattern != "/repos/{owner}/{repo}/issues/*" || len(r.When) != 3 {
		t.Fatalf("parsed %+v", r)
	}
	if _, err := NewSet(nil, []Rule{{ID: "x", Allow: true, Method: "GET", Pattern: "/a/**/b"}}); err == nil {
		t.Errorf("NewSet accepted an invalid hand-built rule")
	}
	if _, err := NewSet(nil, []Rule{{ID: "x", Allow: true, Method: "GET", Pattern: "/a", When: []Cond{{Key: "a", Op: "like"}}}}); err == nil {
		t.Errorf("NewSet accepted an unknown op")
	}
}
