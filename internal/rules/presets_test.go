package rules

import (
	"fmt"
	"testing"
)

var presetOrder = []string{"read", "issues", "pull-requests", "maintain"}

func mustPreset(t *testing.T, provider, name string) []Rule {
	t.Helper()
	rs, err := Preset(provider, name)
	if err != nil {
		t.Fatalf("Preset(%s,%s): %v", provider, name, err)
	}
	return rs
}

func presetAllows(t *testing.T, provider, name, method, p string) bool {
	t.Helper()
	s, err := NewSet([]string{"o/r"}, mustPreset(t, provider, name))
	if err != nil {
		t.Fatal(err)
	}
	return s.Evaluate("", Request{Method: method, EscapedPath: p}).Allowed
}

func TestPresetsAreCumulative(t *testing.T) {
	for _, prov := range []string{"forgejo", "gitea", "github"} {
		for i := 1; i < len(presetOrder); i++ {
			lower, upper := mustPreset(t, prov, presetOrder[i-1]), mustPreset(t, prov, presetOrder[i])
			if len(upper) <= len(lower) {
				t.Errorf("%s: %s not larger than %s", prov, presetOrder[i], presetOrder[i-1])
			}
			for _, lr := range lower {
				found := false
				for _, ur := range upper {
					if ur.Method == lr.Method && ur.Pattern == lr.Pattern && ur.Allow == lr.Allow {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: %s lacks %s %s of %s", prov, presetOrder[i], lr.Method, lr.Pattern, presetOrder[i-1])
				}
			}
		}
		if len(mustPreset(t, prov, "none")) != 0 {
			t.Errorf("%s none not empty", prov)
		}
	}
}

func TestPresetRuleIDs(t *testing.T) {
	for _, name := range presetOrder {
		for i, r := range mustPreset(t, "forgejo", name) {
			if want := fmt.Sprintf("preset:%s#%d", name, i+1); r.ID != want {
				t.Errorf("id %q, want %q", r.ID, want)
			}
		}
		if _, err := NewSet([]string{"o/r"}, mustPreset(t, "github", name)); err != nil {
			t.Errorf("%s ids not unique/valid: %v", name, err)
		}
	}
}

func TestNoPresetAllowsDelete(t *testing.T) {
	for _, prov := range []string{"forgejo", "gitea", "github"} {
		for _, name := range presetOrder {
			for _, r := range mustPreset(t, prov, name) {
				if r.Method == "DELETE" {
					t.Errorf("%s/%s has DELETE rule %s", prov, name, r.ID)
				}
			}
			if presetAllows(t, prov, name, "DELETE", "/repos/o/r/issues/1") {
				t.Errorf("%s/%s allows DELETE", prov, name)
			}
		}
	}
}

func TestPresetReadIncludesIdentity(t *testing.T) {
	if !presetAllows(t, "forgejo", "read", "GET", "/user") {
		t.Error("GET /user denied")
	}
	if !presetAllows(t, "github", "read", "GET", "/repos/o/r/pulls/3") {
		t.Error("repo read denied")
	}
	if presetAllows(t, "github", "read", "GET", "/repos/o/other/pulls/3") {
		t.Error("other repo read allowed")
	}
	if !presetAllows(t, "github", "read", "GET", "/repos/o/r") {
		t.Error("repo metadata denied")
	}
	if presetAllows(t, "github", "read", "GET", "/repos/o/other") {
		t.Error("other repo metadata allowed")
	}
	if presetAllows(t, "github", "read", "GET", "/search/code") {
		t.Error("search allowed")
	}
	if presetAllows(t, "github", "read", "POST", "/repos/o/r/issues") {
		t.Error("read allows write")
	}
}

func TestPresetIssuesAllowsCreateAndComment(t *testing.T) {
	for _, prov := range []string{"forgejo", "gitea", "github"} {
		for _, c := range []struct {
			m, p string
			ok   bool
		}{
			{"POST", "/repos/o/r/issues", true},
			{"PATCH", "/repos/o/r/issues/7", true},
			{"POST", "/repos/o/r/issues/7/comments", true},
			{"PATCH", "/repos/o/r/issues/comments/9", true},
			{"POST", "/repos/o/r/issues/7/labels", true},
			{"PUT", "/repos/o/r/issues/7/labels", true},
			{"POST", "/repos/o/other/issues", false},
			{"POST", "/repos/o/r/pulls", false},
			{"POST", "/repos/o/r/labels", false},
		} {
			if got := presetAllows(t, prov, "issues", c.m, c.p); got != c.ok {
				t.Errorf("%s issues %s %s = %v, want %v", prov, c.m, c.p, got, c.ok)
			}
		}
	}
}

func TestPresetPullRequestsDoesNotMerge(t *testing.T) {
	for _, prov := range []string{"forgejo", "gitea", "github"} {
		for _, c := range []struct {
			m, p string
			ok   bool
		}{
			{"POST", "/repos/o/r/pulls", true},
			{"PATCH", "/repos/o/r/pulls/2", true},
			{"POST", "/repos/o/r/pulls/2/reviews", true},
			{"POST", "/repos/o/r/pulls/2/requested_reviewers", true},
			{"POST", "/repos/o/r/pulls/2/merge", false},
			{"PUT", "/repos/o/r/pulls/2/merge", false},
			{"POST", "/repos/o/r/releases", false},
		} {
			if got := presetAllows(t, prov, "pull-requests", c.m, c.p); got != c.ok {
				t.Errorf("%s pull-requests %s %s = %v, want %v", prov, c.m, c.p, got, c.ok)
			}
		}
	}
}

func TestPresetMaintainMergeMethodPerProvider(t *testing.T) {
	const p = "/repos/o/r/pulls/2/merge"
	for _, prov := range []string{"forgejo", "gitea"} {
		if !presetAllows(t, prov, "maintain", "POST", p) || presetAllows(t, prov, "maintain", "PUT", p) {
			t.Errorf("%s merge method wrong", prov)
		}
	}
	if !presetAllows(t, "github", "maintain", "PUT", p) || presetAllows(t, "github", "maintain", "POST", p) {
		t.Error("github merge method wrong")
	}
	for _, prov := range []string{"forgejo", "gitea", "github"} {
		for _, c := range [][2]string{{"POST", "/repos/o/r/releases"}, {"PATCH", "/repos/o/r/releases/4"}, {"POST", "/repos/o/r/labels"}} {
			if !presetAllows(t, prov, "maintain", c[0], c[1]) {
				t.Errorf("%s maintain denies %v", prov, c)
			}
		}
		if presetAllows(t, prov, "maintain", "DELETE", "/repos/o/r/releases/4") {
			t.Errorf("%s maintain allows release delete", prov)
		}
	}
}

func TestBitbucketHasNoPresets(t *testing.T) {
	_, err := Preset("bitbucket", "read")
	if err == nil || err.Error() != "no presets for bitbucket yet; use preset: none and write rules" {
		t.Fatalf("err = %v", err)
	}
}

func TestPresetUnknownFailsClosed(t *testing.T) {
	if _, err := Preset("gitlab", "read"); err == nil {
		t.Error("unknown provider accepted")
	}
	if _, err := Preset("github", "admin"); err == nil {
		t.Error("unknown preset accepted")
	}
	if _, err := Preset("", ""); err == nil {
		t.Error("empty accepted")
	}
}

func TestBitbucketNoneIsEmptyOthersError(t *testing.T) {
	rs, err := Preset("bitbucket", "none")
	if err != nil || len(rs) != 0 {
		t.Fatalf("none: %v %v", rs, err)
	}
	for _, n := range []string{"read", "issues", "pull-requests", "maintain", "bogus"} {
		_, err := Preset("bitbucket", n)
		if err == nil || err.Error() != "no presets for bitbucket yet; use preset: none and write rules" {
			t.Errorf("%s: err = %v", n, err)
		}
	}
	if _, err := Preset("gitlab", "none"); err == nil {
		t.Error("unknown provider accepted for none")
	}
}
