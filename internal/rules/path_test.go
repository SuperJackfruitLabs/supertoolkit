package rules

import (
	"strings"
	"testing"
)

func TestNormalizePathRefuses(t *testing.T) {
	cases := []struct{ name, in, reason string }{
		{"dot-dot traversal", "/api/v1/repos/o/r/../../admin/users", "dot-segment"},
		{"single dot", "/repos/o/./r", "dot-segment"},
		{"trailing slash-dot", "/repos/o/r/.", "dot-segment"},
		{"trailing dot-dot", "/repos/o/r/..", "dot-segment"},
		{"encoded dot-dot lower", "/repos/%2e%2e/admin", "encoded-separator"},
		{"encoded dot-dot upper", "/repos/%2E%2E/admin", "encoded-separator"},
		{"half encoded dot-dot", "/repos/.%2e/admin", "encoded-separator"},
		{"encoded single dot", "/repos/%2e/r", "encoded-separator"},
		{"encoded slash lower", "/repos/o%2fr/issues", "encoded-separator"},
		{"encoded slash upper", "/repos/o%2Fr/issues", "encoded-separator"},
		{"encoded backslash lower", "/repos/o%5cr", "encoded-separator"},
		{"encoded backslash upper", "/repos/o%5Cr", "encoded-separator"},
		{"double slash interior", "/repos//o/r", "empty-segment"},
		{"double slash leading", "//repos/o/r", "empty-segment"},
		{"triple slash", "/repos///r", "empty-segment"},
		{"path parameter", "/repos/o/r;param=1/issues", "path-parameter"},
		{"encoded semicolon", "/repos/o/r%3Bx/issues", "path-parameter"},
		{"raw backslash", `/repos/o\r/issues`, "backslash"},
		{"backslash dot-dot", `/repos/..\admin`, "backslash"},
		{"NUL raw", "/repos/o\x00/r", "control-byte"},
		{"NUL encoded", "/repos/o%00/r", "control-byte"},
		{"newline encoded", "/repos/o%0Ar", "control-byte"},
		{"CR raw", "/repos/o\rr", "control-byte"},
		{"tab encoded", "/repos/o%09r", "control-byte"},
		{"DEL encoded", "/repos/o%7Fr", "control-byte"},
		{"DEL raw", "/repos/o\x7fr", "control-byte"},
		{"empty path", "", "empty-segment"},
		{"no leading slash", "repos/o/r", "empty-segment"},
		{"bad percent", "/repos/o%zz/r", "bad-encoding"},
		{"truncated percent", "/repos/o%2", "bad-encoding"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizePath(c.in)
			if err == nil {
				t.Fatalf("NormalizePath(%q) = %q, want error", c.in, got)
			}
			if got != "" {
				t.Errorf("NormalizePath(%q) returned %q alongside an error", c.in, got)
			}
			if !strings.Contains(err.Error(), c.reason) {
				t.Errorf("NormalizePath(%q) error = %q, want it to name %q", c.in, err, c.reason)
			}
		})
	}
}

func TestNormalizePathAccepts(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/repos/o/r/issues", "/repos/o/r/issues"},
		{"/repos/o/r/issues/7", "/repos/o/r/issues/7"},
		{"/repos/o/my%20repo/issues", "/repos/o/my repo/issues"},
		{"/", "/"},
		{"/repos/o/r/", "/repos/o/r/"},
		{"/repos/o/a.b/..c/d..", "/repos/o/a.b/..c/d.."},
		{"/repos/o/a%2Eb", "/repos/o/a.b"},
	}
	for _, c := range cases {
		got, err := NormalizePath(c.in)
		if err != nil {
			t.Errorf("NormalizePath(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMatchPath(t *testing.T) {
	cases := []struct {
		name, pattern, path string
		want                bool
		vars                map[string]string
	}{
		{"literal", "/repos/o/r", "/repos/o/r", true, nil},
		{"literal case-sensitive", "/repos/o/r", "/repos/O/r", false, nil},
		{"literal mismatch", "/repos/o/r", "/repos/o/x", false, nil},
		{"star one segment", "/repos/*/issues", "/repos/o/issues", true, nil},
		{"star not two segments", "/repos/*/issues", "/repos/o/r/issues", false, nil},
		{"star not zero segments", "/repos/*/issues", "/repos/issues", false, nil},
		{"doublestar rest", "/repos/o/**", "/repos/o/r/issues/7", true, nil},
		{"doublestar one", "/repos/o/**", "/repos/o/r", true, nil},
		{"doublestar prefix mismatch", "/repos/o/**", "/repos/x/r", false, nil},
		{"capture", "/repos/{owner}/{repo}/issues", "/repos/acme/web/issues", true,
			map[string]string{"owner": "acme", "repo": "web"}},
		{"capture one segment only", "/repos/{owner}", "/repos/a/b", false, nil},
		{"trailing slash no match", "/repos/o/r", "/repos/o/r/", false, nil},
		{"trailing slash pattern no match", "/repos/o/r/", "/repos/o/r", false, nil},
		{"longer path", "/repos/o", "/repos/o/r", false, nil},
		{"shorter path", "/repos/o/r", "/repos/o", false, nil},
		{"root", "/", "/", true, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vars := map[string]string{}
			if got := MatchPath(c.pattern, c.path, vars); got != c.want {
				t.Fatalf("MatchPath(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
			}
			for k, v := range c.vars {
				if vars[k] != v {
					t.Errorf("vars[%q] = %q, want %q", k, vars[k], v)
				}
			}
		})
	}
	// nil vars map must not panic.
	if !MatchPath("/repos/{owner}", "/repos/a", nil) {
		t.Error("nil vars: want match")
	}
}
