package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecide(t *testing.T) {
	cases := []struct {
		name   string
		paths  []string
		labels []string
		fails  bool
	}{
		{"a new flag with no docs", []string{"internal/serve/serve.go"}, nil, true},
		{"a new route with no docs", []string{"internal/webui/api.go", "CHANGELOG.md"}, nil, true},
		{"a config key with no docs", []string{"internal/policy/config.go"}, nil, true},
		{"an env var with no docs", []string{"internal/localstate/paths.go"}, nil, true},
		{"a command with no docs", []string{"cmd/stk/main.go"}, nil, true},
		{"a surface change with a docs page", []string{"internal/serve/serve.go", "docs-site/src/content/docs/run/serve.md"}, nil, false},
		{"a surface change with the README", []string{"internal/catalog/catalog.go", "README.md"}, nil, false},
		{"a surface change with a design doc", []string{"internal/policy/config.go", "docs/forge-broker-design.md"}, nil, false},
		{"a surface change, labelled", []string{"internal/serve/serve.go"}, []string{"bug", Label}, false},
		{"another label is not enough", []string{"internal/serve/serve.go"}, []string{"bug"}, true},
		{"tests only", []string{"internal/serve/serve_test.go", "internal/catalog/testdata/x.json"}, nil, false},
		{"no surface", []string{"internal/egress/egress.go", "landing/src/pages/index.astro"}, nil, false},
		{"docs only", []string{"docs-site/src/content/docs/install.md"}, nil, false},
		{"the baseline is not docs", []string{"internal/policy/config.go", "docs-site/undocumented-baseline.json"}, nil, true},
		{"a file that only starts like a surface file", []string{"internal/credential/key_extra.go"}, nil, false},
		{"nothing", []string{"", "  "}, nil, false},
	}
	for _, c := range cases {
		if got := Decide(c.paths, c.labels).Fails(); got != c.fails {
			t.Errorf("%s: fails = %v, want %v", c.name, got, c.fails)
		}
	}
}

func TestParseLabels(t *testing.T) {
	got, err := ParseLabels(`[{"id":1,"name":"no-docs-needed","color":"ededed"},{"name":"bug"}]`)
	if err != nil || len(got) != 2 || got[0] != Label || got[1] != "bug" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, empty := range []string{"", "null", "[]", " \n"} {
		if got, err := ParseLabels(empty); err != nil || len(got) != 0 {
			t.Errorf("%q: got %v, %v", empty, got, err)
		}
	}
	if _, err := ParseLabels("not json"); err == nil {
		t.Error("an unreadable payload must be an error, not no labels")
	}
}

func TestRun(t *testing.T) {
	var out bytes.Buffer
	if code := run(strings.NewReader("internal/serve/serve.go\n"), "[]", &out); code != 1 || !strings.Contains(out.String(), "internal/serve/serve.go") {
		t.Fatalf("code %d, output %q", code, out.String())
	}
	out.Reset()
	if code := run(strings.NewReader("internal/serve/serve.go\n"), `[{"name":"no-docs-needed"}]`, &out); code != 0 {
		t.Fatalf("labelled: code %d, output %q", code, out.String())
	}
	if code := run(strings.NewReader(""), "{", &out); code != 2 {
		t.Fatalf("a bad payload: code %d", code)
	}
}
