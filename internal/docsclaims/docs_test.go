// Package docsclaims holds the docs site to the code, in both directions.
//
// TestDocsNameTheSurface is a completeness ratchet: every command, flag, environment variable,
// configuration key, `stk ui` route, control-socket method, MCP tool, service and credential
// operation the code has must be named somewhere under docs-site/src/content/docs, unless it is
// listed in docs-site/undocumented-baseline.json. The baseline may only shrink: an item that is
// documented, or no longer in the code, must be taken out of it.
//
// TestDocsCountsAgree checks the counts the pages state (operations, services, MCP tools)
// against the catalogue.
//
// Test-only, so it is no layer of the module (internal/archtest counts shipped code only).
package docsclaims

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
)

const (
	docsDir      = "docs-site/src/content/docs"
	baselinePath = "docs-site/undocumented-baseline.json"
)

// corpus is every page of the docs site, joined.
func corpus(t *testing.T, repo fs.FS) string {
	t.Helper()
	var b strings.Builder
	n := 0
	err := fs.WalkDir(repo, docsDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (path.Ext(p) != ".md" && path.Ext(p) != ".mdx") {
			return nil
		}
		raw, err := fs.ReadFile(repo, p)
		if err != nil {
			return err
		}
		n++
		b.Write(raw)
		b.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("read only %d pages under %s", n, docsDir)
	}
	return b.String()
}

// edge is what may sit either side of a name: anything that cannot continue it.
const edge = `[^A-Za-z0-9_-]`

// named reports whether the docs name item, by the convention of its category.
func named(category, item, docs string) bool {
	q := regexp.QuoteMeta(item)
	var re string
	switch category {
	case "commands":
		// `stk init`, or a subcommand as `stk handover seal` / `handover seal`.
		words := strings.Fields(item)
		if len(words) > 2 {
			q = regexp.QuoteMeta(strings.Join(words[1:], " "))
		}
		re = `(?:^|` + edge + `)` + q + `(?:` + edge + `|$)`
	case "flags", "routes":
		re = `(?:^|` + edge + `)` + q + `(?:[^A-Za-z0-9_/-]|$)`
	case "env":
		re = `\b` + q + `\b`
	case "config":
		// As YAML (`key:`) or in code type (`key`).
		re = "(?:^|[^A-Za-z0-9_])" + q + ":|`" + q + "`"
	case "control_ops", "mcp_tools", "services":
		re = "`" + q + "`"
	case "operations":
		re = q
	default:
		panic("docsclaims: no convention for " + category)
	}
	return regexp.MustCompile(`(?m)` + re).MatchString(docs)
}

func readBaseline(t *testing.T, repo fs.FS) map[string][]string {
	t.Helper()
	raw, err := fs.ReadFile(repo, baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	var b map[string][]string
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("%s: %v", baselinePath, err)
	}
	return b
}

// gaps is the comparison itself, separate from the test so the test of the test can drive it.
func gaps(s surface, baseline map[string][]string, docs string) []string {
	var problems []string
	cats := make([]string, 0, len(s))
	for c := range s {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for c := range baseline {
		if _, ok := s[c]; !ok {
			problems = append(problems, fmt.Sprintf("%s: the baseline has a category %q the check does not read", baselinePath, c))
		}
	}
	for _, c := range cats {
		inCode := map[string]bool{}
		for _, item := range s[c] {
			inCode[item] = true
		}
		base := map[string]bool{}
		for _, item := range baseline[c] {
			base[item] = true
			if !inCode[item] {
				problems = append(problems, fmt.Sprintf("%s: %s %q is no longer in the code; take it out of the baseline", baselinePath, c, item))
			}
		}
		for _, item := range s[c] {
			doc := named(c, item, docs)
			switch {
			case !doc && !base[item]:
				problems = append(problems, fmt.Sprintf("%s %q is not named in %s: document it", c, item, docsDir))
			case doc && base[item]:
				problems = append(problems, fmt.Sprintf("%s: %s %q is documented now; take it out of the baseline (it may only shrink)", baselinePath, c, item))
			}
		}
	}
	return problems
}

func TestDocsNameTheSurface(t *testing.T) {
	repo := repoFS()
	for _, p := range gaps(readSurface(t, repo), readBaseline(t, repo), corpus(t, repo)) {
		t.Error(p)
	}
}

// The surface readers must keep finding what they look for: a refactor that hides a whole
// category from the parser would otherwise pass as "nothing undocumented".
func TestSurfaceIsRead(t *testing.T) {
	s := readSurface(t, repoFS())
	least := map[string]int{
		"commands": 25, "flags": 30, "env": 20, "config": 40, "routes": 8,
		"control_ops": 9, "mcp_tools": 4, "services": 13, "operations": 6,
	}
	for c, n := range least {
		t.Logf("%s: %d read", c, len(s[c]))
		if len(s[c]) < n {
			t.Errorf("read only %d %s from the code (want at least %d): %v", len(s[c]), c, n, s[c])
		}
	}
	for _, want := range []string{"stk publish perform", "stk mcp serve", "stk handover seal", "stk approvals allow"} {
		if !contains(s["commands"], want) {
			t.Errorf("commands: %q not read; got %v", want, s["commands"])
		}
	}
	for c, want := range map[string]string{
		"flags": "--local-commands-socket", "env": "STK_PASSPHRASE_FILE", "config": "approvals_board",
		"routes": "POST /api/approvals/decide", "control_ops": "approvals.decide",
	} {
		if !contains(s[c], want) {
			t.Errorf("%s: %q not read; got %v", c, want, s[c])
		}
	}
	for c, bad := range map[string]string{"flags": "--sock", "env": "PATH"} {
		if contains(s[c], bad) {
			t.Errorf("%s: %q is internal and must not be counted", c, bad)
		}
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// The check must fail both ways: a documented item whose mention is deleted, and a new item in
// the code that nothing names. And the baseline must be held to shrinking.
func TestGapsFailsBothWays(t *testing.T) {
	s := surface{"flags": {"--json", "--new-flag"}, "routes": {"GET /api/status"}}
	docs := "run `stk audit --json`, or `GET /api/status`"
	got := gaps(s, map[string][]string{}, docs)
	if len(got) != 1 || !strings.Contains(got[0], `"--new-flag" is not named`) {
		t.Fatalf("a new undocumented flag: got %v", got)
	}
	got = gaps(s, map[string][]string{"flags": {"--new-flag"}}, strings.ReplaceAll(docs, "--json", ""))
	if len(got) != 1 || !strings.Contains(got[0], `"--json" is not named`) {
		t.Fatalf("a deleted mention: got %v", got)
	}
	got = gaps(s, map[string][]string{"flags": {"--json", "--new-flag"}}, docs)
	if len(got) != 1 || !strings.Contains(got[0], `"--json" is documented now`) {
		t.Fatalf("a documented item left in the baseline: got %v", got)
	}
	got = gaps(s, map[string][]string{"flags": {"--new-flag", "--gone"}}, docs)
	if len(got) != 1 || !strings.Contains(got[0], `"--gone" is no longer in the code`) {
		t.Fatalf("a stale baseline item: got %v", got)
	}
	if !named("flags", "--local", "`--local`") || named("flags", "--local", "`--local-commands-socket`") {
		t.Fatal("a flag must match whole, not as the prefix of a longer one")
	}
	if !named("config", "env", "  env:\n") || named("config", "env", "  env_var:\n") {
		t.Fatal("a config key must match as `key:` and not inside a longer key")
	}
}

var (
	numberWords = map[string]int{
		"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
		"nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
		"fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
	}
	num        = `(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|\d+)`
	opsClaim   = regexp.MustCompile(`(?i)\b` + num + ` (?:credential )?operations\b`)
	opsOfClaim = regexp.MustCompile(`(?i)\b` + num + ` of the ` + num + `(?: credential)? operations\b`)
	// "the thirteen services", "the catalogue has 13 services": a count of the catalogue, not
	// of the services some feature needs.
	servicesClaim = regexp.MustCompile(`(?i)\b(?:the|catalogue has) ` + num + ` (?:built-in )?services\b`)
	toolsClaim    = regexp.MustCompile(`(?i)exactly (?:\*\*)?` + num + `(?:\*\*)? tools\b`)
)

func toNumber(s string) int {
	if n, ok := numberWords[strings.ToLower(s)]; ok {
		return n
	}
	n := 0
	_, _ = fmt.Sscanf(s, "%d", &n)
	return n
}

// operationCounts is how many credential operations the catalogue has, as the pages count them,
// and how many of those never put a long-lived secret on the wire. An operation is an Auth that
// holds a credential (AuthNone holds none), and substituting a token inside a Basic header is
// counted on its own, because it is a different operation on the wire from a plain substitute.
func operationCounts(t *testing.T) (total, never int) {
	t.Helper()
	auths, err := authValues(repoFS())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range auths {
		if a.Fields() == nil {
			continue
		}
		total++
		if !a.LongLivedOnTheWire() {
			never++
		}
	}
	for _, n := range catalog.Names() {
		if e, ok := catalog.Lookup(n); ok && e.Auth == catalog.AuthToken && e.Placement == catalog.BasicHeader {
			total++
			break
		}
	}
	return total, never
}

func TestDocsCountsAgree(t *testing.T) {
	docs := corpus(t, repoFS())
	total, never := operationCounts(t)
	for _, m := range opsClaim.FindAllStringSubmatch(docs, -1) {
		if toNumber(m[1]) != total {
			t.Errorf("the docs say %q; the catalogue has %d operations", m[0], total)
		}
	}
	for _, m := range opsOfClaim.FindAllStringSubmatch(docs, -1) {
		if toNumber(m[1]) != never || toNumber(m[2]) != total {
			t.Errorf("the docs say %q; %d of the %d operations never put a long-lived secret on the wire", m[0], never, total)
		}
	}
	services := len(catalog.Names())
	for _, m := range servicesClaim.FindAllStringSubmatch(docs, -1) {
		if toNumber(m[1]) != services {
			t.Errorf("the docs say %q; the catalogue has %d services", m[0], services)
		}
	}
	for _, m := range toolsClaim.FindAllStringSubmatch(docs, -1) {
		if toNumber(m[1]) != len(mcp.ToolNames) {
			t.Errorf("the docs say %q; stk mcp has %d tools", m[0], len(mcp.ToolNames))
		}
	}
	if len(opsClaim.FindAllString(docs, -1)) == 0 || len(servicesClaim.FindAllString(docs, -1)) == 0 {
		t.Error("the docs no longer state how many operations or services there are; this check reads nothing")
	}
}
