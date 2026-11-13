// Command docs-touched fails a pull request that changes the public surface without touching
// the docs.
//
// It reads the changed paths on stdin, one per line (`git diff --name-only BASE HEAD`), and the
// pull request's labels from PR_LABELS, as the JSON the event payload carries
// (`toJSON(github.event.pull_request.labels)`: a list of objects with a `name`). It exits 1 when a
// path in surfacePaths changed, no path in docsPaths did, and the pull request has no
// `no-docs-needed` label. The docs job in .forgejo/workflows/docs-touched.yml runs it.
//
// The surface is what internal/docsclaims reads: commands and flags, configuration keys,
// environment variables, `stk ui` routes, control-socket methods, MCP tools and the catalogue.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Label is the label that says a surface change needs no docs.
const Label = "no-docs-needed"

// surfacePaths are the files and directories whose shipped code is the public surface. A
// directory ends in "/".
var surfacePaths = []string{
	"cmd/stk/",                     // the command dispatch, stk install's flags, stk help
	"install.sh",                   // the installer and its variables
	"internal/catalog/",            // services, their hosts and variables, the operations
	"internal/policy/",             // every supertoolkit.yaml key
	"internal/controlplane/",       // the control socket's methods
	"internal/daemon/",             // who may call which method
	"internal/webui/",              // the stk ui routes
	"internal/mcp/",                // the four MCP tools
	"internal/localstate/paths.go", // STK_HOME, STK_CONFIG, STK_SOCKET
	"internal/credential/key.go",   // STK_PASSPHRASE, STK_PASSPHRASE_FILE, CREDENTIALS_DIRECTORY
	"internal/broker/childenv.go",  // what a child is given
	"internal/audit/",              // stk audit
	"internal/credcmd/",            // stk verify, stk revoke
	"internal/doctor/",             // stk doctor
	"internal/livepolicy/",         // stk reload
	"internal/managedtoolkit/",     // the managed-* entry points
	"internal/mcpcmd/",             // stk mcp, stk mcp serve, stk approvals
	"internal/proxyenv/",           // stk env
	"internal/publishcmd/",         // stk publish
	"internal/serve/",              // stk serve
	"internal/setup/",              // stk init, add, connect, handover
	"internal/uicmd/",              // stk ui
}

// docsPaths are where the docs live.
var docsPaths = []string{"docs-site/src/content/", "docs/", "README.md"}

func matches(path string, prefixes []string) bool {
	for _, p := range prefixes {
		if path == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return true
		}
	}
	return false
}

// isSurface reports whether a changed path is shipped surface code: tests and fixtures are not.
func isSurface(path string) bool {
	if strings.HasSuffix(path, "_test.go") || strings.Contains(path, "/testdata/") {
		return false
	}
	return matches(path, surfacePaths)
}

// Verdict is the decision for one pull request.
type Verdict struct {
	Surface  []string // surface paths that changed
	Docs     bool     // a docs path changed
	Labelled bool     // the pull request carries Label
}

// Fails reports whether the pull request must be refused.
func (v Verdict) Fails() bool { return len(v.Surface) > 0 && !v.Docs && !v.Labelled }

// Decide classifies the changed paths and the labels.
func Decide(paths, labels []string) Verdict {
	var v Verdict
	for _, p := range paths {
		p = strings.TrimSpace(p)
		switch {
		case p == "":
		case matches(p, docsPaths):
			v.Docs = true
		case isSurface(p):
			v.Surface = append(v.Surface, p)
		}
	}
	for _, l := range labels {
		if l == Label {
			v.Labelled = true
		}
	}
	return v
}

// ParseLabels reads the payload's labels: a JSON list of objects with a name. Empty is none.
func ParseLabels(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var ls []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal([]byte(raw), &ls); err != nil {
		return nil, fmt.Errorf("PR_LABELS is not a list of labels: %w", err)
	}
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.Name)
	}
	return out, nil
}

func run(stdin io.Reader, labelsJSON string, out io.Writer) int {
	labels, err := ParseLabels(labelsJSON)
	if err != nil {
		fmt.Fprintln(out, "docs-touched:", err)
		return 2
	}
	var paths []string
	sc := bufio.NewScanner(stdin)
	for sc.Scan() {
		paths = append(paths, sc.Text())
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(out, "docs-touched: reading the changed paths:", err)
		return 2
	}
	v := Decide(paths, labels)
	switch {
	case len(v.Surface) == 0:
		fmt.Fprintln(out, "docs-touched: no public-surface file changed")
	case v.Docs:
		fmt.Fprintf(out, "docs-touched: %d public-surface file(s) changed, and the docs too\n", len(v.Surface))
	case v.Labelled:
		fmt.Fprintf(out, "docs-touched: %d public-surface file(s) changed with no docs; labelled %s\n", len(v.Surface), Label)
	default:
		fmt.Fprintln(out, "docs-touched: these public-surface files changed, and no docs did:")
		for _, p := range v.Surface {
			fmt.Fprintln(out, "  "+p)
		}
		fmt.Fprintf(out, "Update docs-site/src/content/docs (or docs/, README.md), or, if nothing a reader sees changed, label the pull request %s.\n", Label)
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Stdin, os.Getenv("PR_LABELS"), os.Stdout))
}
