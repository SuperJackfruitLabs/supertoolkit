package archtest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/SuperJackfruitLabs/supertoolkit"

// layers is the internal packages' order, lowest first. A package may import packages in a lower
// layer, never one in its own layer or a higher one, so two packages in one layer are independent
// of each other. A new package fails TestInternalImportsPointDown until it is given a layer.
//
// The order is the one the code has, not an aspiration: each package sits one layer above the
// highest package it imports.
var layers = [][]string{
	// Leaves: they import nothing else in the module.
	{"approval", "catalog", "daemon", "deviceflow", "egress", "install", "isolation", "ledger",
		"managedmcp", "mcphost", "netjail", "notify", "oauth2flow", "rules"},
	// Over the catalogue: the credential operations, policy, and provider verification.
	{"credential", "policy", "verify"},
	// The egress proxy, the sealed hand-over, the MCP meta-tools and fronted-server gate, the web
	// UI's API, and where stk keeps its local state (state directory, policy file, socket, proxy
	// key) and dials its daemon.
	{"broker", "handover", "localstate", "mcp", "mcpserve", "webui"},
	// Where a stored credential becomes what goes on the wire; shared test fixtures.
	{"clitest", "secrets"},
	// The policy in force in a running process and its reload; connecting a credential; verifying
	// and withdrawing one.
	{"credcmd", "livepolicy", "setup"},
	// The durable audit of every effect, and `stk audit`.
	{"audit"},
	// A direct native request through the broker's credential path; a running broker and `stk run`.
	{"native", "session"},
	// What the daemon serves; `stk doctor` and its probe; the managed Toolkit commands; `stk env`.
	{"controlplane", "doctor", "managedtoolkit", "proxyenv"},
	// The commands that run a daemon or speak to one: `stk mcp`, `stk serve`, `stk ui`.
	{"mcpcmd", "serve", "uicmd"},
}

// knownBackEdges are imports that point up or across the layers and are allowed for now. It may
// only shrink, and it is empty.
var knownBackEdges = map[string]bool{}

// moduleImports parses the imports of every shipped .go file under root, keyed by the importing
// package's directory (slash-separated, relative to root), listing the module-relative paths it
// imports from this module. Every build tag counts, so a platform-only file is held too.
func moduleImports(t *testing.T, root string) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	fset := token.NewFileSet()
	err := fs.WalkDir(os.DirFS(root), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, filepath.Join(root, path), nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		pkg := filepath.ToSlash(filepath.Dir(path))
		if out[pkg] == nil {
			out[pkg] = map[string]bool{}
		}
		for _, spec := range f.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			if rel, ok := strings.CutPrefix(p, modulePath+"/"); ok {
				out[pkg][rel] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// layerOf maps "internal/<name>" to its layer index.
func layerOf() map[string]int {
	m := map[string]int{}
	for i, names := range layers {
		for _, n := range names {
			m["internal/"+n] = i
		}
	}
	return m
}

// violations lists every import that breaks the rules: anything importing cmd/, an internal
// package importing one in its own or a higher layer, and an internal package with no layer.
func violations(imports map[string]map[string]bool, layer map[string]int, allowed map[string]bool) []string {
	var out []string
	for pkg, deps := range imports {
		_, pkgLayered := layer[pkg]
		if strings.HasPrefix(pkg, "internal/") && pkg != "internal/archtest" && !pkgLayered {
			out = append(out, pkg+" has no layer; add it to layers")
		}
		for dep := range deps {
			edge := pkg + " -> " + dep
			if strings.HasPrefix(dep, "cmd/") {
				out = append(out, edge+": nothing may import a command")
				continue
			}
			if allowed[edge] || !pkgLayered {
				continue
			}
			if dl, ok := layer[dep]; ok && dl >= layer[pkg] {
				out = append(out, edge+": imports its own layer or a higher one")
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestInternalImportsPointDown(t *testing.T) {
	imports := moduleImports(t, moduleRoot())
	for _, v := range violations(imports, layerOf(), knownBackEdges) {
		t.Error(v)
	}
	// A layer entry with no package behind it is a stale record.
	for name := range layerOf() {
		if _, ok := imports[name]; !ok {
			t.Errorf("%s is in layers but has no shipped code; remove it", name)
		}
	}
	for edge := range knownBackEdges {
		pkg, dep, _ := strings.Cut(edge, " -> ")
		if !imports[pkg][dep] {
			t.Errorf("knownBackEdges lists %s, which no longer exists; remove it", edge)
		}
	}
}

func TestViolationsSeeEveryKindOfBreak(t *testing.T) {
	layer := map[string]int{"internal/low": 0, "internal/mid": 1, "internal/peer": 1, "internal/high": 2}
	got := violations(map[string]map[string]bool{
		"cmd/stk":        {"internal/high": true},
		"internal/high":  {"internal/mid": true, "internal/low": true},
		"internal/mid":   {"internal/high": true, "internal/peer": true},
		"internal/low":   {"cmd/stk": true},
		"internal/stray": {},
		"internal/peer":  {"internal/high": true},
	}, layer, map[string]bool{"internal/peer -> internal/high": true})
	want := []string{
		"internal/low -> cmd/stk: nothing may import a command",
		"internal/mid -> internal/high: imports its own layer or a higher one",
		"internal/mid -> internal/peer: imports its own layer or a higher one",
		"internal/stray has no layer; add it to layers",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("violations =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
