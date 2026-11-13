package docsclaims

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/webui"
)

// The public surface, read from the code with go/parser (and from the registries where the code
// keeps one: the catalogue, the MCP tool list, the web UI's route table). Each function returns
// the names a reader can type or will see; the docs test checks each one is named in docs-site.

const modulePath = "github.com/SuperJackfruitLabs/supertoolkit"

// internalArgs are flags stk passes to itself when it re-executes, never typed by a person:
// `stk __netjail --sock --port` inside a confined child's namespace, and `stk doctor
// --as-uid-probe` when doctor re-runs itself as an agent uid.
var internalArgs = map[string]bool{"--sock": true, "--port": true, "--as-uid-probe": true}

// passThroughEnv are variables stk reads only to hand them on unchanged to a probe child.
var passThroughEnv = map[string]bool{"PATH": true, "HOME": true}

// surface is every category, by the name the baseline file uses.
type surface map[string][]string

func readSurface(t *testing.T, repo fs.FS) surface {
	t.Helper()
	must := func(v []string, err error) []string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	return surface{
		"commands":    must(commands(repo)),
		"flags":       must(flags(repo)),
		"env":         sorted(append(must(envVars(repo)), catalogEnv()...)),
		"config":      must(configKeys(repo)),
		"routes":      must(routes(repo)),
		"control_ops": must(controlOps(repo)),
		"mcp_tools":   sorted(mcp.ToolNames),
		"services":    sorted(catalog.Names()),
		"operations":  must(operationNames(repo)),
	}
}

func sorted(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// parsedFile is one shipped .go file.
type parsedFile struct {
	path string
	file *ast.File
}

// parseDir parses the shipped (non-test) .go files of one directory.
func parseDir(repo fs.FS, dir string) ([]parsedFile, error) {
	entries, err := fs.ReadDir(repo, dir)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var out []parsedFile
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		p := path.Join(dir, name)
		src, err := fs.ReadFile(repo, p)
		if err != nil {
			return nil, err
		}
		f, err := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		out = append(out, parsedFile{path: p, file: f})
	}
	return out, nil
}

// parseTree parses every shipped .go file under the given roots, testdata left out.
func parseTree(repo fs.FS, roots ...string) ([]parsedFile, error) {
	var out []parsedFile
	for _, root := range roots {
		err := fs.WalkDir(repo, root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				return nil
			}
			if d.Name() == "testdata" || d.Name() == "node_modules" {
				return fs.SkipDir
			}
			files, err := parseDir(repo, p)
			out = append(out, files...)
			return err
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// isOSArgs1 reports whether e is `os.Args[1]`.
func isOSArgs1(e ast.Expr) bool {
	ix, ok := e.(*ast.IndexExpr)
	if !ok {
		return false
	}
	sel, ok := ix.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Args" {
		return false
	}
	if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "os" {
		return false
	}
	n, ok := ix.Index.(*ast.BasicLit)
	return ok && n.Value == "1"
}

// dispatch is one command in cmd/stk/main.go's switch and the function it calls.
type dispatch struct {
	names []string
	dir   string // the package directory of the called function
	fn    string
}

// mainDispatch reads `switch os.Args[1]` in cmd/stk/main.go.
func mainDispatch(repo fs.FS) ([]dispatch, error) {
	files, err := parseDir(repo, "cmd/stk")
	if err != nil {
		return nil, err
	}
	var out []dispatch
	for _, pf := range files {
		imports := map[string]string{}
		for _, spec := range pf.file.Imports {
			p, _ := strconv.Unquote(spec.Path.Value)
			if rel, ok := strings.CutPrefix(p, modulePath+"/"); ok {
				imports[path.Base(rel)] = rel
			}
		}
		ast.Inspect(pf.file, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok || !isOSArgs1(sw.Tag) {
				return true
			}
			for _, st := range sw.Body.List {
				cc := st.(*ast.CaseClause)
				d := dispatch{dir: "cmd/stk"}
				for _, e := range cc.List {
					if s, ok := stringLit(e); ok && !strings.HasPrefix(s, "-") {
						d.names = append(d.names, s)
					}
				}
				if len(d.names) == 0 {
					continue
				}
				// The function the case calls: `err = pkg.Func(...)` or `err = local(...)`.
				ast.Inspect(cc, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok || d.fn != "" {
						return d.fn == ""
					}
					switch f := call.Fun.(type) {
					case *ast.SelectorExpr:
						if id, ok := f.X.(*ast.Ident); ok {
							if rel, ok := imports[id.Name]; ok {
								d.dir, d.fn = rel, f.Sel.Name
							}
						}
					case *ast.Ident:
						d.fn = f.Name
					}
					return d.fn == ""
				})
				out = append(out, d)
			}
			return false
		})
	}
	if len(out) == 0 {
		return nil, errorf("found no `switch os.Args[1]` in cmd/stk")
	}
	return out, nil
}

// commands is every `stk <name>` and every `stk <name> <sub>`. A subcommand is a string the
// dispatched function (or a function in its package it hands its whole argument list to)
// compares an element of its arguments with: a `case` of `switch args[i]`, or `args[0] == "x"`.
func commands(repo fs.FS) ([]string, error) {
	ds, err := mainDispatch(repo)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range ds {
		for _, n := range d.names {
			out = append(out, "stk "+n)
		}
		if d.fn == "" {
			continue
		}
		files, err := parseDir(repo, d.dir)
		if err != nil {
			return nil, err
		}
		funcs := map[string]*ast.FuncDecl{}
		for _, pf := range files {
			for _, decl := range pf.file.Decls {
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil {
					funcs[fd.Name.Name] = fd
				}
			}
		}
		subs := map[string]bool{}
		subcommands(funcs, d.fn, map[string]bool{}, subs)
		for s := range subs {
			out = append(out, "stk "+d.names[0]+" "+s)
		}
	}
	return sorted(out), nil
}

func subcommands(funcs map[string]*ast.FuncDecl, name string, seen, out map[string]bool) {
	fd := funcs[name]
	if fd == nil || seen[name] || fd.Body == nil {
		return
	}
	seen[name] = true
	argsName := ""
	for _, field := range fd.Type.Params.List {
		if at, ok := field.Type.(*ast.ArrayType); ok {
			if id, ok := at.Elt.(*ast.Ident); ok && id.Name == "string" && len(field.Names) > 0 {
				argsName = field.Names[0].Name
			}
		}
	}
	if argsName == "" {
		return
	}
	isArg := func(e ast.Expr) bool {
		ix, ok := e.(*ast.IndexExpr)
		if !ok {
			return false
		}
		id, ok := ix.X.(*ast.Ident)
		return ok && id.Name == argsName
	}
	add := func(e ast.Expr) {
		if s, ok := stringLit(e); ok && s != "" && !strings.HasPrefix(s, "-") {
			out[s] = true
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SwitchStmt:
			if n.Tag != nil && isArg(n.Tag) {
				for _, st := range n.Body.List {
					for _, e := range st.(*ast.CaseClause).List {
						add(e)
					}
				}
			}
		case *ast.BinaryExpr:
			if n.Op == token.EQL || n.Op == token.NEQ {
				if isArg(n.X) {
					add(n.Y)
				} else if isArg(n.Y) {
					add(n.X)
				}
			}
		case *ast.CallExpr:
			// Follow a same-package function given the whole argument list.
			if id, ok := n.Fun.(*ast.Ident); ok {
				for _, a := range n.Args {
					if aid, ok := a.(*ast.Ident); ok && aid.Name == argsName {
						subcommands(funcs, id.Name, seen, out)
					}
				}
			}
		}
		return true
	})
}

var flagName = regexp.MustCompile(`^--[a-z][a-z0-9-]*=?$`)

// flags is every `--flag` a command parses: a "--x" literal that is a `case` value, an operand
// of == or !=, or the prefix given to strings.HasPrefix/CutPrefix/TrimPrefix or hasFlag. A
// "--x" inside an error message or an argument list stk builds for another program is none of
// those, so it is not counted.
func flags(repo fs.FS) ([]string, error) {
	files, err := parseTree(repo, "cmd", "internal")
	if err != nil {
		return nil, err
	}
	var out []string
	add := func(e ast.Expr) {
		s, ok := stringLit(e)
		if !ok || !flagName.MatchString(s) {
			return
		}
		s = strings.TrimSuffix(s, "=")
		if !internalArgs[s] {
			out = append(out, s)
		}
	}
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CaseClause:
				for _, e := range n.List {
					add(e)
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					add(n.X)
					add(n.Y)
				}
			case *ast.CallExpr:
				name := ""
				switch f := n.Fun.(type) {
				case *ast.SelectorExpr:
					name = f.Sel.Name
				case *ast.Ident:
					name = f.Name
				}
				switch name {
				case "HasPrefix", "CutPrefix", "TrimPrefix", "hasFlag":
					for _, a := range n.Args {
						add(a)
					}
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		return nil, errorf("found no flags")
	}
	return sorted(out), nil
}

var envName = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)=`)

// envVars is every variable stk reads (os.Getenv, os.LookupEnv) and every one it sets on a
// child (the "NAME=" literals in internal/broker/childenv.go). Lower-case duplicates
// (https_proxy) are the same variable and are left out.
func envVars(repo fs.FS) ([]string, error) {
	files, err := parseTree(repo, "cmd", "internal")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, pf := range files {
		child := pf.path == "internal/broker/childenv.go"
		ast.Inspect(pf.file, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				sel, ok := n.Fun.(*ast.SelectorExpr)
				if !ok || len(n.Args) != 1 {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); !ok || id.Name != "os" {
					return true
				}
				if sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv" {
					if s, ok := stringLit(n.Args[0]); ok && s == strings.ToUpper(s) && !passThroughEnv[s] {
						out = append(out, s)
					}
				}
			case *ast.BasicLit:
				if child {
					if s, ok := stringLit(n); ok {
						if m := envName.FindStringSubmatch(s); m != nil {
							out = append(out, m[1])
						}
					}
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		return nil, errorf("found no environment variables")
	}
	return sorted(out), nil
}

// catalogEnv is where each built-in service's client looks for its credential, and so where
// `stk run` puts the placeholder.
func catalogEnv() []string {
	var out []string
	for _, n := range catalog.Names() {
		if e, ok := catalog.Lookup(n); ok && e.EnvVar != "" {
			out = append(out, e.EnvVar)
		}
	}
	return sorted(out)
}

// configKeys is every key of supertoolkit.yaml: the `yaml:"…"` tag of every struct field in
// internal/policy, the only package that reads the file.
func configKeys(repo fs.FS) ([]string, error) {
	files, err := parseDir(repo, "internal/policy")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			f, ok := n.(*ast.Field)
			if !ok || f.Tag == nil {
				return true
			}
			tag, err := strconv.Unquote(f.Tag.Value)
			if err != nil {
				return true
			}
			if v, ok := reflectTag(tag, "yaml"); ok {
				if name, _, _ := strings.Cut(v, ","); name != "" && name != "-" {
					out = append(out, name)
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		return nil, errorf("found no yaml keys in internal/policy")
	}
	return sorted(out), nil
}

// reflectTag is reflect.StructTag.Lookup without a reflect.StructTag.
func reflectTag(tag, key string) (string, bool) {
	for _, part := range strings.Fields(tag) {
		k, v, ok := strings.Cut(part, ":")
		if ok && k == key {
			s, err := strconv.Unquote(v)
			return s, err == nil
		}
	}
	return "", false
}

var routePattern = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE) /`)

// routes is the `stk ui` API: every "METHOD /path" pattern registered in internal/webui, and the
// route table it declares (webui.Routes), so a route added to either is counted.
func routes(repo fs.FS) ([]string, error) {
	files, err := parseDir(repo, "internal/webui")
	if err != nil {
		return nil, err
	}
	out := append([]string{}, webui.Routes...)
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "HandleFunc" || sel.Sel.Name == "Handle") {
				if s, ok := stringLit(call.Args[0]); ok && routePattern.MatchString(s) {
					out = append(out, s)
				}
			}
			return true
		})
	}
	return sorted(out), nil
}

// controlOps is every method the daemon's control socket answers: the cases of each
// `switch <x>.Method` in internal/controlplane and the case strings of the daemon's own gate.
func controlOps(repo fs.FS) ([]string, error) {
	files, err := parseDir(repo, "internal/controlplane")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, pf := range files {
		ast.Inspect(pf.file, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok || sw.Tag == nil {
				return true
			}
			if sel, ok := sw.Tag.(*ast.SelectorExpr); ok && sel.Sel.Name == "Method" {
				for _, st := range sw.Body.List {
					for _, e := range st.(*ast.CaseClause).List {
						if s, ok := stringLit(e); ok {
							out = append(out, s)
						}
					}
				}
			}
			return true
		})
	}
	if len(out) == 0 {
		return nil, errorf("found no control-socket methods in internal/controlplane")
	}
	return sorted(out), nil
}

// authValues is catalog.Auth's constants, in declaration (iota) order, read from catalog.go.
func authValues(repo fs.FS) ([]catalog.Auth, error) {
	files, err := parseDir(repo, "internal/catalog")
	if err != nil {
		return nil, err
	}
	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST || len(gd.Specs) == 0 {
				continue
			}
			first := gd.Specs[0].(*ast.ValueSpec)
			if id, ok := first.Type.(*ast.Ident); !ok || id.Name != "Auth" {
				continue
			}
			out := make([]catalog.Auth, 0, len(gd.Specs))
			for i := range gd.Specs {
				out = append(out, catalog.Auth(i))
			}
			return out, nil
		}
	}
	return nil, errorf("found no `const ( … Auth = iota … )` in internal/catalog")
}

// operationNames is how `stk doctor` names each credential operation (catalog.Auth.String).
func operationNames(repo fs.FS) ([]string, error) {
	auths, err := authValues(repo)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range auths {
		out = append(out, a.String())
	}
	return sorted(out), nil
}

type surfaceError string

func (e surfaceError) Error() string { return string(e) }

func errorf(s string) error { return surfaceError("docsclaims: " + s) }

// repoFS is the repository root, two directories up from this package.
func repoFS() fs.FS { return os.DirFS("../..") }
