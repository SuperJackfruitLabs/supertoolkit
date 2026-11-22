// Package treatytest checks stk's side of a crossing against treaty's data: the OpenAPI
// documents and case files vendored under testdata/treaty/ (treaty.json lists them, and
// `treaty sync` writes them). Go does not import treaty's TypeScript; it reads the copies.
// Only tests import this package.
package treatytest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// base is where documents are addressed. It is not fetched: Load registers every document it
// reads as a resource and refuses any other load, so a $ref outside the vendored copies fails.
const base = "https://treaty.invalid/"

// Root is testdata/treaty in this module, found from the test's working directory.
func Root(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "treaty")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}

func read(t testing.TB, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(Root(t), filepath.FromSlash(rel))) //nolint:gosec // a vendored copy under testdata
	if err != nil {
		t.Fatalf("%s: %v (is it listed in treaty.json and written by treaty sync?)", rel, err)
	}
	return raw
}

// API is one vendored OpenAPI document.
type API struct {
	path     string
	doc      map[string]any
	compiler *jsonschema.Compiler
}

type refuse struct{}

func (refuse) Load(url string) (any, error) {
	return nil, fmt.Errorf("%s is not vendored", url)
}

// Load reads an OpenAPI document by its treaty path, e.g.
// "schemas/http/superpipeline/approvals.v1.openapi.json".
func Load(t testing.TB, path string) *API {
	t.Helper()
	raw := read(t, path)
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	asMap, ok := doc.(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object", path)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(refuse{})
	if err := c.AddResource(base+path, doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return &API{path: path, doc: asMap, compiler: c}
}

func pointerToken(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// operation finds an operation by id and returns its JSON pointer and value.
func (a *API) operation(t testing.TB, id string) (string, map[string]any) {
	t.Helper()
	paths, _ := a.doc["paths"].(map[string]any)
	for p, item := range paths {
		methods, _ := item.(map[string]any)
		for m, op := range methods {
			o, ok := op.(map[string]any)
			if ok && o["operationId"] == id {
				return "/paths/" + pointerToken(p) + "/" + pointerToken(m), o
			}
		}
	}
	t.Fatalf("%s has no operation %q", a.path, id)
	return "", nil
}

// resolveLocal follows a "#/..." $ref inside the document, returning the pointer it lands on.
func (a *API) resolveLocal(t testing.TB, ptr string, v map[string]any) (string, map[string]any) {
	t.Helper()
	for {
		ref, ok := v["$ref"].(string)
		if !ok {
			return ptr, v
		}
		target, ok := strings.CutPrefix(ref, "#")
		if !ok {
			t.Fatalf("%s: %s points outside the document", a.path, ref)
		}
		var cur any = a.doc
		for _, tok := range strings.Split(strings.TrimPrefix(target, "/"), "/") {
			tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
			m, _ := cur.(map[string]any)
			cur = m[tok]
		}
		next, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: %s resolves to nothing", a.path, ref)
		}
		ptr, v = target, next
	}
}

func (a *API) compile(t testing.TB, ptr string) *jsonschema.Schema {
	t.Helper()
	s, err := a.compiler.Compile(base + a.path + "#" + ptr)
	if err != nil {
		t.Fatalf("%s#%s: %v", a.path, ptr, err)
	}
	return s
}

func (a *API) jsonSchemaAt(t testing.TB, ptr string, holder map[string]any) *jsonschema.Schema {
	t.Helper()
	content, _ := holder["content"].(map[string]any)
	if _, ok := content["application/json"].(map[string]any); !ok {
		t.Fatalf("%s#%s has no application/json content", a.path, ptr)
	}
	return a.compile(t, ptr+"/content/application~1json/schema")
}

// Request is the schema of an operation's JSON request body.
func (a *API) Request(t testing.TB, operationID string) *Schema {
	t.Helper()
	ptr, op := a.operation(t, operationID)
	body, ok := op["requestBody"].(map[string]any)
	if !ok {
		t.Fatalf("%s: %s takes no request body", a.path, operationID)
	}
	ptr, body = a.resolveLocal(t, ptr+"/requestBody", body)
	return &Schema{name: operationID + " request", s: a.jsonSchemaAt(t, ptr, body)}
}

// Response is the schema of an operation's JSON response body for one status.
func (a *API) Response(t testing.TB, operationID, status string) *Schema {
	t.Helper()
	ptr, op := a.operation(t, operationID)
	responses, _ := op["responses"].(map[string]any)
	resp, ok := responses[status].(map[string]any)
	if !ok {
		t.Fatalf("%s: %s has no %s response", a.path, operationID, status)
	}
	ptr, resp = a.resolveLocal(t, ptr+"/responses/"+pointerToken(status), resp)
	return &Schema{name: operationID + " " + status, s: a.jsonSchemaAt(t, ptr, resp)}
}

// Schema is one compiled body schema.
type Schema struct {
	name string
	s    *jsonschema.Schema
}

// Validate checks a JSON body against the schema.
func (s *Schema) Validate(body []byte) error {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: not JSON: %w", s.name, err)
	}
	if err := s.s.Validate(v); err != nil {
		return fmt.Errorf("%s: %w", s.name, err)
	}
	return nil
}

// Case is one named body from a case set.
type Case struct {
	Name string
	Body json.RawMessage
}

// Cases is one part of one operation in a case file: its valid and invalid bodies.
type Cases struct {
	Valid   []Case
	Invalid []Case
}

// LoadCases reads one part ("request", or a status such as "200") of one operation from a
// vendored case file, e.g. "fixtures/http/superpipeline/approvals.v1.cases.json". A part with
// no valid case fails the test: a contract test that iterates nothing proves nothing.
func LoadCases(t testing.TB, path, operationID, part string) Cases {
	t.Helper()
	return parseCases(t, path, read(t, path), operationID, part)
}

func parseCases(t testing.TB, path string, raw []byte, operationID, part string) Cases {
	t.Helper()
	var file struct {
		Operations map[string]struct {
			Request   *caseSet            `json:"request"`
			Responses map[string]*caseSet `json:"responses"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	op, ok := file.Operations[operationID]
	if !ok {
		t.Fatalf("%s has no operation %q", path, operationID)
	}
	set := op.Request
	if part != "request" {
		set = op.Responses[part]
	}
	if set == nil {
		t.Fatalf("%s: %s has no %s cases", path, operationID, part)
	}
	var out Cases
	names := make([]string, 0, len(set.Valid))
	for name := range set.Valid {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out.Valid = append(out.Valid, Case{Name: name, Body: set.Valid[name]})
	}
	for _, c := range set.Invalid {
		out.Invalid = append(out.Invalid, Case{Name: c.Why, Body: c.Body})
	}
	if len(out.Valid) == 0 {
		t.Fatalf("%s: %s %s has no valid cases", path, operationID, part)
	}
	return out
}

type caseSet struct {
	Valid   map[string]json.RawMessage `json:"valid"`
	Invalid []struct {
		Why  string          `json:"why"`
		Body json.RawMessage `json:"body"`
	} `json:"invalid"`
}

// CheckCorpus is the control for a schema: every valid case of the part passes it and every
// invalid one fails. It proves the validator reads the vendored contract before a test trusts
// it with stk's own bodies.
func CheckCorpus(t testing.TB, s *Schema, c Cases) {
	t.Helper()
	for _, v := range c.Valid {
		if err := s.Validate(v.Body); err != nil {
			t.Errorf("valid case %q refused: %v", v.Name, err)
		}
	}
	for _, v := range c.Invalid {
		if err := s.Validate(v.Body); err == nil {
			t.Errorf("invalid case %q accepted", v.Name)
		}
	}
}
