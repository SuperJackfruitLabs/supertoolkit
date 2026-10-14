// Package catalog describes the services supertoolkit knows how to broker:
// which host to intercept, where the credential goes, what each capability
// does, and the request shape it turns into.
//
// A capability's Kind gives policy a safe default — a read may be handed to an
// agent, a write may not.
package catalog

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Kind classifies what a capability does to the world, which decides its
// default policy. Reversibility is the distinction that matters.
type Kind int

const (
	// Read observes and changes nothing.
	Read Kind = iota
	// Write changes something the operator could undo.
	Write
	// Destructive changes something that cannot be undone.
	Destructive
)

// Placement says where in the request the credential belongs.
type Placement int

const (
	// BearerHeader is `Authorization: Bearer <token>`.
	BearerHeader Placement = iota
	// BasicHeader is `Authorization: Basic base64(user:<token>)`.
	BasicHeader
	// APIKeyHeader is a named header carrying the token verbatim.
	APIKeyHeader
	// QueryParam is a named query parameter carrying the token verbatim.
	QueryParam
)

// Param is one input to a capability.
type Param struct {
	Name     string
	Required bool
	// Slashes allows `/` in the value. Only a parameter that genuinely names a
	// path may set it; everything else is a single segment.
	Slashes bool
	Summary string
}

// Capability is one thing a service can be asked to do.
type Capability struct {
	Name    string
	Kind    Kind
	Method  string
	Path    string // may contain {name} placeholders matching Params
	Summary string
	Params  []Param
}

// Entry is one service.
type Entry struct {
	Name string
	// Host is the single hostname the broker intercepts for this service.
	Host string
	// EnvVar is where a client expects to find its credential. `stk run` puts
	// the worthless placeholder here, so the client is configured normally and
	// never learns it is being brokered.
	EnvVar       string
	Placement    Placement
	Field        string
	Capabilities []Capability
}

// builtin is deliberately short. Breadth is not the product: there are hundreds
// of MCP servers already, and an entry here is only needed where we front a
// service directly.
var builtin = map[string]*Entry{
	"github": {
		Name: "github", Host: "api.github.com", Placement: BearerHeader, EnvVar: "GH_TOKEN",
		Capabilities: []Capability{
			{
				Name: "get_user", Kind: Read, Method: "GET", Path: "/user",
				Summary: "The authenticated user.",
			},
			{
				Name: "list_repos", Kind: Read, Method: "GET", Path: "/user/repos",
				Summary: "Repositories the authenticated user can see.",
			},
			{
				Name: "read_file", Kind: Read, Method: "GET",
				Path:    "/repos/{owner}/{repo}/contents/{path}",
				Summary: "One file's contents and metadata.",
				Params: []Param{
					{Name: "owner", Required: true, Summary: "Account or organisation."},
					{Name: "repo", Required: true, Summary: "Repository name."},
					{Name: "path", Required: true, Slashes: true, Summary: "Path inside the repository."},
				},
			},
			{
				Name: "create_issue", Kind: Write, Method: "POST",
				Path:    "/repos/{owner}/{repo}/issues",
				Summary: "Open an issue.",
				Params: []Param{
					{Name: "owner", Required: true},
					{Name: "repo", Required: true},
					{Name: "title", Required: true, Summary: "Issue title."},
				},
			},
			{
				Name: "delete_repo", Kind: Destructive, Method: "DELETE",
				Path:    "/repos/{owner}/{repo}",
				Summary: "Delete a repository. Cannot be undone.",
				Params: []Param{
					{Name: "owner", Required: true},
					{Name: "repo", Required: true},
				},
			},
		},
	},
}

// Lookup returns a known service by name.
func Lookup(name string) (*Entry, bool) {
	e, ok := builtin[name]
	return e, ok
}

// Capability finds one capability on an entry.
func (e *Entry) Capability(name string) (Capability, bool) {
	for _, c := range e.Capabilities {
		if c.Name == name {
			return c, true
		}
	}
	return Capability{}, false
}

// Names lists every known service.
func Names() []string {
	out := make([]string, 0, len(builtin))
	for n := range builtin {
		out = append(out, n)
	}
	return out
}

// Request builds the HTTP request for a capability.
//
// Parameter values arrive from a model, so each is validated before it is
// interpolated. Without that, a capability scoped to `/repos/{owner}/{repo}`
// could be walked out of its own scope with `../`, and the credential would be
// attached to wherever it landed.
func (e *Entry) Request(capability string, args map[string]string) (*http.Request, error) {
	c, ok := e.Capability(capability)
	if !ok {
		return nil, fmt.Errorf("service %q has no capability %q", e.Name, capability)
	}
	path := c.Path
	for _, p := range c.Params {
		v, given := args[p.Name]
		if !given || v == "" {
			if p.Required {
				return nil, fmt.Errorf("%s/%s: parameter %q is required", e.Name, capability, p.Name)
			}
			continue
		}
		if err := validateParam(p, v); err != nil {
			return nil, fmt.Errorf("%s/%s: parameter %q: %w", e.Name, capability, p.Name, err)
		}
		path = strings.ReplaceAll(path, "{"+p.Name+"}", v)
	}
	if i := strings.Index(path, "{"); i >= 0 {
		return nil, fmt.Errorf("%s/%s: unfilled parameter in path %q", e.Name, capability, path)
	}
	u := &url.URL{Scheme: "https", Host: e.Host, Path: path}
	return http.NewRequest(c.Method, u.String(), nil)
}

// validateParam rejects anything that would change the shape of the request
// rather than fill a hole in it.
func validateParam(p Param, v string) error {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains a control character")
		}
		switch r {
		case ' ', '?', '#', '%':
			return fmt.Errorf("contains %q, which would change the request shape", r)
		case '/':
			if !p.Slashes {
				return fmt.Errorf("contains a slash, but this parameter is a single segment")
			}
		}
	}
	// `..` is refused even where slashes are allowed: a path parameter may
	// descend, never ascend.
	for _, seg := range strings.Split(v, "/") {
		if seg == ".." {
			return fmt.Errorf("contains a %q segment", "..")
		}
	}
	if strings.HasPrefix(v, "/") {
		return fmt.Errorf("must not start with a slash")
	}
	return nil
}
