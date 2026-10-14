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

// Auth says which credential operation a service needs. It is what the broker
// dispatches on, so a new scheme is a catalogue entry rather than a branch in
// the request path.
type Auth int

const (
	// AuthToken substitutes a stored token. The simplest case, and the only one
	// where a long-lived secret reaches the wire.
	AuthToken Auth = iota
	// AuthSigV4 signs with a stored key pair. The credential is an HMAC over the
	// whole request, so it cannot be substituted.
	AuthSigV4
	// AuthGitHubApp mints a JWT from a stored private key and exchanges it for a
	// short-lived installation token.
	AuthGitHubApp
)

func (a Auth) String() string {
	switch a {
	case AuthSigV4:
		return "sign (AWS SigV4)"
	case AuthGitHubApp:
		return "acquire (GitHub App installation token)"
	default:
		return "substitute (token)"
	}
}

// Fields are the credential fields a service needs, which `stk connect` prompts
// for and `Material.Require` checks.
func (a Auth) Fields() []string {
	switch a {
	case AuthSigV4:
		return []string{"access_key_id", "secret_access_key"}
	case AuthGitHubApp:
		return []string{"app_id", "installation_id", "private_key"}
	default:
		return []string{"token"}
	}
}

// LongLivedOnTheWire reports whether this operation sends a long-lived secret.
// `stk doctor` shows it, because it is the difference that matters if a request
// is ever logged somewhere it should not be.
func (a Auth) LongLivedOnTheWire() bool { return a == AuthToken }

// Reassurance explains, accurately per scheme, what leaves the broker. Signing
// emits a signature rather than a credential, so one sentence cannot cover both
// without being wrong about one of them.
func (a Auth) Reassurance() string {
	switch a {
	case AuthSigV4:
		return "each request is signed in the broker; the stored key never goes on the wire"
	case AuthGitHubApp:
		return "the broker trades the stored key for a token that expires in an hour; the key never goes on the wire"
	default:
		return "the stored token is what goes on the wire, so treat it as long-lived"
	}
}

// Device describes a provider's device authorization grant, where it offers
// one. Without this a service can still be connected, just not from a machine
// with no browser.
type Device struct {
	AuthorizationURL string
	TokenURL         string
	// ClientID is the public identifier of our own OAuth app. It is not a
	// secret — the device grant exists precisely so a public client can
	// authenticate without one.
	ClientID string
	Scopes   []string
}

// Supported reports whether this service can be connected headlessly.
func (d Device) Supported() bool {
	return d.AuthorizationURL != "" && d.TokenURL != "" && d.ClientID != ""
}

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
	EnvVar    string
	Placement Placement
	Field     string
	// Auth is the credential operation this service needs.
	Auth Auth
	// Device is the headless connect path, where the provider offers one.
	Device Device
	// Region and AWSService are the SigV4 scope, used only when Auth is AuthSigV4.
	Region       string
	AWSService   string
	Capabilities []Capability
}

// builtin is deliberately short. Breadth is not the product: there are hundreds
// of MCP servers already, and an entry here is only needed where we front a
// service directly.
var builtin = map[string]*Entry{
	"aws-sts": {
		// A deliberately read-only entry: GetCallerIdentity is the AWS
		// equivalent of "who am I", so a signing service can be connected and
		// verified without granting anything.
		Name: "aws-sts", Host: "sts.amazonaws.com", Auth: AuthSigV4,
		Region: "us-east-1", AWSService: "sts",
		Capabilities: []Capability{
			{
				Name: "whoami", Kind: Read, Method: "GET",
				Path:    "/?Action=GetCallerIdentity&Version=2011-06-15",
				Summary: "The identity the credentials belong to.",
			},
		},
	},
	"github-app": {
		Name: "github-app", Host: "api.github.com", Auth: AuthGitHubApp,
		Capabilities: []Capability{
			{
				Name: "list_installation_repos", Kind: Read, Method: "GET",
				Path:    "/installation/repositories",
				Summary: "Repositories this installation can reach.",
			},
			{
				Name: "create_issue", Kind: Write, Method: "POST",
				Path:    "/repos/{owner}/{repo}/issues",
				Summary: "Open an issue as the app.",
				Params: []Param{
					{Name: "owner", Required: true},
					{Name: "repo", Required: true},
					{Name: "title", Required: true, Summary: "Issue title."},
				},
			},
		},
	},
	"github": {
		Name: "github", Host: "api.github.com", Placement: BearerHeader, EnvVar: "GH_TOKEN",
		Device: Device{
			AuthorizationURL: "https://github.com/login/device/code",
			TokenURL:         "https://github.com/login/oauth/access_token",
			// Replaced by the operator's own OAuth app id at configure time;
			// this placeholder makes the shape visible without pretending we
			// ship a working client id.
			ClientID: "",
			Scopes:   []string{"repo", "read:org"},
		},
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
	// A shape may carry a literal query string, as the AWS STS action does.
	query := ""
	if i := strings.Index(path, "?"); i >= 0 {
		path, query = path[:i], path[i+1:]
	}
	u := &url.URL{Scheme: "https", Host: e.Host, Path: path, RawQuery: query}
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
