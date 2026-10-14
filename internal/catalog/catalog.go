// Package catalog describes the services supertoolkit knows how to broker:
// which host to intercept, where the credential goes, and what each capability
// does. A capability's Kind is what gives policy a safe default — a read may be
// handed to an agent, a write may not.
package catalog

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

// Capability is one thing a service can be asked to do.
type Capability struct {
	Name string
	Kind Kind
}

// Entry is one service.
type Entry struct {
	Name string
	// Host is the single hostname the broker intercepts for this service.
	Host string
	// EnvVar is where a client expects to find its credential. `stk run` puts
	// the worthless placeholder here, so the client is configured normally and
	// never learns it is being brokered.
	EnvVar string
	// Placement and Field say how to inject. Field names the header or query
	// parameter for APIKeyHeader and QueryParam, and the username for
	// BasicHeader.
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
			{"list_repos", Read},
			{"read_file", Read},
			{"get_user", Read},
			{"create_issue", Write},
			{"delete_repo", Destructive},
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
