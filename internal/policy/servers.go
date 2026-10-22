package policy

import (
	"fmt"
	"runtime"
	"sort"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/egress"
)

// Network modes for a fronted server's child.
const (
	// NetworkConfined starts the child in its own network namespace whose only
	// way out is the broker.
	NetworkConfined = "confined"
	// NetworkHost leaves the child on the host network: configured to use the
	// broker, not forced to.
	NetworkHost = "host"
	// NetworkWatched leaves the child on the host network and watches its
	// sockets: a connection anywhere but the broker is detected, recorded and
	// the child stopped. Detection, not prevention: see docs/limitations.md.
	NetworkWatched = "watched"
)

// Server is an MCP server we did not write, run as a child with no credential
// in its environment.
//
// Its tools become the actions of a category, so the four meta-tools cover it
// identically to a native service — and the child's tools still reach an agent
// only through progressive discovery.
type Server struct {
	Name string
	// Command and Args start the child.
	Command string
	Args    []string
	// Host is the one hostname the broker intercepts for this server, so the
	// placeholder it carries can be substituted on egress.
	Host string
	// EnvVar is the variable the server expects its credential in. The
	// placeholder goes here.
	EnvVar string
	// Env is extra non-secret environment the server needs.
	Env map[string]string
	// Egress decides hosts outside policy that this server's child reaches;
	// nil means the workspace's.
	Egress *egress.Policy
	// Network is NetworkConfined or NetworkHost.
	Network string

	explicit map[string]Action
}

// ToolHint is what MCP's own annotations tell us about a tool. We did not write
// these tools, so a hint is the only evidence available.
type ToolHint struct {
	ReadOnly    bool
	Destructive bool
	Known       bool // whether the server annotated the tool at all
}

// Policy resolves one of the server's tools.
//
// **An unannotated tool defaults to approval.** We cannot know what a tool we
// did not write does, and the absence of a hint is not evidence of safety. A
// read-only hint may promote one to agent; nothing promotes a destructive one.
func (s *Server) Policy(tool string, hint ToolHint) Action {
	a, _ := s.Decide(tool, hint)
	return a
}

// Decide is Policy with the id of the rule that decided it, for the audit
// record: the operator's explicit word, the child's read-only hint, or the
// unannotated default.
func (s *Server) Decide(tool string, hint ToolHint) (Action, string) {
	if a, ok := s.explicit[tool]; ok {
		return a, "server:" + s.Name + "/capabilities." + tool
	}
	if hint.Known && hint.ReadOnly && !hint.Destructive {
		return ActionAgent, "server:" + s.Name + "/default.read-only-hint"
	}
	return ActionApproval, "server:" + s.Name + "/default.unannotated"
}

// Tools lists tools with an explicit policy, sorted. Used by doctor to show
// what an operator has decided rather than inherited.
func (s *Server) Tools() []string {
	out := make([]string, 0, len(s.explicit))
	for t := range s.explicit {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Server finds a configured server.
func (c *Config) Server(name string) (*Server, bool) {
	s, ok := c.servers[name]
	return s, ok
}

// Servers lists configured server names, sorted.
func (c *Config) Servers() []string {
	out := make([]string, 0, len(c.servers))
	for n := range c.servers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Categories is every category an agent may discover: native services and
// fronted servers together, sorted, which is the order discovery reports.
func (c *Config) Categories() []string {
	out := append(c.Services(), c.Servers()...)
	sort.Strings(out)
	return out
}

// IsServer reports whether a category is a fronted server rather than a native
// service.
func (c *Config) IsServer(category string) bool {
	_, ok := c.servers[category]
	return ok
}

func (c *Config) loadServers(path string, decl map[string]serverFile) error {
	for name, sf := range decl {
		if _, clash := c.services[name]; clash {
			// Both become categories, so one would shadow the other and an
			// operator could not tell which they had configured.
			return fmt.Errorf("%s: %q is declared as both a service and a server; a category name must be unique", path, name)
		}
		if sf.Command == "" {
			return fmt.Errorf("%s: server %q has no command to run", path, name)
		}
		eg, err := buildEgress(sf.Egress)
		if err != nil {
			return fmt.Errorf("%s: server %q: %w", path, name, err)
		}
		// A host is how a placeholder becomes a credential. A server that
		// carries none needs no host, but then it must say where it may go.
		if sf.Host == "" && (sf.EnvVar != "" || eg == nil) {
			return fmt.Errorf("%s: server %q declares no host; without one the broker cannot intercept its traffic and its credential would have to be real (a server with no credential declares egress instead)", path, name)
		}
		network := sf.Network
		switch network {
		case "":
			network = NetworkHost
			if eg != nil {
				network = NetworkConfined
			}
		case NetworkConfined, NetworkHost, NetworkWatched:
		default:
			return fmt.Errorf("%s: server %q: network %q: want confined, watched or host", path, name, sf.Network)
		}
		if network != NetworkHost && runtime.GOOS != "linux" {
			// Refused rather than quietly downgraded: a policy that says
			// confined must not run a child that is not.
			return fmt.Errorf("%s: server %q: network: %s needs Linux; on %s say `network: host` explicitly", path, name, network, runtime.GOOS)
		}
		srv := &Server{
			Name: name, Command: sf.Command, Args: sf.Args,
			Host: sf.Host, EnvVar: sf.EnvVar, Env: sf.Env,
			Egress: eg, Network: network,
			explicit: map[string]Action{},
		}
		for tool, want := range sf.Capabilities {
			a, err := parseAction(want)
			if err != nil {
				return fmt.Errorf("%s: server %q tool %q: %w", path, name, tool, err)
			}
			srv.explicit[tool] = a
		}
		c.servers[name] = srv
	}
	return nil
}
