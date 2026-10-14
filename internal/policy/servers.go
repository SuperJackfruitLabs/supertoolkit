package policy

import (
	"fmt"
	"sort"
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
	if a, ok := s.explicit[tool]; ok {
		return a
	}
	if hint.Known && hint.ReadOnly && !hint.Destructive {
		return ActionAgent
	}
	return ActionApproval
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
		if sf.Host == "" {
			return fmt.Errorf("%s: server %q declares no host; without one the broker cannot intercept its traffic and its credential would have to be real", path, name)
		}
		srv := &Server{
			Name: name, Command: sf.Command, Args: sf.Args,
			Host: sf.Host, EnvVar: sf.EnvVar, Env: sf.Env,
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
