// Package policy reads supertoolkit.yaml and answers the only question the
// broker asks of it: may this caller trigger this capability, and if so does a
// human decide first.
//
// The file is committed to a repository, so it must never contain a secret.
// Nothing here reads or stores one.
package policy

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
)

// Action is what may happen when a caller asks for a capability.
type Action int

const (
	// ActionApproval is the default for anything not known to be reversible:
	// the agent may propose, a human decides. It is deliberately the zero
	// value, so a missing or misspelled policy fails safe rather than open.
	ActionApproval Action = iota
	// ActionAgent lets the caller trigger the effect directly.
	ActionAgent
	// ActionDeny makes the capability unavailable to anyone on this workspace.
	ActionDeny
)

func (a Action) String() string {
	switch a {
	case ActionAgent:
		return "agent"
	case ActionDeny:
		return "deny"
	default:
		return "approval"
	}
}

func parseAction(s string) (Action, error) {
	switch s {
	case "agent":
		return ActionAgent, nil
	case "approval":
		return ActionApproval, nil
	case "deny":
		return ActionDeny, nil
	}
	return ActionApproval, fmt.Errorf("unknown policy %q: want agent, approval or deny", s)
}

// Service is one configured service.
type Service struct {
	Name   string
	Scopes []string
	// explicit holds only what the file stated. Everything else is defaulted
	// from the catalogue, so the file stays short and safe.
	explicit map[string]Action
	entry    *catalog.Entry
}

// Entry exposes the catalogue record, which carries the host and the credential
// placement.
func (s *Service) Entry() *catalog.Entry { return s.entry }

// Policy resolves one capability.
//
// Order: what the file says, then the catalogue's classification, then approval.
// A capability nobody has classified is never agent-callable — an unknown effect
// is treated as a write, not as a read.
func (s *Service) Policy(capability string) Action {
	if a, ok := s.explicit[capability]; ok {
		return a
	}
	c, known := s.entry.Capability(capability)
	if !known {
		return ActionApproval
	}
	if c.Kind == catalog.Read {
		return ActionAgent
	}
	return ActionApproval
}

// Config is the whole file.
type Config struct {
	Workspace string
	services  map[string]*Service
}

// Service finds a configured service.
func (c *Config) Service(name string) (*Service, bool) {
	s, ok := c.services[name]
	return s, ok
}

// Services lists configured service names, sorted so output is stable.
func (c *Config) Services() []string {
	out := make([]string, 0, len(c.services))
	for n := range c.services {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// InterceptHosts is the allowlist the broker terminates TLS for. Every other
// host is tunnelled unopened, so this set is the blast radius of interception.
func (c *Config) InterceptHosts() map[string]bool {
	out := map[string]bool{}
	for _, s := range c.services {
		out[s.entry.Host] = true
	}
	return out
}

// file mirrors the on-disk shape. Kept separate from Config so the public type
// never grows a field that could hold a secret by accident.
type file struct {
	Workspace string `yaml:"workspace"`
	Services  map[string]struct {
		Scopes       []string          `yaml:"scopes"`
		Capabilities map[string]string `yaml:"capabilities"`
	} `yaml:"services"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f file
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	cfg := &Config{Workspace: f.Workspace, services: map[string]*Service{}}
	for name, sf := range f.Services {
		entry, ok := catalog.Lookup(name)
		if !ok {
			return nil, fmt.Errorf("%s: unknown service %q: known services are %v", path, name, catalog.Names())
		}
		svc := &Service{Name: name, Scopes: sf.Scopes, explicit: map[string]Action{}, entry: entry}
		for cap, want := range sf.Capabilities {
			a, err := parseAction(want)
			if err != nil {
				return nil, fmt.Errorf("%s: service %q capability %q: %w", path, name, cap, err)
			}
			svc.explicit[cap] = a
		}
		cfg.services[name] = svc
	}
	return cfg, nil
}
