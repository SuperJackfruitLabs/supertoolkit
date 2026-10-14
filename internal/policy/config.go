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

// ParseAction reads a policy word, for callers outside this package.
func ParseAction(s string) (Action, error) { return parseAction(s) }

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
	// device holds what the catalogue cannot know: the operator's own OAuth
	// app, and — for a self-hosted instance such as GitHub Enterprise Server —
	// endpoints that are not the public ones. A client id is public by OAuth's
	// design, naming an app without authorising anything, so both belong in the
	// committed file beside the rest of the policy.
	device deviceOverride
}

// Entry exposes the catalogue record, which carries the host and the credential
// placement.
func (s *Service) Entry() *catalog.Entry { return s.entry }

// Device describes the headless connect path for this service: the
// catalogue's endpoints, with the operator's own client id filled in.
//
// Without a client id the flow cannot start, and Supported() reports false, so
// `stk connect --device` can say which piece is missing instead of failing at
// the provider.
func (s *Service) Device() catalog.Device {
	d := s.entry.Device
	if s.device.ClientID != "" {
		d.ClientID = s.device.ClientID
	}
	// A self-hosted instance speaks the same protocol at different addresses.
	// Overriding one endpoint without the other would send the poll somewhere
	// that never issued the code, so they move together or not at all.
	if s.device.AuthorizationURL != "" && s.device.TokenURL != "" {
		d.AuthorizationURL = s.device.AuthorizationURL
		d.TokenURL = s.device.TokenURL
	}
	return d
}

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
	// profiles is name -> service -> capability -> allowed.
	profiles map[string]map[string]map[string]bool
	// servers are MCP servers we did not write, fronted as categories.
	servers map[string]*Server
	notify  Notify
}

// Notify returns the configured notification routes.
func (c *Config) Notify() Notify { return c.notify }

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
	// A fronted server's host is intercepted too: that is how its placeholder
	// becomes a real credential on the way out.
	for _, s := range c.servers {
		out[s.Host] = true
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
		Device       deviceOverride    `yaml:"device"`
	} `yaml:"services"`
	Profiles map[string]map[string][]string `yaml:"profiles"`
	Servers  map[string]serverFile          `yaml:"servers"`
	Notify   notifyFile                     `yaml:"notify"`
}

// deviceOverride mirrors a service's `device:` block.
type deviceOverride struct {
	ClientID         string `yaml:"client_id"`
	AuthorizationURL string `yaml:"authorization_url"`
	TokenURL         string `yaml:"token_url"`
}

// notifyFile mirrors the `notify:` block: the routes by which a machine reaches
// the person it is waiting on. A URL is not a secret, so it may sit here; a
// token in one would be, which is why only unauthenticated endpoints are
// supported for now.
type notifyFile struct {
	Webhook string `yaml:"webhook"`
	File    string `yaml:"file"`
}

// Notify is where to reach the operator. The terminal is always a route and is
// never configured, so it does not appear here.
type Notify struct {
	Webhook string
	File    string
}

// serverFile mirrors one `servers:` entry on disk.
type serverFile struct {
	Command      string            `yaml:"command"`
	Args         []string          `yaml:"args"`
	Host         string            `yaml:"host"`
	EnvVar       string            `yaml:"env_var"`
	Env          map[string]string `yaml:"env"`
	Capabilities map[string]string `yaml:"capabilities"`
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

	cfg := &Config{
		Workspace: f.Workspace,
		services:  map[string]*Service{},
		profiles:  map[string]map[string]map[string]bool{},
		servers:   map[string]*Server{},
		notify:    Notify{Webhook: f.Notify.Webhook, File: f.Notify.File},
	}
	for name, sf := range f.Services {
		entry, ok := catalog.Lookup(name)
		if !ok {
			return nil, fmt.Errorf("%s: unknown service %q: known services are %v", path, name, catalog.Names())
		}
		svc := &Service{
			Name: name, Scopes: sf.Scopes, explicit: map[string]Action{}, entry: entry,
			device: sf.Device,
		}
		if (sf.Device.AuthorizationURL == "") != (sf.Device.TokenURL == "") {
			return nil, fmt.Errorf("%s: service %q: device needs both authorization_url and token_url, or neither — polling an endpoint that did not issue the code never succeeds", path, name)
		}
		for cap, want := range sf.Capabilities {
			a, err := parseAction(want)
			if err != nil {
				return nil, fmt.Errorf("%s: service %q capability %q: %w", path, name, cap, err)
			}
			svc.explicit[cap] = a
		}
		cfg.services[name] = svc
	}

	if err := cfg.loadServers(path, f.Servers); err != nil {
		return nil, err
	}

	for pname, svcs := range f.Profiles {
		allow := map[string]map[string]bool{}
		for sname, caps := range svcs {
			_, isService := cfg.services[sname]
			_, isServer := cfg.servers[sname]
			if !isService && !isServer {
				return nil, fmt.Errorf("%s: profile %q names %q, which is neither a configured service nor a server", path, pname, sname)
			}
			set := map[string]bool{}
			for _, c := range caps {
				set[c] = true
			}
			allow[sname] = set
		}
		cfg.profiles[pname] = allow
	}
	return cfg, nil
}
