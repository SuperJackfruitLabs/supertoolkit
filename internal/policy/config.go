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
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/rules"
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
	// oauth2 is the operator's own OAuth app for the authorization-code path.
	// The client id is public, for the same reason the device one is.
	oauth2 oauth2Override
	// ruleSet and allowGraphQL are set only for a forge service.
	ruleSet      *rules.Set
	allowGraphQL bool
}

// Rules is the request rule set of a forge service, nil for a built-in.
func (s *Service) Rules() *rules.Set { return s.ruleSet }

// AllowGraphQL reports whether /graphql is reachable; false unless set.
func (s *Service) AllowGraphQL() bool { return s.allowGraphQL }

// APIPrefix is the forge's API path prefix, "" for a built-in.
func (s *Service) APIPrefix() string {
	if s.entry.Forge == nil {
		return ""
	}
	return s.entry.Forge.APIPrefix
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

// OAuth2 describes the authorization-code path for this service: the
// catalogue's endpoints with the operator's own client id filled in, exactly as
// Device does for the headless path.
func (s *Service) OAuth2() catalog.OAuth2 {
	o := s.entry.OAuth2
	if s.oauth2.ClientID != "" {
		o.ClientID = s.oauth2.ClientID
	}
	if s.oauth2.AuthorizeURL != "" && s.oauth2.TokenURL != "" {
		o.AuthorizeURL = s.oauth2.AuthorizeURL
		o.TokenURL = s.oauth2.TokenURL
	}
	o.RedirectURI = s.oauth2.RedirectURI
	return o
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
		// Every host the service's credential must work on, not only the
		// primary: a provider split across hostnames would otherwise have its
		// other hosts tunnelled, and the placeholder would reach them unswapped.
		for _, h := range s.entry.Hosts() {
			out[h] = true
		}
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
		// Kind is empty for a built-in service and "forge" for one defined here.
		Kind         string            `yaml:"kind"`
		Provider     string            `yaml:"provider"`
		Host         string            `yaml:"host"`
		APIPrefix    string            `yaml:"api_prefix"`
		Auth         string            `yaml:"auth"`
		Scheme       string            `yaml:"scheme"`
		EnvVar       string            `yaml:"env_var"`
		Repositories []string          `yaml:"repositories"`
		Preset       string            `yaml:"preset"`
		Scopes       []string          `yaml:"scopes"`
		Capabilities map[string]string `yaml:"capabilities"`
		Device       deviceOverride    `yaml:"device"`
		OAuth2       oauth2Override    `yaml:"oauth2"`
		Rules        []yaml.Node       `yaml:"rules"`
		AllowGraphQL *bool             `yaml:"allow_graphql"`
	} `yaml:"services"`
	Profiles map[string]map[string][]string `yaml:"profiles"`
	Servers  map[string]serverFile          `yaml:"servers"`
	Notify   notifyFile                     `yaml:"notify"`
}

// ruleFile is one `rules:` item: exactly one of allow or deny.
type ruleFile struct {
	Allow string         `yaml:"allow"`
	Deny  string         `yaml:"deny"`
	When  map[string]any `yaml:"when"`
}

// decodeRule reads one rules item, refusing any key but allow, deny and when.
// A dropped misspelling such as `whn:` would turn a conditional allow into an
// unconditional one, so unknown keys fail the load. Strictness is local to
// rules; the rest of the file keeps its lenient decoding.
func decodeRule(n *yaml.Node) (ruleFile, error) {
	var rf ruleFile
	if n.Kind != yaml.MappingNode {
		return rf, fmt.Errorf("want a mapping with allow or deny")
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		switch k := n.Content[i].Value; k {
		case "allow", "deny", "when":
		default:
			return rf, fmt.Errorf("unknown key %q (line %d): want allow, deny or when", k, n.Content[i].Line)
		}
	}
	if err := n.Decode(&rf); err != nil {
		return rf, err
	}
	return rf, nil
}

// buildRules is the preset's rules followed by the operator's.
func buildRules(name string, entry *catalog.Entry, nodes []yaml.Node) (*rules.Set, error) {
	f := entry.Forge
	all, err := rules.Preset(f.Provider, f.Preset)
	if err != nil {
		return nil, fmt.Errorf("service %q: %w", name, err)
	}
	for i := range nodes {
		id := fmt.Sprintf("user#%d", i+1)
		rf, err := decodeRule(&nodes[i])
		if err != nil {
			return nil, fmt.Errorf("service %q rule %s: %w", name, id, err)
		}
		if (rf.Allow == "") == (rf.Deny == "") {
			return nil, fmt.Errorf("service %q rule %s: want exactly one of allow or deny", name, id)
		}
		allow, line := true, rf.Allow
		if rf.Deny != "" {
			allow, line = false, rf.Deny
		}
		r, err := rules.ParseRule(id, line, rf.When, allow)
		if err != nil {
			return nil, fmt.Errorf("service %q rule %s: %w", name, id, err)
		}
		if len(r.When) > 0 && (strings.EqualFold(r.Pattern, "/graphql") || strings.HasPrefix(strings.ToLower(r.Pattern), "/graphql/")) {
			return nil, fmt.Errorf("service %q rule %s: a body condition cannot apply to %s: graphql bodies are not inspected", name, id, r.Pattern)
		}
		if allow {
			var owner, repo bool
			for _, seg := range strings.Split(r.Pattern, "/") {
				owner = owner || seg == "{owner}"
				repo = repo || seg == "{repo}"
			}
			if owner != repo {
				return nil, fmt.Errorf("service %q rule %s: an allow rule must use both {owner} and {repo} or neither; one alone binds more loosely than an exact repository", name, id)
			}
		}
		all = append(all, r)
	}
	set, err := rules.NewSet(f.Repositories, all)
	if err != nil {
		return nil, fmt.Errorf("service %q: %w", name, err)
	}
	return set, nil
}

// deviceOverride mirrors a service's `device:` block.
type deviceOverride struct {
	ClientID         string `yaml:"client_id"`
	AuthorizationURL string `yaml:"authorization_url"`
	TokenURL         string `yaml:"token_url"`
}

// oauth2Override mirrors a service's `oauth2:` block. Only the client id lives
// here: a client secret is a secret and belongs in the sealed store, which is
// why `stk connect --browser` reads it from stdin instead.
type oauth2Override struct {
	ClientID string `yaml:"client_id"`
	// RedirectURI matches an already-registered callback.
	//
	// A provider validates this by exact match, and an operator with an
	// existing app should not have to edit it to suit us. It must be a
	// loopback address: the broker listens for the redirect itself, and a URI
	// pointing anywhere else is one it can never receive.
	RedirectURI string `yaml:"redirect_uri"`
	// A self-hosted instance speaks the same protocol at other addresses, and
	// the two endpoints move together for the same reason the device ones do:
	// exchanging a code at a server that did not issue it never succeeds.
	AuthorizeURL string `yaml:"authorize_url"`
	TokenURL     string `yaml:"token_url"`
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
		var entry *catalog.Entry
		switch sf.Kind {
		case "":
			var ok bool
			entry, ok = catalog.Lookup(name)
			if !ok {
				return nil, fmt.Errorf("%s: unknown service %q: known services are %v (a git forge is defined with `kind: forge`)", path, name, catalog.Names())
			}
		case "forge":
			var err error
			entry, err = catalog.NewForgeEntry(catalog.ForgeSpec{
				Name: name, Provider: sf.Provider, Host: sf.Host, APIPrefix: sf.APIPrefix,
				Auth: sf.Auth, Scheme: sf.Scheme, EnvVar: sf.EnvVar,
				Repositories: sf.Repositories, Preset: sf.Preset,
			})
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
		default:
			return nil, fmt.Errorf("%s: service %q: unknown kind %q: want forge, or leave kind out for a built-in", path, name, sf.Kind)
		}
		if entry.Forge == nil && (len(sf.Rules) > 0 || sf.AllowGraphQL != nil) {
			return nil, fmt.Errorf("%s: service %q: rules and allow_graphql apply only to a `kind: forge` service", path, name)
		}
		svc := &Service{
			Name: name, Scopes: sf.Scopes, explicit: map[string]Action{}, entry: entry,
			device: sf.Device, oauth2: sf.OAuth2,
		}
		if (sf.Device.AuthorizationURL == "") != (sf.Device.TokenURL == "") {
			return nil, fmt.Errorf("%s: service %q: device needs both authorization_url and token_url, or neither — polling an endpoint that did not issue the code never succeeds", path, name)
		}
		if (sf.OAuth2.AuthorizeURL == "") != (sf.OAuth2.TokenURL == "") {
			return nil, fmt.Errorf("%s: service %q: oauth2 needs both authorize_url and token_url, or neither — exchanging a code at a server that did not issue it never succeeds", path, name)
		}
		if entry.Forge != nil {
			set, err := buildRules(name, entry, sf.Rules)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			svc.ruleSet = set
			svc.allowGraphQL = sf.AllowGraphQL != nil && *sf.AllowGraphQL
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

	// The proxy maps a host to one service, so two services on one host would
	// have one silently win. Checked across every service, built-in or forge,
	// and after the whole file is read so the order they are written in cannot
	// hide it.
	owner := map[string]string{}
	for _, name := range cfg.Services() {
		for _, h := range cfg.services[name].entry.Hosts() {
			if other, taken := owner[h]; taken {
				return nil, fmt.Errorf("%s: services %q and %q both use host %s: one service per host", path, other, name, h)
			}
			owner[h] = name
		}
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
