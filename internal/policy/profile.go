package policy

import "sort"

// Profile is one caller's view of the workspace.
//
// A profile **narrows and never widens**. The service policy is the ceiling: a
// profile selects a subset of it, so listing a write does not make it
// agent-callable, and a capability the service denied cannot be recovered by
// naming it. The consequence is that a mistake in a profile can only ever grant
// less than intended.
//
// Narrowing also happens at discovery, not just at execution: a capability a
// profile lacks is reported as absent rather than refused, so the agent is
// never told it exists.
type Profile struct {
	Name string
	cfg  *Config
	// allow is service -> capability -> true. A nil allow means "everything the
	// service policy permits", which is the default profile.
	allow map[string]map[string]bool
}

// Visible reports whether this profile may see a capability at all.
func (p *Profile) Visible(service, capability string) bool {
	svc, ok := p.cfg.Service(service)
	if !ok {
		return false
	}
	// Deny is a floor as well as a ceiling: nothing makes a denied capability
	// visible.
	if svc.Policy(capability) == ActionDeny {
		return false
	}
	if _, known := svc.Entry().Capability(capability); !known {
		return false
	}
	if p.allow == nil {
		return true
	}
	caps, ok := p.allow[service]
	if !ok {
		return false
	}
	return caps["*"] || caps[capability]
}

// Resolve gives the action for a capability, which is the service policy
// unchanged for anything visible, and deny otherwise.
func (p *Profile) Resolve(service, capability string) Action {
	if !p.Visible(service, capability) {
		return ActionDeny
	}
	svc, _ := p.cfg.Service(service)
	return svc.Policy(capability)
}

// Services lists the services this profile can see anything in.
func (p *Profile) Services() []string {
	var out []string
	for _, name := range p.cfg.Services() {
		if len(p.Capabilities(name)) > 0 {
			out = append(out, name)
		}
	}
	return out
}

// Capabilities lists the visible capabilities of one service, sorted.
func (p *Profile) Capabilities(service string) []string {
	svc, ok := p.cfg.Service(service)
	if !ok {
		return nil
	}
	var out []string
	for _, c := range svc.Entry().Capabilities {
		if p.Visible(service, c.Name) {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Profile returns a declared profile, or the default profile for the empty name.
//
// An unknown name does not resolve. Falling back to the default would turn a
// typo in an agent's configuration into full access.
func (c *Config) Profile(name string) (*Profile, bool) {
	if name == "" {
		return &Profile{Name: "", cfg: c, allow: nil}, true
	}
	allow, ok := c.profiles[name]
	if !ok {
		return nil, false
	}
	return &Profile{Name: name, cfg: c, allow: allow}, true
}

// Profiles lists declared profile names, sorted.
func (c *Config) Profiles() []string {
	out := make([]string, 0, len(c.profiles))
	for n := range c.profiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
