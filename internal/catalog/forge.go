package catalog

import (
	"fmt"
	"strings"
)

// ForgeSpec is a git forge as an operator writes it in the policy file.
//
// A forge is defined in configuration rather than compiled in: the host differs
// per deployment (a self-hosted Forgejo, GitHub Enterprise), so a fixed
// catalogue entry could never name it.
type ForgeSpec struct {
	Name, Provider, Host, APIPrefix, Auth, Scheme, EnvVar string
	// Repositories are the "owner/name" pairs this service is granted. They are
	// not secret.
	Repositories []string
	Preset       string
}

// ForgeInfo is what a forge entry knows beyond an ordinary service.
type ForgeInfo struct {
	Provider  string
	APIPrefix string
	Preset    string
	// IdentityPath is the read-only endpoint, relative to APIPrefix, that names
	// the account a credential acts as. `stk verify` calls it.
	IdentityPath string
	Repositories []string
}

type providerDefaults struct {
	apiPrefix, identityPath string
}

var forgeProviders = map[string]providerDefaults{
	"forgejo":   {"/api/v1", "/user"},
	"gitea":     {"/api/v1", "/user"},
	"github":    {"", "/user"},
	"bitbucket": {"/2.0", "/user"},
}

var forgePresets = map[string]bool{
	"read": true, "issues": true, "pull-requests": true, "maintain": true, "none": true,
}

// Providers lists the forge providers a `kind: forge` service may name.
func Providers() []string {
	return []string{"forgejo", "gitea", "github", "bitbucket"}
}

// NewForgeEntry builds a service entry from a forge spec.
//
// Each call returns a fresh Entry. Built-ins share one pointer from the map, so
// a per-instance host could never be set on them.
func NewForgeEntry(s ForgeSpec) (*Entry, error) {
	if s.Name == "" {
		return nil, fmt.Errorf("forge service needs a name")
	}
	def, ok := forgeProviders[s.Provider]
	if !ok {
		return nil, fmt.Errorf("forge %q: unknown provider %q: known providers are %v", s.Name, s.Provider, Providers())
	}
	if err := checkHost(s.Host); err != nil {
		return nil, fmt.Errorf("forge %q: %w", s.Name, err)
	}
	switch s.Auth {
	case "", "token":
	case "app":
		return nil, fmt.Errorf("forge %q: app auth arrives with the GitHub adapter; use auth: token", s.Name)
	default:
		return nil, fmt.Errorf("forge %q: unknown auth %q: want token", s.Name, s.Auth)
	}
	switch s.Scheme {
	case "", "bearer":
	case "token":
		return nil, fmt.Errorf("forge %q: scheme token is not supported yet", s.Name)
	default:
		return nil, fmt.Errorf("forge %q: unknown scheme %q: want bearer or token", s.Name, s.Scheme)
	}
	if len(s.Repositories) == 0 {
		return nil, fmt.Errorf("forge %q: repositories is required: a forge grant names the repositories it covers", s.Name)
	}
	for _, r := range s.Repositories {
		parts := strings.Split(r, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(r, " \t") {
			return nil, fmt.Errorf("forge %q: repository %q must be owner/name", s.Name, r)
		}
	}
	preset := s.Preset
	if preset == "" {
		preset = "read"
	}
	if !forgePresets[preset] {
		return nil, fmt.Errorf("forge %q: unknown preset %q: want read, issues, pull-requests, maintain or none", s.Name, s.Preset)
	}
	prefix := s.APIPrefix
	if prefix == "" {
		prefix = def.apiPrefix
	}
	return &Entry{
		Name:      s.Name,
		Host:      s.Host,
		EnvVar:    s.EnvVar,
		Placement: BearerHeader,
		Auth:      AuthToken,
		RevokeAt:  "https://" + s.Host + "/user/settings/applications",
		Forge: &ForgeInfo{
			Provider: s.Provider, APIPrefix: prefix, Preset: preset,
			IdentityPath: def.identityPath,
			Repositories: append([]string(nil), s.Repositories...),
		},
	}, nil
}

// checkHost rejects anything that is not a bare hostname. A scheme or path in
// the host would never match the hostname the proxy sees, and the failure would
// be a credential silently not substituted.
func checkHost(h string) error {
	if h == "" {
		return fmt.Errorf("host is required")
	}
	if strings.ContainsAny(h, "/: \t\r\n?#@") {
		return fmt.Errorf("host %q must be a bare hostname, with no scheme, port, path or spaces", h)
	}
	return nil
}
