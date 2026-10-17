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
	// APIBase is where an app grant exchanges its JWT, set only for auth: app.
	APIBase string
	// Owner and RepositoryNames split Repositories for an app grant: an
	// installation belongs to one account, and GitHub restricts an
	// installation token by repository name alone.
	Owner           string
	RepositoryNames []string
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
	if strings.Contains(s.Name, ".scope-") {
		return nil, fmt.Errorf("forge %q: a service name may not contain \".scope-\", which names a scoped token cache entry", s.Name)
	}
	def, ok := forgeProviders[s.Provider]
	if !ok {
		return nil, fmt.Errorf("forge %q: unknown provider %q: known providers are %v", s.Name, s.Provider, Providers())
	}
	if err := checkHost(s.Host); err != nil {
		return nil, fmt.Errorf("forge %q: %w", s.Name, err)
	}
	auth := AuthToken
	switch s.Auth {
	case "", "token":
	case "app":
		// A GitHub App is GitHub's construct; no other provider has an
		// installation-token exchange to perform.
		if s.Provider != "github" {
			return nil, fmt.Errorf("forge %q: auth app is a GitHub App grant and provider %q has none; use auth: token", s.Name, s.Provider)
		}
		auth = AuthGitHubApp
	default:
		return nil, fmt.Errorf("forge %q: unknown auth %q: want token or app", s.Name, s.Auth)
	}
	placement, field := BearerHeader, ""
	switch s.Scheme {
	case "", "bearer":
	case "token":
		placement, field = SchemeHeader, "token"
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
	var owner, apiBase string
	var names []string
	if auth == AuthGitHubApp {
		// An installation belongs to one account, so a token restricted to
		// repositories can only name repositories of that account.
		for _, r := range s.Repositories {
			o, n, _ := strings.Cut(r, "/")
			if owner != "" && o != owner {
				return nil, fmt.Errorf("forge %q: auth app repositories must share one owner (an installation belongs to one account): got %q and %q", s.Name, owner, o)
			}
			owner = o
			names = append(names, n)
		}
		// An installation token is sent as a bearer token; asking for another
		// scheme is a contradiction, not a preference.
		if s.Scheme == "token" {
			return nil, fmt.Errorf("forge %q: auth app sends its installation token as a Bearer header; scheme token cannot be used with it", s.Name)
		}
		apiBase = "https://" + s.Host + "/api/v3"
		if s.Host == "api.github.com" {
			apiBase = "https://api.github.com"
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
		// GitHub Enterprise serves its API under /api/v3; only github.com has
		// a dedicated API host. Without this every rule silently never matches.
		if s.Provider == "github" && s.Host != "api.github.com" {
			prefix = "/api/v3"
		}
	}
	return &Entry{
		Name:      s.Name,
		Host:      s.Host,
		EnvVar:    s.EnvVar,
		Placement: placement,
		Field:     field,
		Auth:      auth,
		RevokeAt:  "https://" + s.Host + "/user/settings/applications",
		Forge: &ForgeInfo{
			Provider: s.Provider, APIPrefix: prefix, Preset: preset,
			IdentityPath: def.identityPath,
			Repositories: append([]string(nil), s.Repositories...),
			APIBase:      apiBase, Owner: owner, RepositoryNames: names,
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
