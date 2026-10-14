package credential

import (
	"fmt"
	"sort"
)

// Material is a service's credential, which is not always a single token.
//
// Signing needs an access-key pair, minting needs a private key, and GitHub App
// needs an app id, a private key and an installation id. Keeping this a map
// rather than a struct per scheme means a new scheme adds a catalogue entry
// instead of a storage migration.
type Material map[string]string

// Field names used across the schemes. Declared so a typo is a compile error in
// our own code rather than a credential that silently is not found.
const (
	FieldToken           = "token"
	FieldAccessKeyID     = "access_key_id"
	FieldSecretAccessKey = "secret_access_key"
	FieldPrivateKey      = "private_key"
	FieldAppID           = "app_id"
	FieldInstallationID  = "installation_id"
	FieldClientID        = "client_id"
	FieldClientSecret    = "client_secret"
	FieldTokenURL        = "token_url"
	FieldUsername        = "username"
	// FieldRefreshToken is the long-lived half of an OAuth 2.0 user grant. It
	// never reaches an API — only the provider's own token endpoint.
	FieldRefreshToken = "refresh_token"
)

// Token is the single-token shorthand, for the schemes that use one.
func (m Material) Token() string { return m[FieldToken] }

// Require checks that every named field is present and non-empty, naming all
// the missing ones at once so an operator fixes them in one pass.
func (m Material) Require(fields ...string) error {
	var missing []string
	for _, f := range fields {
		if m[f] == "" {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("credential is missing %v", missing)
}

// Fields lists the field names present, sorted. Names only — never values, so
// this is safe to log or show an operator.
func (m Material) Fields() []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
