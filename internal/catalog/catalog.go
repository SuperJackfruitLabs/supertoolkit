// Package catalog describes the services supertoolkit knows how to broker:
// which host to intercept, where the credential goes, what each capability
// does, and the request shape it turns into.
//
// A capability's Kind gives policy a safe default — a read may be handed to an
// agent, a write may not.
package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

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

// Auth says which credential operation a service needs. It is what the broker
// dispatches on, so a new scheme is a catalogue entry rather than a branch in
// the request path.
type Auth int

const (
	// AuthToken substitutes a stored token. The simplest case, and the only one
	// where a long-lived secret reaches the wire.
	AuthToken Auth = iota
	// AuthSigV4 signs with a stored key pair. The credential is an HMAC over the
	// whole request, so it cannot be substituted.
	AuthSigV4
	// AuthGitHubApp mints a JWT from a stored private key and exchanges it for a
	// short-lived installation token.
	AuthGitHubApp
	// AuthOAuth2 refreshes a stored refresh token into a short-lived access
	// token, and substitutes that. The scheme most providers now want: X
	// recommends it over OAuth 1.0a and requires it for media upload, and
	// Google, Slack user tokens and Notion all use it.
	AuthOAuth2
)

func (a Auth) String() string {
	switch a {
	case AuthSigV4:
		return "sign (AWS SigV4)"
	case AuthGitHubApp:
		return "acquire (GitHub App installation token)"
	case AuthOAuth2:
		return "acquire (OAuth 2.0 refresh)"
	default:
		return "substitute (token)"
	}
}

// Fields are the credential fields a service needs, which `stk connect` prompts
// for and `Material.Require` checks.
func (a Auth) Fields() []string {
	switch a {
	case AuthSigV4:
		return []string{"access_key_id", "secret_access_key"}
	case AuthGitHubApp:
		return []string{"app_id", "installation_id", "private_key"}
	case AuthOAuth2:
		// client_secret is deliberately absent: a public client has none, and
		// Require would then reject a perfectly good connection.
		return []string{"client_id", "refresh_token"}
	default:
		return []string{"token"}
	}
}

// LongLivedOnTheWire reports whether this operation sends a long-lived secret.
// `stk doctor` shows it, because it is the difference that matters if a request
// is ever logged somewhere it should not be.
func (a Auth) LongLivedOnTheWire() bool { return a == AuthToken }

// Reassurance explains, accurately per scheme, what leaves the broker. Signing
// emits a signature rather than a credential, so one sentence cannot cover both
// without being wrong about one of them.
func (a Auth) Reassurance() string {
	switch a {
	case AuthSigV4:
		return "each request is signed in the broker; the stored key never goes on the wire"
	case AuthGitHubApp:
		return "the broker trades the stored key for a token that expires in an hour; the key never goes on the wire"
	case AuthOAuth2:
		return "the broker trades the stored refresh token for a short-lived access token; the refresh token only ever reaches the provider's token endpoint, never the API"
	default:
		return "the stored token is what goes on the wire, so treat it as long-lived"
	}
}

// Device describes a provider's device authorization grant, where it offers
// one. Without this a service can still be connected, just not from a machine
// with no browser.
type Device struct {
	AuthorizationURL string
	TokenURL         string
	// ClientID is the public identifier of our own OAuth app. It is not a
	// secret — the device grant exists precisely so a public client can
	// authenticate without one.
	ClientID string
	Scopes   []string
}

// Supported reports whether this service can be connected headlessly.
func (d Device) Supported() bool {
	return d.AuthorizationURL != "" && d.TokenURL != "" && d.ClientID != ""
}

// OAuth2 describes a provider's authorization-code endpoints.
//
// ClientID is empty in the catalogue for the same reason Device's is: a shared
// client id would make every installation look like the same app. The operator
// registers their own and names it in the committed policy file, where it is
// safe — a client id identifies an app and authorises nothing.
type OAuth2 struct {
	AuthorizeURL string
	TokenURL     string
	ClientID     string
	Scopes       []string
	// Confidential says the provider requires a client secret at the token
	// endpoint, which `stk connect --browser` then reads from stdin rather than
	// from the committed file.
	Confidential bool
	// RedirectURI, when set, is an already-registered callback to use instead
	// of the default. Always loopback. Set from the policy file, never here.
	RedirectURI string
}

// Supported reports whether the authorization-code path is configured.
func (o OAuth2) Supported() bool {
	return o.AuthorizeURL != "" && o.TokenURL != "" && o.ClientID != ""
}

// Hosts is every hostname the broker intercepts for this service.
func (e *Entry) Hosts() []string {
	return append([]string{e.Host}, e.AlsoHosts...)
}

// Param is one input to a capability.
type Param struct {
	Name     string
	Required bool
	// In says where the value goes. The zero value is InPath, which is the
	// strict case: a path parameter is validated against anything that could
	// change the shape of the request. A parameter that forgets to declare
	// itself is therefore treated as the most restricted kind, and the
	// catalogue's coherence test catches it for filling no hole in the path.
	In Where
	// Slashes allows `/` in the value. Only a parameter that genuinely names a
	// path may set it; everything else is a single segment.
	Slashes bool
	Summary string
}

// Where says which part of the request a parameter fills.
type Where int

const (
	// InPath substitutes into the path, and is validated strictly.
	InPath Where = iota
	// InBody becomes a field of a JSON body. A title or a message legitimately
	// contains spaces and punctuation, so body values are not path-validated —
	// they are encoded by the JSON marshaller, which cannot change the shape of
	// the request.
	InBody
	// InQuery becomes a query parameter, encoded by net/url.
	InQuery
)

// Capability is one thing a service can be asked to do.
type Capability struct {
	Name   string
	Kind   Kind
	Method string
	Path   string // may contain {name} placeholders matching Params
	// Host overrides the service's primary host for this one capability. A
	// provider split across hostnames — Sheets and Drive — needs it; everything
	// else leaves it empty.
	Host    string
	Summary string
	Params  []Param
}

// Entry is one service.
type Entry struct {
	Name string
	// Host is the hostname a capability's path is relative to, and the one the
	// broker intercepts by default.
	Host string
	// AlsoHosts are further hostnames this service's credential must work on,
	// and which the broker therefore also intercepts. A provider is not always
	// one host: Google's token endpoint, Sheets and Drive are three, and a
	// credential that only worked on one of them would not be connected.
	AlsoHosts []string
	// EnvVar is where a client expects to find its credential. `stk run` puts
	// the worthless placeholder here, so the client is configured normally and
	// never learns it is being brokered.
	EnvVar    string
	Placement Placement
	Field     string
	// Auth is the credential operation this service needs.
	Auth Auth
	// Device is the headless connect path, where the provider offers one.
	Device Device
	// OAuth2 is the authorization-code path, used when Auth is AuthOAuth2.
	OAuth2 OAuth2
	// RevokeURL is a provider endpoint that invalidates a token, where one
	// exists and we can reach it. Empty means we cannot revoke on the
	// operator's behalf, and `stk revoke` says so rather than implying the
	// credential is dead when it still works.
	RevokeURL string
	// RevokeAt is where a person can withdraw access themselves. It is always
	// set, because there is always somewhere — and it is what an operator needs
	// when a credential has leaked and the local copy is beside the point.
	RevokeAt string
	// Headers are static headers the request shape requires, independent of the
	// credential. Notion rejects any request without a dated Notion-Version,
	// which makes it part of the shape rather than something a caller should
	// have to know.
	Headers map[string]string
	// Region and AWSService are the SigV4 scope, used only when Auth is AuthSigV4.
	Region       string
	AWSService   string
	Capabilities []Capability
}

// builtin is deliberately short. Breadth is not the product: there are hundreds
// of MCP servers already, and an entry here is only needed where we front a
// service directly.
var builtin = map[string]*Entry{
	"aws-sts": {
		RevokeAt: "https://console.aws.amazon.com/iam/home#/security_credentials",
		// A deliberately read-only entry: GetCallerIdentity is the AWS
		// equivalent of "who am I", so a signing service can be connected and
		// verified without granting anything.
		Name: "aws-sts", Host: "sts.amazonaws.com", Auth: AuthSigV4,
		Region: "us-east-1", AWSService: "sts",
		Capabilities: []Capability{
			{
				Name: "whoami", Kind: Read, Method: "GET",
				Path:    "/?Action=GetCallerIdentity&Version=2011-06-15",
				Summary: "The identity the credentials belong to.",
			},
		},
	},
	"github-app": {
		RevokeAt: "https://github.com/settings/installations",
		Name:     "github-app", Host: "api.github.com", Auth: AuthGitHubApp,
		Capabilities: []Capability{
			{
				Name: "list_installation_repos", Kind: Read, Method: "GET",
				Path:    "/installation/repositories",
				Summary: "Repositories this installation can reach.",
			},
			{
				Name: "create_issue", Kind: Write, Method: "POST",
				Path:    "/repos/{owner}/{repo}/issues",
				Summary: "Open an issue as the app.",
				Params: []Param{
					{Name: "owner", Required: true},
					{Name: "repo", Required: true},
					{Name: "title", Required: true, In: InBody, Summary: "Issue title."},
				},
			},
		},
	},
	// --- X ---
	//
	// Checked against docs.x.com on 2026-10-15, because X's API changes often
	// and three things differ from what a stale memory would produce: the host
	// is api.x.com, media upload moved to /2/media/upload/{initialize,append,
	// finalize}, and that upload is OAuth 2.0 only — the OAuth 1.0a request is
	// still an open ask in X's own developer forum. Posting with an image is
	// therefore impossible on 1.0a, which is why this entry is OAuth 2.0.
	"x": {
		RevokeURL: "https://api.x.com/2/oauth2/revoke",
		RevokeAt:  "https://x.com/settings/connected_accounts",
		Name:      "x", Host: "api.x.com", EnvVar: "X_BEARER_TOKEN",
		Placement: BearerHeader, Auth: AuthOAuth2,
		OAuth2: OAuth2{
			AuthorizeURL: "https://x.com/i/oauth2/authorize",
			TokenURL:     "https://api.x.com/2/oauth2/token",
			// offline.access is what makes a refresh token available at all;
			// without it the connection dies in two hours and cannot recover.
			Scopes:       []string{"tweet.read", "tweet.write", "users.read", "media.write", "offline.access"},
			Confidential: true,
		},
		Capabilities: []Capability{
			{
				Name: "whoami", Kind: Read, Method: "GET", Path: "/2/users/me",
				Summary: "The authenticated account. The safe way to check a connection.",
			},
			{
				Name: "get_tweet", Kind: Read, Method: "GET", Path: "/2/tweets/{id}",
				Summary: "One post by id.",
				Params:  []Param{{Name: "id", Required: true}},
			},
			{
				Name: "search_recent", Kind: Read, Method: "GET", Path: "/2/tweets/search/recent",
				Summary: "Recent posts matching a query.",
			},
			{
				Name: "post_tweet", Kind: Write, Method: "POST", Path: "/2/tweets",
				Summary: "Publish a post. Public the moment it succeeds, so it defaults to approval.",
			},
			{
				// Deleting a published post cannot be undone: the id is gone,
				// and so are its replies and metrics.
				Name: "delete_tweet", Kind: Destructive, Method: "DELETE", Path: "/2/tweets/{id}",
				Summary: "Delete a post. Cannot be undone.",
				Params:  []Param{{Name: "id", Required: true}},
			},
			{
				Name: "media_init", Kind: Write, Method: "POST", Path: "/2/media/upload/initialize",
				Summary: "Begin a media upload. JSON body, not multipart.",
			},
			{
				Name: "media_append", Kind: Write, Method: "POST", Path: "/2/media/upload/{id}/append",
				Summary: "Upload one segment, 5 MB or less, multipart.",
				Params:  []Param{{Name: "id", Required: true}},
			},
			{
				Name: "media_finalize", Kind: Write, Method: "POST", Path: "/2/media/upload/{id}/finalize",
				Summary: "Complete a media upload.",
				Params:  []Param{{Name: "id", Required: true}},
			},
		},
	},
	// --- Slack ---
	"slack": {
		RevokeAt: "https://slack.com/apps/manage",
		Name:     "slack", Host: "slack.com", EnvVar: "SLACK_BOT_TOKEN",
		Placement: BearerHeader, Auth: AuthToken,
		Capabilities: []Capability{
			{
				Name: "auth_test", Kind: Read, Method: "POST", Path: "/api/auth.test",
				Summary: "Which workspace and identity this token belongs to.",
			},
			{
				Name: "list_channels", Kind: Read, Method: "GET", Path: "/api/conversations.list",
				Summary: "Channels the token can see.",
			},
			{
				Name: "post_message", Kind: Write, Method: "POST", Path: "/api/chat.postMessage",
				Summary: "Send a message to a channel.",
			},
			{
				// Slack deletions are not recoverable through the API.
				Name: "delete_message", Kind: Destructive, Method: "POST", Path: "/api/chat.delete",
				Summary: "Delete a message. Cannot be undone.",
			},
		},
	},
	// --- Notion ---
	//
	// Notion-Version is a dated header and a request without it is rejected;
	// 2026-03-11 is what developers.notion.com showed on 2026-10-15. It is the
	// kind of value that goes stale silently, so it lives here next to the
	// paths rather than in a client.
	"notion": {
		RevokeAt: "https://www.notion.so/my-integrations",
		Name:     "notion", Host: "api.notion.com", EnvVar: "NOTION_TOKEN",
		Placement: BearerHeader, Auth: AuthToken,
		Headers: map[string]string{"Notion-Version": "2026-03-11"},
		Capabilities: []Capability{
			{
				Name: "search", Kind: Read, Method: "POST", Path: "/v1/search",
				Summary: "Search pages and databases the integration can see.",
			},
			{
				Name: "get_page", Kind: Read, Method: "GET", Path: "/v1/pages/{page_id}",
				Summary: "One page's properties.",
				Params:  []Param{{Name: "page_id", Required: true}},
			},
			{
				Name: "create_page", Kind: Write, Method: "POST", Path: "/v1/pages",
				Summary: "Create a page.",
			},
			{
				Name: "append_blocks", Kind: Write, Method: "PATCH", Path: "/v1/blocks/{block_id}/children",
				Summary: "Append content to a page or block.",
				Params:  []Param{{Name: "block_id", Required: true}},
			},
		},
	},
	// --- Google ---
	//
	// The entry that needed AlsoHosts. A Google credential is refreshed at
	// oauth2.googleapis.com and spent at sheets.googleapis.com or
	// www.googleapis.com; intercepting only one of the three would leave the
	// others tunnelled and the placeholder would arrive unswapped.
	"google": {
		RevokeURL: "https://oauth2.googleapis.com/revoke",
		RevokeAt:  "https://myaccount.google.com/permissions",
		Name:      "google", Host: "sheets.googleapis.com",
		AlsoHosts: []string{"oauth2.googleapis.com", "www.googleapis.com"},
		EnvVar:    "GOOGLE_ACCESS_TOKEN",
		Placement: BearerHeader, Auth: AuthOAuth2,
		OAuth2: OAuth2{
			AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:     "https://oauth2.googleapis.com/token",
			Scopes: []string{
				"https://www.googleapis.com/auth/spreadsheets",
				"https://www.googleapis.com/auth/drive.file",
			},
			Confidential: true,
		},
		Capabilities: []Capability{
			{
				Name: "get_values", Kind: Read, Method: "GET",
				Path:    "/v4/spreadsheets/{spreadsheet_id}/values/{range}",
				Summary: "Read a range from a spreadsheet.",
				Params: []Param{
					{Name: "spreadsheet_id", Required: true},
					{Name: "range", Required: true},
				},
			},
			{
				Name: "append_values", Kind: Write, Method: "POST",
				Path:    "/v4/spreadsheets/{spreadsheet_id}/values/{range}:append",
				Summary: "Append rows to a spreadsheet.",
				Params: []Param{
					{Name: "spreadsheet_id", Required: true},
					{Name: "range", Required: true},
				},
			},
			{
				Name: "list_files", Kind: Read, Method: "GET", Path: "/drive/v3/files",
				Host:    "www.googleapis.com",
				Summary: "Files this credential can see in Drive.",
			},
		},
	},
	// --- Stripe ---
	//
	// The entry that keeps basic auth honest. Stripe sends the secret key as
	// the Basic username with an empty password, and scheme-aware substitution
	// — decode, replace, re-encode — is the only thing that works. A plain
	// string swap silently did nothing until a catalogue review caught it, so
	// a live connector now depends on it.
	"stripe": {
		RevokeAt: "https://dashboard.stripe.com/apikeys",
		Name:     "stripe", Host: "api.stripe.com", EnvVar: "STRIPE_SECRET_KEY",
		Placement: BasicHeader, Auth: AuthToken,
		Capabilities: []Capability{
			{
				Name: "get_balance", Kind: Read, Method: "GET", Path: "/v1/balance",
				Summary: "Account balance. The safe way to check a connection.",
			},
			{
				Name: "list_charges", Kind: Read, Method: "GET", Path: "/v1/charges",
				Summary: "Recent charges.",
			},
			{
				Name: "list_customers", Kind: Read, Method: "GET", Path: "/v1/customers",
				Summary: "Customers.",
			},
			{
				// A refund moves real money and Stripe cannot reverse it.
				Name: "create_refund", Kind: Destructive, Method: "POST", Path: "/v1/refunds",
				Summary: "Refund a charge. Moves money and cannot be reversed.",
			},
		},
	},
	// --- OpenAI ---
	"openai": {
		RevokeAt: "https://platform.openai.com/api-keys",
		Name:     "openai", Host: "api.openai.com", EnvVar: "OPENAI_API_KEY",
		Placement: BearerHeader, Auth: AuthToken,
		Capabilities: []Capability{
			{
				Name: "list_models", Kind: Read, Method: "GET", Path: "/v1/models",
				Summary: "Models this key can use.",
			},
			{
				// Billable, but nothing in the world changes and nothing needs
				// undoing, so it is a read by the only test that matters here.
				Name: "chat", Kind: Read, Method: "POST", Path: "/v1/chat/completions",
				Summary: "A completion. Billable, but changes nothing.",
			},
			{
				Name: "embeddings", Kind: Read, Method: "POST", Path: "/v1/embeddings",
				Summary: "Embeddings. Billable, but changes nothing.",
			},
		},
	},
	// --- Cloudflare ---
	"cloudflare": {
		RevokeAt: "https://dash.cloudflare.com/profile/api-tokens",
		Name:     "cloudflare", Host: "api.cloudflare.com", EnvVar: "CLOUDFLARE_API_TOKEN",
		Placement: BearerHeader, Auth: AuthToken,
		Capabilities: []Capability{
			{
				Name: "verify_token", Kind: Read, Method: "GET", Path: "/client/v4/user/tokens/verify",
				Summary: "Whether this token is valid, and what it can do.",
			},
			{
				Name: "list_zones", Kind: Read, Method: "GET", Path: "/client/v4/zones",
				Summary: "Zones this token can see.",
			},
			{
				Name: "list_dns_records", Kind: Read, Method: "GET",
				Path:    "/client/v4/zones/{zone_id}/dns_records",
				Summary: "DNS records in a zone.",
				Params:  []Param{{Name: "zone_id", Required: true}},
			},
			{
				Name: "create_dns_record", Kind: Write, Method: "POST",
				Path:    "/client/v4/zones/{zone_id}/dns_records",
				Summary: "Create a DNS record.",
				Params:  []Param{{Name: "zone_id", Required: true}},
			},
			{
				// Deleting a record can take a site off the internet, and the
				// record's content is not recoverable from the API afterwards.
				Name: "delete_dns_record", Kind: Destructive, Method: "DELETE",
				Path:    "/client/v4/zones/{zone_id}/dns_records/{id}",
				Summary: "Delete a DNS record. Can take a site offline.",
				Params: []Param{
					{Name: "zone_id", Required: true},
					{Name: "id", Required: true},
				},
			},
		},
	},
	// --- Resend ---
	//
	// Linear was the eighth candidate and is GraphQL-only: every call is
	// POST /graphql, so a method and a path cannot tell one capability from
	// another, and neither policy nor the audit ledger could name what
	// happened. That is a catalogue-model gap rather than a missing afternoon,
	// and it is recorded in docs/limitations.md. Resend takes the slot: REST,
	// and an agent that can send email is a real capability.
	"resend": {
		RevokeAt: "https://resend.com/api-keys",
		Name:     "resend", Host: "api.resend.com", EnvVar: "RESEND_API_KEY",
		Placement: BearerHeader, Auth: AuthToken,
		Capabilities: []Capability{
			{
				Name: "list_domains", Kind: Read, Method: "GET", Path: "/domains",
				Summary: "Sending domains. The safe way to check a connection.",
			},
			{
				Name: "get_email", Kind: Read, Method: "GET", Path: "/emails/{id}",
				Summary: "One sent email.",
				Params:  []Param{{Name: "id", Required: true}},
			},
			{
				// Sending cannot be recalled, and reaches someone who did not
				// ask this agent for anything.
				Name: "send_email", Kind: Destructive, Method: "POST", Path: "/emails",
				Summary: "Send an email. Cannot be recalled.",
			},
		},
	},
	"github": {
		RevokeAt: "https://github.com/settings/applications",
		Name:     "github", Host: "api.github.com", Placement: BearerHeader, EnvVar: "GH_TOKEN",
		Device: Device{
			AuthorizationURL: "https://github.com/login/device/code",
			TokenURL:         "https://github.com/login/oauth/access_token",
			// Replaced by the operator's own OAuth app id at configure time;
			// this placeholder makes the shape visible without pretending we
			// ship a working client id.
			ClientID: "",
			Scopes:   []string{"repo", "read:org"},
		},
		Capabilities: []Capability{
			{
				Name: "get_user", Kind: Read, Method: "GET", Path: "/user",
				Summary: "The authenticated user.",
			},
			{
				Name: "list_repos", Kind: Read, Method: "GET", Path: "/user/repos",
				Summary: "Repositories the authenticated user can see.",
			},
			{
				Name: "read_file", Kind: Read, Method: "GET",
				Path:    "/repos/{owner}/{repo}/contents/{path}",
				Summary: "One file's contents and metadata.",
				Params: []Param{
					{Name: "owner", Required: true, Summary: "Account or organisation."},
					{Name: "repo", Required: true, Summary: "Repository name."},
					{Name: "path", Required: true, Slashes: true, Summary: "Path inside the repository."},
				},
			},
			{
				Name: "create_issue", Kind: Write, Method: "POST",
				Path:    "/repos/{owner}/{repo}/issues",
				Summary: "Open an issue.",
				Params: []Param{
					{Name: "owner", Required: true},
					{Name: "repo", Required: true},
					{Name: "title", Required: true, In: InBody, Summary: "Issue title."},
				},
			},
			{
				Name: "delete_repo", Kind: Destructive, Method: "DELETE",
				Path:    "/repos/{owner}/{repo}",
				Summary: "Delete a repository. Cannot be undone.",
				Params: []Param{
					{Name: "owner", Required: true},
					{Name: "repo", Required: true},
				},
			},
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

// CapabilityFor names the capability a request represents, matching the
// method and the path against each capability's template.
//
// The proxy only ever sees a method and a path; the audit ledger wants the name
// an operator would recognise. Without this, an audit entry reads
// `POST /2/tweets` where it could read `post_tweet`, and the difference decides
// whether anyone reads the ledger at all.
func (e *Entry) CapabilityFor(method, path string) (Capability, bool) {
	for _, c := range e.Capabilities {
		if !strings.EqualFold(c.Method, method) {
			continue
		}
		if pathMatchesTemplate(path, c.Path) {
			return c, true
		}
	}
	return Capability{}, false
}

// pathMatchesTemplate compares a concrete path against one holding {name}
// segments. A template segment matches any single non-empty segment, which is
// enough because every catalogue path is a fixed shape — no wildcards, no
// optional tails.
func pathMatchesTemplate(path, template string) bool {
	// A shape may carry a literal query string, as the AWS STS action does.
	// The wire path never includes it, so compare paths only — otherwise STS
	// resolved to no capability at all and its audit entries read
	// "(not in the catalogue)".
	if i := strings.Index(template, "?"); i >= 0 {
		template = template[:i]
	}
	if i := strings.Index(path, "?"); i >= 0 {
		path = path[:i]
	}
	if template == path {
		return true
	}
	ps := strings.Split(strings.Trim(path, "/"), "/")
	ts := strings.Split(strings.Trim(template, "/"), "/")
	if len(ps) != len(ts) {
		return false
	}
	for i := range ts {
		if !segmentMatches(ps[i], ts[i]) {
			return false
		}
	}
	return true
}

// segmentMatches compares one path segment against one template segment.
//
// A template segment is not always either a literal or a bare {param}: Sheets
// appends an action to the parameter, as in `{range}:append`, so the parameter
// can carry a literal prefix and suffix that must both match.
func segmentMatches(got, template string) bool {
	open := strings.Index(template, "{")
	if open < 0 {
		return template == got
	}
	close := strings.Index(template[open:], "}")
	if close < 0 {
		return template == got
	}
	close += open
	prefix, suffix := template[:open], template[close+1:]
	if len(got) < len(prefix)+len(suffix)+1 {
		return false // the parameter would be empty
	}
	return strings.HasPrefix(got, prefix) && strings.HasSuffix(got, suffix)
}

// Names lists every known service.
func Names() []string {
	out := make([]string, 0, len(builtin))
	for n := range builtin {
		out = append(out, n)
	}
	return out
}

// Request builds the HTTP request for a capability.
//
// Parameter values arrive from a model, so each is validated before it is
// interpolated. Without that, a capability scoped to `/repos/{owner}/{repo}`
// could be walked out of its own scope with `../`, and the credential would be
// attached to wherever it landed.
func (e *Entry) Request(capability string, args map[string]string) (*http.Request, error) {
	c, ok := e.Capability(capability)
	if !ok {
		return nil, fmt.Errorf("service %q has no capability %q", e.Name, capability)
	}
	path := c.Path
	body := map[string]string{}
	extraQuery := url.Values{}
	for _, p := range c.Params {
		v, given := args[p.Name]
		if !given || v == "" {
			if p.Required {
				return nil, fmt.Errorf("%s/%s: parameter %q is required", e.Name, capability, p.Name)
			}
			continue
		}
		switch p.In {
		case InBody:
			body[p.Name] = v
		case InQuery:
			extraQuery.Set(p.Name, v)
		default:
			if err := validateParam(p, v); err != nil {
				return nil, fmt.Errorf("%s/%s: parameter %q: %w", e.Name, capability, p.Name, err)
			}
			path = strings.ReplaceAll(path, "{"+p.Name+"}", v)
		}
	}
	if i := strings.Index(path, "{"); i >= 0 {
		return nil, fmt.Errorf("%s/%s: unfilled parameter in path %q", e.Name, capability, path)
	}
	// A shape may carry a literal query string, as the AWS STS action does.
	query := ""
	if i := strings.Index(path, "?"); i >= 0 {
		path, query = path[:i], path[i+1:]
	}
	host := e.Host
	if c.Host != "" {
		host = c.Host
	}
	if len(extraQuery) > 0 {
		if query != "" {
			query += "&"
		}
		query += extraQuery.Encode()
	}
	u := &url.URL{Scheme: "https", Host: host, Path: path, RawQuery: query}

	// A write with no body is the bug this models away. `create_issue` declared
	// a required title and sent nothing, because the request was built with a
	// nil body and the value had nowhere to go — a value the contract did not
	// model vanished silently, and the provider answered 422.
	var reader io.Reader
	var encoded []byte
	if len(body) > 0 {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(c.Method, u.String(), reader)
	if err != nil {
		return nil, err
	}
	if encoded != nil {
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(encoded))
	}
	for k, v := range e.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

// validateParam rejects anything that would change the shape of the request
// rather than fill a hole in it.
func validateParam(p Param, v string) error {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains a control character")
		}
		switch r {
		case ' ', '?', '#', '%':
			return fmt.Errorf("contains %q, which would change the request shape", r)
		case '/':
			if !p.Slashes {
				return fmt.Errorf("contains a slash, but this parameter is a single segment")
			}
		}
	}
	// `..` is refused even where slashes are allowed: a path parameter may
	// descend, never ascend.
	for _, seg := range strings.Split(v, "/") {
		if seg == ".." {
			return fmt.Errorf("contains a %q segment", "..")
		}
	}
	if strings.HasPrefix(v, "/") {
		return fmt.Errorf("must not start with a slash")
	}
	return nil
}
