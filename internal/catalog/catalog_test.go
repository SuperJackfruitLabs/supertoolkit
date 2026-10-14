package catalog

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestRequestBuildsFromTheCatalogue(t *testing.T) {
	e, ok := Lookup("github")
	if !ok {
		t.Fatal("github not in the catalogue")
	}
	req, err := e.Request("get_user", nil)
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if req.Method != "GET" {
		t.Errorf("Method = %q, want GET", req.Method)
	}
	if got := req.URL.String(); got != "https://api.github.com/user" {
		t.Errorf("URL = %q, want https://api.github.com/user", got)
	}
}

func TestRequestSubstitutesPathParameters(t *testing.T) {
	e, _ := Lookup("github")
	req, err := e.Request("read_file", map[string]string{
		"owner": "SuperJackfruitLabs", "repo": "supertoolkit", "path": "README.md",
	})
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	want := "https://api.github.com/repos/SuperJackfruitLabs/supertoolkit/contents/README.md"
	if got := req.URL.String(); got != want {
		t.Errorf("URL = %q, want %q", got, want)
	}
}

func TestRequestRefusesMissingRequiredParameter(t *testing.T) {
	e, _ := Lookup("github")
	_, err := e.Request("read_file", map[string]string{"owner": "o"})
	if err == nil {
		t.Fatal("Request() with a missing parameter returned no error")
	}
	if !strings.Contains(err.Error(), "repo") {
		t.Errorf("error = %q, want it to name the missing parameter", err)
	}
}

func TestRequestRefusesUnknownCapability(t *testing.T) {
	e, _ := Lookup("github")
	if _, err := e.Request("not_a_capability", nil); err == nil {
		t.Fatal("Request() on an unknown capability returned no error")
	}
}

// A parameter reaches us from a model. Interpolating one into a path without
// checking it would let a capability scoped to `/repos/{owner}/{repo}` walk out
// of its own scope — and the credential would be attached to wherever it landed.
func TestRequestRefusesPathTraversalAndControlCharacters(t *testing.T) {
	e, _ := Lookup("github")
	for _, bad := range []string{
		"../../orgs/someone-else",
		"a/../../b",
		"with\nnewline",
		"with\rcarriage",
		"has space",
		"query?injected=1",
		"frag#ment",
		"", // empty is not a valid path segment either
	} {
		t.Run(bad, func(t *testing.T) {
			_, err := e.Request("read_file", map[string]string{
				"owner": "o", "repo": bad, "path": "README.md",
			})
			if err == nil {
				t.Fatalf("Request() accepted %q as a path parameter", bad)
			}
		})
	}
}

// The path itself may legitimately contain slashes, since a file path does.
// This asserts the distinction the guard has to make.
func TestRequestAllowsSlashesOnlyWhereTheShapeSaysSo(t *testing.T) {
	e, _ := Lookup("github")
	req, err := e.Request("read_file", map[string]string{
		"owner": "o", "repo": "r", "path": "docs/design.md",
	})
	if err != nil {
		t.Fatalf("a nested file path must be allowed: %v", err)
	}
	if !strings.HasSuffix(req.URL.String(), "/contents/docs/design.md") {
		t.Errorf("URL = %q, want the nested path preserved", req.URL.String())
	}
	// But the parameters that are not paths must still refuse a slash.
	if _, err := e.Request("read_file", map[string]string{
		"owner": "o/../x", "repo": "r", "path": "a",
	}); err == nil {
		t.Error("a slash in a non-path parameter must be refused")
	}
}

func TestCapabilityKindsAreDeclared(t *testing.T) {
	e, _ := Lookup("github")
	for _, c := range e.Capabilities {
		if c.Method == "" || c.Path == "" {
			t.Errorf("capability %q has no request shape", c.Name)
		}
		if c.Summary == "" {
			t.Errorf("capability %q has no summary, so an agent cannot choose it", c.Name)
		}
	}
}

func TestEveryServiceDeclaresItsOperationAndFields(t *testing.T) {
	for _, name := range Names() {
		e, _ := Lookup(name)
		if len(e.Auth.Fields()) == 0 {
			t.Errorf("service %q declares no credential fields", name)
		}
		if e.Auth.String() == "" {
			t.Errorf("service %q has no operation description", name)
		}
		if e.Auth == AuthSigV4 && (e.Region == "" || e.AWSService == "") {
			t.Errorf("service %q signs with SigV4 but declares no region or service scope", name)
		}
	}
}

// A shape may carry a literal query, which the AWS action needs.
func TestRequestKeepsALiteralQueryInTheShape(t *testing.T) {
	e, ok := Lookup("aws-sts")
	if !ok {
		t.Fatal("aws-sts missing from the catalogue")
	}
	req, err := e.Request("whoami", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.URL.Query().Get("Action"); got != "GetCallerIdentity" {
		t.Fatalf("Action = %q, want GetCallerIdentity (url = %s)", got, req.URL)
	}
}

// The reassurance shown to an operator must be true for each scheme. Signing
// emits a signature, not a short-lived credential, and saying otherwise would
// misdescribe what protects them.
func TestReassuranceIsAccuratePerScheme(t *testing.T) {
	if got := AuthSigV4.Reassurance(); strings.Contains(got, "token") {
		t.Errorf("SigV4 reassurance mentions a token: %q", got)
	}
	if got := AuthGitHubApp.Reassurance(); !strings.Contains(got, "expires") {
		t.Errorf("the acquiring reassurance should say the result expires: %q", got)
	}
	if got := AuthToken.Reassurance(); !strings.Contains(got, "long-lived") {
		t.Errorf("the token reassurance should warn it is long-lived: %q", got)
	}
	for _, a := range []Auth{AuthToken, AuthSigV4, AuthGitHubApp} {
		if a.Reassurance() == "" {
			t.Errorf("%v has no reassurance", a)
		}
	}
}

// Every entry is checked as data, because a catalogue is data and a wrong
// entry is a credential doing the wrong thing on an agent's say-so.
func TestEveryEntryIsCoherent(t *testing.T) {
	for _, name := range Names() {
		e, _ := Lookup(name)
		t.Run(name, func(t *testing.T) {
			if e.Host == "" {
				t.Error("no host: the broker would have nothing to intercept")
			}
			hosts := map[string]bool{}
			for _, h := range e.Hosts() {
				if strings.Contains(h, "/") || strings.Contains(h, ":") {
					t.Errorf("host %q is not a bare hostname", h)
				}
				hosts[h] = true
			}
			if len(e.Capabilities) == 0 {
				t.Error("no capabilities")
			}
			seen := map[string]bool{}
			for _, c := range e.Capabilities {
				if seen[c.Name] {
					t.Errorf("duplicate capability %q", c.Name)
				}
				seen[c.Name] = true

				switch c.Method {
				case "GET", "POST", "PUT", "PATCH", "DELETE":
				default:
					t.Errorf("%s: method %q", c.Name, c.Method)
				}
				if !strings.HasPrefix(c.Path, "/") {
					t.Errorf("%s: path %q does not start with /", c.Name, c.Path)
				}
				// A capability pointed at a host the broker does not intercept
				// would have its placeholder tunnelled out unswapped.
				if c.Host != "" && !hosts[c.Host] {
					t.Errorf("%s: host %q is not one this service intercepts %v", c.Name, c.Host, e.Hosts())
				}
				if c.Summary == "" {
					t.Errorf("%s: no summary, so the agent cannot tell what it does", c.Name)
				}
				// Every hole in the path has a path parameter, and every path
				// parameter fills a hole. Either mismatch is a request that
				// cannot be built, or a parameter that silently does nothing —
				// which is exactly how create_issue came to send no title.
				rest := c.Path
				for _, p := range c.Params {
					if p.In != InPath {
						if strings.Contains(c.Path, "{"+p.Name+"}") {
							t.Errorf("%s: parameter %q is in the path but declared elsewhere", c.Name, p.Name)
						}
						continue
					}
					if !strings.Contains(c.Path, "{"+p.Name+"}") {
						t.Errorf("%s: path parameter %q fills no hole in %q — declare it In: InBody or InQuery, or it will vanish", c.Name, p.Name, c.Path)
					}
					rest = strings.ReplaceAll(rest, "{"+p.Name+"}", "")
				}
				if strings.Contains(rest, "{") {
					t.Errorf("%s: path %q has a hole no parameter fills", c.Name, c.Path)
				}
				// A write that takes no arguments at all is suspicious: the
				// caller has no way to say what to write.
				if c.Kind != Read && len(c.Params) == 0 && !strings.Contains(c.Path, "{") {
					t.Logf("%s: a write with no parameters — the body comes from the caller, not the catalogue", c.Name)
				}
			}
		})
	}
}

// The test that ruled Linear out. Linear's API is GraphQL: every call is
// POST /graphql, so a method and a path cannot tell one capability from
// another — policy could not name what it was allowing and the audit ledger
// could not say what happened. Any entry with that shape fails here.
func TestNoTwoCapabilitiesAreIndistinguishableOnTheWire(t *testing.T) {
	for _, name := range Names() {
		e, _ := Lookup(name)
		for _, c := range e.Capabilities {
			// Build a concrete path the way a real request would look.
			concrete := c.Path
			for _, p := range c.Params {
				concrete = strings.ReplaceAll(concrete, "{"+p.Name+"}", "VALUE")
			}
			if i := strings.Index(concrete, "?"); i >= 0 {
				concrete = concrete[:i]
			}
			got, ok := e.CapabilityFor(c.Method, concrete)
			if !ok {
				t.Errorf("%s/%s: %s %s resolves to no capability", name, c.Name, c.Method, concrete)
				continue
			}
			if got.Name != c.Name {
				t.Errorf("%s: %s %s resolves to %q, not %q — the two are indistinguishable on the wire, so neither policy nor the audit ledger could tell them apart",
					name, c.Method, concrete, got.Name, c.Name)
			}
		}
	}
}

// A destructive capability is one an agent must never trigger alone, so the
// classification is load-bearing rather than documentation.
func TestDestructiveCapabilitiesNeverDefaultToTheAgent(t *testing.T) {
	for _, name := range Names() {
		e, _ := Lookup(name)
		for _, c := range e.Capabilities {
			if c.Kind == Read && destructiveSounding(c.Name) {
				t.Errorf("%s/%s is classified Read but reads like an irreversible effect", name, c.Name)
			}
		}
	}
}

func destructiveSounding(name string) bool {
	for _, w := range []string{"delete", "remove", "destroy", "refund", "send", "revoke", "purge"} {
		if strings.Contains(name, w) {
			return true
		}
	}
	return false
}

// A service whose auth is AuthOAuth2 must carry endpoints, or `stk connect
// --browser` has nothing to do and the service can never be connected at all.
func TestOAuth2ServicesCarryTheirEndpoints(t *testing.T) {
	for _, name := range Names() {
		e, _ := Lookup(name)
		if e.Auth != AuthOAuth2 {
			continue
		}
		if e.OAuth2.AuthorizeURL == "" || e.OAuth2.TokenURL == "" {
			t.Errorf("%s needs OAuth2 but has no endpoints", name)
		}
		if len(e.OAuth2.Scopes) == 0 {
			t.Errorf("%s requests no scopes", name)
		}
		// A refresh token is the whole point: without offline access the
		// connection dies and cannot recover itself.
		if name == "x" || name == "google" {
			var offline bool
			for _, sc := range e.OAuth2.Scopes {
				if strings.Contains(sc, "offline") {
					offline = true
				}
			}
			if !offline && name == "x" {
				t.Errorf("%s does not request offline access, so the connection cannot refresh itself", name)
			}
		}
	}
}

// The bug this models away: create_issue declared a required title and sent
// nothing. Request() built every request with a nil body, so a value the
// contract did not model vanished silently and GitHub answered 422.
func TestBodyParametersReachTheRequest(t *testing.T) {
	e, _ := Lookup("github")
	req, err := e.Request("create_issue", map[string]string{
		"owner": "SuperJackfruitLabs", "repo": "supertoolkit",
		"title": "A title with spaces, punctuation & a ? in it",
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.Body == nil {
		t.Fatal("the request has no body, so the title was dropped")
	}
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("the body is not JSON: %q", raw)
	}
	if got["title"] != "A title with spaces, punctuation & a ? in it" {
		t.Errorf("title = %q, want it verbatim — a body value is encoded by JSON, not path-validated", got["title"])
	}
	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	// ContentLength must be set, or a provider behind a proxy that requires it
	// rejects the request.
	if req.ContentLength != int64(len(raw)) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(raw))
	}
	// The path is unaffected: a body parameter must not leak into it.
	if strings.Contains(req.URL.Path, "title") || strings.Contains(req.URL.RawQuery, "title") {
		t.Errorf("the title reached the URL: %s", req.URL)
	}
}

// A path parameter stays strict: it is the one that could change the shape of
// the request.
func TestPathParametersAreStillValidatedStrictly(t *testing.T) {
	e, _ := Lookup("github")
	for _, bad := range []string{"../../etc", "a b", "a?b", "a#b", "a%2f"} {
		if _, err := e.Request("create_issue", map[string]string{
			"owner": bad, "repo": "r", "title": "t",
		}); err == nil {
			t.Errorf("owner %q was accepted into the path", bad)
		}
	}
}

// Notion rejects any request without a dated version header, which makes it
// part of the request shape rather than something a caller must remember.
func TestStaticHeadersAreAppliedFromTheCatalogue(t *testing.T) {
	e, _ := Lookup("notion")
	req, err := e.Request("search", nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := req.Header.Get("Notion-Version"); v == "" {
		t.Fatal("no Notion-Version header; Notion rejects the request")
	}
}

// Google is the entry that needed more than one host.
func TestMultiHostServiceTargetsTheRightHostPerCapability(t *testing.T) {
	e, _ := Lookup("google")
	sheets, err := e.Request("get_values", map[string]string{"spreadsheet_id": "sid", "range": "A1:B2"})
	if err != nil {
		t.Fatal(err)
	}
	if sheets.URL.Host != "sheets.googleapis.com" {
		t.Errorf("get_values host = %q", sheets.URL.Host)
	}
	drive, err := e.Request("list_files", nil)
	if err != nil {
		t.Fatal(err)
	}
	if drive.URL.Host != "www.googleapis.com" {
		t.Errorf("list_files host = %q, want the override", drive.URL.Host)
	}
	// And the broker must intercept all three, or a placeholder is tunnelled
	// out unswapped.
	hosts := e.Hosts()
	for _, want := range []string{"sheets.googleapis.com", "oauth2.googleapis.com", "www.googleapis.com"} {
		var found bool
		for _, h := range hosts {
			if h == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not intercepted; its traffic would be tunnelled", want)
		}
	}
}
