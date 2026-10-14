package catalog

import (
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
