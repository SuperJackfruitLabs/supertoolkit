package approval

import (
	"bytes"
	"context"
	"net/http"
	"testing"
)

func baseRequest() CapabilityRequest {
	return CapabilityRequest{Service: "github", Capability: "create_issue", Profile: "writer",
		Method: "POST", URL: "https://api.github.com/repos/o/r/issues", Body: []byte(`{"title":"t"}`),
		Args: map[string]string{"owner": "o", "repo": "r", "title": "t"}}
}

// Every field the approval binds must change the digest, or a request that
// differs in that field would pass as the approved one.
func TestDigestBindsEveryField(t *testing.T) {
	base := baseRequest().Digest()
	mutations := map[string]func(*CapabilityRequest){
		"service":    func(r *CapabilityRequest) { r.Service = "gitlab" },
		"capability": func(r *CapabilityRequest) { r.Capability = "close_issue" },
		"profile":    func(r *CapabilityRequest) { r.Profile = "" },
		"method":     func(r *CapabilityRequest) { r.Method = "PUT" },
		"url":        func(r *CapabilityRequest) { r.URL = "https://api.github.com/repos/o/other/issues" },
		"body":       func(r *CapabilityRequest) { r.Body = []byte(`{"title":"u"}`) },
		"arg value":  func(r *CapabilityRequest) { r.Args = map[string]string{"owner": "o", "repo": "r", "title": "u"} },
		"extra arg": func(r *CapabilityRequest) {
			r.Args = map[string]string{"owner": "o", "repo": "r", "title": "t", "x": ""}
		},
	}
	for name, mutate := range mutations {
		r := baseRequest()
		mutate(&r)
		if r.Digest() == base {
			t.Errorf("changing the %s left the digest unchanged", name)
		}
	}
}

// Length prefixes keep field boundaries unambiguous.
func TestDigestBoundariesAreUnambiguous(t *testing.T) {
	a := CapabilityRequest{Args: map[string]string{"a": "bc"}}
	b := CapabilityRequest{Args: map[string]string{"ab": "c"}}
	if a.Digest() == b.Digest() {
		t.Fatal(`args {"a":"bc"} and {"ab":"c"} share a digest`)
	}
	c := CapabilityRequest{Service: "gi", Capability: "thub"}
	d := CapabilityRequest{Service: "git", Capability: "hub"}
	if c.Digest() == d.Digest() {
		t.Fatal("service/capability boundary is ambiguous")
	}
}

func TestHTTPCapabilityRequestLeavesTheBodyReadable(t *testing.T) {
	req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://api.github.com/repos/o/r/issues", bytes.NewReader([]byte(`{"title":"t"}`)))
	got, err := HTTPCapabilityRequest("github", "create_issue", "writer", map[string]string{"owner": "o", "repo": "r", "title": "t"}, req)
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest() != baseRequest().Digest() {
		t.Fatal("the HTTP form and the literal form of one request disagree")
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(req.Body)
	if buf.String() != `{"title":"t"}` {
		t.Fatalf("describing the request consumed its body: %q", buf.String())
	}
}

func TestVerifyDigestRefusesMissingAndDifferent(t *testing.T) {
	r := baseRequest()
	if err := VerifyDigest(&Effect{RequestDigest: r.Digest()}, r); err != nil {
		t.Fatalf("the same request was refused: %v", err)
	}
	if err := VerifyDigest(&Effect{}, r); err == nil {
		t.Fatal("an effect with no digest was accepted")
	}
	other := baseRequest()
	other.URL += "?x=1"
	if err := VerifyDigest(&Effect{RequestDigest: r.Digest()}, other); err == nil {
		t.Fatal("a different request was accepted")
	}
}
