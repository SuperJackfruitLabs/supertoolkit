package credential

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// AWS's own published vector (aws-sig-v4-test-suite, get-vanilla). Testing
// against their expected output rather than ours means the test cannot pass by
// agreeing with a mistake of our own.
const (
	vecAccess    = "AKIDEXAMPLE"
	vecSecret    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	vecRegion    = "us-east-1"
	vecService   = "service"
	vecSignature = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
)

func vecTime(t *testing.T) time.Time {
	t.Helper()
	ts, err := time.Parse("20060102T150405Z", "20150830T123600Z")
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestSigV4MatchesAWSPublishedVector(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	req.Host = "example.amazonaws.com"

	m := Material{FieldAccessKeyID: vecAccess, FieldSecretAccessKey: vecSecret}
	// The vector signs only host and x-amz-date, so the extra content-sha256
	// header this implementation adds is excluded for the comparison.
	if err := signSigV4For(req, m, vecRegion, vecService, vecTime(t), []string{"host", "x-amz-date"}); err != nil {
		t.Fatal(err)
	}
	got := req.Header.Get("Authorization")
	if !strings.Contains(got, "Signature="+vecSignature) {
		t.Fatalf("Authorization = %q\nwant signature %s", got, vecSignature)
	}
	if !strings.Contains(got, "SignedHeaders=host;x-amz-date") {
		t.Errorf("SignedHeaders wrong in %q", got)
	}
}

// The property that makes substitution impossible: the body is signed.
func TestSigV4SignatureCoversTheBody(t *testing.T) {
	sigFor := func(body string) string {
		req, _ := http.NewRequest("POST", "https://example.amazonaws.com/", strings.NewReader(body))
		req.Host = "example.amazonaws.com"
		m := Material{FieldAccessKeyID: vecAccess, FieldSecretAccessKey: vecSecret}
		if err := SignSigV4(req, m, vecRegion, vecService, vecTime(t)); err != nil {
			t.Fatal(err)
		}
		return req.Header.Get("Authorization")
	}
	a := sigFor(`{"a":1}`)
	b := sigFor(`{"a":2}`)
	if a == b {
		t.Fatal("one byte of body change did not change the signature; the body is not being signed")
	}
}

// And the body must still be sendable after being read for hashing.
func TestSigV4LeavesTheBodyReadable(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.amazonaws.com/", strings.NewReader("payload"))
	req.Host = "example.amazonaws.com"
	m := Material{FieldAccessKeyID: vecAccess, FieldSecretAccessKey: vecSecret}
	if err := SignSigV4(req, m, vecRegion, vecService, vecTime(t)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _ := req.Body.Read(buf)
	if string(buf[:n]) != "payload" {
		t.Fatalf("body after signing = %q, want %q", string(buf[:n]), "payload")
	}
	if req.ContentLength != 7 {
		t.Errorf("ContentLength = %d, want 7", req.ContentLength)
	}
}

// The secret access key is used and never sent.
func TestSigV4NeverPutsTheSecretOnTheWire(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/path?b=2&a=1", nil)
	req.Host = "example.amazonaws.com"
	m := Material{FieldAccessKeyID: vecAccess, FieldSecretAccessKey: vecSecret}
	if err := SignSigV4(req, m, vecRegion, vecService, vecTime(t)); err != nil {
		t.Fatal(err)
	}
	for name, vs := range req.Header {
		for _, v := range vs {
			if strings.Contains(v, vecSecret) {
				t.Fatalf("header %q contains the secret access key", name)
			}
		}
	}
	if strings.Contains(req.URL.String(), vecSecret) {
		t.Fatal("the URL contains the secret access key")
	}
	// The access key id is public and is expected.
	if !strings.Contains(req.Header.Get("Authorization"), vecAccess) {
		t.Error("Authorization should carry the access key id")
	}
}

func TestSigV4RefusesIncompleteMaterial(t *testing.T) {
	for _, m := range []Material{
		{},
		{FieldAccessKeyID: vecAccess},
		{FieldSecretAccessKey: vecSecret},
	} {
		req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
		if err := SignSigV4(req, m, vecRegion, vecService, vecTime(t)); err == nil {
			t.Fatalf("SignSigV4() signed with incomplete material %v", m.Fields())
		}
		if got := req.Header.Get("Authorization"); got != "" {
			t.Errorf("a failed signing left an Authorization header: %q", got)
		}
	}
}

func TestSigV4QueryIsCanonicallyOrdered(t *testing.T) {
	// Two requests differing only in query order must sign identically.
	sig := func(u string) string {
		req, _ := http.NewRequest("GET", u, nil)
		req.Host = "example.amazonaws.com"
		m := Material{FieldAccessKeyID: vecAccess, FieldSecretAccessKey: vecSecret}
		SignSigV4(req, m, vecRegion, vecService, vecTime(t))
		return req.Header.Get("Authorization")
	}
	if sig("https://example.amazonaws.com/?a=1&b=2") != sig("https://example.amazonaws.com/?b=2&a=1") {
		t.Fatal("query parameter order changed the signature; it must be canonicalised")
	}
}
