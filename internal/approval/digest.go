package approval

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
)

// DigestSchema names the canonical encoding below. It is the first field
// hashed, so a digest from another encoding can never collide with one of these.
const DigestSchema = "stk-capability/v1"

// CapabilityRequest is the exact request an approval binds: what a person is
// shown and what stk will send. Its digest is computed when the effect is
// submitted and computed again from the request actually about to be sent, and
// the two must be equal or nothing is sent.
type CapabilityRequest struct {
	Service    string
	Capability string
	Profile    string
	// Method, URL and Body are the built request. A fronted MCP server's tool
	// call has no HTTP request: its Method is "MCP" and its URL names the tool.
	Method string
	URL    string
	Body   []byte
	Args   map[string]string
}

// Digest is "sha256:" and the hex SHA-256 of a length-prefixed encoding:
// every field is written as label then value, each preceded by its length as a
// big-endian uint64, so no two field boundaries are ambiguous. The fields, in
// order: schema, service, capability, profile, method, url, body, the number of
// arguments, then each argument as label "arg:<name>" in byte order of name.
func (r CapabilityRequest) Digest() string {
	h := sha256.New()
	write := func(label string, value []byte) {
		_ = binary.Write(h, binary.BigEndian, uint64(len(label)))
		_, _ = h.Write([]byte(label))
		_ = binary.Write(h, binary.BigEndian, uint64(len(value)))
		_, _ = h.Write(value)
	}
	write("schema", []byte(DigestSchema))
	write("service", []byte(r.Service))
	write("capability", []byte(r.Capability))
	write("profile", []byte(r.Profile))
	write("method", []byte(r.Method))
	write("url", []byte(r.URL))
	write("body", r.Body)
	keys := make([]string, 0, len(r.Args))
	for k := range r.Args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	_ = binary.Write(h, binary.BigEndian, uint64(len(keys)))
	for _, k := range keys {
		write("arg:"+k, []byte(r.Args[k]))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// HTTPCapabilityRequest describes a built request without consuming its body.
func HTTPCapabilityRequest(service, capability, profile string, args map[string]string, req *http.Request) (CapabilityRequest, error) {
	r := CapabilityRequest{Service: service, Capability: capability, Profile: profile,
		Method: req.Method, URL: req.URL.String(), Args: args}
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return r, errors.New("the request body cannot be read twice, so it cannot be bound to an approval")
		}
		body, err := req.GetBody()
		if err != nil {
			return r, err
		}
		defer body.Close()
		if r.Body, err = io.ReadAll(body); err != nil {
			return r, err
		}
	}
	return r, nil
}

// ToolCapabilityRequest describes a fronted MCP server's tool call.
func ToolCapabilityRequest(server, tool, profile string, args map[string]string) CapabilityRequest {
	return CapabilityRequest{Service: server, Capability: tool, Profile: profile,
		Method: "MCP", URL: "mcp://" + server + "/" + tool, Args: args}
}

// DigestMismatchError says the request about to be sent is not the one that
// was approved. Nothing is sent.
type DigestMismatchError struct{ Approved, Actual string }

func (e DigestMismatchError) Error() string {
	if e.Approved == "" {
		return "the approval carries no request digest, so it cannot be bound to a request; nothing was sent — ask again"
	}
	return fmt.Sprintf("the request is not the one approved (approved %s, now %s); nothing was sent", e.Approved, e.Actual)
}

// VerifyDigest refuses unless the effect's stored digest equals the digest of
// the request about to be performed. An effect with no digest is refused too:
// it was submitted by an stk that did not bind requests, and its approval
// cannot say what it approved.
func VerifyDigest(e *Effect, actual CapabilityRequest) error {
	got := actual.Digest()
	if e.RequestDigest != got { // got is never empty, so a missing digest never matches
		return DigestMismatchError{Approved: e.RequestDigest, Actual: got}
	}
	return nil
}
