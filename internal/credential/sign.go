package credential

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// SignSigV4 signs a request with AWS Signature Version 4.
//
// This is the operation that cannot be a substitution. A SigV4 credential is not
// a value sitting in a header to be swapped: it is an HMAC over the method, the
// URI, the query string, the signed headers and the SHA-256 of the body. Change
// one byte of the body and the signature changes, so the only way to broker such
// a service is to hold the key and sign inside the broker.
//
// The secret access key is used here and never written to the request. What goes
// on the wire is the access key id, which is public, plus a signature.
func SignSigV4(req *http.Request, m Material, region, service string, now time.Time) error {
	return signSigV4For(req, m, region, service, now, nil)
}

// signSigV4For is SignSigV4 with an explicit signed-header list, which exists so
// the test can reproduce AWS's published vector — that vector signs only host
// and x-amz-date, while this implementation also sends x-amz-content-sha256.
func signSigV4For(req *http.Request, m Material, region, service string, now time.Time, only []string) error {
	if err := m.Require(FieldAccessKeyID, FieldSecretAccessKey); err != nil {
		return fmt.Errorf("sigv4: %w", err)
	}
	access := m[FieldAccessKeyID]
	secret := m[FieldSecretAccessKey]

	body, err := readAndRestoreBody(req)
	if err != nil {
		return fmt.Errorf("sigv4: reading the body to sign it: %w", err)
	}
	payloadHash := sha256Hex(body)

	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if req.Header.Get("Host") == "" && req.Host == "" {
		req.Host = req.URL.Host
	}
	// The payload hash is part of the signature for most services and is
	// conventionally sent, so a proxy cannot alter the body unnoticed.
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signed, canonHeaders := canonicalHeaders(req, only)
	canonRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req),
		canonicalQuery(req),
		canonHeaders,
		signed,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonRequest)),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secret), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		access, scope, signed, signature))
	return nil
}

// readAndRestoreBody reads the body for hashing and puts it back, so the caller
// can still send it.
func readAndRestoreBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	raw, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	req.ContentLength = int64(len(raw))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	return raw, nil
}

func canonicalURI(req *http.Request) string {
	p := req.URL.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}

func canonicalQuery(req *http.Request) string {
	q := req.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, awsEscape(k)+"="+awsEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

// awsEscape is RFC 3986 unreserved-only escaping, which is stricter than
// url.QueryEscape — notably a space is %20 and not +.
func awsEscape(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func canonicalHeaders(req *http.Request, only []string) (signedList, canonical string) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "authorization", "user-agent", "content-length":
			// Excluded by convention: a proxy or client may alter them.
			continue
		}
		vals := make([]string, 0, len(vs))
		for _, v := range vs {
			vals = append(vals, strings.Join(strings.Fields(v), " "))
		}
		headers[lk] = strings.Join(vals, ",")
	}
	if len(only) > 0 {
		keep := map[string]bool{}
		for _, n := range only {
			keep[strings.ToLower(n)] = true
		}
		for k := range headers {
			if !keep[k] {
				delete(headers, k)
			}
		}
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(headers[n])
		b.WriteByte('\n')
	}
	return strings.Join(names, ";"), b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
