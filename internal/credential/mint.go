package credential

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// MintJWT signs a short-lived JWT with a stored private key.
//
// The private key never leaves the broker; what goes on the wire is a token
// valid for minutes. So a credential that leaks downstream expires on its own,
// which is the property that makes this operation preferable to handing out a
// long-lived secret.
//
// `iat` is set slightly in the past on purpose: GitHub rejects a JWT whose
// issued-at time is ahead of its own clock, and a few seconds of drift between
// a laptop and a provider is normal.
func MintJWT(m Material, claims map[string]any, ttl time.Duration) (string, error) {
	if err := m.Require(FieldPrivateKey); err != nil {
		return "", fmt.Errorf("mint: %w", err)
	}
	key, err := parseRSAPrivateKey(m[FieldPrivateKey])
	if err != nil {
		return "", fmt.Errorf("mint: %w", err)
	}
	now := time.Now()
	all := map[string]any{
		"iat": now.Add(-30 * time.Second).Unix(),
		"exp": now.Add(ttl).Unix(),
	}
	for k, v := range claims {
		all[k] = v
	}

	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(all)
	if err != nil {
		return "", err
	}
	signingInput := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("mint: signing: %w", err)
	}
	return signingInput + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// parseRSAPrivateKey accepts both PKCS#1 and PKCS#8, because providers hand out
// both and an operator should not have to know which they were given.
func parseRSAPrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("the private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the private key is neither PKCS#1 nor PKCS#8: %w", err)
	}
	k, ok := any.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("the private key is not RSA (%T); RS256 needs RSA", any)
	}
	return k, nil
}
