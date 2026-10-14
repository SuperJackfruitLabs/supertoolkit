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
	"strings"
	"testing"
	"time"
)

func testKeyPEM(t *testing.T, pkcs8 bool) (string, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var der []byte
	typ := "RSA PRIVATE KEY"
	if pkcs8 {
		der, err = x509.MarshalPKCS8PrivateKey(k)
		typ = "PRIVATE KEY"
		if err != nil {
			t.Fatal(err)
		}
	} else {
		der = x509.MarshalPKCS1PrivateKey(k)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})), k
}

func TestMintedJWTVerifiesAgainstThePublicKey(t *testing.T) {
	for _, pkcs8 := range []bool{false, true} {
		name := "pkcs1"
		if pkcs8 {
			name = "pkcs8"
		}
		t.Run(name, func(t *testing.T) {
			keyPEM, key := testKeyPEM(t, pkcs8)
			tok, err := MintJWT(Material{FieldPrivateKey: keyPEM}, map[string]any{"iss": "123456"}, 9*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(tok, ".")
			if len(parts) != 3 {
				t.Fatalf("token has %d parts, want 3", len(parts))
			}
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
				t.Fatalf("the minted JWT does not verify: %v", err)
			}
		})
	}
}

// iat must be in the past, because a provider with a slightly slower clock
// rejects a token issued in its future.
func TestMintedJWTHasATolerantIssuedAtAndABoundedLifetime(t *testing.T) {
	keyPEM, _ := testKeyPEM(t, false)
	tok, err := MintJWT(Material{FieldPrivateKey: keyPEM}, nil, 9*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	json.Unmarshal(payload, &claims)

	iat := int64(claims["iat"].(float64))
	exp := int64(claims["exp"].(float64))
	now := time.Now().Unix()
	if iat > now {
		t.Errorf("iat %d is in the future; a provider with a slower clock would refuse it", iat)
	}
	if now-iat > 120 {
		t.Errorf("iat %d is more than two minutes old", iat)
	}
	if exp <= now {
		t.Error("exp is already past")
	}
	if exp-now > 600 {
		t.Errorf("the token lives %ds, which is longer than requested", exp-now)
	}
}

func TestMintRefusesBadKeyMaterial(t *testing.T) {
	for name, m := range map[string]Material{
		"missing":   {},
		"not pem":   {FieldPrivateKey: "just a string"},
		"empty pem": {FieldPrivateKey: "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----"},
	} {
		t.Run(name, func(t *testing.T) {
			if tok, err := MintJWT(m, nil, time.Minute); err == nil {
				t.Fatalf("MintJWT() returned %q with %s key material", tok, name)
			}
		})
	}
}

// The minted token must not be, or contain, the key it was signed with.
func TestMintedJWTDoesNotContainTheKey(t *testing.T) {
	keyPEM, _ := testKeyPEM(t, false)
	tok, err := MintJWT(Material{FieldPrivateKey: keyPEM}, nil, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tok, "PRIVATE KEY") {
		t.Fatal("the token contains PEM text")
	}
	// Compare on the base64 body of the key, since whitespace differs.
	body := strings.ReplaceAll(strings.Join(strings.Split(keyPEM, "\n")[1:], ""), "-", "")
	if len(body) > 40 && strings.Contains(tok, body[:40]) {
		t.Fatal("the token contains key material")
	}
}

func TestMintErrorDoesNotLeakTheKey(t *testing.T) {
	keyPEM, _ := testKeyPEM(t, false)
	// An ECDSA key in PKCS#8 is valid PEM but wrong for RS256.
	_, err := MintJWT(Material{FieldPrivateKey: strings.Replace(keyPEM, "RSA PRIVATE KEY", "PRIVATE KEY", 2)}, nil, time.Minute)
	if err == nil {
		return // accepted as PKCS#8 RSA, which is fine
	}
	if strings.Contains(err.Error(), "MII") {
		t.Fatalf("the error contains key material: %v", err)
	}
}
