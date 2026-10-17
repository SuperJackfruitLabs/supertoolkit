package handover

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
)

func material() credential.Material {
	return credential.Material{
		credential.FieldAccessKeyID:     "AKIAEXAMPLE",
		credential.FieldSecretAccessKey: "the-secret-that-must-not-travel-in-clear",
	}
}

func TestSealedMaterialOpensOnlyWithTheBrokersKey(t *testing.T) {
	dir := t.TempDir()
	broker, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(broker.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(pub, material())
	if err != nil {
		t.Fatal(err)
	}

	// The envelope must not carry the secret in the clear.
	if strings.Contains(env, "the-secret-that-must-not-travel-in-clear") {
		t.Fatal("the envelope contains the secret in plaintext")
	}

	got, err := broker.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	if got[credential.FieldSecretAccessKey] != material()[credential.FieldSecretAccessKey] {
		t.Fatalf("the material did not survive: %v", got.Fields())
	}

	// A different broker must not be able to open it.
	other, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(env); err == nil {
		t.Fatal("another broker opened the envelope")
	}
}

// A tampered envelope must fail rather than yield partial material.
func TestTamperedEnvelopeFailsClosed(t *testing.T) {
	broker, _ := Load(t.TempDir())
	pub, _ := ParsePublicKey(broker.PublicKey())
	env, _ := Seal(pub, material())

	body := strings.TrimPrefix(env, prefix)
	flipped := prefix + "A" + body[1:]
	if m, err := broker.Open(flipped); err == nil {
		t.Fatalf("a tampered envelope opened and returned %v", m.Fields())
	}
	if _, err := broker.Open(prefix + "not-base64!!"); err == nil {
		t.Fatal("rubbish opened")
	}
	if _, err := broker.Open("no-prefix"); err == nil {
		t.Fatal("an envelope with no prefix opened")
	}
}

func TestKeypairIsStableAndOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey() != b.PublicKey() {
		t.Fatal("the key changed between loads; envelopes would stop opening")
	}
	fi, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", fi.Mode().Perm())
	}
	// The private half must not be in what we publish.
	raw, _ := os.ReadFile(filepath.Join(dir, keyFile))
	if strings.Contains(a.PublicKey(), string(raw[:10])) {
		t.Error("the published key resembles the stored file")
	}
}

func TestEmptyMaterialIsRefused(t *testing.T) {
	broker, _ := Load(t.TempDir())
	pub, _ := ParsePublicKey(broker.PublicKey())
	if _, err := Seal(pub, credential.Material{}); err == nil {
		t.Fatal("an empty credential was sealed")
	}
}

func TestPublicKeyIsRecognisable(t *testing.T) {
	broker, _ := Load(t.TempDir())
	k := broker.PublicKey()
	if !strings.HasPrefix(k, "stk-handover-v1:") {
		t.Errorf("PublicKey() = %q, want a prefix someone can recognise", k)
	}
	if _, err := ParsePublicKey("ssh-rsa AAAA"); err == nil {
		t.Error("an unrelated key was accepted")
	}
}

// vectorFile is the conformance vector for stk-handover-v1. An independent
// implementation (agentpod seals from TypeScript) must be able to produce an
// envelope this code opens, and open the one recorded here. The private key is
// a test fixture and protects nothing.
type vectorFile struct {
	PublicKey  string            `json:"public_key"`
	PrivateKey string            `json:"private_key"`
	Material   map[string]string `json:"material"`
	Envelope   string            `json:"envelope"`
}

func loadVector(t *testing.T) (*Keypair, vectorFile) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "handover-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	priv, err := base64.RawURLEncoding.DecodeString(v.PrivateKey)
	if err != nil || len(priv) != 32 {
		t.Fatalf("private_key is not 32 bytes of base64url: %v", err)
	}
	kp := &Keypair{priv: new([32]byte), pub: new([32]byte)}
	copy(kp.priv[:], priv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(kp.pub[:], pub)
	return kp, v
}

func TestHandoverV1Vector(t *testing.T) {
	kp, v := loadVector(t)
	if kp.PublicKey() != v.PublicKey {
		t.Errorf("PublicKey() = %q, want the recorded %q", kp.PublicKey(), v.PublicKey)
	}
	got, err := kp.Open(v.Envelope)
	if err != nil {
		t.Fatalf("the recorded envelope does not open: %v", err)
	}
	if len(got) != len(v.Material) {
		t.Fatalf("material has %d fields, want %d", len(got), len(v.Material))
	}
	for k, want := range v.Material {
		if got[k] != want {
			t.Errorf("field %q = %q, want %q", k, got[k], want)
		}
	}
}

func TestVectorKeyOpensAFreshSeal(t *testing.T) {
	kp, v := loadVector(t)
	pub, err := ParsePublicKey(v.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(pub, credential.Material(v.Material))
	if err != nil {
		t.Fatal(err)
	}
	if env == v.Envelope {
		t.Error("two seals produced the same envelope: the ephemeral key is not fresh")
	}
	if _, err := kp.Open(env); err != nil {
		t.Errorf("a fresh envelope does not open with the vector key: %v", err)
	}
}
