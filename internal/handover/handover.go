// Package handover moves a credential from a machine that has a browser to a
// broker that does not, without anything in between being able to read it.
//
// This is the last of the three headless paths and the only one where the
// credential exists, briefly, somewhere other than the provider and the broker.
// That cost is stated by the commands that use it rather than hidden, because a
// fallback that hides what it gives up is worse than one that admits it.
//
// The broker publishes a public key. The operator's machine seals the material
// to it. Only the broker's private key opens the result — not a hub, not us,
// not anything the envelope passes through.
package handover

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/nacl/box"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
)

const (
	keyFile = "handover.key"
	prefix  = "stk-handover-v1:"
)

// Keypair is the broker's hand-over identity.
type Keypair struct {
	pub  *[32]byte
	priv *[32]byte
}

// Load reads the broker's keypair, creating one on first use.
func Load(dir string) (*Keypair, error) {
	p := filepath.Join(dir, keyFile)
	raw, err := os.ReadFile(p)
	if err == nil {
		var k struct{ Pub, Priv []byte }
		if err := json.Unmarshal(raw, &k); err != nil {
			return nil, fmt.Errorf("the hand-over key is unreadable: %w", err)
		}
		if len(k.Pub) != 32 || len(k.Priv) != 32 {
			return nil, fmt.Errorf("the hand-over key is the wrong size")
		}
		kp := &Keypair{pub: new([32]byte), priv: new([32]byte)}
		copy(kp.pub[:], k.Pub)
		copy(kp.priv[:], k.Priv)
		return kp, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	out, _ := json.Marshal(struct{ Pub, Priv []byte }{pub[:], priv[:]})
	if err := os.WriteFile(p, out, 0o600); err != nil {
		return nil, err
	}
	return &Keypair{pub: pub, priv: priv}, nil
}

// PublicKey is what the operator's machine needs, and is safe to print, paste
// or send over any channel.
func (k *Keypair) PublicKey() string {
	return prefix + base64.RawURLEncoding.EncodeToString(k.pub[:])
}

// ParsePublicKey reads a published key.
func ParsePublicKey(s string) (*[32]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("that is not a supertoolkit hand-over key")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, prefix))
	if err != nil {
		return nil, fmt.Errorf("the key is not valid base64")
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("the key is %d bytes, want 32", len(raw))
	}
	var pub [32]byte
	copy(pub[:], raw)
	return &pub, nil
}

// Seal encrypts material to a broker's public key.
//
// Anonymous sealed boxes: the sender needs no key of their own, and the
// envelope names neither party.
func Seal(pub *[32]byte, m credential.Material) (string, error) {
	if len(m) == 0 {
		return "", fmt.Errorf("refusing to seal an empty credential")
	}
	plain, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sealed, err := box.SealAnonymous(nil, plain, pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts an envelope.
//
// A tampered envelope fails rather than yielding partial material: NaCl's box
// is authenticated, so there is no half-open to return.
func (k *Keypair) Open(envelope string) (credential.Material, error) {
	envelope = strings.TrimSpace(envelope)
	if !strings.HasPrefix(envelope, prefix) {
		return nil, fmt.Errorf("that is not a supertoolkit hand-over envelope")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, prefix))
	if err != nil {
		return nil, fmt.Errorf("the envelope is not valid base64")
	}
	plain, ok := box.OpenAnonymous(nil, raw, k.pub, k.priv)
	if !ok {
		return nil, fmt.Errorf("the envelope does not open: it was sealed to a different broker, or it was altered")
	}
	var m credential.Material
	if err := json.Unmarshal(plain, &m); err != nil {
		return nil, fmt.Errorf("the envelope held something that is not a credential")
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("the envelope held an empty credential")
	}
	return m, nil
}
