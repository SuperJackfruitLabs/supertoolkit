package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

// Store holds credentials on disk, encrypted with a key derived from a
// passphrase.
//
// Two decisions matter here. The key is derived with **Argon2id**, not by
// padding or truncating the passphrase to 32 bytes — that approach leaves a weak
// passphrase weak, and it is a mistake already present elsewhere in this estate.
// And the plaintext is padded to a fixed block before sealing, so the file does
// not reveal how long a token is.
type Store struct {
	dir  string
	key  []byte
	salt []byte
}

const (
	saltLen  = 16
	keyLen   = 32
	padBlock = 256 // tokens are padded up to a multiple of this, hiding length
)

// Argon2id parameters. Deliberately modest, because this runs on a laptop at
// every broker start, not once at login.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
)

// OpenStore opens, or creates, a credential store.
func OpenStore(dir, passphrase string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	saltPath := filepath.Join(dir, "salt")
	salt, err := os.ReadFile(saltPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		if err := os.WriteFile(saltPath, salt, 0o600); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir, key: deriveKey(passphrase, salt), salt: salt}, nil
}

// deriveKey turns a passphrase into an encryption key.
//
// Exported-for-test via the package boundary on purpose: the property that
// distinguishes a real KDF from padding a passphrase to 32 bytes is that the
// **salt changes the key**. Padding ignores the salt, so a test that only varies
// the passphrase cannot tell the two apart.
func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, keyLen)
}

func (s *Store) path(service string) string {
	// Service names come from the catalogue, not from user input, but Base
	// keeps a traversal out of the path regardless.
	return filepath.Join(s.dir, filepath.Base(service)+".cred")
}

type sealed struct {
	Nonce []byte `json:"nonce"`
	Data  []byte `json:"data"`
}

// Put stores a single-token credential, replacing any previous one.
func (s *Store) Put(service, secret string) error {
	return s.PutMaterial(service, Material{FieldToken: secret})
}

// PutMaterial stores a credential of any shape.
func (s *Store) PutMaterial(service string, m Material) error {
	if len(m) == 0 {
		return fmt.Errorf("refusing to store an empty credential for %q", service)
	}
	blob, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.putSealed(service, string(blob))
}

func (s *Store) putSealed(service, secret string) error {
	out, err := s.seal(service, secret)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path(service), []byte(out))
}

// writeFileAtomic replaces path with data so that a concurrent reader sees the
// old file or the new one, never a truncated or half-written one. The proxy
// reads the credential on every request, so a replace that truncates first
// fails a call that was perfectly authorised.
func writeFileAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// seal encrypts with the store's key, binding the result to `aad`.
//
// The additional data is what stops one sealed value being substituted for
// another: a cached access token sealed under a different aad cannot be moved
// into a credential file and opened there.
func (s *Store) seal(aad, secret string) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	// Length hiding: prefix the real length, then pad to a block boundary.
	raw := []byte(secret)
	total := ((len(raw)+4)/padBlock + 1) * padBlock
	plain := make([]byte, total)
	plain[0] = byte(len(raw) >> 24)
	plain[1] = byte(len(raw) >> 16)
	plain[2] = byte(len(raw) >> 8)
	plain[3] = byte(len(raw))
	copy(plain[4:], raw)
	if _, err := io.ReadFull(rand.Reader, plain[4+len(raw):]); err != nil {
		return "", err
	}

	out, err := json.Marshal(sealed{Nonce: nonce, Data: aead.Seal(nil, nonce, plain, []byte(aad))})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// open reverses seal. A value sealed under a different aad will not open.
func (s *Store) open(aad, envelope string) (string, error) {
	var env sealed
	if err := json.Unmarshal([]byte(envelope), &env); err != nil {
		return "", fmt.Errorf("sealed value is corrupt: %w", err)
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := aead.Open(nil, env.Nonce, env.Data, []byte(aad))
	if err != nil {
		// A wrong passphrase lands here. Return nothing alongside the error:
		// a partial or garbage value is worse than none.
		return "", fmt.Errorf("could not decrypt: wrong passphrase, or the store was tampered with")
	}
	if len(plain) < 4 {
		return "", fmt.Errorf("sealed value is truncated")
	}
	n := int(plain[0])<<24 | int(plain[1])<<16 | int(plain[2])<<8 | int(plain[3])
	if n < 0 || 4+n > len(plain) {
		return "", fmt.Errorf("sealed value has an invalid length header")
	}
	return string(plain[4 : 4+n]), nil
}

// Get returns a single-token credential.
//
// Along with Material, this is the only path that produces a secret, and it is
// reachable only from the broker's own executor — never from a request handler,
// and never over any socket.
func (s *Store) Get(service string) (string, error) {
	m, err := s.Material(service)
	if err != nil {
		return "", err
	}
	if t := m.Token(); t != "" {
		return t, nil
	}
	return "", fmt.Errorf("the credential for %q is not a token: it holds %v", service, m.Fields())
}

// Material returns a stored credential of any shape.
//
// A credential written by an older single-token store still reads, as
// {"token": ...}, so an existing install keeps working.
func (s *Store) Material(service string) (Material, error) {
	raw, err := s.getSealed(service)
	if err != nil {
		return nil, err
	}
	var m Material
	if err := json.Unmarshal([]byte(raw), &m); err != nil || m == nil {
		// Not JSON: a credential from before material was typed. Treat the
		// whole value as the token rather than failing on it.
		return Material{FieldToken: raw}, nil
	}
	if len(m) == 0 {
		// An empty map would read as "no credential needed", which is worse
		// than an error.
		return nil, fmt.Errorf("the credential for %q is empty", service)
	}
	return m, nil
}

func (s *Store) getSealed(service string) (string, error) {
	raw, err := os.ReadFile(s.path(service))
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no credential stored for %q: run `stk connect %s`", service, service)
		}
		return "", err
	}
	out, err := s.open(service, string(raw))
	if err != nil {
		return "", fmt.Errorf("credential for %q: %w", service, err)
	}
	return out, nil
}

// Revoke deletes a stored credential.
func (s *Store) Revoke(service string) error {
	err := os.Remove(s.path(service))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Fields lists the field names a stored credential has, decrypting only to read
// the names. Names only — never values, which is what makes this safe to show.
func (s *Store) Fields(service string) []string {
	m, err := s.Material(service)
	if err != nil {
		return nil
	}
	return m.Fields()
}

// Has reports whether a credential is stored, without decrypting it.
func (s *Store) Has(service string) bool {
	_, err := os.Stat(s.path(service))
	return err == nil
}
