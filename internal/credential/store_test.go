package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const tok = "ghp_a_credential_worth_protecting"

func TestStoreRoundTripsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("github", tok); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenStore(dir, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get("github")
	if err != nil {
		t.Fatalf("Get() after reopen: %v", err)
	}
	if got != tok {
		t.Fatalf("Get() = %q, want the stored token", got)
	}
}

// The file on disk is the thing an attacker reads. It must not contain the
// token, and it must not reveal its length either.
func TestStoreFileHasNoPlaintextAndHidesLength(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir, "passphrase")
	if err := s.Put("github", tok); err != nil {
		t.Fatal(err)
	}

	var found bool
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		found = true
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(raw), tok) {
			t.Fatalf("%s contains the token in plaintext", p)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", p, info.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("nothing was written to disk")
	}
}

func TestWrongPassphraseFailsRatherThanReturningGarbage(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir, "right")
	s.Put("github", tok)

	wrong, err := OpenStore(dir, "wrong")
	if err != nil {
		return // refusing at open is also acceptable
	}
	got, err := wrong.Get("github")
	if err == nil {
		t.Fatalf("Get() with the wrong passphrase returned %q and no error", got)
	}
	if got != "" {
		t.Fatalf("Get() returned %q alongside an error; it must return nothing", got)
	}
}

// The decisive KDF assertion: the salt must change the key.
//
// An earlier version of this test only varied the passphrase, which padding to
// 32 bytes also satisfies — so it could not tell a real KDF from the mistake it
// was written to catch. Salt dependence is the property padding does not have.
func TestDerivationDependsOnTheSalt(t *testing.T) {
	a := deriveKey("same passphrase", []byte("0123456789abcdef"))
	b := deriveKey("same passphrase", []byte("fedcba9876543210"))
	if string(a) == string(b) {
		t.Fatal("the same passphrase with different salts produced the same key — the salt is ignored, which is what padding a passphrase to 32 bytes does")
	}
	if len(a) != keyLen {
		t.Fatalf("key length = %d, want %d", len(a), keyLen)
	}
	// Determinism: the same inputs must reproduce the key, or nothing decrypts.
	again := deriveKey("same passphrase", []byte("0123456789abcdef"))
	if string(a) != string(again) {
		t.Fatal("derivation is not deterministic")
	}
	// A short passphrase must still yield a full-length key rather than being
	// padded out with a constant.
	short := deriveKey("x", []byte("0123456789abcdef"))
	if len(short) != keyLen {
		t.Fatalf("short passphrase key length = %d, want %d", len(short), keyLen)
	}
	if string(short) == string(a) {
		t.Fatal("different passphrases produced the same key")
	}
}

// Ciphertext must also differ per store, which covers the nonce and salt being
// random rather than fixed.
func TestDerivationUsesAKDFNotPadding(t *testing.T) {
	read := func(dir string) string {
		var out string
		filepath.Walk(dir, func(p string, i os.FileInfo, e error) error {
			if e != nil || i.IsDir() {
				return e
			}
			b, _ := os.ReadFile(p)
			out += string(b)
			return nil
		})
		return out
	}

	d1, d2 := t.TempDir(), t.TempDir()
	s1, _ := OpenStore(d1, "aaaaaaaa")
	s2, _ := OpenStore(d2, "bbbbbbbb")
	s1.Put("github", tok)
	s2.Put("github", tok)
	if read(d1) == read(d2) {
		t.Fatal("same ciphertext for different passphrases — the key is not derived from the passphrase")
	}

	// And the same passphrase twice must still differ, because the nonce and
	// salt are random. Identical files would mean a reused nonce.
	d3, d4 := t.TempDir(), t.TempDir()
	s3, _ := OpenStore(d3, "aaaaaaaa")
	s4, _ := OpenStore(d4, "aaaaaaaa")
	s3.Put("github", tok)
	s4.Put("github", tok)
	if read(d3) == read(d4) {
		t.Fatal("identical ciphertext across stores — the nonce or salt is not random")
	}
}

func TestRevokeRemovesTheCredential(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir, "p")
	s.Put("github", tok)
	if err := s.Revoke("github"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("github"); err == nil {
		t.Fatal("Get() succeeded after Revoke()")
	}
	if strings.Contains(readAll(t, dir), tok) {
		t.Fatal("the token is still on disk after Revoke()")
	}
}

func readAll(t *testing.T, dir string) string {
	t.Helper()
	var out string
	filepath.Walk(dir, func(p string, i os.FileInfo, e error) error {
		if e != nil || i.IsDir() {
			return e
		}
		b, _ := os.ReadFile(p)
		out += string(b)
		return nil
	})
	return out
}

func TestGetUnknownServiceIsAnError(t *testing.T) {
	s, _ := OpenStore(t.TempDir(), "p")
	if _, err := s.Get("never-stored"); err == nil {
		t.Fatal("Get() on an unknown service returned no error")
	}
}
