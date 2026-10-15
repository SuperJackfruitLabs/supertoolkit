package broker

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// One CA per install, not per session.
//
// It used to be minted per session and written to a path the whole install
// shared, which three commands did independently. Two parallel `stk run`
// invocations left the first one's child trusting a CA that had not signed its
// broker's leaf — a loud TLS failure with no obvious cause — and the
// certificate `stk init` tells an operator to trust for Go clients was
// destroyed by the very first run.
func TestTheCAIsStableAcrossSessions(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreateCA(dir, "test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateCA(dir, "test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.CertPEM(), b.CertPEM()) {
		t.Fatal("a second session minted a different CA; the first session's children would stop trusting their own broker")
	}

	// A leaf from one must verify against the other's pool, which is the
	// property a child actually depends on.
	leaf, err := a.leafFor("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: b.Pool(), DNSName: "api.github.com"}); err != nil {
		t.Fatalf("a leaf from one session does not verify against another's CA: %v", err)
	}
}

func TestTheCAKeyIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateCA(dir, "test CA", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Anyone who can read this key can impersonate every intercepted host.
	fi, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode = %o, want 600", fi.Mode().Perm())
	}
	// The certificate is public and must stay readable by clients.
	fi, err = os.Stat(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o044 == 0 {
		t.Errorf("ca.pem mode = %o; clients must be able to read it", fi.Mode().Perm())
	}
}

// A mismatched pair must be replaced rather than used, and must not make the
// install permanently broken.
func TestAMismatchedCAPairIsReplaced(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateCA(dir, "test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the key with one from a different CA.
	other := t.TempDir()
	if _, err := LoadOrCreateCA(other, "other CA", time.Hour); err != nil {
		t.Fatal(err)
	}
	k, _ := os.ReadFile(filepath.Join(other, "ca.key"))
	os.WriteFile(filepath.Join(dir, "ca.key"), k, 0o600)

	got, err := LoadOrCreateCA(dir, "test CA", time.Hour)
	if err != nil {
		t.Fatalf("a mismatched pair made the install unusable: %v", err)
	}
	if bytes.Equal(got.CertPEM(), first.CertPEM()) {
		t.Error("the mismatched certificate was kept")
	}
	// And the replacement is self-consistent.
	if _, err := got.leafFor("api.github.com"); err != nil {
		t.Errorf("the replacement CA cannot mint a leaf: %v", err)
	}
}

// A CA whose whole lifetime is shorter than the renewal window would be
// replaced on every load and never be stable at all.
func TestRenewalWindowScalesWithLifetime(t *testing.T) {
	cases := []struct {
		lifetime time.Duration
		want     time.Duration
	}{
		{365 * 24 * time.Hour, 24 * time.Hour},         // capped at a day
		{48 * time.Hour, 4*time.Hour + 48*time.Minute}, // a tenth, under the cap
		{time.Hour, 6 * time.Minute},                   // a tenth
		{10 * time.Minute, time.Minute},                // a tenth
	}
	for _, c := range cases {
		if got := renewWithin(c.lifetime); got != c.want {
			t.Errorf("renewWithin(%v) = %v, want %v", c.lifetime, got, c.want)
		}
		if got := renewWithin(c.lifetime); got >= c.lifetime {
			t.Errorf("renewWithin(%v) = %v, which is the whole life — it would never be stable", c.lifetime, got)
		}
	}
}

// One that really is near expiry must be replaced.
func TestAnExpiringCAIsReplaced(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreateCA(dir, "test CA", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite it as something that expires in thirty seconds.
	short, err := NewCA("test CA", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalECPrivateKey(short.key)
	os.WriteFile(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "ca.pem"), short.CertPEM(), 0o644)

	got, err := LoadOrCreateCA(dir, "test CA", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got.CertPEM(), short.CertPEM()) {
		t.Error("a CA expiring in thirty seconds was kept; it would expire mid-session")
	}
	if bytes.Equal(got.CertPEM(), first.CertPEM()) {
		t.Error("unexpectedly reused the original")
	}
}
