package broker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA signs the short-lived leaf certificates the broker presents to clients for
// hosts it intercepts. The private key never leaves this process and is written
// with owner-only permissions.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// NewCA creates a certificate authority.
func NewCA(commonName string, lifetime time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"supertoolkit"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(lifetime),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, leafs: map[string]*tls.Certificate{}}, nil
}

// LoadOrCreateCA returns the install's one certificate authority, creating it
// on first use.
//
// The CA used to be minted per session and written to a path shared by the
// whole install, which three commands did independently — `stk init`,
// `stk run` and `stk doctor --probe`. Each overwrote the others. Two parallel
// `stk run` invocations left the first one's child trusting a CA that had not
// signed its broker's leaf, and the certificate `stk init` tells an operator to
// trust in their keychain for Go clients was destroyed by the very first run.
//
// So there is one CA per install and it persists, which also makes trusting it
// a thing worth doing. The private key is written owner-only beside the
// credentials: anyone who can read it can impersonate the hosts this broker
// intercepts, which is the same reach as reading the credential store itself.
func LoadOrCreateCA(dir, commonName string, lifetime time.Duration) (*CA, error) {
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca.key")

	certPEM, cerr := os.ReadFile(certPath)
	keyPEM, kerr := os.ReadFile(keyPath)
	if cerr == nil && kerr == nil {
		ca, err := parseCA(certPEM, keyPEM)
		switch {
		case err != nil:
			// Unreadable is treated as absent rather than fatal: a half-written
			// pair should be replaced, not turned into a permanently broken
			// install. The operator re-trusts the new one.
		case time.Now().After(ca.cert.NotAfter.Add(-renewWithin(lifetime))):
			// Close enough to expiry to replace now rather than mid-session.
		default:
			return ca, nil
		}
	}

	ca, err := NewCA(commonName, lifetime)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	// The key first, owner-only: a certificate on disk without its key is
	// merely useless, while the reverse ordering could expose a key before its
	// permissions are set.
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	if _, err := ca.WriteCert(dir); err != nil {
		return nil, err
	}
	return ca, nil
}

// renewWithin is how long before expiry a stored CA is replaced.
//
// A tenth of its lifetime, capped at a day. A fixed day would have replaced any
// CA whose whole life was shorter than that — every time it was loaded, so it
// would never be stable at all.
func renewWithin(lifetime time.Duration) time.Duration {
	d := lifetime / 10
	if d > 24*time.Hour {
		d = 24 * time.Hour
	}
	return d
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("ca: not a PEM pair")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("ca: the stored key does not match the stored certificate")
	}
	return &CA{cert: cert, key: key, leafs: map[string]*tls.Certificate{}}, nil
}

// CertPEM is the certificate clients must trust. Only the public half.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})
}

// WriteCert writes the public certificate for clients to trust, and returns its
// path. The private key is never written by this method.
func (c *CA) WriteCert(dir string) (string, error) {
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, c.CertPEM(), 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// Pool is the CA as a trust pool, for wiring our own clients in tests.
func (c *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(c.cert)
	return p
}

// LeafForTest mints a leaf, for tests that need to stand up a provider signed
// by a CA of their own. Production code uses leafFor through the handshake path.
func (c *CA) LeafForTest(host string) (*tls.Certificate, error) { return c.leafFor(host) }

// leafFor mints, and then reuses, a leaf for one hostname.
func (c *CA) leafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if l, ok := c.leafs[host]; ok {
		return l, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("minting a leaf for %s: %w", host, err)
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}
	c.leafs[host] = leaf
	return leaf, nil
}
