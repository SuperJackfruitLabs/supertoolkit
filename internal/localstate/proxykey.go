package localstate

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	ProxyKeyFile  = "proxy.key"
	ProxyAddrFile = "proxy.addr"
)

// LoadOrCreateProxyKey returns this install's proxy key, creating it on first
// use.
//
// The key is what stops another local process using a fixed loopback proxy as
// a credential-injecting relay, so the file holding it is held to the same
// standard as the credential store: owner-only, and refused outright if it is
// anything wider rather than quietly tightened — a key a second user could
// already read is a key that must be rotated, not repaired.
func LoadOrCreateProxyKey(dir string) (string, error) {
	path := filepath.Join(dir, ProxyKeyFile)
	if key, err := ReadProxyKey(path); !errors.Is(err, os.ErrNotExist) {
		return key, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key := base64.RawURLEncoding.EncodeToString(buf)
	// Written to a private temp file and linked into place, so a reader never
	// sees a partial key and two first runs cannot overwrite each other.
	tmp, err := writeTemp0600(dir, ProxyKeyFile, []byte(key))
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ReadProxyKey(path) // lost the race; use the winner's
		}
		return "", err
	}
	return key, nil
}

func ReadProxyKey(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file; refusing to use it as the proxy key", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s has mode %04o; it must be 0600 or stricter. Delete it to have a new key generated, then restart the proxy",
			path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(b))
	if raw, err := base64.RawURLEncoding.DecodeString(key); err != nil || len(raw) != 32 {
		return "", fmt.Errorf("%s is not a valid proxy key; delete it to have a new one generated", path)
	}
	return key, nil
}

// writeTemp0600 writes data to a new 0600 file beside its destination.
func writeTemp0600(dir, name string, data []byte) (tmp string, err error) {
	f, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(f.Name())
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err = f.Write(data); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// writeAtomic0600 replaces path with data, readers seeing the old or new file.
func writeAtomic0600(path string, data []byte) error {
	tmp, err := writeTemp0600(filepath.Dir(path), filepath.Base(path), data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// WriteProxyAddr records where the fixed proxy listens, and which process owns
// it, for `stk env`. Two lines: the address, then the pid.
func WriteProxyAddr(dir, addr string) error {
	return WriteProxyAddrPID(dir, addr, os.Getpid())
}

func WriteProxyAddrPID(dir, addr string, pid int) error {
	return writeAtomic0600(filepath.Join(dir, ProxyAddrFile), []byte(fmt.Sprintf("%s\n%d\n", addr, pid)))
}

func RemoveProxyAddr(dir string) { os.Remove(filepath.Join(dir, ProxyAddrFile)) }
