package credential

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeySource says where the store key came from, so doctor can be honest about
// how well protected the credentials actually are.
type KeySource string

const (
	// KeyFromEnv is an operator-supplied passphrase.
	KeyFromEnv KeySource = "STK_PASSPHRASE"
	// KeyFromKeychain is the OS keychain, which needs the user's own
	// authentication to unseal.
	KeyFromKeychain KeySource = "os keychain"
	// KeyFromFile is a machine key beside the ciphertext. Anything that can
	// read one file can read the other, so this is reported as a weakness.
	KeyFromFile KeySource = "file beside the ciphertext"
)

// StoreKey finds or creates the key for the credential store, preferring the
// strongest source available.
func StoreKey(dir string) (string, KeySource, error) {
	if p := os.Getenv("STK_PASSPHRASE"); p != "" {
		return p, KeyFromEnv, nil
	}
	if k, ok, err := passphraseFile(); err != nil {
		return "", "", err
	} else if ok {
		return k, KeyFromCredentialFile, nil
	}
	account := accountName(dir)
	if keychainAvailable() {
		if k, err := keychainGet(account); err == nil && k != "" {
			return k, KeyFromKeychain, nil
		}
		k, err := newKey()
		if err != nil {
			return "", "", err
		}
		if err := keychainPut(account, k); err == nil {
			return k, KeyFromKeychain, nil
		}
		// The keychain refused — fall through to the file rather than failing,
		// and let doctor report which one is in use.
	}
	p := filepath.Join(dir, "machine.key")
	if b, err := os.ReadFile(p); err == nil {
		return string(b), KeyFromFile, nil
	} else if !os.IsNotExist(err) {
		return "", "", err
	}
	k, err := newKey()
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(p, []byte(k), 0o600); err != nil {
		return "", "", fmt.Errorf("writing the machine key: %w", err)
	}
	return k, KeyFromFile, nil
}

// passphraseFile reads a passphrase handed over as a file: STK_PASSPHRASE_FILE
// if set, else systemd's $CREDENTIALS_DIRECTORY/stk-passphrase. A file that is
// named but unreadable is an error rather than a fall back, because a
// different key would silently open (or create) a different store.
func passphraseFile() (string, bool, error) {
	path := os.Getenv("STK_PASSPHRASE_FILE")
	named := path != ""
	if !named {
		cd := os.Getenv("CREDENTIALS_DIRECTORY")
		if cd == "" {
			return "", false, nil
		}
		path = filepath.Join(cd, "stk-passphrase")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !named && os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading the passphrase file: %w", err)
	}
	k := strings.TrimSuffix(string(b), "\n")
	if strings.TrimSpace(k) == "" {
		return "", false, fmt.Errorf("the passphrase file %s is blank", path)
	}
	return k, true, nil
}

// accountName keys the keychain entry by directory, so two workspaces on one
// machine do not share a store key.
func accountName(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	return abs
}

func newKey() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// KeyFromCredentialFile is a passphrase file handed over by the service
// manager (systemd LoadCredential) or named by STK_PASSPHRASE_FILE.
const KeyFromCredentialFile KeySource = "passphrase file"
