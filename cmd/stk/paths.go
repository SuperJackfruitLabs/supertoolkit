package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// home is where supertoolkit keeps local state: the CA, the salt, the sealed
// credentials. Never the config file, which belongs in the project and is
// committed.
func home() (string, error) {
	if d := os.Getenv("STK_HOME"); d != "" {
		return d, os.MkdirAll(d, 0o700)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(base, "supertoolkit")
	return d, os.MkdirAll(d, 0o700)
}

// configPath is the committed policy file, looked for in the working directory.
func configPath() string {
	if p := os.Getenv("STK_CONFIG"); p != "" {
		return p
	}
	return "supertoolkit.yaml"
}

// passphrase returns the key material for the credential store.
//
// Phase 0 keeps a machine key in a 0600 file beside the ciphertext, which is a
// real weakness and is reported by `stk doctor` rather than hidden: anything
// that can read one file can read the other. The Phase 1 answer is the OS
// keychain — macOS Keychain, Windows Credential Manager, Linux Secret Service —
// which requires system authentication to unseal.
func passphrase(dir string) (string, bool, error) {
	if p := os.Getenv("STK_PASSPHRASE"); p != "" {
		return p, false, nil
	}
	p := filepath.Join(dir, "machine.key")
	b, err := os.ReadFile(p)
	if err == nil {
		return string(b), true, nil
	}
	if !os.IsNotExist(err) {
		return "", false, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", false, err
	}
	key := base64.StdEncoding.EncodeToString(raw)
	if err := os.WriteFile(p, []byte(key), 0o600); err != nil {
		return "", false, fmt.Errorf("writing the machine key: %w", err)
	}
	return key, true, nil
}
