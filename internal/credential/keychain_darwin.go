//go:build darwin

package credential

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// keychainAvailable reports whether the OS keychain can be used.
func keychainAvailable() bool {
	_, err := exec.LookPath("security")
	return err == nil
}

// keychainName is the service name the key is filed under.
const keychainName = "supertoolkit-store-key"

// keychainGet reads the store key from the macOS keychain.
//
// The keychain is better than a file beside the ciphertext because unsealing it
// requires the user's own authentication, so reading the encrypted credentials
// is no longer enough to decrypt them.
func keychainGet(account string) (string, error) {
	cmd := exec.Command("security", "find-generic-password", "-s", keychainName, "-a", account, "-w")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("keychain: %s", strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// keychainPut stores the store key, replacing any previous entry.
//
// The value is passed with -w on the argument list, which is visible in the
// process table for the moment the command runs. That is a real, narrow
// exposure and is accepted here because the alternative — a temporary file —
// trades it for a worse one. It happens once, at `stk init`.
func keychainPut(account, secret string) error {
	cmd := exec.Command("security", "add-generic-password",
		"-s", keychainName, "-a", account, "-w", secret, "-U")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("keychain: %s", strings.TrimSpace(errb.String()))
	}
	return nil
}
