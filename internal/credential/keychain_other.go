//go:build !darwin

package credential

import "fmt"

// No OS keychain is wired on this platform yet, so the file fallback is used
// and `stk doctor` says so rather than implying protection that is not there.
// Linux Secret Service is the obvious next one.
func keychainAvailable() bool { return false }

func keychainGet(string) (string, error) { return "", fmt.Errorf("no keychain on this platform") }

func keychainPut(string, string) error { return fmt.Errorf("no keychain on this platform") }
