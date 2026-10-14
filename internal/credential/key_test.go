package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreKeyPrefersTheEnvironmentPassphrase(t *testing.T) {
	t.Setenv("STK_PASSPHRASE", "operator supplied")
	k, src, err := StoreKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if k != "operator supplied" || src != KeyFromEnv {
		t.Fatalf("StoreKey() = %q/%v, want the env passphrase", k, src)
	}
}

func TestStoreKeyIsStableAcrossCalls(t *testing.T) {
	t.Setenv("STK_PASSPHRASE", "")
	dir := t.TempDir()
	first, src1, err := StoreKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, src2, err := StoreKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("StoreKey() returned a different key on the second call; nothing would decrypt")
	}
	if src1 != src2 {
		t.Errorf("source changed between calls: %v then %v", src1, src2)
	}
}

// The source must be reported honestly, because doctor tells the operator how
// well protected their credentials are based on it.
func TestStoreKeySourceIsReported(t *testing.T) {
	t.Setenv("STK_PASSPHRASE", "")
	dir := t.TempDir()
	_, src, err := StoreKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	switch src {
	case KeyFromKeychain:
		// Nothing should have been written beside the ciphertext.
		if _, err := os.Stat(filepath.Join(dir, "machine.key")); err == nil {
			t.Error("a machine key was written even though the keychain was used")
		}
	case KeyFromFile:
		fi, err := os.Stat(filepath.Join(dir, "machine.key"))
		if err != nil {
			t.Fatalf("source says file, but no machine.key exists: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("machine.key mode = %o, want 600", fi.Mode().Perm())
		}
	default:
		t.Fatalf("unexpected source %q", src)
	}
	if strings.TrimSpace(string(src)) == "" {
		t.Error("the key source must never be empty")
	}
}

// Two workspaces on one machine must not share a key, or revoking one would
// unseal the other.
func TestDifferentDirectoriesGetDifferentKeys(t *testing.T) {
	t.Setenv("STK_PASSPHRASE", "")
	a, _, err := StoreKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := StoreKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two workspaces received the same store key")
	}
}
