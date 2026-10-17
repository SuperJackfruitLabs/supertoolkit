package credential

import (
	"os"
	"path/filepath"
	"testing"
)

// systemd's LoadCredential exposes the passphrase as a file under
// $CREDENTIALS_DIRECTORY, so the unit never carries it in Environment=.
func TestCredentialStoreKeyReadsCredentialsDirectory(t *testing.T) {
	t.Setenv("STK_PASSPHRASE", "")
	t.Setenv("STK_PASSPHRASE_FILE", "")
	creds := t.TempDir()
	os.WriteFile(filepath.Join(creds, "stk-passphrase"), []byte("from systemd\n"), 0o400)
	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "machine.key"), []byte("machine"), 0o600)

	k, src, err := StoreKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if k != "from systemd" || src != KeyFromCredentialFile {
		t.Fatalf("StoreKey() = %q/%v, want the credential file (one newline trimmed)", k, src)
	}
}

func TestCredentialStoreKeyPrecedence(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "machine.key"), []byte("machine"), 0o600)
	creds := t.TempDir()
	os.WriteFile(filepath.Join(creds, "stk-passphrase"), []byte("credsdir"), 0o400)
	explicit := filepath.Join(t.TempDir(), "pf")
	os.WriteFile(explicit, []byte("explicit\n\n"), 0o400)

	t.Setenv("CREDENTIALS_DIRECTORY", creds)
	t.Setenv("STK_PASSPHRASE_FILE", explicit)
	t.Setenv("STK_PASSPHRASE", "env")
	if k, _, _ := StoreKey(dir); k != "env" {
		t.Fatalf("STK_PASSPHRASE must win, got %q", k)
	}
	t.Setenv("STK_PASSPHRASE", "")
	if k, _, _ := StoreKey(dir); k != "explicit\n" {
		t.Fatalf("STK_PASSPHRASE_FILE must beat the credentials dir and trim one newline, got %q", k)
	}
	t.Setenv("STK_PASSPHRASE_FILE", "")
	if k, _, _ := StoreKey(dir); k != "credsdir" {
		t.Fatalf("credentials dir must beat machine.key, got %q", k)
	}
	if keychainAvailable() {
		return // the keychain sits between the file and machine.key here
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if k, src, _ := StoreKey(dir); k != "machine" || src != KeyFromFile {
		t.Fatalf("machine.key fallback, got %q/%v", k, src)
	}
}

// A named passphrase file that cannot be read is an error, not a silent fall
// back to a different key that would open (or create) a different store.
func TestCredentialStoreKeyMissingNamedFileFailsClosed(t *testing.T) {
	t.Setenv("STK_PASSPHRASE", "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv("STK_PASSPHRASE_FILE", filepath.Join(t.TempDir(), "absent"))
	if _, _, err := StoreKey(t.TempDir()); err == nil {
		t.Fatal("a missing STK_PASSPHRASE_FILE was ignored")
	}
}
