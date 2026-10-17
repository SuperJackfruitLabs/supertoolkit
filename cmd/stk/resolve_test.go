package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
)

const forgeConfig = `
services:
  forge-main:
    kind: forge
    provider: forgejo
    host: forge.superjackfruit.com
    env_var: FORGEJO_TOKEN
    repositories: [SuperJackfruitLabs/supertoolkit]
    preset: issues
`

// forgeEnv points the CLI at a temp home and a policy file holding one forge.
func forgeEnv(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	cfg := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	if err := os.WriteFile(cfg, []byte(forgeConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STK_HOME", home)
	t.Setenv("STK_CONFIG", cfg)
	t.Setenv("STK_PASSPHRASE", "test-passphrase")
	return home
}

// withStdin runs fn with os.Stdin reading `in`, and returns what fn wrote to
// os.Stdout.
func withStdin(t *testing.T, in string, fn func()) string {
	t.Helper()
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	go func() { inW.WriteString(in); inW.Close() }()
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut }()
	done := make(chan string)
	go func() { b, _ := io.ReadAll(outR); done <- string(b) }()
	fn()
	outW.Close()
	return <-done
}

func openTestStore(t *testing.T, home string) *credential.Store {
	t.Helper()
	s, err := credential.OpenStore(home, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResolveEntryPrefersConfig(t *testing.T) {
	forgeEnv(t)
	e, err := resolveEntry("forge-main")
	if err != nil || e.Forge == nil {
		t.Fatalf("resolveEntry(forge-main) = %v, %v", e, err)
	}
	if b, err := resolveEntry("github"); err != nil || b.Forge != nil {
		t.Errorf("a built-in must still resolve with a config present: %v, %v", b, err)
	}
}

func TestResolveEntryWithNoConfigStillFindsBuiltins(t *testing.T) {
	t.Setenv("STK_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	if _, err := resolveEntry("github"); err != nil {
		t.Errorf("resolveEntry(github) with no config = %v", err)
	}
}

func TestResolveEntryUnknownMentionsForgeKind(t *testing.T) {
	t.Setenv("STK_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	_, err := resolveEntry("forgejo")
	if err == nil || !strings.Contains(err.Error(), "kind: forge") {
		t.Errorf("error = %v, want a hint about kind: forge", err)
	}
}

func TestConnectForgeServiceFromStdin(t *testing.T) {
	home := forgeEnv(t)
	const token = "ZZ-forge-token-ZZ"
	out := withStdin(t, token+"\n", func() {
		if err := cmdConnect([]string{"forge-main"}); err != nil {
			t.Errorf("cmdConnect() error = %v", err)
		}
	})
	if !openTestStore(t, home).Has("forge-main") {
		t.Error("credential was not stored")
	}
	if strings.Contains(out, token) {
		t.Errorf("connect printed the token: %q", out)
	}
}

func TestRevokeForgeServiceLocal(t *testing.T) {
	home := forgeEnv(t)
	withStdin(t, "tok\n", func() { _ = cmdConnect([]string{"forge-main"}) })
	withStdin(t, "", func() {
		if err := cmdRevoke([]string{"forge-main", "--local"}); err != nil {
			t.Errorf("cmdRevoke() error = %v", err)
		}
	})
	if openTestStore(t, home).Has("forge-main") {
		t.Error("credential still stored after revoke --local")
	}
}
