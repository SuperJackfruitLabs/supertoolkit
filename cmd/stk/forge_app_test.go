package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

const appForgeConfig = `
services:
  gh-app-a:
    kind: forge
    provider: github
    host: api.github.com
    auth: app
    env_var: GH_TOKEN
    repositories: [SuperJackfruitLabs/a]
  gh-app-b:
    kind: forge
    provider: github
    host: github.example.com
    auth: app
    env_var: GHE_TOKEN
    repositories: [Corp/b]
`

func appForgeEnv(t *testing.T) (home, cfgPath string) {
	t.Helper()
	home = t.TempDir()
	cfgPath = filepath.Join(t.TempDir(), "supertoolkit.yaml")
	if err := os.WriteFile(cfgPath, []byte(appForgeConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STK_HOME", home)
	t.Setenv("STK_CONFIG", cfgPath)
	t.Setenv("STK_PASSPHRASE", "test-passphrase")
	return home, cfgPath
}

func TestAppEntryRequiresAppFields(t *testing.T) {
	home, _ := appForgeEnv(t)
	var err error
	withStdin(t, "app_id=1\ninstallation_id=2\n", func() { err = cmdConnect([]string{"gh-app-a"}) })
	if err == nil || !strings.Contains(err.Error(), "private_key") {
		t.Fatalf("connect with a missing field: err = %v, want a refusal naming private_key", err)
	}
	if openTestStore(t, home).Has("gh-app-a") {
		t.Fatal("incomplete material was stored")
	}
	withStdin(t, "app_id=1\ninstallation_id=2\nprivate_key=-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----\n",
		func() { err = cmdConnect([]string{"gh-app-a"}) })
	if err != nil {
		t.Fatalf("connect with all three fields: %v", err)
	}
	if !openTestStore(t, home).Has("gh-app-a") {
		t.Fatal("complete material was not stored")
	}
}

func TestAppForgeAcquirerIsPerService(t *testing.T) {
	home, cfgPath := appForgeEnv(t)
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	acqs := newAcquirers(cfg, openTestStore(t, home), http.DefaultClient)
	a, b, builtin := acqs.app("gh-app-a"), acqs.app("gh-app-b"), acqs.app("github-app")
	if a == nil || b == nil || builtin == nil {
		t.Fatalf("acquirers: a=%v b=%v builtin=%v", a, b, builtin)
	}
	if a == b {
		t.Error("two app forge services share one acquirer (and so one cache)")
	}
	if a == acqs.githubApp || b == acqs.githubApp {
		t.Error("an app forge service shares the built-in github-app acquirer")
	}
	if builtin != acqs.githubApp {
		t.Error("the built-in github-app no longer uses its own acquirer")
	}
}

// Revoking an app forge must drop the token cached under its scoped key, or
// the next call would still be served the installation token.
func TestRevokeAppForgeDropsScopedCachedToken(t *testing.T) {
	home, cfgPath := appForgeEnv(t)
	withStdin(t, "app_id=1\ninstallation_id=2\nprivate_key=-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----\n",
		func() { _ = cmdConnect([]string{"gh-app-a"}) })
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store := openTestStore(t, home)
	acq := newAcquirers(cfg, store, http.DefaultClient).app("gh-app-a")
	if err := acq.Shared.CacheToken("gh-app-a", "ghs_cached", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	withStdin(t, "", func() {
		if err := cmdRevoke([]string{"gh-app-a", "--local"}); err != nil {
			t.Errorf("revoke: %v", err)
		}
	})
	if _, _, ok := acq.Shared.CachedToken("gh-app-a", 0); ok {
		t.Fatal("the scoped cached installation token survived revoke")
	}
}
