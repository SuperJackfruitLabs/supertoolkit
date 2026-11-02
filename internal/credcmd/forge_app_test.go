package credcmd

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/clitest"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/secrets"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/setup"
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
	clitest.WithStdin(t, "app_id=1\ninstallation_id=2\n", func() { err = setup.Connect([]string{"gh-app-a"}) })
	if err == nil || !strings.Contains(err.Error(), "private_key") {
		t.Fatalf("connect with a missing field: err = %v, want a refusal naming private_key", err)
	}
	if clitest.OpenTestStore(t, home).Has("gh-app-a") {
		t.Fatal("incomplete material was stored")
	}
	clitest.WithStdin(t, "app_id=1\ninstallation_id=2\nprivate_key=-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----\n",
		func() { err = setup.Connect([]string{"gh-app-a"}) })
	if err != nil {
		t.Fatalf("connect with all three fields: %v", err)
	}
	if !clitest.OpenTestStore(t, home).Has("gh-app-a") {
		t.Fatal("complete material was not stored")
	}
}

func TestAppForgeAcquirerIsPerService(t *testing.T) {
	home, cfgPath := appForgeEnv(t)
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	acqs := secrets.NewAcquirers(cfg, clitest.OpenTestStore(t, home), http.DefaultClient)
	a, b, builtin := acqs.App("gh-app-a"), acqs.App("gh-app-b"), acqs.App("github-app")
	if a == nil || b == nil || builtin == nil {
		t.Fatalf("acquirers: a=%v b=%v builtin=%v", a, b, builtin)
	}
	if a == b {
		t.Error("two app forge services share one acquirer (and so one cache)")
	}
	if a == acqs.GitHubApp || b == acqs.GitHubApp {
		t.Error("an app forge service shares the built-in github-app acquirer")
	}
	if builtin != acqs.GitHubApp {
		t.Error("the built-in github-app no longer uses its own acquirer")
	}
}

// Revoking an app forge must drop the token cached under its scoped key, or
// the next call would still be served the installation token.
func TestRevokeAppForgeDropsScopedCachedToken(t *testing.T) {
	home, cfgPath := appForgeEnv(t)
	clitest.WithStdin(t, "app_id=1\ninstallation_id=2\nprivate_key=-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----\n",
		func() { _ = setup.Connect([]string{"gh-app-a"}) })
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store := clitest.OpenTestStore(t, home)
	acq := secrets.NewAcquirers(cfg, store, http.DefaultClient).App("gh-app-a")
	if err := acq.Shared.CacheToken("gh-app-a", "ghs_cached", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	clitest.WithStdin(t, "", func() {
		if err := Revoke([]string{"gh-app-a", "--local"}); err != nil {
			t.Errorf("revoke: %v", err)
		}
	})
	if _, _, ok := acq.Shared.CachedToken("gh-app-a", 0); ok {
		t.Fatal("the scoped cached installation token survived revoke")
	}
}

func writeAppForgeConfig(t *testing.T, cfgPath, reposA string) {
	t.Helper()
	c := strings.Replace(appForgeConfig, "[SuperJackfruitLabs/a]", "["+reposA+"]", 1)
	if err := os.WriteFile(cfgPath, []byte(c), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeDropsTokensCachedUnderAnOldScope(t *testing.T) {
	home, cfgPath := appForgeEnv(t)
	clitest.WithStdin(t, "app_id=1\ninstallation_id=2\nprivate_key=k\n", func() { _ = setup.Connect([]string{"gh-app-a"}) })
	clitest.WithStdin(t, "app_id=1\ninstallation_id=2\nprivate_key=k\n", func() { _ = setup.Connect([]string{"gh-app-b"}) })
	cfg, _ := policy.Load(cfgPath)
	store := clitest.OpenTestStore(t, home)
	old := secrets.NewAcquirers(cfg, store, http.DefaultClient)
	old.App("gh-app-a").Shared.CacheToken("gh-app-a", "ghs_old", time.Now().Add(time.Hour))
	old.App("gh-app-b").Shared.CacheToken("gh-app-b", "ghs_b", time.Now().Add(time.Hour))
	writeAppForgeConfig(t, cfgPath, "SuperJackfruitLabs/a, SuperJackfruitLabs/z")
	clitest.WithStdin(t, "", func() {
		if err := Revoke([]string{"gh-app-a", "--local"}); err != nil {
			t.Errorf("revoke: %v", err)
		}
	})
	if _, _, ok := old.App("gh-app-a").Shared.CachedToken("gh-app-a", 0); ok {
		t.Error("the token cached under the old scope survived revoke")
	}
	if _, _, ok := old.App("gh-app-b").Shared.CachedToken("gh-app-b", 0); !ok {
		t.Error("revoking gh-app-a removed gh-app-b's cached token")
	}
}

func TestAppScopeKeyIncludesOwner(t *testing.T) {
	_, cfgPath := appForgeEnv(t)
	key := func(repos string) string {
		writeAppForgeConfig(t, cfgPath, repos)
		cfg, err := policy.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		svc, _ := cfg.Service("gh-app-a")
		return secrets.SharedCacheKey(svc.Entry(), "gh-app-a")
	}
	if key("Corp/a") == key("Other/a") {
		t.Error("changing the owner did not change the cache key")
	}
}

func TestConnectDropsCachedTokensOnlyOnSuccess(t *testing.T) {
	home, _ := appForgeEnv(t)
	store := clitest.OpenTestStore(t, home)
	store.CacheToken("github-app", "ghs_cached", time.Now().Add(time.Hour))
	clitest.WithStdin(t, "app_id=1\n", func() { _ = setup.Connect([]string{"github-app"}) })
	if _, _, ok := clitest.OpenTestStore(t, home).CachedToken("github-app", 0); !ok {
		t.Fatal("a failed connect dropped the cached token")
	}
	clitest.WithStdin(t, "app_id=9\ninstallation_id=2\nprivate_key=k\n", func() {
		if err := setup.Connect([]string{"github-app"}); err != nil {
			t.Errorf("connect: %v", err)
		}
	})
	if _, _, ok := clitest.OpenTestStore(t, home).CachedToken("github-app", 0); ok {
		t.Fatal("new material left the old cached token in place")
	}
}
