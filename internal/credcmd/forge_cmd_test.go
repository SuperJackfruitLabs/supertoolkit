package credcmd

import (
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/clitest"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/setup"
)

func TestConnectForgeServiceFromStdin(t *testing.T) {
	home := clitest.ForgeEnv(t)
	const token = "ZZ-forge-token-ZZ"
	out := clitest.WithStdin(t, token+"\n", func() {
		if err := setup.Connect([]string{"forge-main"}); err != nil {
			t.Errorf("cmdConnect() error = %v", err)
		}
	})
	if !clitest.OpenTestStore(t, home).Has("forge-main") {
		t.Error("credential was not stored")
	}
	if strings.Contains(out, token) {
		t.Errorf("connect printed the token: %q", out)
	}
}

func TestRevokeForgeServiceLocal(t *testing.T) {
	home := clitest.ForgeEnv(t)
	clitest.WithStdin(t, "tok\n", func() { _ = setup.Connect([]string{"forge-main"}) })
	clitest.WithStdin(t, "", func() {
		if err := Revoke([]string{"forge-main", "--local"}); err != nil {
			t.Errorf("cmdRevoke() error = %v", err)
		}
	})
	if clitest.OpenTestStore(t, home).Has("forge-main") {
		t.Error("credential still stored after revoke --local")
	}
}
