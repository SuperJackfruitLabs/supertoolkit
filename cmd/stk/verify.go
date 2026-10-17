package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/verify"
)

// verifyHTTP and verifyBaseURL let tests point verify at a fake provider. They
// are nil and empty in production.
var (
	verifyHTTP    *http.Client
	verifyBaseURL string
)

// cmdVerify checks that a stored credential works, and acts as the account it
// should. It prints a login or a reason, never the credential.
func cmdVerify(args []string) error {
	var name, expect string
	asJSON := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--json":
			asJSON = true
		case "--expect-login":
			i++
			if i >= len(args) {
				return fmt.Errorf("usage: stk verify <service> [--expect-login <login>] [--json]")
			}
			expect = args[i]
		default:
			if name != "" {
				return fmt.Errorf("usage: stk verify <service> [--expect-login <login>] [--json]")
			}
			name = a
		}
	}
	if name == "" {
		return fmt.Errorf("usage: stk verify <service> [--expect-login <login>] [--json]")
	}
	entry, err := resolveEntry(name)
	if err != nil {
		return err
	}
	dir, err := home()
	if err != nil {
		return err
	}
	pass, _, err := credential.StoreKey(dir)
	if err != nil {
		return err
	}
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		return err
	}
	in := verify.Input{Entry: entry, ExpectLogin: expect, HTTP: verifyHTTP, BaseURL: verifyBaseURL}
	if entry.Forge != nil && entry.Auth == catalog.AuthGitHubApp {
		in.App, err = appVerifyInput(name, store)
		if err != nil {
			return err
		}
	} else {
		in.Secret, err = store.Get(name)
		if err != nil {
			return fmt.Errorf("%s has no stored credential: connect it first (`stk connect %s`)", name, name)
		}
	}
	res := verify.Run(context.Background(), in)
	if asJSON {
		if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
			return err
		}
	} else if res.OK {
		fmt.Printf("  %s verified · acting as %s\n", name, res.Login)
	}
	if !res.OK {
		if res.Login != "" {
			return fmt.Errorf("%s failed verification: %s (acting as %s)", name, res.Reason, res.Login)
		}
		return fmt.Errorf("%s failed verification: %s", name, res.Reason)
	}
	return nil
}

// appVerifyInput supplies an app grant's two credentials from the store and
// the service's own acquirer, the same ones the proxy uses: the JWT is minted
// from the stored material as the exchange mints it, and the installation
// token comes through secretSource, already restricted to the configured
// repositories. Neither is held until verify asks for it.
func appVerifyInput(name string, store *credential.Store) (*verify.AppInput, error) {
	cfg, err := policy.Load(configPath())
	if err != nil {
		return nil, err
	}
	if _, ok := cfg.Service(name); !ok {
		return nil, fmt.Errorf("%s is not configured", name)
	}
	if _, err := store.Material(name); err != nil {
		return nil, fmt.Errorf("%s has no stored credential: connect it first (`stk connect %s`)", name, name)
	}
	client := verifyHTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	source := secretSource(cfg, store, newAcquirers(cfg, store, client))
	return &verify.AppInput{
		JWT: func() (string, error) {
			m, err := store.Material(name)
			if err != nil {
				return "", err
			}
			return credential.MintJWT(m, map[string]any{"iss": m[credential.FieldAppID]}, 9*time.Minute)
		},
		InstallationToken: func() (string, error) { return source(name) },
	}, nil
}
