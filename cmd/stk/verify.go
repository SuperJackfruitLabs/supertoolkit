package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
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
	secret, err := store.Get(name)
	if err != nil {
		return fmt.Errorf("%s has no stored credential: connect it first (`stk connect %s`)", name, name)
	}
	res := verify.Run(context.Background(), verify.Input{
		Entry: entry, Secret: secret, ExpectLogin: expect, HTTP: verifyHTTP, BaseURL: verifyBaseURL,
	})
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
