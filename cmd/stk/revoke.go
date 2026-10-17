package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
)

// cmdRevoke withdraws a credential, and is careful about what that word means.
//
// Deleting our copy does not invalidate the token at the provider. A command
// called `revoke` that leaves a live credential on GitHub would be the most
// dangerous sentence in this product: somebody containing a leak would believe
// they had contained it. So this does as much as it can and states exactly what
// it did and did not do, with the place to finish the job.
//
// It existed only in the web UI before, which is backwards: on a machine with
// no browser the CLI is the one surface that can be reached, and withdrawing a
// credential there meant deleting a file by hand — the reach-into-the-internals
// habit this product exists to replace.
func cmdRevoke(args []string) error {
	local := false
	var name string
	for _, a := range args {
		switch a {
		case "--local", "--forget":
			local = true
		default:
			if name != "" {
				return fmt.Errorf("usage: stk revoke <service> [--local]")
			}
			name = a
		}
	}
	if name == "" {
		return fmt.Errorf("usage: stk revoke <service> [--local]   (known: %s)", knownServices())
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
	if !store.Has(name) {
		return fmt.Errorf("%s is not connected here, so there is nothing to withdraw", name)
	}

	// Ask the provider first, while the credential still exists to ask with.
	atProvider := ""
	if !local && entry.RevokeURL != "" {
		m, merr := store.Material(name)
		if merr != nil {
			atProvider = "could not read the credential to revoke it: " + merr.Error()
		} else {
			atProvider = revokeAtProvider(entry, m)
		}
	}

	// Then forget it here, whatever the provider said. A credential we failed
	// to revoke upstream is one we especially do not want to keep.
	if err := store.ForgetCachedToken(name); err != nil {
		fmt.Fprintln(os.Stderr, "stk: could not drop the cached token:", err)
	}
	if err := store.Revoke(name); err != nil {
		return err
	}

	fmt.Printf("\n  %s forgotten here · removed from %s\n", name, dir)
	switch {
	case local:
		fmt.Printf("  not sent to the provider, because you asked for --local\n")
	case entry.RevokeURL == "":
		fmt.Printf("  %s offers us no way to revoke it on your behalf\n", name)
	case atProvider == "":
		fmt.Printf("  revoked at the provider — the credential no longer works anywhere\n")
	default:
		fmt.Printf("  NOT revoked at the provider: %s\n", atProvider)
	}

	// The line that matters when a credential has leaked, and the reason this
	// command does not simply say "revoked".
	if local || entry.RevokeURL == "" || atProvider != "" {
		fmt.Printf("\n  the credential may still be valid at %s.\n", entry.Name)
		fmt.Printf("  withdraw it there: %s\n", entry.RevokeAt)
	}
	fmt.Println()
	return nil
}

// revokeAtProvider calls the provider's revocation endpoint. It returns an
// empty string on success, and the reason otherwise.
func revokeAtProvider(entry *catalog.Entry, m credential.Material) string {
	// Revoke the refresh token where there is one: revoking it invalidates the
	// grant, while revoking only an access token leaves the grant alive and a
	// new access token a single exchange away.
	token := m[credential.FieldRefreshToken]
	hint := "refresh_token"
	if token == "" {
		token, hint = m[credential.FieldToken], "access_token"
	}
	if token == "" {
		return "the stored credential has no token to revoke"
	}

	form := url.Values{"token": {token}, "token_type_hint": {hint}}
	if id := m[credential.FieldClientID]; id != "" {
		form.Set("client_id", id)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", entry.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err.Error()
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if secret := m[credential.FieldClientSecret]; secret != "" {
		req.SetBasicAuth(url.QueryEscape(m[credential.FieldClientID]), url.QueryEscape(secret))
	}

	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return "could not reach " + entry.RevokeURL
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		// The provider's own words, which carry no credential of ours.
		return fmt.Sprintf("%s answered %s: %s", entry.RevokeURL, resp.Status, strings.TrimSpace(string(body)))
	}
	return ""
}
