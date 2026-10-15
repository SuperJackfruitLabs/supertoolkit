package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/deviceflow"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/handover"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/notify"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/oauth2flow"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// connectDevice connects a service on a machine with no browser.
//
// The provider issues a short code, a person approves it in their own browser
// wherever they happen to be, and the token comes back to this broker directly.
// It never passes through the operator's machine, a hub, or us — which is the
// whole reason to prefer this over the hand-over path below.
func connectDevice(name string, out io.Writer) error {
	cfg, err := policy.Load(configPath())
	if err != nil {
		return fmt.Errorf("%w — run `stk init` first", err)
	}
	svc, ok := cfg.Service(name)
	if !ok {
		return fmt.Errorf("%q is not configured: run `stk add %s` first, which is also where the device client id goes", name, name)
	}
	dev := svc.Device()
	if !dev.Supported() {
		return unsupportedDevice(name, svc.Entry(), dev)
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

	// Say what is about to happen before it happens. A person who is about to
	// be asked for a code in a browser should already know why.
	fmt.Fprintf(out, "\n  connecting %s without a browser on this machine\n", name)
	fmt.Fprintf(out, "    1. %s issues a short code\n", dev.AuthorizationURL)
	fmt.Fprintf(out, "    2. you approve it in a browser, anywhere\n")
	fmt.Fprintf(out, "    3. the token comes back here, to this broker only\n")
	if len(dev.Scopes) > 0 {
		fmt.Fprintf(out, "    asking for: %s\n", strings.Join(dev.Scopes, ", "))
	}
	fmt.Fprintln(out)

	// Ctrl-C has to cancel the poll, not kill the process mid-store: a
	// half-connected service is worse than an unconnected one.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	auth, err := deviceflow.Start(ctx, deviceflow.Config{
		AuthorizationURL: dev.AuthorizationURL,
		TokenURL:         dev.TokenURL,
		ClientID:         dev.ClientID,
		Scopes:           dev.Scopes,
	})
	if err != nil {
		return err
	}

	where := auth.VerificationURI
	if auth.VerificationURIComplete != "" {
		where = auth.VerificationURIComplete
	}
	n := &notify.Notifier{Sinks: sinks(out, cfg.Notify())}
	if err := n.Notify(ctx, notify.Message{
		Title:   fmt.Sprintf("supertoolkit is connecting %s", name),
		Body:    "enter the code to approve it; it is useless to anyone who does not",
		Code:    auth.UserCode,
		URL:     where,
		Expires: auth.ExpiresAt,
	}); err != nil {
		// Reaching nobody is fatal: polling for a code no one will ever see
		// just burns the provider's rate limit until the code expires.
		return fmt.Errorf("%w\n\n  the code was not shown anywhere, so nothing is waiting for it", err)
	}

	fmt.Fprintf(out, "  waiting — checking every %s, giving up at %s\n\n",
		auth.Interval, auth.ExpiresAt.Format(time.Kitchen))

	tok, err := deviceflow.Poll(ctx, deviceflow.Config{
		TokenURL: dev.TokenURL, ClientID: dev.ClientID,
	}, auth)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintf(out, "\n  cancelled. %s is not connected, and nothing was stored.\n", name)
			return nil
		}
		return err
	}

	if err := store.PutMaterial(name, credential.Material{credential.FieldToken: tok.AccessToken}); err != nil {
		return err
	}
	fmt.Fprintf(out, "  %s connected · %s\n", name, svc.Entry().Auth)
	fmt.Fprintf(out, "  sealed in %s, never in %s\n", dir, configPath())
	if tok.Scope != "" {
		fmt.Fprintf(out, "  granted: %s\n", tok.Scope)
	}
	if !tok.ExpiresAt.IsZero() {
		fmt.Fprintf(out, "  expires %s\n", tok.ExpiresAt.Format(time.RFC3339))
	}
	fmt.Fprintf(out, "  %s\n", svc.Entry().Auth.Reassurance())
	return nil
}

// unsupportedDevice says which piece is missing, and what to do instead.
//
// There are two different "no": the provider does not offer the flow, which no
// configuration can fix, and the operator has not registered an app yet, which
// one line of YAML fixes.
func unsupportedDevice(name string, entry *catalog.Entry, dev catalog.Device) error {
	if dev.AuthorizationURL == "" || dev.TokenURL == "" {
		return fmt.Errorf(`%s does not offer the device authorization grant.

  two paths remain on a machine with no browser:
    stk ui --bind <private-addr>   if a browser can reach this host
    stk handover key               seal the credential from a machine that has one`, name)
	}
	return fmt.Errorf(`%s offers the device flow, but no client id is configured.

  the device grant identifies an OAuth app, and supertoolkit does not ship one —
  a shared client id would make every installation look like the same app.
  register your own, then add it to %s:

    services:
      %s:
        device:
          client_id: <your app's client id>

  a client id is public by OAuth's design: it names an app and authorises
  nothing, so it is safe in a committed file. %s`, name, configPath(), name, entry.Auth.Reassurance())
}

// sinks builds the notification routes. The terminal always exists; the others
// are configured, and matter when nobody is watching this terminal.
func sinks(out io.Writer, n policy.Notify) []notify.Sink {
	s := []notify.Sink{notify.Terminal{W: out}}
	if n.Webhook != "" {
		s = append(s, notify.Webhook{URL: n.Webhook})
	}
	if n.File != "" {
		s = append(s, notify.File{Path: n.File})
	}
	return s
}

// cmdHandover is the last resort, and says so.
func cmdHandover(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: stk handover key | stk handover open <service>")
	}
	dir, err := home()
	if err != nil {
		return err
	}
	kp, err := handover.Load(dir)
	if err != nil {
		return err
	}

	switch args[0] {
	case "key":
		fmt.Println(kp.PublicKey())
		fmt.Fprintln(os.Stderr, `
  this broker's hand-over key. It is public: it can only seal, never open.

  on a machine that has a browser, with stk installed there:
    stk connect <service>            # or however you obtain the credential
    stk handover seal <service> --to '<the key above>'

  what this path costs, plainly: the credential exists on that machine for as
  long as it takes to seal it. The device flow and the web UI do not have that
  property, so prefer them when either is possible.`)
		return nil

	case "seal":
		return handoverSeal(args[1:], dir)

	case "open":
		if len(args) != 2 {
			return fmt.Errorf("usage: stk handover open <service>   (the envelope is read from stdin)")
		}
		name := args[1]
		entry, ok := catalog.Lookup(name)
		if !ok {
			return fmt.Errorf("unknown service %q: known services are %s", name, knownServices())
		}
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		m, err := kp.Open(strings.TrimSpace(string(raw)))
		if err != nil {
			return err
		}
		if err := m.Require(entry.Auth.Fields()...); err != nil {
			return fmt.Errorf("the envelope opened, but %w", err)
		}
		pass, _, err := credential.StoreKey(dir)
		if err != nil {
			return err
		}
		store, err := credential.OpenStore(dir, pass)
		if err != nil {
			return err
		}
		if err := store.PutMaterial(name, m); err != nil {
			return err
		}
		fmt.Printf("  %s connected from a sealed envelope · %s\n", name, entry.Auth)
		fmt.Printf("  %d field(s) sealed in %s: %s\n", len(m), dir, strings.Join(m.Fields(), ", "))
		fmt.Printf("  now delete it where it was sealed — it still exists there.\n")
		return nil
	}
	return fmt.Errorf("stk handover: unknown subcommand %q: want key, seal or open", args[0])
}

// handoverSeal runs on the machine that has the browser.
func handoverSeal(args []string, dir string) error {
	var name, to string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--to":
			if i+1 >= len(args) {
				return fmt.Errorf("--to needs the broker's hand-over key, from `stk handover key`")
			}
			to = args[i+1]
			i++
		default:
			name = args[i]
		}
	}
	if name == "" || to == "" {
		return fmt.Errorf("usage: stk handover seal <service> --to <key>")
	}
	entry, ok := catalog.Lookup(name)
	if !ok {
		return fmt.Errorf("unknown service %q: known services are %s", name, knownServices())
	}
	pub, err := handover.ParsePublicKey(to)
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
	m, err := store.Material(name)
	if err != nil {
		return fmt.Errorf("%s is not connected here, so there is nothing to seal: %w", name, err)
	}
	if err := m.Require(entry.Auth.Fields()...); err != nil {
		return err
	}
	env, err := handover.Seal(pub, m)
	if err != nil {
		return err
	}
	fmt.Println(env)
	fmt.Fprintf(os.Stderr, `
  sealed to that broker and to nothing else. Pipe it there:
    stk handover open %s

  it is safe in a paste buffer, a chat message or a file: only the broker
  holding the matching private key can open it. The credential it carries,
  however, still exists on this machine — in this store.
`, name)
	return nil
}

// connectBrowser runs the OAuth 2.0 authorization code flow with PKCE.
//
// This is the path for a provider that offers no device grant — X and Google
// among them — and it needs a browser on this machine, because the redirect
// comes back to a loopback listener. On a machine with no browser the order of
// preference is the device grant, then the broker's own UI over a private
// network, then `stk handover`.
//
// What is stored is the refresh token, the client id and, for a confidential
// client, the client secret. The access token is never stored: it is acquired
// on demand and lives in memory, so a stolen store yields something that has to
// be exchanged with the provider before it is worth anything.
func connectBrowser(name string, out io.Writer, in io.Reader, openBrowser func(string) error) error {
	cfg, err := policy.Load(configPath())
	if err != nil {
		return fmt.Errorf("%w — run `stk init` first", err)
	}
	svc, ok := cfg.Service(name)
	if !ok {
		return fmt.Errorf("%q is not configured: run `stk add %s` first, which is also where the client id goes", name, name)
	}
	o := svc.OAuth2()
	if !o.Supported() {
		return unsupportedOAuth2(name, svc.Entry(), o)
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

	// A confidential client's secret is a secret, so it is read from stdin and
	// never from a flag or the committed file.
	clientSecret := ""
	if o.Confidential {
		fmt.Fprintf(out, "\n  %s needs its client secret. Paste it and press ctrl-D:\n", name)
		raw, err := io.ReadAll(in)
		if err != nil {
			return err
		}
		clientSecret = strings.TrimSpace(string(raw))
		if clientSecret == "" {
			return fmt.Errorf("no client secret was supplied, and %s is a confidential client — its token endpoint will refuse the exchange", name)
		}
	}

	state, err := oauth2flow.NewState()
	if err != nil {
		return err
	}
	pkce, err := oauth2flow.NewPKCE()
	if err != nil {
		return err
	}
	// A provider matches the redirect URI exactly against what was registered,
	// so an operator with an existing app names theirs here and we listen on
	// its port and path instead of insisting on ours.
	port, path, err := loopbackRedirect(o.RedirectURI)
	if err != nil {
		return err
	}
	rec, redirectURI, err := oauth2flow.ListenAt(port, path, state)
	if err != nil {
		return err
	}
	defer rec.Close()
	if o.RedirectURI != "" {
		// Use their registered string verbatim: "localhost" and "127.0.0.1"
		// are the same host and different strings, and the provider compares
		// strings.
		redirectURI = o.RedirectURI
	}

	flow := oauth2flow.Config{
		AuthorizeURL: o.AuthorizeURL, TokenURL: o.TokenURL,
		ClientID: o.ClientID, ClientSecret: clientSecret, Scopes: o.Scopes,
	}
	authURL := oauth2flow.AuthorizeURL(flow, redirectURI, state, pkce)

	fmt.Fprintf(out, "\n  connecting %s in your browser\n", name)
	fmt.Fprintf(out, "    1. you approve the request at %s\n", o.AuthorizeURL)
	fmt.Fprintf(out, "    2. the provider redirects to %s — this machine only\n", redirectURI)
	fmt.Fprintf(out, "    3. the broker exchanges the code for a token, and keeps it\n")
	if len(o.Scopes) > 0 {
		fmt.Fprintf(out, "    asking for: %s\n", strings.Join(o.Scopes, ", "))
	}
	fmt.Fprintf(out, "\n  %s must be registered as a redirect URI for your app, exactly.\n\n", redirectURI)

	// The URL is always printed, even when a browser opened.
	//
	// It was previously hidden on success, which cost exactly when it was worth
	// most: a provider that refuses the request shows a generic page, and
	// without the URL there is nothing to inspect. It also assumes the default
	// browser is the one signed in to the right account, which is often not
	// true for a work account — someone needs to be able to paste it elsewhere.
	fmt.Fprintf(out, "  the request, in full:\n\n    %s\n\n", authURL)
	if openBrowser != nil {
		if err := openBrowser(authURL); err != nil {
			fmt.Fprintf(out, "  could not open a browser (%v) — open the link above yourself.\n\n", err)
		} else {
			fmt.Fprintf(out, "  opened in your default browser. If that is not where you are signed in\n  to %s, paste the link into the one that is.\n\n", name)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// A person has to find the tab, read the scopes and decide. Five minutes is
	// generous without waiting forever on an abandoned flow.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	got, err := rec.Wait(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintf(out, "\n  cancelled. %s is not connected, and nothing was stored.\n", name)
			return nil
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("nothing came back within five minutes, so %s is not connected — nothing was stored", name)
		}
		return err
	}

	tok, err := oauth2flow.Exchange(ctx, flow, got.Code, redirectURI, pkce.Verifier)
	if err != nil {
		return err
	}
	if tok.RefreshToken == "" {
		return fmt.Errorf(`%s returned no refresh token, so the connection would die when the access token expires and could not recover.

  this means the grant did not include offline access. Check that your app
  requests it: %s`, name, strings.Join(o.Scopes, ", "))
	}

	m := credential.Material{
		credential.FieldClientID:     o.ClientID,
		credential.FieldRefreshToken: tok.RefreshToken,
	}
	if clientSecret != "" {
		m[credential.FieldClientSecret] = clientSecret
	}
	if err := store.PutMaterial(name, m); err != nil {
		return err
	}

	fmt.Fprintf(out, "  %s connected · %s\n", name, svc.Entry().Auth)
	fmt.Fprintf(out, "  sealed in %s, never in %s\n", dir, configPath())
	if tok.Scope != "" {
		fmt.Fprintf(out, "  granted: %s\n", tok.Scope)
	}
	fmt.Fprintf(out, "  the refresh token is stored; the access token is not — it is acquired on demand\n")
	fmt.Fprintf(out, "  %s\n", svc.Entry().Auth.Reassurance())
	return nil
}

// oauthPort is fixed because a provider matches the redirect URI exactly
// against the one registered for the app. A random port would mean
// re-registering before every connect.
//
// A variable rather than a constant only so a test can ask for an ephemeral
// port and run alongside others.
var oauthPort = 7837

// loopbackRedirect reads a configured callback into a port and path.
//
// It must be loopback. The broker receives the redirect itself, so a URI
// pointing at any other host is one it can never hear — and a redirect
// reachable from the network is one anybody on that network can deliver a code
// to.
func loopbackRedirect(uri string) (int, string, error) {
	if uri == "" {
		return oauthPort, "/callback", nil
	}
	u, err := url.Parse(uri)
	if err != nil {
		return 0, "", fmt.Errorf("redirect_uri %q is not a URL: %w", uri, err)
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return 0, "", fmt.Errorf(`redirect_uri %q points at %q.

  it must be loopback — 127.0.0.1 or localhost — because the broker listens for
  the redirect itself. A callback anywhere else never reaches this machine, and
  one reachable from the network lets anybody on it deliver a code here.

  register a loopback callback for the app, or use the device grant:
    stk connect %s --device`, uri, host, "<service>")
	}
	port := oauthPort
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return 0, "", fmt.Errorf("redirect_uri %q has no usable port", uri)
		}
		port = n
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return port, path, nil
}

func unsupportedOAuth2(name string, entry *catalog.Entry, o catalog.OAuth2) error {
	if o.AuthorizeURL == "" || o.TokenURL == "" {
		return fmt.Errorf(`%s does not use the OAuth 2.0 authorization code flow.

  it uses %s — connect it with:
    stk connect %s`, name, entry.Auth, name)
	}
	return fmt.Errorf(`%s uses OAuth 2.0, but no client id is configured.

  supertoolkit ships no client id: a shared one would make every installation
  look like the same app. Register your own, add http://127.0.0.1:%d/callback as
  a redirect URI, then name the client id in %s:

    services:
      %s:
        oauth2:
          client_id: <your app's client id>

  a client id is public by OAuth's design: it identifies an app and authorises
  nothing, so it is safe in a committed file. The client secret is not, so
  stk connect %s --browser reads it from stdin.`, name, oauthPort, configPath(), name, name)
}

// openInBrowser is best-effort: a failure prints the URL instead, which is the
// same thing a headless machine needs anyway.
func openInBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	return exec.Command(cmd, append(args, url)...).Start()
}
