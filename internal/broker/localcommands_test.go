package broker

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Operator ruling 2026-10-30: local commands reach the network only through a dedicated socket,
// and every connection on it is the local-commands identity, whatever the client claims. A
// command can read its own HTTP_PROXY, so the proxy user name must not be able to choose another
// identity's egress, and no brokered service is reachable from it.
const localCommandsSocketPolicy = `
workspace: t
egress:
  preset: public-only
services:
  github:
    scopes: [repo:read]
servers:
  fetch:
    command: mcp-server-fetch
    network: host
    egress:
      preset: public-only
      schemes: [https, http]
      methods: [GET]
  local-commands:
    command: none
    network: host
    egress:
      hosts: ["public.test"]
`

// serveLocalCommands serves the fixture's broker on a dedicated unix socket pinned to the
// local-commands identity, as stk serve --local-commands-socket does.
func (f *egressFixture) serveLocalCommands(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "lc.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	go f.b.ServeAs(ln, LocalCommandsIdentity)
	t.Cleanup(func() { ln.Close() })
	return sock
}

// viaSocket fetches u through the unix socket, presenting proxy user `user`.
func (f *egressFixture) viaSocket(t *testing.T, sock, user, u string) (int, string, error) {
	t.Helper()
	pu := &url.URL{Scheme: "http", User: url.UserPassword(user, "anything"), Host: "stk.local"}
	c := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(pu),
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
			TLSClientConfig:   f.clientCA,
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}
	resp, err := c.Get(u)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

func (f *egressFixture) recordWithRule(t *testing.T, rule string) (Record, bool) {
	t.Helper()
	for _, r := range f.b.Audit() {
		if r.Rule == rule {
			return r, true
		}
	}
	return Record{}, false
}

func TestLocalCommandsSocketTunnelsAListedHost(t *testing.T) {
	f := newEgressFixture(t, localCommandsSocketPolicy)
	sock := f.serveLocalCommands(t)
	code, body, err := f.viaSocket(t, sock, "stk+local-commands", "https://public.test/page")
	if err != nil || code != 200 || body != "public GET /page" {
		t.Fatalf("listed host through the socket: %d %q %v", code, body, err)
	}
	if rec := f.lastRecord(t); rec.Service != LocalCommandsIdentity || rec.Rule != "egress:hosts#1+egress:public-only" {
		t.Fatalf("record %+v", rec)
	}
	f.assertNoSSRF(t)
}

func TestLocalCommandsSocketForcesItsIdentityOverAClaimedOne(t *testing.T) {
	f := newEgressFixture(t, localCommandsSocketPolicy)
	sock := f.serveLocalCommands(t)
	// fetch's egress allows any public host; local-commands lists only public.test. A command that
	// renames itself stk+fetch must still be decided as local-commands.
	lookups := f.lookups.Load()
	code, _, err := f.viaSocket(t, sock, "stk+fetch", "https://rebind.test/")
	if err == nil && code != http.StatusForbidden {
		t.Fatalf("a claimed stk+fetch reached an unlisted host: %d", code)
	}
	rec, ok := f.recordWithRule(t, "egress:hosts/not-listed")
	if !ok || rec.Service != LocalCommandsIdentity {
		t.Fatalf("not decided as local-commands: %+v (found %v)", rec, ok)
	}
	if f.lookups.Load() != lookups {
		t.Fatal("an unlisted host was resolved")
	}
	over, ok := f.recordWithRule(t, "local-commands:identity-forced")
	if !ok || !strings.Contains(over.Status, "stk+fetch") || over.Service != LocalCommandsIdentity {
		t.Fatalf("the attempted override is not recorded: %+v (found %v)", over, ok)
	}
	f.assertNoSSRF(t)
}

func TestLocalCommandsSocketRefusesABrokeredService(t *testing.T) {
	f := newEgressFixture(t, localCommandsSocketPolicy)
	sock := f.serveLocalCommands(t)
	code, _, err := f.viaSocket(t, sock, "stk", "https://api.github.com/user")
	if err == nil && code != http.StatusForbidden {
		t.Fatalf("a brokered service was reachable through the local-commands socket: %d", code)
	}
	rec, ok := f.recordWithRule(t, "local-commands:brokered-service")
	if !ok || rec.Host != "api.github.com" || !strings.HasPrefix(rec.Status, "403 denied") {
		t.Fatalf("record %+v (found %v)", rec, ok)
	}
	if d := f.dialed(); len(d) != 0 {
		t.Fatalf("the broker dialled %v for a refused brokered service", d)
	}
}

func TestLocalCommandsSocketWithNoPolicyEntryRefusesEverything(t *testing.T) {
	// The workspace egress allows public hosts; the socket must not fall back to it.
	f := newEgressFixture(t, `
workspace: t
egress:
  preset: public-only
servers:
  fetch:
    command: mcp-server-fetch
    network: host
    egress:
      preset: public-only
`)
	sock := f.serveLocalCommands(t)
	code, _, err := f.viaSocket(t, sock, "stk+local-commands", "https://public.test/page")
	if err == nil && code != http.StatusForbidden {
		t.Fatalf("no local-commands entry, yet public.test was reached: %d", code)
	}
	if _, ok := f.recordWithRule(t, "local-commands:no-policy"); !ok {
		t.Fatalf("refusal not recorded: %+v", f.b.Audit())
	}
	if d := f.dialed(); len(d) != 0 {
		t.Fatalf("dialled %v with no local-commands policy", d)
	}
}

func TestLocalCommandsSocketWithAnEmptyListRefusesEverything(t *testing.T) {
	f := newEgressFixture(t, `
workspace: t
servers:
  local-commands:
    command: none
    network: host
    egress:
      hosts: []
`)
	sock := f.serveLocalCommands(t)
	code, _, err := f.viaSocket(t, sock, "stk+local-commands", "https://public.test/page")
	if err == nil && code != http.StatusForbidden {
		t.Fatalf("empty list let public.test through the socket: %d", code)
	}
	if rec := f.lastRecord(t); rec.Rule != "egress:hosts/not-listed" || rec.Service != LocalCommandsIdentity {
		t.Fatalf("record %+v", rec)
	}
}

func TestLocalCommandsSocketPlainHTTPToABrokeredHostIsRefused(t *testing.T) {
	f := newEgressFixture(t, localCommandsSocketPolicy)
	sock := f.serveLocalCommands(t)
	code, body, err := f.viaSocket(t, sock, "stk", "http://api.github.com/user")
	if err != nil || code != http.StatusForbidden || !strings.Contains(body, "local-commands:brokered-service") {
		t.Fatalf("plain http to a brokered host: %d %q %v", code, body, err)
	}
}
