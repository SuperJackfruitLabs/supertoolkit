package broker

import (
	"net/http"
	"strings"
	"testing"
)

// Operator ruling 2026-10-30 (network allowlist for local commands): the local-commands
// identity reaches only the hosts its egress lists.
const localCommandsEgress = `
workspace: t
servers:
  local-commands:
    command: none
    network: host
    egress:
      hosts: ["public.test", "http://plain.public.test", "*.wild.test"]
`

func TestHostsEgressTunnelsAListedHostAndRecordsIt(t *testing.T) {
	f := newEgressFixture(t, localCommandsEgress)
	code, body, err := f.get(t, "local-commands", "https://public.test/page")
	if err != nil || code != 200 || body != "public GET /page" {
		t.Fatalf("listed host: %d %q %v", code, body, err)
	}
	rec := f.lastRecord(t)
	if rec.Rule != "egress:hosts#1+egress:public-only" || rec.Service != "local-commands" || rec.Host != "public.test" ||
		!strings.HasPrefix(rec.Addr, fakePublic+":") {
		t.Fatalf("record %+v", rec)
	}
	f.assertNoSSRF(t)
}

func TestHostsEgressRefusesAnUnlistedHostNamingTheFix(t *testing.T) {
	f := newEgressFixture(t, localCommandsEgress)
	lookups := f.lookups.Load()
	code, body, err := f.get(t, "local-commands", "https://rebind.test/")
	if err == nil && code != http.StatusForbidden {
		t.Fatalf("unlisted host: status %d, want refused", code)
	}
	_ = body
	rec := f.lastRecord(t)
	if rec.Rule != "egress:hosts/not-listed" || !strings.HasPrefix(rec.Status, "403 denied") || rec.Service != "local-commands" {
		t.Fatalf("record %+v", rec)
	}
	if f.lookups.Load() != lookups {
		t.Fatal("an unlisted host was resolved")
	}
	f.assertNoSSRF(t)
}

func TestHostsEgressRefusalBodyNamesTheFix(t *testing.T) {
	f := newEgressFixture(t, localCommandsEgress)
	// Plain http so the 403 body reaches the client (a refused CONNECT body is not shown).
	code, body, err := f.get(t, "local-commands", "http://public.test/page")
	if err != nil || code != http.StatusForbidden {
		t.Fatalf("plain http to an https-only host: %d %v", code, err)
	}
	if !strings.Contains(body, "egress:hosts/http-not-listed") || !strings.Contains(body, "egress.hosts") {
		t.Fatalf("body %q does not name the rule and the fix", body)
	}
}

func TestHostsEgressRefusesIPLiteralsAndPrivateAnswers(t *testing.T) {
	f := newEgressFixture(t, localCommandsEgress)
	for u, rule := range map[string]string{
		"https://" + fakePublic + "/": "egress:hosts/ip-literal",
		"https://127.0.0.1:3101/":     "egress:hosts/ip-literal",
		"https://public.test:8443/":   "egress:hosts/port",
	} {
		code, _, err := f.get(t, "local-commands", u)
		if err == nil && code != http.StatusForbidden {
			t.Errorf("%s: status %d, want refused", u, code)
		}
		if rec := f.lastRecord(t); rec.Rule != rule {
			t.Errorf("%s: rule %s, want %s", u, rec.Rule, rule)
		}
	}
	f.assertNoSSRF(t)
}

func TestHostsEgressAllowsPlainHTTPOnlyForAHostListedForIt(t *testing.T) {
	f := newEgressFixture(t, `
workspace: t
servers:
  local-commands:
    command: none
    network: host
    egress:
      hosts: ["http://public.test"]
`)
	code, body, err := f.get(t, "local-commands", "http://public.test/page")
	if err != nil || code != 200 || body != "public GET /page" {
		t.Fatalf("http-listed host: %d %q %v", code, body, err)
	}
	if rec := f.lastRecord(t); rec.Rule != "egress:hosts#1+egress:public-only" {
		t.Fatalf("record %+v", rec)
	}
}

func TestAnEmptyHostsEgressRefusesEveryHost(t *testing.T) {
	f := newEgressFixture(t, `
workspace: t
servers:
  local-commands:
    command: none
    network: host
    egress:
      hosts: []
`)
	code, _, err := f.get(t, "local-commands", "https://public.test/page")
	if err == nil && code != http.StatusForbidden {
		t.Fatalf("empty hosts list let public.test through: %d", code)
	}
	if rec := f.lastRecord(t); rec.Rule != "egress:hosts/not-listed" {
		t.Fatalf("record %+v", rec)
	}
}
