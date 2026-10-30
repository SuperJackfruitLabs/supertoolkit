package egress

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

// Operator ruling 2026-10-30 (network allowlist): a `hosts:` egress allows exactly the listed
// names, decided before DNS; the address checks still run after.
func hostsPolicy(t *testing.T, entries ...string) *Policy {
	t.Helper()
	p := &Policy{Preset: PresetPublicOnly, HostsSet: true}
	for _, e := range entries {
		r, err := ParseHostRule(e)
		if err != nil {
			t.Fatalf("ParseHostRule(%q): %v", e, err)
		}
		p.Hosts = append(p.Hosts, r)
	}
	return p
}

func publicResolver(addr string) Resolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(addr)}, nil
	}
}

func TestHostsAllowExactAndWildcardSubdomainsOnly(t *testing.T) {
	p := hostsPolicy(t, "registry.npmjs.org", "*.pythonhosted.org")
	res := publicResolver("93.184.215.14")
	for _, ok := range []string{"registry.npmjs.org:443", "Registry.NPMJS.org.:443", "files.pythonhosted.org:443", "a.b.pythonhosted.org:443"} {
		if d, _, err := p.ResolveFor(context.Background(), res, ok, false); err != nil || !d.Allowed {
			t.Errorf("%s: refused (%v, %s), want allowed", ok, err, d.Rule)
		}
	}
	for _, bad := range []string{"pythonhosted.org:443", "evil-registry.npmjs.org:443", "npmjs.org:443", "registry.npmjs.org.evil.test:443", "example.org:443"} {
		d, _, err := p.ResolveFor(context.Background(), res, bad, false)
		if err == nil || d.Allowed || d.Rule != "egress:hosts/not-listed" {
			t.Errorf("%s: %v %s, want refused as not listed", bad, err, d.Rule)
		}
	}
}

func TestHostsRefuseIPLiteralsAndNonHTTPSPorts(t *testing.T) {
	p := hostsPolicy(t, "registry.npmjs.org")
	res := publicResolver("93.184.215.14")
	for hp, rule := range map[string]string{
		"93.184.215.14:443":       "egress:hosts/ip-literal",
		"[2001:4860::1]:443":      "egress:hosts/ip-literal",
		"registry.npmjs.org:8443": "egress:hosts/port",
		"registry.npmjs.org:22":   "egress:hosts/port",
		"registry.npmjs.org:80":   "egress:hosts/port",
	} {
		d, _, err := p.ResolveFor(context.Background(), res, hp, false)
		if err == nil || d.Allowed || d.Rule != rule {
			t.Errorf("%s: %v %s, want %s", hp, err, d.Rule, rule)
		}
	}
}

func TestPlainHTTPOnlyForAHostListedForIt(t *testing.T) {
	p := hostsPolicy(t, "registry.npmjs.org", "http://deb.debian.org")
	res := publicResolver("93.184.215.14")
	if d, _, err := p.ResolveFor(context.Background(), res, "deb.debian.org:80", true); err != nil || !d.Allowed {
		t.Fatalf("listed http host refused: %v %s", err, d.Rule)
	}
	if d, _, err := p.ResolveFor(context.Background(), res, "deb.debian.org:443", false); err != nil || !d.Allowed {
		t.Fatalf("http-listed host must still allow https: %v %s", err, d.Rule)
	}
	d, _, err := p.ResolveFor(context.Background(), res, "registry.npmjs.org:80", true)
	if err == nil || d.Allowed || d.Rule != "egress:hosts/http-not-listed" {
		t.Fatalf("plain http to an https-only host: %v %s", err, d.Rule)
	}
	if !p.AllowsScheme("http") {
		t.Fatal("a hosts egress with an http host must let plain http reach the per-host check")
	}
	if hostsPolicy(t, "registry.npmjs.org").AllowsScheme("http") {
		t.Fatal("a hosts egress without an http host allows plain http")
	}
}

func TestAnEmptyHostsListRefusesEverything(t *testing.T) {
	p := hostsPolicy(t)
	d, _, err := p.ResolveFor(context.Background(), publicResolver("93.184.215.14"), "registry.npmjs.org:443", false)
	if err == nil || d.Allowed || d.Rule != "egress:hosts/not-listed" {
		t.Fatalf("empty list: %v %s", err, d.Rule)
	}
	if !strings.Contains(err.Error(), "egress.hosts") {
		t.Fatalf("refusal must name the fix, got %q", err)
	}
}

func TestAListedNameThatResolvesPrivateIsStillRefused(t *testing.T) {
	p := hostsPolicy(t, "intranet.example")
	d, _, err := p.ResolveFor(context.Background(), publicResolver("10.0.0.5"), "intranet.example:443", false)
	if err == nil || d.Allowed || d.Rule != "egress:public-only/private" {
		t.Fatalf("listed name resolving private: %v %s", err, d.Rule)
	}
}

func TestHostsAreNotResolvedBeforeTheyAreAllowed(t *testing.T) {
	p := hostsPolicy(t, "registry.npmjs.org")
	looked := 0
	res := func(_ context.Context, host string) ([]netip.Addr, error) {
		looked++
		return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
	}
	if _, _, err := p.ResolveFor(context.Background(), res, "unlisted.example:443", false); err == nil || looked != 0 {
		t.Fatalf("an unlisted host was resolved (%d lookups)", looked)
	}
}

func TestParseHostRuleRefusesJunk(t *testing.T) {
	for _, bad := range []string{"", "*", "*.", "*.*.org", "a.*.org", "1.2.3.4", "[::1]", "registry.npmjs.org:443",
		"https://registry.npmjs.org", "ftp://x.org", "x.org/path", "exa mple.org"} {
		if _, err := ParseHostRule(bad); err == nil {
			t.Errorf("ParseHostRule(%q) accepted junk", bad)
		}
	}
	if r, err := ParseHostRule("Bücher.Example."); err != nil || r.Name != "xn--bcher-kva.example" {
		t.Errorf("IDNA normalisation: %+v %v", r, err)
	}
}

func TestPoliciesWithoutHostsAreUnchanged(t *testing.T) {
	p := &Policy{Preset: PresetPublicOnly}
	if d, _, err := p.Resolve(context.Background(), publicResolver("93.184.215.14"), "anything.example:8443"); err != nil || !d.Allowed {
		t.Fatalf("a policy with no hosts list changed behaviour: %v %s", err, d.Rule)
	}
}
