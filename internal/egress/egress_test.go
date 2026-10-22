package egress

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func publicOnly() *Policy { return &Policy{Preset: PresetPublicOnly} }

func TestPublicOnlyRefusesEveryNonPublicClass(t *testing.T) {
	cases := map[string]Class{
		"127.0.0.1":              Loopback,
		"127.9.9.9":              Loopback,
		"::1":                    Loopback,
		"10.1.2.3":               Private,
		"172.16.0.1":             Private,
		"192.168.1.1":            Private,
		"169.254.169.254":        LinkLocal,
		"fe80::1":                LinkLocal,
		"100.64.0.1":             CGNAT,
		"100.78.52.87":           CGNAT,
		"fd00:ec2::254":          ULA,
		"0.0.0.0":                Unspecified,
		"::":                     Unspecified,
		"224.0.0.1":              Multicast,
		"255.255.255.255":        Reserved,
		"::ffff:127.0.0.1":       Loopback,  // IPv4-mapped
		"64:ff9b::a9fe:a9fe":     LinkLocal, // NAT64 of 169.254.169.254
		"2002:7f00:1::1":         Loopback,  // 6to4 of 127.0.0.1
		"::ffff:169.254.169.254": LinkLocal,
	}
	p := publicOnly()
	for s, want := range cases {
		a := netip.MustParseAddr(s)
		d := p.Decide(a)
		if d.Allowed {
			t.Errorf("%s allowed by %s, want refused as %s", s, d.Rule, want)
		}
		if d.Class != want || d.Rule != "egress:public-only/"+string(want) {
			t.Errorf("%s: class %s rule %s, want %s", s, d.Class, d.Rule, want)
		}
	}
}

func TestPublicOnlyAllowsPublic(t *testing.T) {
	for _, s := range []string{"93.184.215.14", "1.1.1.1", "2606:4700:4700::1111", "100.128.0.1"} {
		d := publicOnly().Decide(netip.MustParseAddr(s))
		if !d.Allowed || d.Rule != "egress:public-only" {
			t.Errorf("%s: %+v, want allowed by egress:public-only", s, d)
		}
	}
}

func TestDenyBeatsAllowBeatsPreset(t *testing.T) {
	allow, _ := ParseMatcher("10.0.0.0/8")
	deny, _ := ParseMatcher("10.9.0.0/16")
	p := &Policy{Preset: PresetPublicOnly, Allow: []Matcher{allow}, Deny: []Matcher{deny}}
	if d := p.Decide(netip.MustParseAddr("10.1.1.1")); !d.Allowed || d.Rule != "egress:allow#1" {
		t.Errorf("allow exception: %+v", d)
	}
	if d := p.Decide(netip.MustParseAddr("10.9.1.1")); d.Allowed || d.Rule != "egress:deny#1" {
		t.Errorf("deny wins: %+v", d)
	}
	cls, _ := ParseMatcher("cgnat")
	p = &Policy{Deny: []Matcher{cls}}
	if d := p.Decide(netip.MustParseAddr("100.100.100.200")); d.Allowed || d.Rule != "egress:deny#1" {
		t.Errorf("class deny: %+v", d)
	}
	if d := p.Decide(netip.MustParseAddr("127.0.0.1")); !d.Allowed || d.Rule != "egress:default" {
		t.Errorf("no preset allows by default: %+v", d)
	}
}

func TestParseMatcherRefusesJunk(t *testing.T) {
	if _, err := ParseMatcher("intranet"); err == nil {
		t.Fatal("an unknown word parsed")
	}
}

func fakeResolver(m map[string][]string) Resolver {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, s := range m[host] {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

func TestResolveRefusesANameThatResolvesPrivate(t *testing.T) {
	res := fakeResolver(map[string][]string{
		"sneaky.example": {"93.184.215.14", "127.0.0.1"},
		"intra.example":  {"10.0.0.5"},
		"public.example": {"93.184.215.14"},
	})
	p := publicOnly()
	for _, h := range []string{"sneaky.example:443", "intra.example:80"} {
		d, addr, err := p.Resolve(context.Background(), res, h)
		if err == nil || d.Allowed || addr != "" {
			t.Errorf("%s: allowed (%+v %q)", h, d, addr)
		}
	}
	d, addr, err := p.Resolve(context.Background(), res, "public.example:443")
	if err != nil || !d.Allowed || addr != "93.184.215.14:443" {
		t.Fatalf("public: %+v %q %v", d, addr, err)
	}
}

func TestResolvePinsTheAddressNotTheName(t *testing.T) {
	// The address returned is what is dialled: a literal, never the hostname,
	// so no second lookup happens downstream.
	_, addr, err := publicOnly().Resolve(context.Background(),
		fakeResolver(map[string][]string{"x.example": {"2606:4700::1"}}), "x.example:443")
	if err != nil || strings.Contains(addr, "x.example") || addr != "[2606:4700::1]:443" {
		t.Fatalf("addr %q err %v", addr, err)
	}
}

func TestLiteralsAreNotResolved(t *testing.T) {
	called := false
	res := func(context.Context, string) ([]netip.Addr, error) { called = true; return nil, nil }
	d, _, err := publicOnly().Resolve(context.Background(), res, "[::1]:80")
	if err == nil || d.Allowed || called {
		t.Fatalf("literal ::1: %+v err=%v resolver called=%v", d, err, called)
	}
}

func TestSchemesAndMethods(t *testing.T) {
	p := &Policy{Schemes: []string{"https", "http"}, Methods: []string{"GET"}}
	if !p.AllowsScheme("HTTP") || p.AllowsScheme("ftp") {
		t.Error("schemes")
	}
	if !p.AllowsMethod("get") || p.AllowsMethod("POST") {
		t.Error("methods")
	}
	if (&Policy{}).AllowsScheme("http") {
		t.Error("the default scheme set is https only")
	}
}
