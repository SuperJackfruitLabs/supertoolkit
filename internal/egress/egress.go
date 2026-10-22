// Package egress decides where a brokered client may connect, by address.
//
// Path rules answer "may this request go to this declared host". They cannot
// answer "any public host, but nothing on this machine, this network or the
// cloud's metadata service", which is what a fetch-style tool needs. This
// package answers that, after DNS resolution, on the address actually dialled.
package egress

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Class names a range of addresses that is not the public internet.
type Class string

const (
	Loopback    Class = "loopback"
	Private     Class = "private"
	LinkLocal   Class = "link-local"
	CGNAT       Class = "cgnat"
	ULA         Class = "ula"
	Unspecified Class = "unspecified"
	Multicast   Class = "multicast"
	Reserved    Class = "reserved"
	// Public is the absence of every other class.
	Public Class = "public"
)

// Classes are the non-public classes, in the order they are checked.
var Classes = []Class{Loopback, Private, LinkLocal, CGNAT, ULA, Unspecified, Multicast, Reserved}

var ranges = map[Class][]netip.Prefix{
	Loopback:    pfx("127.0.0.0/8", "::1/128"),
	Private:     pfx("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
	LinkLocal:   pfx("169.254.0.0/16", "fe80::/10"),
	CGNAT:       pfx("100.64.0.0/10"),
	ULA:         pfx("fc00::/7"),
	Unspecified: pfx("0.0.0.0/8", "::/128"),
	Multicast:   pfx("224.0.0.0/4", "ff00::/8"),
	Reserved: pfx("240.0.0.0/4", "192.0.0.0/24", "198.18.0.0/15",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "100::/64"),
}

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

var (
	nat64  = netip.MustParsePrefix("64:ff9b::/96")
	sixTo4 = netip.MustParsePrefix("2002::/16")
)

// canonical returns the IPv4 address an IPv6 one carries, where it carries one
// that the network will deliver to: IPv4-mapped, NAT64 and 6to4. Without this,
// ::ffff:127.0.0.1 or 64:ff9b::a9fe:a9fe would launder a refused address.
func canonical(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if !a.Is6() {
		return a
	}
	b := a.As16()
	if nat64.Contains(a) {
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if sixTo4.Contains(a) {
		return netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
	}
	return a
}

// Classify names the class of one address. Zone is ignored.
func Classify(a netip.Addr) Class {
	a = canonical(a.WithZone(""))
	for _, c := range Classes {
		for _, p := range ranges[c] {
			if p.Contains(a) {
				return c
			}
		}
	}
	return Public
}

// Matcher is one allow or deny entry: a prefix or a class.
type Matcher struct {
	Prefix netip.Prefix
	Class  Class
}

func (m Matcher) matches(a netip.Addr) bool {
	if m.Class != "" {
		return Classify(a) == m.Class
	}
	return m.Prefix.Contains(canonical(a.WithZone(""))) || m.Prefix.Contains(a.WithZone(""))
}

// ParseMatcher reads "10.0.0.0/8", "192.0.2.7", or a class name.
func ParseMatcher(s string) (Matcher, error) {
	s = strings.TrimSpace(s)
	for _, c := range append(Classes, Public) {
		if s == string(c) {
			return Matcher{Class: c}, nil
		}
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return Matcher{Prefix: p.Masked()}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return Matcher{Prefix: netip.PrefixFrom(a, a.BitLen())}, nil
	}
	return Matcher{}, fmt.Errorf("%q is neither a CIDR, an address nor a class (%s)", s, classList())
}

func classList() string {
	names := make([]string, 0, len(Classes)+1)
	for _, c := range append(Classes, Public) {
		names = append(names, string(c))
	}
	return strings.Join(names, ", ")
}

// Preset is a named default.
type Preset string

const (
	// PresetNone refuses no address by class.
	PresetNone Preset = "none"
	// PresetPublicOnly refuses every non-public class.
	PresetPublicOnly Preset = "public-only"
)

// Policy is one egress declaration. The zero value allows every address.
type Policy struct {
	Preset  Preset
	Allow   []Matcher
	Deny    []Matcher
	Schemes []string // lower-case; empty means https only
	Methods []string // upper-case; empty means any
}

// Decision is the answer for one address.
type Decision struct {
	Allowed bool
	Rule    string
	Addr    netip.Addr
	Class   Class
}

// Decide answers for one address. Order: deny, allow, preset, default.
func (p *Policy) Decide(a netip.Addr) Decision {
	d := Decision{Addr: a, Class: Classify(a)}
	for i, m := range p.Deny {
		if m.matches(a) {
			d.Rule = fmt.Sprintf("egress:deny#%d", i+1)
			return d
		}
	}
	for i, m := range p.Allow {
		if m.matches(a) {
			d.Allowed, d.Rule = true, fmt.Sprintf("egress:allow#%d", i+1)
			return d
		}
	}
	if p.Preset == PresetPublicOnly {
		if d.Class != Public {
			d.Rule = "egress:public-only/" + string(d.Class)
			return d
		}
		d.Allowed, d.Rule = true, "egress:public-only"
		return d
	}
	d.Allowed, d.Rule = true, "egress:default"
	return d
}

// AllowsScheme reports whether a URL scheme may be used.
func (p *Policy) AllowsScheme(s string) bool {
	s = strings.ToLower(s)
	if len(p.Schemes) == 0 {
		return s == "https"
	}
	for _, x := range p.Schemes {
		if x == s {
			return true
		}
	}
	return false
}

// AllowsMethod reports whether a request method may be used.
func (p *Policy) AllowsMethod(m string) bool {
	if len(p.Methods) == 0 {
		return true
	}
	for _, x := range p.Methods {
		if x == strings.ToUpper(m) {
			return true
		}
	}
	return false
}

// Inspects reports whether requests must be seen one by one, which an HTTPS
// tunnel allows only when it is opened.
func (p *Policy) Inspects() bool { return len(p.Methods) > 0 }

// Resolver looks a hostname up. net.DefaultResolver.LookupNetIP satisfies it.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// DefaultResolver is the system resolver.
func DefaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Resolve decides a host:port and returns the one address to dial.
//
// The host is resolved once, here, and **every** answer must be allowed: a name
// with one public and one private answer is refused, because which one a later
// lookup returns is the attacker's choice. The caller dials the returned
// address, not the name, so a second DNS answer cannot move the connection
// (rebinding).
func (p *Policy) Resolve(ctx context.Context, res Resolver, hostport string) (Decision, string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return Decision{Rule: "egress:bad-address"}, "", err
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		if res == nil {
			res = DefaultResolver
		}
		addrs, err = res(ctx, host)
		if err != nil || len(addrs) == 0 {
			return Decision{Rule: "egress:unresolved"}, "", fmt.Errorf("resolving %s: %v", host, err)
		}
	}
	var first Decision
	for i, a := range addrs {
		d := p.Decide(a)
		if !d.Allowed {
			return d, "", fmt.Errorf("%s resolves to %s (%s), refused by %s", host, a, d.Class, d.Rule)
		}
		if i == 0 {
			first = d
		}
	}
	return first, net.JoinHostPort(first.Addr.WithZone("").String(), port), nil
}
