package policy

import (
	"net/netip"
	"strings"
	"testing"
)

const fetchPolicy = `
workspace: t
egress: { preset: public-only }
servers:
  fetch:
    command: mcp-server-fetch
    egress:
      preset: public-only
      deny: [93.184.0.0/16]
      schemes: [https, http]
      methods: [get]
    capabilities:
      fetch: agent
`

func TestEgressParsesForWorkspaceAndServer(t *testing.T) {
	cfg, err := Parse("t.yaml", []byte(fetchPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Egress() == nil || cfg.Egress().Decide(netip.MustParseAddr("127.0.0.1")).Allowed {
		t.Fatal("workspace egress is not public-only")
	}
	srv, _ := cfg.Server("fetch")
	if srv.Host != "" || srv.Network != NetworkConfined {
		t.Errorf("host %q network %q", srv.Host, srv.Network)
	}
	eg := cfg.EgressFor("fetch")
	if eg == cfg.Egress() || !eg.AllowsMethod("GET") || eg.AllowsMethod("POST") || !eg.AllowsScheme("http") {
		t.Errorf("server egress not its own: %+v", eg)
	}
	if d := eg.Decide(netip.MustParseAddr("93.184.215.14")); d.Allowed || d.Rule != "egress:deny#1" {
		t.Errorf("server deny: %+v", d)
	}
	if cfg.EgressFor("nobody") != cfg.Egress() {
		t.Error("an unknown identity does not fall back to the workspace egress")
	}
	if a, rule := srv.Decide("fetch", ToolHint{}); a != ActionAgent || rule != "server:fetch/capabilities.fetch" {
		t.Errorf("tool decision %v %s", a, rule)
	}
	if _, rule := srv.Decide("other", ToolHint{}); rule != "server:fetch/default.unannotated" {
		t.Errorf("unannotated rule %s", rule)
	}
}

func TestEgressMistakesFailTheLoad(t *testing.T) {
	for _, bad := range []string{
		"egress: { preset: public }",
		"egress: { deny: [intranet] }",
		"egress: { schemes: [ftp] }",
		"servers: { f: { command: x, egress: { preset: publik-only } } }",
		"servers: { f: { command: x, egress: {}, network: sandbox } }",
		// A server with a credential still needs the host its placeholder is swapped on.
		"servers: { f: { command: x, env_var: TOKEN, egress: {} } }",
		// And one with neither says nothing about where it may go.
		"servers: { f: { command: x } }",
	} {
		if _, err := Parse("t.yaml", []byte("workspace: t\n"+bad)); err == nil {
			t.Errorf("loaded: %s", bad)
		} else if !strings.Contains(err.Error(), "t.yaml") {
			t.Errorf("error does not name the file: %v", err)
		}
	}
}
