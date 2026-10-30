package policy

import (
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/egress"
)

func TestEgressHostsLoadDefaultsToPublicOnlyAndRefusesJunk(t *testing.T) {
	cfg, err := Parse("t.yaml", []byte(`
workspace: t
servers:
  local-commands:
    command: none
    network: host
    egress:
      hosts: ["registry.npmjs.org", "*.pythonhosted.org", "http://deb.debian.org"]
`))
	if err != nil {
		t.Fatal(err)
	}
	eg := cfg.EgressFor("local-commands")
	if eg == nil || !eg.HostsSet || len(eg.Hosts) != 3 || eg.Preset != egress.PresetPublicOnly || !eg.Hosts[2].HTTP || !eg.Hosts[1].Wildcard {
		t.Fatalf("parsed %+v", eg)
	}
	empty, err := Parse("t.yaml", []byte("workspace: t\nservers:\n  local-commands:\n    command: none\n    network: host\n    egress:\n      hosts: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if e := empty.EgressFor("local-commands"); e == nil || !e.HostsSet || len(e.Hosts) != 0 {
		t.Fatalf("an empty hosts list must load as refuse-everything, got %+v", e)
	}
	none, _ := Parse("t.yaml", []byte("workspace: t\nservers:\n  fetch:\n    command: none\n    network: host\n    egress: { preset: public-only }\n"))
	if e := none.EgressFor("fetch"); e == nil || e.HostsSet {
		t.Fatalf("an egress without hosts must not turn the hosts check on: %+v", e)
	}
	for _, bad := range []string{`["1.2.3.4"]`, `["x.org:443"]`, `["https://x.org"]`, `["*"]`} {
		_, err := Parse("t.yaml", []byte("workspace: t\nservers:\n  local-commands:\n    command: none\n    network: host\n    egress:\n      hosts: "+bad+"\n"))
		if err == nil || !strings.Contains(err.Error(), "hosts") {
			t.Errorf("hosts %s: err %v, want a plain hosts error", bad, err)
		}
	}
}
