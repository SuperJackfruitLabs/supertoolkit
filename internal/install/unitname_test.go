package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The default unit's bytes are pinned: a plan with no UnitName must render
// exactly what it always has, so existing installs see no change.
const defaultUnitBytes = `[Unit]
Description=supertoolkit credential broker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=stk
Group=stk
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/stk /run/stk
UMask=0077
RuntimeDirectory=stk
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
LoadCredential=stk-passphrase:/var/lib/stk/stk-passphrase.key
Environment=STK_HOME=/var/lib/stk STK_CONFIG=/etc/stk/supertoolkit.yaml STK_SOCKET=/run/stk/stk.sock
ExecStart=/usr/local/bin/stk serve --proxy-listen 127.0.0.1:8899 --socket-mode 0600 --allow-uid 1001 --allow-uid 1000
Restart=on-failure

[Install]
WantedBy=multi-user.target
`

func TestDefaultUnitBytesAreUnchanged(t *testing.T) {
	if got := Unit(plan()); got != defaultUnitBytes {
		t.Fatalf("default unit changed:\n%s", got)
	}
	named := plan()
	named.UnitName = "stk" // spelling the default is the default
	if got := Unit(named); got != defaultUnitBytes {
		t.Fatalf("UnitName=stk changed the unit:\n%s", got)
	}
}

func second() Plan {
	return Plan{
		User: "stk-st2", Group: "stk-st2", StateDir: "/var/lib/stk-st2", RuntimeDir: "/run/stk-st2",
		ConfigPath: "/etc/stk-st2/supertoolkit.yaml", AgentUIDs: []int{2001},
		Binary: "/usr/local/bin/stk", ProxyPort: 8900, UnitName: "stk-st2",
	}
}

func TestUnitNameFlowsToPathDryRunReportAndDescription(t *testing.T) {
	asRoot(t, 0)
	p := second()
	if !strings.Contains(Unit(p), "Description=supertoolkit credential broker (stk-st2)\n") {
		t.Errorf("description does not name the instance:\n%s", Unit(p))
	}
	dry := DryRun(p)
	if !strings.Contains(dry, "would write /etc/systemd/system/stk-st2.service:") || strings.Contains(dry, "/stk.service") {
		t.Errorf("dry run path:\n%s", dry)
	}
	root := t.TempDir()
	rep, err := Run(context.Background(), p, root, newRecorder())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/stk-st2.service")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/stk.service")); err == nil {
		t.Error("wrote the default stk.service")
	}
	if !strings.Contains(rep.String(), "systemctl enable --now stk-st2") {
		t.Errorf("report does not say how to start it:\n%s", rep.String())
	}
	if p.StartHint() != "systemctl enable --now stk-st2" || plan().StartHint() != "systemctl enable --now stk" {
		t.Errorf("hint: %q / %q", p.StartHint(), plan().StartHint())
	}
}

func TestValidateUnitName(t *testing.T) {
	for _, ok := range []string{"", "stk", "stk-st2", "a", "Stk_1.x", strings.Repeat("a", 64)} {
		p := plan()
		p.UnitName = ok
		if err := p.Validate(); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"stk.service", "stk@a", "-stk", ".stk", "a b", "a/b", "../x", strings.Repeat("a", 65), "stk\n", "a:b"} {
		p := plan()
		p.UnitName = bad
		if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "unit-name") {
			t.Errorf("%q accepted (err=%v)", bad, err)
		}
	}
}

func TestUnitNameCollisionWithAnotherInstanceIsRefused(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	if _, err := Run(context.Background(), plan(), root, newRecorder()); err != nil {
		t.Fatal(err)
	}
	unitFile := filepath.Join(root, "etc/systemd/system/stk.service")
	before, _ := os.ReadFile(unitFile)

	// Different user and state dir, same (default) unit name.
	clash := second()
	clash.UnitName = ""
	r := newRecorder()
	_, err := Run(context.Background(), clash, root, r)
	if err == nil || !strings.Contains(err.Error(), "stk.service") || !strings.Contains(err.Error(), "--unit-name") {
		t.Fatalf("collision not refused clearly: %v", err)
	}
	if after, _ := os.ReadFile(unitFile); string(after) != string(before) {
		t.Error("another instance's unit was overwritten")
	}
	// Refused before any change to the host.
	if len(r.calls) != 0 {
		t.Errorf("host touched before refusing: %v", r.calls)
	}
	if _, err := os.Stat(filepath.Join(root, "var/lib/stk-st2")); err == nil {
		t.Error("created the clashing instance's state dir before refusing")
	}

	// Same user, different state dir is also another instance.
	p := plan()
	p.StateDir = "/srv/stk"
	if _, err := Run(context.Background(), p, root, newRecorder()); err == nil {
		t.Error("different state dir under the same unit name accepted")
	}
	// Same state dir, different user is too.
	p = plan()
	p.User, p.Group = "other", "other"
	if _, err := Run(context.Background(), p, root, newRecorder()); err == nil {
		t.Error("different user under the same unit name accepted")
	}
}

func TestSameInstanceMayChangeOtherUnitSettings(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	if _, err := Run(context.Background(), plan(), root, newRecorder()); err != nil {
		t.Fatal(err)
	}
	p := plan()
	p.ProxyPort = 9001 // same User + StateDir: the same instance, re-planned
	rep, err := Run(context.Background(), p, root, newRecorder())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Changed) == 0 {
		t.Errorf("unit not reported changed: %+v", rep)
	}
	b, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/stk.service"))
	if !strings.Contains(string(b), "127.0.0.1:9001") {
		t.Error("unit not updated")
	}
}

func TestUnitFileThatIsNotAnStkUnitIsNotOverwritten(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	path := filepath.Join(root, "etc/systemd/system/foo.service")
	os.MkdirAll(filepath.Dir(path), 0o755)
	os.WriteFile(path, []byte("[Service]\nExecStart=/bin/true\n"), 0o644)
	p := plan()
	p.UnitName = "foo"
	if _, err := Run(context.Background(), p, root, newRecorder()); err == nil {
		t.Fatal("overwrote a unit that names no stk user or state dir")
	}
	if b, _ := os.ReadFile(path); !strings.Contains(string(b), "/bin/true") {
		t.Error("foreign unit changed")
	}
}

// Two stations on one host: nothing one install writes is something the other
// reads, writes or shares.
func TestTwoInstancesShareNothing(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	r := newRecorder()
	a, b := plan(), second()
	if _, err := Run(context.Background(), a, root, r); err != nil {
		t.Fatal(err)
	}
	afterA := snapshot(t, root)
	if _, err := Run(context.Background(), b, root, r); err != nil {
		t.Fatal(err)
	}
	// Everything A wrote is byte- and mode-identical after B's install.
	afterB := snapshot(t, root)
	for k, v := range afterA {
		if afterB[k] != v {
			t.Errorf("installing B changed A's %s", k)
		}
	}
	// Re-running A afterwards changes nothing either (B did not clobber it).
	if rep, err := Run(context.Background(), a, root, r); err != nil || len(rep.Created)+len(rep.Changed) != 0 {
		t.Fatalf("A not idempotent after B: %v %+v", err, rep)
	}
	pa, _ := os.ReadFile(filepath.Join(root, "var/lib/stk/stk-passphrase.key"))
	pb, _ := os.ReadFile(filepath.Join(root, "var/lib/stk-st2/stk-passphrase.key"))
	if len(pa) == 0 || len(pb) == 0 || string(pa) == string(pb) {
		t.Error("passphrases missing or shared")
	}
	ua, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/stk.service"))
	ub, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/stk-st2.service"))
	if string(ua) != Unit(a) || string(ub) != Unit(b) {
		t.Fatal("units are not each instance's own")
	}
	// Every instance-specific value appears in its unit and not in the other's.
	for _, s := range []string{"stk-st2", "2001", "8900"} {
		if strings.Contains(string(ua), s) {
			t.Errorf("A's unit mentions B's %q", s)
		}
	}
	for _, s := range []string{"1001", "1000", "8899", "/var/lib/stk ", "/run/stk "} {
		if strings.Contains(string(ub), s) {
			t.Errorf("B's unit mentions A's %q:\n%s", s, ub)
		}
	}
	if !strings.Contains(string(ub), "--allow-uid 2001\n") || strings.Count(string(ub), "--allow-uid") != 1 {
		t.Errorf("B's allow-uids:\n%s", ub)
	}
	for _, c := range []string{"chown stk-st2:stk-st2 " + filepath.Join(root, "var/lib/stk-st2"),
		"chown stk:stk " + filepath.Join(root, "var/lib/stk")} {
		if !r.saw(c) {
			t.Errorf("missing %q", c)
		}
	}
	// A's state dir is not B's parent or child (so 0700 on one cannot expose the other).
	if strings.HasPrefix(b.StateDir+"/", a.StateDir+"/") || strings.HasPrefix(a.StateDir+"/", b.StateDir+"/") {
		t.Error("nested state dirs")
	}
}
