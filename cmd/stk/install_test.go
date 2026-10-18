package main

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/install"
)

type nopRunner struct{ calls int }

func (n *nopRunner) Run(string, ...string) error { n.calls++; return nil }

func TestInstallFlags(t *testing.T) {
	p, dry, err := parseInstallArgs([]string{"--user", "stk", "--group=agents", "--agent-uid", "1001",
		"--agent-uid=1000", "--proxy-port", "9000", "--dry-run", "--state-dir", "/srv/stk"})
	if err != nil {
		t.Fatal(err)
	}
	want := install.Plan{User: "stk", Group: "agents", StateDir: "/srv/stk", RuntimeDir: "/run/stk",
		ConfigPath: "/etc/stk/supertoolkit.yaml", AgentUIDs: []int{1001, 1000}, ProxyPort: 9000}
	p.Binary = ""
	if !dry || !reflect.DeepEqual(p, want) {
		t.Fatalf("got %+v dry=%v", p, dry)
	}
	for _, bad := range [][]string{{}, {"--user"}, {"--user", "stk", "--agent-uid", "x"}, {"--user", "stk", "--bogus"}} {
		if _, _, err := parseInstallArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestInstallCommandDryRunWritesNothingAndIsLinuxOnly(t *testing.T) {
	root := t.TempDir()
	r := &nopRunner{}
	var out bytes.Buffer
	if err := runInstall([]string{"--user", "stk", "--agent-uid", "1000", "--dry-run"}, "linux", root, r, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ExecStart=") || r.calls != 0 {
		t.Fatalf("dry run: calls=%d out=%s", r.calls, out.String())
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatal("dry run wrote files")
	}
	err := runInstall([]string{"--user", "stk", "--agent-uid", "1000", "--dry-run"}, "darwin", root, r, &out)
	if err == nil || err.Error() != "install is Linux/systemd only" {
		t.Fatalf("non-linux: %v", err)
	}
}

func TestInstallUnitNameFlag(t *testing.T) {
	p, _, err := parseInstallArgs([]string{"--user", "u", "--unit-name", "stk-st2"})
	if err != nil || p.UnitName != "stk-st2" {
		t.Fatalf("got %+v %v", p, err)
	}
	if p, _, _ = parseInstallArgs([]string{"--user", "u", "--unit-name=x"}); p.UnitName != "x" {
		t.Fatalf("= form: %+v", p)
	}
	if p, _, _ = parseInstallArgs([]string{"--user", "u"}); p.UnitName != "" {
		t.Fatalf("default must stay empty: %q", p.UnitName)
	}
	root := t.TempDir()
	var out bytes.Buffer
	err = runInstall([]string{"--user", "u", "--agent-uid", "1", "--unit-name", "bad.service", "--dry-run"}, "linux", root, &nopRunner{}, &out)
	if err == nil || !strings.Contains(err.Error(), "unit-name") {
		t.Fatalf("bad name: %v", err)
	}
	out.Reset()
	if err := runInstall([]string{"--user", "u", "--agent-uid", "1", "--unit-name", "stk-st2", "--dry-run"}, "linux", root, &nopRunner{}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "/etc/systemd/system/stk-st2.service") {
		t.Fatalf("dry run:\n%s", out.String())
	}
}
