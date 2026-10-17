package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/isolation"
)

func noProbe(t *testing.T) {
	t.Helper()
	old := doctorProbe
	doctorProbe = func() check { return check{} }
	t.Cleanup(func() { doctorProbe = old })
}

func TestDoctorJSONShape(t *testing.T) {
	noProbe(t)
	dir := t.TempDir()
	t.Setenv("STK_HOME", filepath.Join(dir, "state"))
	t.Setenv("STK_SOCKET", "")
	cfg := filepath.Join(dir, "supertoolkit.yaml")
	if err := os.WriteFile(cfg, []byte("agent_uids: [4242]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STK_CONFIG", cfg)

	var out bytes.Buffer
	_ = runDoctor([]string{"--json", "--agent-uid", "4243"}, &out)
	var got struct {
		Checks    []map[string]any `json:"checks"`
		Isolation map[string]any   `json:"isolation"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if len(got.Checks) == 0 {
		t.Fatal("no checks")
	}
	for _, c := range got.Checks {
		for _, k := range []string{"name", "ok", "detail"} {
			if _, ok := c[k]; !ok {
				t.Fatalf("check %v lacks %q", c, k)
			}
		}
	}
	lvl, _ := got.Isolation["level"].(string)
	if lvl != isolation.SeparateUser && lvl != isolation.SameUser {
		t.Fatalf("isolation level = %q with agent uids configured: %v", lvl, got.Isolation)
	}
	if got.Isolation["method"] == nil {
		t.Fatalf("no method: %v", got.Isolation)
	}
	if _, ok := got.Isolation["reasons"].([]any); !ok {
		t.Fatalf("reasons is not a list: %v", got.Isolation)
	}

	// No agent uids anywhere: say unknown, never omit.
	if err := os.WriteFile(cfg, []byte("workspace: w\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_ = runDoctor([]string{"--json"}, &out)
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Isolation["level"] != "unknown" || !strings.Contains(out.String(), "no agent uids configured") {
		t.Fatalf("isolation = %v", got.Isolation)
	}

	// JSON mode still exits non-zero when a check fails.
	t.Setenv("STK_CONFIG", filepath.Join(dir, "missing.yaml"))
	out.Reset()
	if err := runDoctor([]string{"--json"}, &out); err == nil {
		t.Fatal("a failed check exited zero in JSON mode")
	}
	if !json.Valid(out.Bytes()) {
		t.Fatalf("failing run did not print JSON: %s", out.String())
	}
}

func TestDoctorArgs(t *testing.T) {
	o, err := parseDoctorArgs([]string{"--json", "--agent-uid", "5", "--agent-uid=6"})
	if err != nil || !o.json || !reflect.DeepEqual(o.agentUIDs, []int{5, 6}) {
		t.Fatalf("got %+v, %v", o, err)
	}
	for _, bad := range [][]string{{"--agent-uid"}, {"--agent-uid", "x"}, {"--agent-uid=-3"}, {"--nope"}} {
		if _, err := parseDoctorArgs(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	o, err = parseDoctorArgs([]string{"--as-uid-probe", "/a", "/b"})
	if err != nil || !reflect.DeepEqual(o.asUIDProbe, []string{"/a", "/b"}) {
		t.Fatalf("got %+v, %v", o, err)
	}
}

func TestIsolationPaths(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "github.cred"), nil, 0o600)
	got := isolationPaths(dir, "/etc/stk/supertoolkit.yaml", "/run/stk/stk.sock")
	for _, want := range []string{dir, filepath.Join(dir, "github.cred"), filepath.Join(dir, "salt"),
		filepath.Join(dir, "handover.key"), filepath.Join(dir, "proxy.key"), filepath.Join(dir, "proxy.addr"),
		filepath.Join(dir, "stk-passphrase.key"), filepath.Join(dir, "machine.key"), filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "audit.log"), filepath.Join(dir, "approvals"),
		"/etc/stk/supertoolkit.yaml", "/run/stk/stk.sock"} {
		found := false
		for _, g := range got {
			found = found || g == want
		}
		if !found {
			t.Errorf("missing %s in %v", want, got)
		}
	}
}

func TestAccessAttemptReasons(t *testing.T) {
	run := func(uid int, paths []string) ([]string, error) {
		switch uid {
		case 1:
			return []string{paths[0]}, nil
		case 2:
			return nil, errors.New("exec failed")
		}
		return nil, nil
	}
	got := accessAttempt([]string{"/s/salt"}, []int{1, 2, 3}, run)
	if len(got) != 2 || !strings.Contains(got[0], "uid 1 opened /s/salt") || !strings.Contains(got[1], "uid 2") {
		t.Fatalf("got %v", got)
	}
}

func TestRootAccessAttemptForcesSameUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the access attempt needs root to switch uid")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "stk")
	if out, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	os.Chmod(dir, 0o755)
	open := filepath.Join(dir, "salt")
	os.WriteFile(open, []byte("x"), 0o644)
	closed := filepath.Join(dir, "gh.cred")
	os.WriteFile(closed, []byte("x"), 0o600)
	const nobody = 65534
	reasons := accessAttempt([]string{open, closed}, []int{nobody}, uidOpener(exe))
	if len(reasons) != 1 || !strings.Contains(reasons[0], open) {
		t.Fatalf("reasons = %v, want exactly %s", reasons, open)
	}
	r := isolation.WithAccess(isolation.Report{Level: isolation.SeparateUser, Method: isolation.MethodModeBits}, reasons)
	if r.Level != isolation.SameUser || r.Method != isolation.MethodAccess {
		t.Fatalf("got %+v", r)
	}
}
