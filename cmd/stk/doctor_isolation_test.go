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
	// t.TempDir's parents may be 0700 root, which uid 65534 cannot traverse
	// to exec the binary. Build where every component is 0755.
	dir, err := os.MkdirTemp("/tmp", "stk-access-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for d := dir; d != "/"; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil || fi.Mode().Perm()&0o005 != 0o005 {
			t.Fatalf("%s is not traversable by others (%v)", d, err)
		}
	}
	exe := filepath.Join(dir, "stk")
	if out, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	os.Chmod(exe, 0o755)
	open := filepath.Join(dir, "salt")
	os.WriteFile(open, []byte("x"), 0o644)
	closed := filepath.Join(dir, "gh.cred")
	os.WriteFile(closed, []byte("x"), 0o600)
	const nobody = 65534

	// The child must have run: an exec failure would also be a reason, and
	// must not be mistaken for a detection.
	opened, err := uidOpener(exe)(nobody, []string{open, closed})
	if err != nil {
		t.Fatalf("access attempt could not run as uid %d: %v", nobody, err)
	}
	if len(opened) != 1 || opened[0] != open {
		t.Fatalf("opened = %v, want exactly %s", opened, open)
	}
	reasons := accessAttempt([]string{open, closed}, []int{nobody}, uidOpener(exe))
	if len(reasons) != 1 || !strings.Contains(reasons[0], "opened "+open) {
		t.Fatalf("reasons = %v", reasons)
	}
	r := isolation.WithAccess(isolation.Report{Level: isolation.SeparateUser, Method: isolation.MethodModeBits}, reasons)
	if r.Level != isolation.SameUser || r.Method != isolation.MethodAccess {
		t.Fatalf("got %+v", r)
	}
}

func TestDoctorTextFooterFollowsIsolationLevel(t *testing.T) {
	noProbe(t)
	oldC, oldI := doctorCheckFn, doctorIsolation
	t.Cleanup(func() { doctorCheckFn, doctorIsolation = oldC, oldI })
	doctorCheckFn = func() []check { return []check{{ok: true, label: "all good"}} }
	for _, tc := range []struct {
		rep        isolation.Report
		want, deny string
	}{
		{isolation.Report{Level: isolation.SeparateUser, Method: isolation.MethodModeBits}, "the agent cannot reach a credential.", "not proven"},
		{isolation.Report{Level: isolation.SameUser, Method: isolation.MethodModeBits, Reasons: []string{"a", "b"}}, "isolation is not proven: 2 reason(s)", "cannot reach a credential"},
		{isolation.NoAgents(), "isolation is not proven: 1 reason(s)", "cannot reach a credential"},
	} {
		doctorIsolation = func([]int) isolation.Report { return tc.rep }
		var out bytes.Buffer
		if err := runDoctor(nil, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), tc.want) || strings.Contains(out.String(), tc.deny) {
			t.Errorf("%s: output\n%s", tc.rep.Level, out.String())
		}
	}
}

func TestDoctorTextNamesTheACLLimitation(t *testing.T) {
	noProbe(t)
	oldC, oldI := doctorCheckFn, doctorIsolation
	t.Cleanup(func() { doctorCheckFn, doctorIsolation = oldC, oldI })
	doctorCheckFn = func() []check { return []check{{ok: true, label: "all good"}} }
	doctorIsolation = func([]int) isolation.Report {
		return isolation.Report{Level: isolation.SeparateUser, Method: isolation.MethodModeBits}
	}
	var out bytes.Buffer
	runDoctor(nil, &out)
	if !strings.Contains(out.String(), "ACL") {
		t.Fatalf("text output does not state the ACL limitation:\n%s", out.String())
	}
}

func TestDoctorProbeRoutesInAnyOrder(t *testing.T) {
	for _, args := range [][]string{{"--probe"}, {"--json", "--probe"}, {"--probe", "--json"}, {"--with-proxy-key", "--probe"}} {
		o, err := parseDoctorArgs(args)
		if err != nil || !o.probe {
			t.Errorf("%v: %+v %v", args, o, err)
		}
	}
}

func TestSecretPathsUseExactConfigPath(t *testing.T) {
	got := secretPaths([]string{"/s", "/s/stk.yml", "/etc/supertoolkit.yaml", "/run/stk.sock"}, "/etc/supertoolkit.yaml", "/run/stk.sock")
	if !reflect.DeepEqual(got, []string{"/s", "/s/stk.yml"}) {
		t.Fatalf("got %v", got)
	}
}

// Two instances on one host: doctor run with the second's environment reports
// the second's paths only. Nothing is hard-coded to the default instance.
func TestDoctorIsolationFollowsTheInstanceEnvironment(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) (home, cfg, sock string) {
		home = filepath.Join(dir, name, "state")
		os.MkdirAll(home, 0o700)
		cfg = filepath.Join(dir, name, "supertoolkit.yaml")
		os.WriteFile(cfg, []byte("agent_uids: [4242]\n"), 0o600)
		return home, cfg, filepath.Join(dir, name, "run", "stk.sock")
	}
	h1, c1, s1 := mk("one")
	h2, c2, s2 := mk("two")
	t.Setenv("STK_HOME", h2)
	t.Setenv("STK_CONFIG", c2)
	t.Setenv("STK_SOCKET", s2)
	paths := isolationPaths(h2, configPath(), socketPath(h2))
	for _, p := range paths {
		if strings.HasPrefix(p, filepath.Join(dir, "one")) || strings.HasPrefix(p, "/var/lib/stk") || strings.HasPrefix(p, "/run/stk") || strings.HasPrefix(p, "/etc/stk") {
			t.Errorf("instance two's checked paths leak %q", p)
		}
	}
	has := func(want string) bool {
		for _, p := range paths {
			if p == want {
				return true
			}
		}
		return false
	}
	for _, want := range []string{h2, absPath(c2), s2, filepath.Join(h2, "stk-passphrase.key"), filepath.Join(h2, "proxy.key")} {
		if !has(want) {
			t.Errorf("instance two's path %q not checked: %v", want, paths)
		}
	}
	// And it picks instance two's agent uids from instance two's config only.
	os.WriteFile(c1, []byte("agent_uids: [1111]\n"), 0o600)
	os.WriteFile(c2, []byte("agent_uids: [2222]\n"), 0o600)
	if got := agentUIDsFor(doctorOpts{}); len(got) != 1 || got[0] != 2222 {
		t.Errorf("agent uids = %v, want [2222]", got)
	}
	_, _ = h1, s1
}
