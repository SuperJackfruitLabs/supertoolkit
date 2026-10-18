package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
)

// recorder stands in for the host. It never runs anything; it remembers what
// was asked and answers getent from the users and groups it has "created".
type recorder struct {
	calls  []string
	users  map[string]bool
	groups map[string]bool
	owners map[string]string // path -> "user:group"; unknown paths are root:root
}

func newRecorder() *recorder {
	r := &recorder{users: map[string]bool{}, groups: map[string]bool{}, owners: map[string]string{}}
	OwnerOf = r.ownerOf
	return r
}

func (r *recorder) ownerOf(path string) (string, string, error) {
	o, ok := r.owners[path]
	if !ok {
		o = "root:root"
	}
	u, g, _ := strings.Cut(o, ":")
	return u, g, nil
}

func (r *recorder) Run(name string, args ...string) error {
	r.calls = append(r.calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	switch {
	case name == "getent" && len(args) == 2 && args[0] == "passwd":
		if !r.users[args[1]] {
			return errors.New("exit status 2")
		}
	case name == "getent" && len(args) == 2 && args[0] == "group":
		if !r.groups[args[1]] {
			return errors.New("exit status 2")
		}
	case name == "useradd":
		r.users[args[len(args)-1]] = true
	case name == "chown" && len(args) == 2:
		r.owners[args[1]] = args[0]
	case name == "groupadd":
		r.groups[args[len(args)-1]] = true
	}
	return nil
}

func (r *recorder) count(prefix string) int {
	n := 0
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (r *recorder) saw(call string) bool {
	for _, c := range r.calls {
		if c == call {
			return true
		}
	}
	return false
}

func asRoot(t *testing.T, euid int) {
	t.Helper()
	old := Geteuid
	Geteuid = func() int { return euid }
	oldOwner := OwnerOf
	t.Cleanup(func() { Geteuid = old; OwnerOf = oldOwner })
}

func plan() Plan {
	return Plan{
		User: "stk", StateDir: "/var/lib/stk", RuntimeDir: "/run/stk",
		ConfigPath: "/etc/stk/supertoolkit.yaml", AgentUIDs: []int{1001, 1000},
		Binary: "/usr/local/bin/stk", ProxyPort: 8899,
	}
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		v := fi.Mode().String()
		if !fi.IsDir() {
			b, _ := os.ReadFile(p)
			v += ":" + string(b)
		}
		out[rel] = v
		return nil
	})
	return out
}

func TestInstallCreatesUserDirsAndUnit(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	r := newRecorder()
	rep, err := Run(context.Background(), plan(), root, r)
	if err != nil {
		t.Fatal(err)
	}
	if r.count("useradd ") != 1 || !r.saw("useradd --system --no-create-home --shell /usr/sbin/nologin --user-group stk") {
		t.Fatalf("useradd calls: %v", r.calls)
	}
	if got := mode(t, filepath.Join(root, "var/lib/stk")); got != 0o700 {
		t.Errorf("state dir %o, want 0700", got)
	}
	for _, c := range []string{"chown stk:stk " + filepath.Join(root, "var/lib/stk"),
		"chown stk:stk " + filepath.Join(root, "run/stk"),
		"chown stk:stk " + filepath.Join(root, "var/lib/stk/stk-passphrase.key")} {
		if !r.saw(c) {
			t.Errorf("missing %q in %v", c, r.calls)
		}
	}
	unit, err := os.ReadFile(filepath.Join(root, "etc/systemd/system/stk.service"))
	if err != nil {
		t.Fatal(err)
	}
	if string(unit) != Unit(plan()) {
		t.Error("written unit differs from Unit(plan)")
	}
	for _, want := range []string{
		"User=stk\n", "Group=stk\n", "NoNewPrivileges=yes\n", "PrivateTmp=yes\n",
		"ProtectSystem=strict\n", "ProtectHome=yes\n",
		"ReadWritePaths=/var/lib/stk /run/stk\n", "UMask=0077\n",
		"LoadCredential=stk-passphrase:/var/lib/stk/stk-passphrase.key\n",
		"Environment=STK_HOME=/var/lib/stk STK_CONFIG=/etc/stk/supertoolkit.yaml STK_SOCKET=/run/stk/stk.sock\n",
		"ExecStart=/usr/local/bin/stk serve --proxy-listen 127.0.0.1:8899 --socket-mode 0600 --allow-uid 1001 --allow-uid 1000\n",
	} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
	if strings.Contains(string(unit), "STK_PASSPHRASE") {
		t.Error("unit mentions STK_PASSPHRASE")
	}
	if len(rep.Created) == 0 {
		t.Errorf("report lists nothing created: %+v", rep)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	r := newRecorder()
	if _, err := Run(context.Background(), plan(), root, r); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, root)
	r.calls = nil
	rep, err := Run(context.Background(), plan(), root, r)
	if err != nil {
		t.Fatal(err)
	}
	if r.count("useradd") != 0 || r.count("groupadd") != 0 || r.count("chown") != 0 || r.count("systemctl") != 0 {
		t.Errorf("second run changed the host: %v", r.calls)
	}
	after := snapshot(t, root)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Errorf("files changed on the second run")
	}
	if len(rep.Created) != 0 || len(rep.Changed) != 0 || len(rep.Unchanged) == 0 {
		t.Errorf("second run report: %+v", rep)
	}
}

func TestInstallNeverOverwritesAnExistingStore(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	state := filepath.Join(root, "var/lib/stk")
	os.MkdirAll(state, 0o700)
	files := map[string]string{
		"salt": "SALTSALT", "github.cred": "sealed", "stk-passphrase.key": "existing-pass",
		"handover.key": "hk", "proxy.key": "pk", "machine.key": "mk",
	}
	for n, v := range files {
		os.WriteFile(filepath.Join(state, n), []byte(v), 0o600)
	}
	if _, err := Run(context.Background(), plan(), root, newRecorder()); err != nil {
		t.Fatal(err)
	}
	for n, v := range files {
		b, err := os.ReadFile(filepath.Join(state, n))
		if err != nil || string(b) != v {
			t.Errorf("%s was changed: %q, %v", n, b, err)
		}
	}
}

// A store sealed under some other key (machine.key, an env passphrase) must not
// silently gain a fresh passphrase: the service would then open it with the
// wrong key, or create a second store over it.
func TestInstallRefusesAStoreWithoutItsPassphrase(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	state := filepath.Join(root, "var/lib/stk")
	os.MkdirAll(state, 0o700)
	os.WriteFile(filepath.Join(state, "salt"), []byte("S"), 0o600)
	if _, err := Run(context.Background(), plan(), root, newRecorder()); err == nil {
		t.Fatal("installed a passphrase over an existing store")
	}
	if _, err := os.Stat(filepath.Join(state, "stk-passphrase.key")); !os.IsNotExist(err) {
		t.Fatal("stk-passphrase.key was written")
	}
}

func TestInstallRefusesNonRoot(t *testing.T) {
	asRoot(t, 1000)
	root := t.TempDir()
	r := newRecorder()
	if _, err := Run(context.Background(), plan(), root, r); err == nil {
		t.Fatal("non-root install was allowed")
	}
	if len(r.calls) != 0 {
		t.Errorf("ran %v", r.calls)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Errorf("wrote %v", ents)
	}
}

func TestDryRunOutputShowsUnitAndNoPassphraseVariable(t *testing.T) {
	asRoot(t, 1000) // dry-run needs no root
	out := DryRun(plan())
	if !strings.Contains(out, Unit(plan())) || !strings.Contains(out, "stk") {
		t.Errorf("dry run does not show the plan and unit:\n%s", out)
	}
	if strings.Contains(out, "STK_PASSPHRASE") {
		t.Error("dry run mentions STK_PASSPHRASE")
	}
}

func TestUnitDoesNotGrantAgentUIDsAccess(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	r := newRecorder()
	if _, err := Run(context.Background(), plan(), root, r); err != nil {
		t.Fatal(err)
	}
	if got := mode(t, filepath.Join(root, "var/lib/stk")); got != 0o700 {
		t.Errorf("state dir %o, want 0700", got)
	}
	// No group named: the runtime dir is owner-only.
	if got := mode(t, filepath.Join(root, "run/stk")); got != 0o700 {
		t.Errorf("runtime dir %o, want 0700 without a group", got)
	}
	for _, c := range r.calls {
		for _, uid := range []string{"1000", "1001"} {
			if strings.HasPrefix(c, "chown") && strings.Contains(c, uid) {
				t.Errorf("agent uid given ownership: %q", c)
			}
		}
	}
	unit := Unit(plan())
	for _, bad := range []string{"SupplementaryGroups", "ReadOnlyPaths", "DynamicUser"} {
		if strings.Contains(unit, bad) {
			t.Errorf("unit has %s", bad)
		}
	}

	// With a group: the runtime dir is group-traversable, the socket 0660, and
	// the state dir still 0700.
	root2 := t.TempDir()
	p := plan()
	p.Group = "stkagents"
	r2 := newRecorder()
	if _, err := Run(context.Background(), p, root2, r2); err != nil {
		t.Fatal(err)
	}
	if got := mode(t, filepath.Join(root2, "run/stk")); got != 0o750 {
		t.Errorf("runtime dir %o, want 0750 with a group", got)
	}
	if got := mode(t, filepath.Join(root2, "var/lib/stk")); got != 0o700 {
		t.Errorf("state dir %o, want 0700", got)
	}
	if !r2.saw("groupadd --system stkagents") || !r2.saw("useradd --system --no-create-home --shell /usr/sbin/nologin --gid stkagents stk") {
		t.Errorf("calls: %v", r2.calls)
	}
	if !strings.Contains(Unit(p), "--socket-mode 0660") || !strings.Contains(Unit(p), "Group=stkagents\n") {
		t.Errorf("unit:\n%s", Unit(p))
	}
}

func TestPassphraseFile0400(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	if _, err := Run(context.Background(), plan(), root, newRecorder()); err != nil {
		t.Fatal(err)
	}
	pf := filepath.Join(root, "var/lib/stk/stk-passphrase.key")
	if got := mode(t, pf); got != 0o400 {
		t.Errorf("passphrase file %o, want 0400", got)
	}
	b, _ := os.ReadFile(pf)
	if len(strings.TrimSpace(string(b))) != 44 { // base64 of 32 bytes
		t.Errorf("passphrase is %d chars, want 44", len(strings.TrimSpace(string(b))))
	}
}

func TestUnitHasNoPassphraseInEnvironment(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	rep, err := Run(context.Background(), plan(), root, newRecorder())
	if err != nil {
		t.Fatal(err)
	}
	pass, err := os.ReadFile(filepath.Join(root, "var/lib/stk/stk-passphrase.key"))
	if err != nil || len(pass) == 0 {
		t.Fatal("no passphrase generated", err)
	}
	secret := strings.TrimSpace(string(pass))
	haystacks := map[string]string{"unit": Unit(plan()), "report": rep.String(), "dry-run": DryRun(plan())}
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() && !strings.HasSuffix(p, "stk-passphrase.key") {
			b, _ := os.ReadFile(p)
			haystacks[p] = string(b)
		}
		return nil
	})
	for name, h := range haystacks {
		if strings.Contains(h, secret) {
			t.Errorf("%s contains the generated passphrase", name)
		}
		if strings.Contains(h, "STK_PASSPHRASE") {
			t.Errorf("%s mentions STK_PASSPHRASE", name)
		}
	}
}

func TestUnitAllowUIDOrder(t *testing.T) {
	p := plan()
	p.AgentUIDs = []int{7, 3, 5}
	if !strings.Contains(Unit(p), " --allow-uid 7 --allow-uid 3 --allow-uid 5\n") {
		t.Errorf("unit:\n%s", Unit(p))
	}
}

// I1: the passphrase file sits outside the store's <service>.cred namespace,
// so storing a credential for a service named "passphrase" cannot replace it.
func TestStoreServiceNamedPassphraseDoesNotTouchTheKey(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	if _, err := Run(context.Background(), plan(), root, newRecorder()); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "var/lib/stk")
	key := filepath.Join(state, PassphraseFile)
	before, _ := os.ReadFile(key)
	st, err := credential.OpenStore(state, "pw")
	if err != nil {
		t.Fatal(err)
	}
	for _, svc := range []string{"passphrase", "stk-passphrase", "stk-passphrase.key"} {
		if err := st.Put(svc, "s3cret"); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadFile(key)
	if err != nil || string(after) != string(before) {
		t.Fatalf("store write touched %s: %v", PassphraseFile, err)
	}
}

// I2: with no --group the service user still reads the config (0640 root:<user>),
// and wrong ownership is corrected even when the mode was already right.
func TestConfigReadableByServiceUser(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	cfg := filepath.Join(root, "etc/stk/supertoolkit.yaml")
	os.MkdirAll(filepath.Dir(cfg), 0o750)
	os.WriteFile(cfg, []byte("workspace: x\n"), 0o640) // right mode, root:root
	r := newRecorder()
	rep, err := Run(context.Background(), plan(), root, r)
	if err != nil {
		t.Fatal(err)
	}
	if got := mode(t, cfg); got != 0o640 {
		t.Errorf("config %o, want 0640", got)
	}
	if !r.saw("chown root:stk " + cfg) {
		t.Errorf("config not chowned root:stk: %v", r.calls)
	}
	if !strings.Contains(fmt.Sprint(rep.Changed), cfg) {
		t.Errorf("config not reported changed: %+v", rep)
	}
	r.calls = nil
	if _, err := Run(context.Background(), plan(), root, r); err != nil {
		t.Fatal(err)
	}
	if r.count("chown") != 0 {
		t.Errorf("second run chowned: %v", r.calls)
	}
}

// I4: an existing root-owned state dir with the right mode is handed to the
// service user; once right, it is left alone.
func TestExistingRootOwnedStateDirIsChowned(t *testing.T) {
	asRoot(t, 0)
	root := t.TempDir()
	state := filepath.Join(root, "var/lib/stk")
	os.MkdirAll(state, 0o700)
	r := newRecorder()
	rep, err := Run(context.Background(), plan(), root, r)
	if err != nil {
		t.Fatal(err)
	}
	if !r.saw("chown stk:stk " + state) {
		t.Errorf("state dir not chowned: %v", r.calls)
	}
	if !strings.Contains(fmt.Sprint(rep.Changed), state) || strings.Contains(fmt.Sprint(rep.Unchanged), state) {
		t.Errorf("state dir not reported changed: %+v", rep)
	}
	r.calls = nil
	if _, err := Run(context.Background(), plan(), root, r); err != nil {
		t.Fatal(err)
	}
	if r.count("chown") != 0 {
		t.Errorf("second run chowned: %v", r.calls)
	}
}

// I3 + M2.
func TestValidateRefusesUnsafePlans(t *testing.T) {
	p := plan()
	p.AgentUIDs = nil
	err := p.Validate()
	if err == nil || err.Error() != "stk install needs at least one --agent-uid: without it the socket allowlist is empty and any member of the group would be served" {
		t.Errorf("empty allowlist: %v", err)
	}
	p.Group = "agents"
	if p.Validate() == nil {
		t.Error("group with empty allowlist accepted")
	}
	for _, rd := range []string{"/var/run/stk", "/run/stk/sub", "/run/", "/tmp/stk"} {
		p := plan()
		p.RuntimeDir = rd
		if p.Validate() == nil {
			t.Errorf("runtime dir %q accepted", rd)
		}
	}
	asRoot(t, 0)
	p = plan()
	p.AgentUIDs = nil
	r := newRecorder()
	if _, err := Run(context.Background(), p, t.TempDir(), r); err == nil || len(r.calls) != 0 {
		t.Errorf("Run with empty allowlist: %v %v", err, r.calls)
	}
}

func TestReportTellsOperatorToAddAgentsToGroup(t *testing.T) {
	asRoot(t, 0)
	p := plan()
	p.Group = "agents"
	r := newRecorder()
	rep, err := Run(context.Background(), p, t.TempDir(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep.String(), "add each agent user to group agents") {
		t.Errorf("report:\n%s", rep.String())
	}
	if r.count("usermod") != 0 {
		t.Error("install ran usermod")
	}
}
