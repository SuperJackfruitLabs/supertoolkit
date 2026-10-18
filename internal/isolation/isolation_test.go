//go:build unix

package isolation

import (
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeInfo is a FileInfo whose Sys() is a *syscall.Stat_t, so tests set the
// owner and group the checker reads without touching the host.
type fakeInfo struct {
	name   string
	mode   fs.FileMode
	uid    int
	target string // symlink target, when mode has ModeSymlink
	noStat bool
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) LinkTarget() string { return f.target }
func (f fakeInfo) Sys() any {
	if f.noStat {
		return nil
	}
	st := &syscall.Stat_t{}
	st.Uid = uint32(f.uid)
	return st
}

const (
	svc   = 990  // the stk service user
	agent = 1001 // the agent
)

// tree is a fake filesystem: a healthy installation, root-owned parents,
// everything below /var/lib/stk owned by the service at 0700/0600.
func tree() map[string]fakeInfo {
	return map[string]fakeInfo{
		"/":                      {mode: fs.ModeDir | 0o755, uid: 0},
		"/var":                   {mode: fs.ModeDir | 0o755, uid: 0},
		"/var/lib":               {mode: fs.ModeDir | 0o755, uid: 0},
		"/var/lib/stk":           {mode: fs.ModeDir | 0o700, uid: svc},
		"/var/lib/stk/salt":      {mode: 0o600, uid: svc},
		"/var/lib/stk/gh.cred":   {mode: 0o600, uid: svc},
		"/var/lib/stk/approvals": {mode: fs.ModeDir | 0o700, uid: svc},
		"/run":                   {mode: fs.ModeDir | 0o755, uid: 0},
		"/run/stk":               {mode: fs.ModeDir | 0o750, uid: svc},
		"/run/stk/stk.sock":      {mode: fs.ModeSocket | 0o660, uid: svc},
	}
}

var paths = []string{"/var/lib/stk", "/var/lib/stk/salt", "/var/lib/stk/gh.cred",
	"/var/lib/stk/approvals", "/var/lib/stk/handover.key", "/run/stk/stk.sock"}

func inspector(m map[string]fakeInfo) func(string) (fs.FileInfo, error) {
	return func(p string) (fs.FileInfo, error) {
		fi, ok := m[p]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return fi, nil
	}
}

// linux is the options for a host where ACLs are examined and none exist.
var linux = Options{GOOS: "linux", ACL: func(string) (bool, error) { return false, nil }}

func run(t *testing.T, m map[string]fakeInfo) Report {
	t.Helper()
	return CheckWith(paths, []int{agent}, inspector(m), linux)
}

func wantSame(t *testing.T, r Report, mention string) {
	t.Helper()
	if r.Level != "same-user" {
		t.Fatalf("Level = %q, want same-user; reasons %v", r.Level, r.Reasons)
	}
	for _, s := range r.Reasons {
		if strings.Contains(s, mention) {
			return
		}
	}
	t.Fatalf("no reason mentions %q: %v", mention, r.Reasons)
}

func TestSeparateUserWhenOwnedByServiceAndMode0700(t *testing.T) {
	r := run(t, tree())
	if r.Level != "separate-user" || r.Method != "mode-bits" || len(r.Reasons) != 0 {
		t.Fatalf("got %+v, want separate-user by mode-bits with no reasons", r)
	}
}

func TestGroupReadableIsSameUser(t *testing.T) {
	m := tree()
	m["/var/lib/stk/salt"] = fakeInfo{mode: 0o640, uid: svc}
	wantSame(t, run(t, m), "/var/lib/stk/salt")
}

func TestOtherReadableIsSameUser(t *testing.T) {
	m := tree()
	m["/var/lib/stk/gh.cred"] = fakeInfo{mode: 0o604, uid: svc}
	wantSame(t, run(t, m), "/var/lib/stk/gh.cred")
}

func TestOwnedByAgentUIDIsSameUser(t *testing.T) {
	m := tree()
	m["/var/lib/stk/gh.cred"] = fakeInfo{mode: 0o600, uid: agent}
	wantSame(t, run(t, m), "agent uid 1001")
}

func TestParentDirOwnedByAgentIsSameUser(t *testing.T) {
	m := tree()
	m["/var/lib"] = fakeInfo{mode: fs.ModeDir | 0o755, uid: agent}
	wantSame(t, run(t, m), "/var/lib ")
}

func TestWorldWritableParentIsSameUser(t *testing.T) {
	m := tree()
	m["/var"] = fakeInfo{mode: fs.ModeDir | 0o777, uid: 0}
	wantSame(t, run(t, m), "/var ")
}

func TestSymlinkOutOfTreeIsSameUser(t *testing.T) {
	m := tree()
	m["/var/lib/stk/salt"] = fakeInfo{mode: fs.ModeSymlink | 0o777, uid: svc, target: "/home/agent/salt"}
	m["/home/agent/salt"] = fakeInfo{mode: 0o600, uid: svc}
	wantSame(t, run(t, m), "symlink")

	// A link that stays inside the checked tree is followed, not refused.
	m = tree()
	m["/var/lib/stk/salt"] = fakeInfo{mode: fs.ModeSymlink | 0o777, uid: svc, target: "gh.cred"}
	if r := run(t, m); r.Level != "separate-user" {
		t.Fatalf("in-tree link: %+v", r)
	}
}

func TestUnknownPathReportsReasonNotSeparate(t *testing.T) {
	m := tree()
	insp := inspector(m)
	r := CheckWith(paths, []int{agent}, func(p string) (fs.FileInfo, error) {
		if p == "/var/lib/stk/gh.cred" {
			return nil, &fs.PathError{Op: "lstat", Path: p, Err: os.ErrPermission}
		}
		return insp(p)
	}, linux)
	wantSame(t, r, "/var/lib/stk/gh.cred")

	// An owner the checker cannot read is unknown too, and unknown is not safe.
	m["/var/lib/stk/salt"] = fakeInfo{mode: 0o600, noStat: true}
	wantSame(t, run(t, m), "owner")

	// Nothing present at all proves nothing.
	r = CheckWith(paths, []int{agent}, func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }, linux)
	if r.Level == "separate-user" {
		t.Fatalf("nothing exists, yet %+v", r)
	}
}

func TestNoAgentUIDsMeansUnknownNotSeparate(t *testing.T) {
	r := CheckWith(paths, nil, inspector(tree()), linux)
	if r.Level != "unknown" || len(r.Reasons) != 1 || r.Reasons[0] != "no agent uids configured" {
		t.Fatalf("got %+v", r)
	}
}

func TestSocketGroupAccessIsAllowedButNotAgentOwned(t *testing.T) {
	// 0660 socket is the install's design: allowed (covered by the healthy tree).
	m := tree()
	m["/run/stk/stk.sock"] = fakeInfo{mode: fs.ModeSocket | 0o660, uid: agent}
	wantSame(t, run(t, m), "/run/stk/stk.sock")
}

func TestConfigMayBeGroupReadableButNotWritable(t *testing.T) {
	m := tree()
	m["/etc"] = fakeInfo{mode: fs.ModeDir | 0o755, uid: 0}
	m["/etc/stk"] = fakeInfo{mode: fs.ModeDir | 0o750, uid: 0}
	m["/etc/stk/supertoolkit.yaml"] = fakeInfo{mode: 0o640, uid: 0}
	ps := append([]string{"/etc/stk/supertoolkit.yaml"}, paths...)
	opts := linux
	opts.ConfigPath = "/etc/stk/supertoolkit.yaml"
	if r := CheckWith(ps, []int{agent}, inspector(m), opts); r.Level != "separate-user" {
		t.Fatalf("0640 config: %+v", r)
	}
	m["/etc/stk/supertoolkit.yaml"] = fakeInfo{mode: 0o660, uid: 0}
	r := CheckWith(ps, []int{agent}, inspector(m), opts)
	wantSame(t, r, "supertoolkit.yaml")
}

func TestAccessReasonsForceSameUser(t *testing.T) {
	r := WithAccess(run(t, tree()), []string{"agent uid 1001 opened /var/lib/stk/salt"})
	if r.Level != "same-user" || r.Method != "mode-bits+access" {
		t.Fatalf("got %+v", r)
	}
	r = WithAccess(run(t, tree()), nil)
	if r.Level != "separate-user" || r.Method != "mode-bits+access" {
		t.Fatalf("got %+v", r)
	}
}

func TestSecretDirNamedLikeConfigIsNotExempt(t *testing.T) {
	m := tree()
	m["/var/lib/stk.yml"] = fakeInfo{mode: fs.ModeDir | 0o750, uid: svc}
	opts := linux
	opts.ConfigPath = "/etc/stk/supertoolkit.yaml"
	r := CheckWith(append([]string{"/var/lib/stk.yml"}, paths...), []int{agent}, inspector(m), opts)
	wantSame(t, r, "/var/lib/stk.yml")
}

func TestGroupTraverseOnSecretDirIsSameUser(t *testing.T) {
	m := tree()
	m["/var/lib/stk/approvals"] = fakeInfo{mode: fs.ModeDir | 0o711, uid: svc}
	wantSame(t, run(t, m), "/var/lib/stk/approvals")
}

func TestAgentUIDZeroIsRoot(t *testing.T) {
	r := CheckWith(paths, []int{0}, inspector(tree()), linux)
	wantSame(t, r, "agent uid 0 is root; isolation is impossible")
}

func TestStickyWorldWritableParentIsSameUser(t *testing.T) {
	m := tree()
	m["/var"] = fakeInfo{mode: fs.ModeDir | fs.ModeSticky | 0o777, uid: 0}
	wantSame(t, run(t, m), "/var ")
}

func TestWorldSocketOwnedByServiceIsAllowed(t *testing.T) {
	m := tree()
	m["/run/stk/stk.sock"] = fakeInfo{mode: fs.ModeSocket | 0o666, uid: svc}
	if r := run(t, m); r.Level != "separate-user" {
		t.Fatalf("got %+v", r)
	}
}

func TestACLOnLinuxIsSameUser(t *testing.T) {
	opts := Options{GOOS: "linux", ACL: func(p string) (bool, error) { return p == "/var/lib/stk/salt", nil }}
	wantSame(t, CheckWith(paths, []int{agent}, inspector(tree()), opts), "ACL")

	opts.ACL = func(p string) (bool, error) {
		if p == "/var/lib/stk/gh.cred" {
			return false, os.ErrPermission
		}
		return false, nil
	}
	wantSame(t, CheckWith(paths, []int{agent}, inspector(tree()), opts), "/var/lib/stk/gh.cred")

	// No way to read ACLs on Linux is not a pass either.
	wantSame(t, CheckWith(paths, []int{agent}, inspector(tree()), Options{GOOS: "linux"}), "ACLs are not examined")
}

func TestACLUnexaminedOnDarwinIsNeverSeparate(t *testing.T) {
	r := CheckWith(paths, []int{agent}, inspector(tree()), Options{GOOS: "darwin"})
	wantSame(t, r, "ACLs are not examined on darwin; mode bits alone cannot prove isolation")
}

func TestParentDirACLIsSameUser(t *testing.T) {
	opts := Options{GOOS: "linux", ACL: func(p string) (bool, error) { return p == "/var/lib", nil }}
	wantSame(t, CheckWith(paths, []int{agent}, inspector(tree()), opts), "/var/lib has an ACL")

	opts.ACL = func(p string) (bool, error) {
		if p == "/var" {
			return false, syscall.EIO
		}
		return false, nil
	}
	wantSame(t, CheckWith(paths, []int{agent}, inspector(tree()), opts), "/var")
}

func TestACLErrnoClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		get     func(attr string) (int, error)
		has     bool
		wantErr string
	}{
		{"ENODATA is none", func(string) (int, error) { return 0, syscall.ENODATA }, false, ""},
		{"empty read is none", func(string) (int, error) { return 0, nil }, false, ""},
		{"present", func(a string) (int, error) {
			if a == "system.posix_acl_default" {
				return 28, nil
			}
			return 0, syscall.ENODATA
		}, true, ""},
		{"ENOTSUP is a reason", func(string) (int, error) { return 0, syscall.ENOTSUP }, false, "does not report POSIX ACLs"},
		{"EOPNOTSUPP is a reason", func(string) (int, error) { return 0, syscall.EOPNOTSUPP }, false, "does not report POSIX ACLs"},
		{"EACCES is a reason", func(string) (int, error) { return 0, syscall.EACCES }, false, "permission"},
		{"EIO is a reason", func(string) (int, error) { return 0, syscall.EIO }, false, "input/output"},
	} {
		has, err := classifyACL(tc.get)
		if has != tc.has || (tc.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
			t.Errorf("%s: has=%v err=%v", tc.name, has, err)
		}
	}
	// The reason Check records for an unsupported filesystem names the path.
	opts := Options{GOOS: "linux", ACL: func(p string) (bool, error) {
		return classifyACL(func(string) (int, error) { return 0, syscall.ENOTSUP })
	}}
	wantSame(t, CheckWith(paths, []int{agent}, inspector(tree()), opts),
		"/var/lib/stk/salt: filesystem does not report POSIX ACLs; ACLs cannot be ruled out")
}
