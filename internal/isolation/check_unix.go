//go:build unix

package isolation

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"syscall"
)

// maxLinks bounds how many in-tree symlinks are followed from one path; a
// longer chain (or a loop) is a reason rather than a hang.
const maxLinks = 8

// Check returns separate-user only if ALL of these hold; each failure is a
// reason and the verdict becomes same-user:
//
//	(a) no listed path, and no parent directory up to "/", is owned by an
//	    agent uid; and the owner is known (a FileInfo without a Unix uid is
//	    a reason, since an unknown owner might be the agent).
//	(b) no secret-holding path grants a group or other read or write bit.
//	    Agent gids are not configured, so any group bit counts. Every listed
//	    path is secret-holding (state dir, salt, *.cred, keys, approvals)
//	    except the socket and the policy file.
//	(c) no parent directory is writable by group or other (or owned by an
//	    agent uid, which is (a)), since a writer of a parent can swap the
//	    component beneath it. A sticky bit does not excuse it: the checker
//	    does not reason about who created the entry.
//	(d) no component (listed path or parent) is a symlink whose target
//	    resolves outside the checked tree; an in-tree target is followed and
//	    checked as if it were the listed path.
//	(e) a path the inspector cannot stat for any reason other than "does not
//	    exist" is a reason: unknown is not safe. Absent files are fine (a
//	    fresh install has no *.cred yet), but if nothing listed exists at all
//	    nothing has been shown.
//	(f) the socket may be group-accessible by design (`stk install
//	    --socket-mode 0660`), so it is exempt from (b), but it must not be
//	    owned by an agent uid. The policy file likewise may be group-readable
//	    (install makes it 0640) but must not be group/other-writable.
//
//	(g) ACLs: on linux every listed path and every parent directory with a
//	    POSIX ACL, or whose ACL cannot be read or ruled out (see classifyACL
//	    for the errno table; ENOTSUP is a reason), is a reason; on any other GOOS ACLs are not examined
//	    and that itself is a reason.
//	(h) an agent uid of 0 is root, which reaches everything: a reason.
//
// Check uses this host's GOOS and ACL reader and no config path; CheckWith
// takes them explicitly.
func Check(paths []string, agentUIDs []int, inspect func(path string) (fs.FileInfo, error)) Report {
	return CheckWith(paths, agentUIDs, inspect, Options{GOOS: runtime.GOOS, ACL: HasACL})
}

// CheckWith is Check with the config path, GOOS and ACL reader explicit.
func CheckWith(paths []string, agentUIDs []int, inspect func(path string) (fs.FileInfo, error), o Options) Report {
	if len(agentUIDs) == 0 {
		return NoAgents()
	}
	c := &checker{inspect: inspect, opts: o, roots: roots(paths), agents: map[int]bool{}, seenDir: map[string]bool{}}
	for _, u := range agentUIDs {
		c.agents[u] = true
		if u == 0 {
			c.add("agent uid 0 is root; isolation is impossible")
		}
	}
	if o.GOOS != "linux" {
		c.add("ACLs are not examined on %s; mode bits alone cannot prove isolation", o.GOOS)
	} else if o.ACL == nil {
		c.add("ACLs are not examined (no ACL reader); mode bits alone cannot prove isolation")
	}
	cfg := ""
	if o.ConfigPath != "" {
		cfg = filepath.Clean(o.ConfigPath)
	}
	for _, p := range paths {
		p = filepath.Clean(p)
		c.leaf(p, cfg != "" && p == cfg, 0)
		c.parents(p)
	}
	if c.present == 0 {
		c.add("none of the checked paths exists, so nothing was shown to be out of the agent's reach")
	}
	r := Report{Level: SeparateUser, Method: MethodModeBits, Reasons: c.reasons}
	if len(c.reasons) > 0 {
		r.Level = SameUser
	}
	return r
}

type checker struct {
	opts    Options
	inspect func(string) (fs.FileInfo, error)
	roots   []string
	agents  map[int]bool
	seenDir map[string]bool
	reasons []string
	seen    map[string]bool
	present int
}

func (c *checker) add(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if !c.seen[s] {
		c.seen[s] = true
		c.reasons = append(c.reasons, s)
	}
}

// stat applies rule (e). ok=false means there is nothing more to check.
func (c *checker) stat(p string) (fs.FileInfo, bool) {
	fi, err := c.inspect(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	if err != nil || fi == nil {
		c.add("cannot inspect %s (%v) — unknown is not safe", p, err)
		return nil, false
	}
	return fi, true
}

// owner applies rule (a).
func (c *checker) owner(p string, fi fs.FileInfo) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		c.add("owner of %s is unknown — unknown is not safe", p)
		return
	}
	if uid := int(st.Uid); c.agents[uid] {
		c.add("%s is owned by agent uid %d", p, uid)
	}
}

// follow applies rule (d): the in-tree target, or "" after recording a reason.
func (c *checker) follow(p string, fi fs.FileInfo, depth int) string {
	lt, ok := fi.(linkTargeter)
	if !ok || lt.LinkTarget() == "" {
		c.add("%s is a symlink whose target is unknown", p)
		return ""
	}
	t := lt.LinkTarget()
	if !filepath.IsAbs(t) {
		t = filepath.Join(filepath.Dir(p), t)
	}
	t = filepath.Clean(t)
	if !inTree(t, c.roots) {
		c.add("%s is a symlink to %s, outside the checked tree", p, t)
		return ""
	}
	if depth >= maxLinks {
		c.add("%s: too many symlinks", p)
		return ""
	}
	return t
}

func (c *checker) leaf(p string, config bool, depth int) {
	fi, ok := c.stat(p)
	if !ok {
		return
	}
	if depth == 0 {
		c.present++
	}
	c.owner(p, fi)
	c.acl(p)
	mode := fi.Mode()
	switch {
	case mode&fs.ModeSymlink != 0:
		if t := c.follow(p, fi, depth); t != "" {
			c.leaf(t, config, depth+1)
			c.parents(t)
		}
	case mode&fs.ModeSocket != 0:
		// (f): group access to the socket is the install's design.
	case config:
		if mode.Perm()&0o022 != 0 {
			c.add("%s is writable by group or other (mode %o)", p, mode.Perm())
		}
	case mode.IsDir():
		// (b) for a secret-holding directory: any group/other bit, even
		// traverse-only 0711, lets another user reach entries by name.
		if mode.Perm()&0o077 != 0 {
			c.add("%s grants group or other access (mode %o)", p, mode.Perm())
		}
	default:
		// (b)
		if mode.Perm()&0o066 != 0 {
			c.add("%s grants group or other access (mode %o)", p, mode.Perm())
		}
	}
}

// acl applies (g) on linux.
func (c *checker) acl(p string) {
	if c.opts.GOOS != "linux" || c.opts.ACL == nil {
		return
	}
	has, err := c.opts.ACL(p)
	if errors.Is(err, errNoPOSIXACL) {
		c.add("%s: %v", p, errNoPOSIXACL)
		return
	}
	if err != nil {
		c.add("cannot read the ACL of %s (%v) — unknown is not safe", p, err)
		return
	}
	if has {
		c.add("%s has an ACL, which may grant an agent access its mode bits do not show", p)
	}
}

// parents applies (a), (c) and (d) to every directory above p, up to "/".
func (c *checker) parents(p string) {
	for d := filepath.Dir(p); ; d = filepath.Dir(d) {
		c.parent(d, 0)
		if d == filepath.Dir(d) {
			return
		}
	}
}

func (c *checker) parent(d string, depth int) {
	if depth == 0 {
		if c.seenDir[d] {
			return
		}
		c.seenDir[d] = true
	}
	fi, ok := c.stat(d)
	if !ok {
		return
	}
	c.owner(d, fi)
	if fi.Mode()&fs.ModeSymlink != 0 {
		if t := c.follow(d, fi, depth); t != "" {
			c.parent(t, depth+1)
		}
		return
	}
	// (g) for parents: an ACL such as u:agent:rwx on a parent permits the
	// same component swap the write-bit rule exists to catch.
	c.acl(d)
	if fi.Mode().Perm()&0o022 != 0 {
		c.add("%s is writable by group or other (mode %o)", d, fi.Mode().Perm())
	}
}

// errNoPOSIXACL marks a filesystem that will not say whether a POSIX ACL
// exists (ENOTSUP/EOPNOTSUPP: NFSv4, FUSE, some overlays). Those may still
// enforce ACLs of their own, so it is a reason, never "none".
var errNoPOSIXACL = errors.New("filesystem does not report POSIX ACLs; ACLs cannot be ruled out")

// classifyACL turns getxattr results for the two POSIX ACL attributes into a
// verdict. Per attribute:
//
//	success, size > 0     -> ACL present
//	success, size 0       -> none
//	ENODATA               -> none
//	ENOTSUP / EOPNOTSUPP  -> errNoPOSIXACL (a reason: fail closed)
//	anything else (EACCES, EIO, ...) -> that error (a reason)
//
// Consequence: a state dir on a filesystem without POSIX ACL support can
// never be reported separate-user. That is intended.
func classifyACL(get func(attr string) (int, error)) (bool, error) {
	for _, attr := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		n, err := get(attr)
		switch {
		case err == nil && n > 0:
			return true, nil
		case err == nil, errors.Is(err, syscall.ENODATA):
			continue
		case errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.EOPNOTSUPP):
			return false, errNoPOSIXACL
		default:
			return false, err
		}
	}
	return false, nil
}
