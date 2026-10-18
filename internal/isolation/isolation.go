// Package isolation decides whether stk really runs as a different OS user
// from the agent, by looking at the files that would let the agent reach a
// credential.
//
// A false "separate-user" is a security bug: it tells an operator a token is
// out of the agent's reach when it is not. So the verdict is separate-user
// only when every rule holds for every path and every parent directory, and
// anything the checker cannot establish (an unreadable path, an unknown
// owner, nothing present at all) is a reason for same-user. Unknown is not
// safe.
//
// Mode bits are not the whole story: an ACL can grant the agent read access
// to a 0600 file. On Linux the production ACL reader (HasACL) looks for the
// POSIX ACL xattrs and any ACL on a checked path or parent directory is a
// reason. Only ENODATA (or an empty read) means "no ACL"; ENOTSUP/EOPNOTSUPP
// (NFSv4, FUSE, some overlays, which may enforce ACLs of their own) and any
// other error are reasons, so a state dir on a filesystem without POSIX ACL
// support is never reported separate-user. That is intended. On macOS and
// other Unixes ACLs cannot be read without cgo, so the verdict there always
// carries the reason "ACLs are not examined on <GOOS>" and is never
// separate-user on mode bits alone.
//
// Check is pure with respect to the host: everything it learns comes through
// the injected inspector. The root-only access attempt (re-executing stk as
// each agent uid and trying to open the files) lives in the caller and is
// folded in with WithAccess.
package isolation

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Levels and methods.
const (
	SeparateUser = "separate-user"
	SameUser     = "same-user"
	Unknown      = "unknown"

	// MethodModeBits: owner, mode bits and (on Linux only) POSIX ACLs were
	// inspected. Elsewhere ACLs were not, and the reasons say so.
	MethodModeBits = "mode-bits"
	// MethodAccess: as MethodModeBits, plus a real open() attempted as each
	// agent uid (root only). The attempt catches what ACLs grant too.
	MethodAccess = "mode-bits+access"
)

// Report is the verdict, shaped for `stk doctor --json`.
type Report struct {
	Level   string   `json:"level"`
	Method  string   `json:"method,omitempty"`
	Reasons []string `json:"reasons"`
}

// NoAgents is the verdict when no agent uid is configured. Omitting the
// section would read as "not separate" by silence; saying so is honest.
func NoAgents() Report {
	return Report{Level: Unknown, Reasons: []string{"no agent uids configured"}}
}

// WithAccess folds the result of the root access attempt into a mode-bit
// report. Any path an agent uid could open is a reason, and forces same-user
// whatever the mode bits said.
func WithAccess(r Report, accessReasons []string) Report {
	if r.Level == Unknown {
		return r
	}
	r.Method = MethodAccess
	if len(accessReasons) > 0 {
		r.Reasons = append(append([]string(nil), r.Reasons...), accessReasons...)
		r.Level = SameUser
	}
	return r
}

// linkTargeter is implemented by FileInfos that know a symlink's target. The
// production inspector (Lstat) provides it; Check never calls Readlink itself,
// so it stays pure.
type linkTargeter interface{ LinkTarget() string }

// lstatInfo is os.Lstat's FileInfo plus the link target, read eagerly.
type lstatInfo struct {
	fs.FileInfo
	target string
}

func (l lstatInfo) LinkTarget() string { return l.target }

// Lstat is the production inspector: Lstat so a symlink is seen as a symlink
// rather than silently followed, with the target attached for rule (d).
func Lstat(path string) (fs.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	li := lstatInfo{FileInfo: fi}
	if fi.Mode()&fs.ModeSymlink != 0 {
		li.target, _ = os.Readlink(path)
	}
	return li, nil
}

// roots is the checked tree: a path that is an ancestor of another listed path
// is a root itself; otherwise the path's directory is.
func roots(paths []string) []string {
	var out []string
	for _, p := range paths {
		p = filepath.Clean(p)
		r := filepath.Dir(p)
		for _, q := range paths {
			if strings.HasPrefix(filepath.Clean(q), p+string(filepath.Separator)) {
				r = p
				break
			}
		}
		out = append(out, r)
	}
	return out
}

func inTree(target string, roots []string) bool {
	for _, r := range roots {
		if target == r || strings.HasPrefix(target, strings.TrimSuffix(r, "/")+"/") {
			return true
		}
	}
	return false
}

// Options carries what the verdict depends on beyond the paths.
type Options struct {
	// ConfigPath is the policy file, compared exactly against the listed
	// paths. It holds no secret and `stk install` makes it 0640
	// root:<group>, so it is exempt from the read-bit rule but not from the
	// owner and write rules. Nothing else is exempt, whatever its name.
	ConfigPath string
	// GOOS decides whether ACLs can be examined. Only on linux is there an
	// ACL reader without cgo; anywhere else an unexamined ACL is a reason.
	GOOS string
	// ACL reports whether a path carries an ACL. Nil means ACLs cannot be
	// examined, which is a reason.
	ACL func(path string) (bool, error)
}
