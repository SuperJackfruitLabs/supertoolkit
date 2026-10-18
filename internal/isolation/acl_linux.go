//go:build linux

package isolation

import "golang.org/x/sys/unix"

// HasACL reports whether path (not followed if a symlink) carries a POSIX
// access or default ACL. Errors are classified by classifyACL: only ENODATA
// or an empty read mean none; ENOTSUP and every other error are reasons.
func HasACL(path string) (bool, error) {
	return classifyACL(func(attr string) (int, error) { return unix.Lgetxattr(path, attr, nil) })
}
