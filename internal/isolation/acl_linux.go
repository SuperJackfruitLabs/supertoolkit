//go:build linux

package isolation

import (
	"errors"

	"golang.org/x/sys/unix"
)

// HasACL reports whether path (not followed if a symlink) carries a POSIX
// access or default ACL. ENODATA means none; ENOTSUP means the filesystem
// has no POSIX ACLs (reported as none: mode bits are then the whole story).
func HasACL(path string) (bool, error) {
	for _, attr := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		_, err := unix.Lgetxattr(path, attr, nil)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, unix.ENODATA), errors.Is(err, unix.ENOTSUP):
			continue
		default:
			return false, err
		}
	}
	return false, nil
}
