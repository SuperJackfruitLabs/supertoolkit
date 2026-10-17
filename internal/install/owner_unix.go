//go:build unix

package install

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// ownerOf reads the inode's uid and gid and names them.
func ownerOf(path string) (string, string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", "", fmt.Errorf("%s: no ownership information", path)
	}
	un, gn := strconv.Itoa(int(st.Uid)), strconv.Itoa(int(st.Gid))
	if u, err := user.LookupId(un); err == nil {
		un = u.Username
	}
	if g, err := user.LookupGroupId(gn); err == nil {
		gn = g.Name
	}
	return un, gn, nil
}
