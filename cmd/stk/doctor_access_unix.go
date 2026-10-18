//go:build unix

package main

import (
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// uidOpener re-executes stk as uid (with that user's primary and
// supplementary groups when the account exists, else gid = uid) running the
// hidden `doctor --as-uid-probe`, and returns the paths it could open.
func uidOpener(exe string) func(int, []string) ([]string, error) {
	return func(uid int, paths []string) ([]string, error) {
		gid := uid
		var groups []uint32
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			if g, err := strconv.Atoi(u.Gid); err == nil {
				gid = g
			}
			if ids, err := u.GroupIds(); err == nil {
				for _, s := range ids {
					if g, err := strconv.Atoi(s); err == nil {
						groups = append(groups, uint32(g))
					}
				}
			}
		}
		cmd := exec.Command(exe, append([]string{"doctor", "--as-uid-probe"}, paths...)...)
		cmd.Dir = "/"
		cmd.Env = []string{"PATH=/usr/bin:/bin"}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: uint32(uid), Gid: uint32(gid), Groups: groups,
		}}
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		return parseOpened(out), nil
	}
}
