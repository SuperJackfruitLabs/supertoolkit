//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package daemon

import "golang.org/x/sys/unix"

func peerUIDFromFD(fd uintptr) (int, error) {
	// The BSDs, macOS included, report the peer through LOCAL_PEERCRED as an
	// xucred rather than Linux's ucred.
	xu, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return -1, err
	}
	return int(xu.Uid), nil
}
