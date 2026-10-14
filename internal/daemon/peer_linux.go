//go:build linux

package daemon

import "golang.org/x/sys/unix"

func peerUIDFromFD(fd uintptr) (int, error) {
	ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return -1, err
	}
	return int(ucred.Uid), nil
}
