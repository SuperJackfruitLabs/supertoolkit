//go:build unix

package daemon

import (
	"fmt"
	"net"
)

// PeerUID reports the uid of the process at the other end of a Unix socket.
//
// This is the kernel's answer, not the caller's claim, so it cannot be forged
// and costs no round trip. It is how the daemon knows who is talking to it
// without any shared secret existing to be stolen.
//
// The mechanism differs by platform — Linux reports it through SO_PEERCRED and
// the BSDs, macOS included, through LOCAL_PEERCRED — so the syscall lives in a
// per-platform file and this stays the single entry point.
func PeerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return -1, fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var uid int
	var serr error
	if err := raw.Control(func(fd uintptr) { uid, serr = peerUIDFromFD(fd) }); err != nil {
		return -1, err
	}
	return uid, serr
}
