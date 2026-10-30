package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Operator ruling 2026-10-30: local commands get their own socket, pinned to local-commands.
func TestServeLocalCommandsSocketFlags(t *testing.T) {
	o, err := parseServeArgs(nil)
	if err != nil || o.localCommandsSocket != "" || o.localCommandsMode != 0o600 {
		t.Fatalf("default: %q %o %v (want off, 0600)", o.localCommandsSocket, o.localCommandsMode, err)
	}
	o, err = parseServeArgs([]string{"--local-commands-socket", "/run/stk/local-commands.sock", "--local-commands-mode=0660"})
	if err != nil || o.localCommandsSocket != "/run/stk/local-commands.sock" || o.localCommandsMode != 0o660 {
		t.Fatalf("parsed %q %o %v", o.localCommandsSocket, o.localCommandsMode, err)
	}
	for _, bad := range [][]string{{"--local-commands-socket"}, {"--local-commands-socket", "relative.sock"},
		{"--local-commands-mode", "0666"}} {
		if _, err := parseServeArgs(bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

func TestListenLocalCommandsSetsModeAndReplacesAStaleSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "lc.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil { // a stale leftover, not listening
		t.Fatal(err)
	}
	ln, err := listenLocalCommands(sock, 0o660)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o660 || st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket %v mode %v", err, st.Mode())
	}
	// A second listener refuses rather than stealing a live socket.
	if _, err := listenLocalCommands(sock, 0o660); err == nil {
		t.Fatal("a live local-commands socket was taken over")
	}
	if c, err := net.Dial("unix", sock); err != nil {
		t.Fatalf("cannot reach the socket: %v", err)
	} else {
		c.Close()
	}
}
