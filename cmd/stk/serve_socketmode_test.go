package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
)

func TestServeSocketModeFlag(t *testing.T) {
	o, err := parseServeArgs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if o.socketMode != 0o600 {
		t.Fatalf("default socket mode %o, want 0600 (unchanged)", o.socketMode)
	}
	o, err = parseServeArgs([]string{"--socket-mode", "0660"})
	if err != nil || o.socketMode != 0o660 {
		t.Fatalf("parsed %o, %v", o.socketMode, err)
	}
	if o, err = parseServeArgs([]string{"--socket-mode=660"}); err != nil || o.socketMode != 0o660 {
		t.Fatalf("parsed %o, %v", o.socketMode, err)
	}
	// Never world-reachable, never executable bits, never more than owner+group rw.
	for _, bad := range []string{"0666", "0606", "0700", "0670", "abc", "", "01660"} {
		if _, err := parseServeArgs([]string{"--socket-mode", bad}); err == nil {
			t.Errorf("--socket-mode %q was accepted", bad)
		}
	}

	dir, err := os.MkdirTemp("", "sm")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "s.sock")
	d, err := daemon.ListenWith(sock, nil, daemon.Options{SocketMode: 0o660})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	fi, _ := os.Stat(sock)
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %o, want 0660", fi.Mode().Perm())
	}
}
