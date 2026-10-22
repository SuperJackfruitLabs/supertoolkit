//go:build linux

package netjail

import (
	"context"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestParseHexAddr(t *testing.T) {
	ap, ok := parseHexAddr("0100007F:22C3")
	if !ok || ap.String() != "127.0.0.1:8899" {
		t.Fatalf("%v %v", ap, ok)
	}
	ap, ok = parseHexAddr("00000000000000000000000001000000:0050")
	if !ok || ap.String() != "[::1]:80" {
		t.Fatalf("%v %v", ap, ok)
	}
}

// TestWatchSeesADirectConnection: a child that connects somewhere other than
// the broker is reported, and one that connects only to the broker is not.
func TestWatchSeesADirectConnection(t *testing.T) {
	brokerLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer brokerLn.Close()
	otherLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer otherLn.Close()
	for _, ln := range []net.Listener{brokerLn, otherLn} {
		go func(ln net.Listener) {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
			}
		}(ln)
	}
	broker := netip.MustParseAddrPort(brokerLn.Addr().String())
	for name, target := range map[string]string{"broker": brokerLn.Addr().String(), "direct": otherLn.Addr().String()} {
		self, _ := os.Executable()
		// A grandchild makes the connection, so descendants must be watched.
		cmd := exec.Command("sh", "-c", `"$0" & wait`, self)
		cmd.Env = append(os.Environ(), "STK_WATCH_CHILD="+target)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var mu sync.Mutex
		var got []Violation
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		Watch(ctx, cmd.Process.Pid, []netip.AddrPort{broker}, 50*time.Millisecond, func(v Violation) {
			mu.Lock()
			got = append(got, v)
			mu.Unlock()
		})
		cancel()
		cmd.Process.Kill()
		cmd.Wait()
		if name == "broker" && len(got) != 0 {
			t.Errorf("a broker-only child was reported: %v", got)
		}
		if name == "direct" && (len(got) == 0 || got[0].Remote.String() != target) {
			t.Errorf("a direct connection to %s was not reported: %v", target, got)
		}
	}
}
