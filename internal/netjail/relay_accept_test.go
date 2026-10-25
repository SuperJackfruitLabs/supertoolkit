//go:build linux

package netjail

import (
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// flakyListener fails Accept with EMFILE a few times, then hands out real connections: what a
// relay sees when its process runs out of file descriptors and some are freed again.
type flakyListener struct {
	net.Listener
	mu    sync.Mutex
	fails int
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.fails > 0 {
		l.fails--
		l.mu.Unlock()
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: syscall.EMFILE}
	}
	l.mu.Unlock()
	return l.Listener.Accept()
}

func echoUnix(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "up.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return sock
}

func roundTrip(t *testing.T, addr string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("relay did not carry the connection after accept errors: %q %v", buf, err)
	}
}

// The relay inside the namespace used to return on the first Accept error, so one EMFILE left
// every later fetch failing instantly, without reaching the broker, until the client was killed.
func TestShimRelayKeepsServingThroughTemporaryAcceptErrors(t *testing.T) {
	sock := echoUnix(t)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := &flakyListener{Listener: inner, fails: 2}
	defer ln.Close()
	go relayTo(ln, sock)
	roundTrip(t, inner.Addr().String())
}

func TestHostRelayKeepsServingThroughTemporaryAcceptErrors(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		for {
			c, err := up.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	sock := filepath.Join(t.TempDir(), "proxy.sock")
	inner, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	j := &Jail{dir: t.TempDir(), sock: sock, ln: &flakyListener{Listener: inner, fails: 2}, proxy: up.Addr().String()}
	go j.serve()
	defer j.Close()
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("pong"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("host relay stopped after accept errors: %q %v", buf, err)
	}
}

// A closed listener still ends the relay: only temporary errors are retried.
func TestRelayStopsWhenItsListenerIsClosed(t *testing.T) {
	sock := echoUnix(t)
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { relayTo(inner, sock); close(done) }()
	inner.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay kept running after its listener was closed")
	}
	if !errors.Is(net.ErrClosed, net.ErrClosed) {
		t.Fatal("unreachable")
	}
}
