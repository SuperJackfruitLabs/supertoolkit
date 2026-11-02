// Package netjail starts a child whose only way off the machine is the broker.
//
// A proxy cannot see a client that never speaks to it. For a child stk itself
// starts, that is fixable: on Linux the child runs in its own user and network
// namespace, which has a loopback interface and nothing else. A shim inside it
// listens on 127.0.0.1 and relays each connection over a Unix socket — which a
// network namespace does not cut, because it is addressed by path — to the
// broker. Anything the child tries to reach directly has no route.
package netjail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// ShimCommand is the hidden stk subcommand that runs inside the namespace.
const ShimCommand = "__netjail"

// ErrUnsupported is returned where no confinement is possible.
var ErrUnsupported = errors.New("network confinement needs Linux user and network namespaces")

// Jail is the host side: a private Unix socket that relays to the proxy.
type Jail struct {
	dir   string
	sock  string
	ln    net.Listener
	proxy string
}

// Open prepares a relay to proxyAddr (host:port of the broker's proxy).
func Open(proxyAddr string) (*Jail, error) {
	dir, err := os.MkdirTemp("", "stk-netjail-")
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	sock := filepath.Join(dir, "proxy.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	j := &Jail{dir: dir, sock: sock, ln: ln, proxy: proxyAddr}
	go j.serve()
	return j, nil
}

func (j *Jail) serve() {
	for {
		c, err := accept(j.ln)
		if err != nil {
			return
		}
		go func() {
			up, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", j.proxy)
			if err != nil {
				c.Close()
				return
			}
			pipe(c, up)
		}()
	}
}

// Socket is the relay's path, passed to the shim.
func (j *Jail) Socket() string { return j.sock }

// Close stops the relay and removes its socket.
func (j *Jail) Close() error {
	j.ln.Close()
	return os.RemoveAll(j.dir)
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src) // a relay ends when either side closes
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite() // a half-close of a side that already closed changes nothing
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// relayTo accepts on ln and relays each connection to the Unix socket.
func relayTo(ln net.Listener, sock string) {
	for {
		c, err := accept(ln)
		if err != nil {
			return
		}
		go func() {
			up, err := (&net.Dialer{}).DialContext(context.Background(), "unix", sock)
			if err != nil {
				c.Close()
				return
			}
			pipe(c, up)
		}()
	}
}

func usageErr() error {
	return fmt.Errorf("usage: stk %s --sock <path> --port <n> -- <command> [args...]", ShimCommand)
}

// Violation is one socket of a watched process tree that goes somewhere other
// than the broker.
type Violation struct {
	PID    int
	Proto  string // tcp, tcp6, udp, udp6
	Remote netip.AddrPort
}

func (v Violation) String() string {
	return fmt.Sprintf("pid %d %s to %s", v.PID, v.Proto, v.Remote)
}

// accept is Accept that survives temporary failures. A relay used to return on the first error,
// so one EMFILE (a process out of file descriptors) left every later fetch failing instantly,
// without reaching the broker, until its client was killed. Only a closed listener ends a relay;
// anything else backs off (5ms doubling to 1s) and accepts again, as net/http's server does.
func accept(ln net.Listener) (net.Conn, error) {
	delay := 5 * time.Millisecond
	for {
		c, err := ln.Accept()
		if err == nil {
			return c, nil
		}
		if errors.Is(err, net.ErrClosed) {
			return nil, err
		}
		time.Sleep(delay)
		if delay *= 2; delay > time.Second {
			delay = time.Second
		}
	}
}
