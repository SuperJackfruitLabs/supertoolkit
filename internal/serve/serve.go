package serve

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/controlplane"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/livepolicy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/localstate"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/session"
)

type serveArgs struct {
	listen    string
	allowUIDs []int
	// socketMode is the control socket's file mode. 0600 by default; an
	// install under its own user passes 0660 so the agent's group can reach
	// the socket at all, while --allow-uid stays the authorisation.
	socketMode os.FileMode
	// localCommandsSocket, when set, is a unix socket that serves the proxy pinned to the
	// local-commands identity (operator ruling 2026-10-30). localCommandsMode is its file mode.
	localCommandsSocket string
	localCommandsMode   os.FileMode
}

const serveUsage = "usage: stk serve [--proxy-listen <loopback host:port>] [--allow-uid <n>]... [--socket-mode 0600|0660] [--local-commands-socket <absolute path>] [--local-commands-mode 0600|0660]"

// parseSocketMode accepts only owner rw, optionally plus group rw. Anything
// reachable by other users, or with execute or special bits, is refused: the
// filesystem mode is the first gate and must never be the open one.
func parseSocketMode(v string) (os.FileMode, error) {
	n, err := strconv.ParseUint(v, 8, 32)
	if err != nil || (n != 0o600 && n != 0o660) {
		return 0, fmt.Errorf("--socket-mode must be 0600 or 0660, got %q", v)
	}
	return os.FileMode(n), nil
}

func parseServeArgs(args []string) (serveArgs, error) {
	o := serveArgs{socketMode: 0o600, localCommandsMode: 0o600}
	setMode := func(v string) error {
		m, err := parseSocketMode(v)
		if err != nil {
			return err
		}
		o.socketMode = m
		return nil
	}
	addUID := func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("--allow-uid wants a non-negative integer, got %q", v)
		}
		o.allowUIDs = append(o.allowUIDs, n)
		return nil
	}
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--proxy-listen":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--proxy-listen needs a loopback host:port")
			}
			i++
			o.listen = args[i]
		case strings.HasPrefix(a, "--proxy-listen="):
			o.listen = strings.TrimPrefix(a, "--proxy-listen=")
		case a == "--allow-uid":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--allow-uid needs a uid")
			}
			i++
			if err := addUID(args[i]); err != nil {
				return o, err
			}
		case strings.HasPrefix(a, "--allow-uid="):
			if err := addUID(strings.TrimPrefix(a, "--allow-uid=")); err != nil {
				return o, err
			}
		case a == "--socket-mode":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--socket-mode needs 0600 or 0660")
			}
			i++
			if err := setMode(args[i]); err != nil {
				return o, err
			}
		case strings.HasPrefix(a, "--socket-mode="):
			if err := setMode(strings.TrimPrefix(a, "--socket-mode=")); err != nil {
				return o, err
			}
		case a == "--local-commands-socket" || strings.HasPrefix(a, "--local-commands-socket="):
			v, ok := strings.CutPrefix(a, "--local-commands-socket=")
			if !ok {
				if i+1 >= len(args) {
					return o, fmt.Errorf("--local-commands-socket needs an absolute socket path")
				}
				i++
				v = args[i]
			}
			if !filepath.IsAbs(v) {
				return o, fmt.Errorf("--local-commands-socket wants an absolute path, got %q", v)
			}
			o.localCommandsSocket = v
		case a == "--local-commands-mode" || strings.HasPrefix(a, "--local-commands-mode="):
			v, ok := strings.CutPrefix(a, "--local-commands-mode=")
			if !ok {
				if i+1 >= len(args) {
					return o, fmt.Errorf("--local-commands-mode needs 0600 or 0660")
				}
				i++
				v = args[i]
			}
			m, err := parseSocketMode(v)
			if err != nil {
				return o, fmt.Errorf("--local-commands-mode: %w", err)
			}
			o.localCommandsMode = m
		default:
			return o, fmt.Errorf("serve: unknown argument %q (%s)", a, serveUsage)
		}
	}
	return o, nil
}

func Command(args []string, version string) error {
	sa, err := parseServeArgs(args)
	if err != nil {
		return err
	}
	listen := sa.listen
	var opts session.Options
	if listen != "" {
		ap, err := parseProxyListen(listen)
		if err != nil {
			return err
		}
		opts.Listen = ap.String()
	}
	// SIGHUP's default action kills the process, so it is caught before any
	// startup work: a reload signal sent while serve is still starting is
	// held (one is enough) and applied once the loop below runs.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	cfg, store, dir, err := localstate.LoadForRun()
	if err != nil {
		return err
	}
	if listen != "" {
		if opts.Key, err = localstate.LoadOrCreateProxyKey(dir); err != nil {
			return err
		}
	}
	// One policy holder for the daemon path, the observer and the proxy's
	// secret source, so a reload reaches all of them.
	live := livepolicy.New(cfg, store, &http.Client{Timeout: 60 * time.Second})
	svc, err := controlplane.NewWith(live, store, dir, "serve", version)
	if err != nil {
		return err
	}
	defer svc.CloseHosts()
	opts.Live = live

	// Fronted children need the broker's address, so the broker starts first
	// and the child environment is built from it.
	sess, err := session.StartWith(cfg, store, dir, opts)
	if err != nil {
		return err
	}
	defer sess.Stop()
	if listen != "" {
		if err := localstate.WriteProxyAddr(dir, sess.Addr); err != nil {
			return err
		}
		defer localstate.RemoveProxyAddr(dir)
	}
	svc.ChildEnvFor = sess.ChildEnvFor
	svc.ProxyAddr, svc.ProxyKey, svc.CAPath = sess.Addr, opts.Key, sess.CAPath
	rl := livepolicy.NewReloader(localstate.ConfigPath(), live, sess.Broker, store)
	svc.Reload = rl.Reload

	if sa.localCommandsSocket != "" {
		lc, err := listenLocalCommands(sa.localCommandsSocket, sa.localCommandsMode)
		if err != nil {
			return err
		}
		defer func() { lc.Close(); os.Remove(sa.localCommandsSocket) }()
		go sess.Broker.ServeAs(lc, broker.LocalCommandsIdentity)
		fmt.Printf("  local-commands proxy on %s (%04o; every connection is local-commands)\n", sa.localCommandsSocket, sa.localCommandsMode)
	}

	sock := localstate.SocketPath(dir)
	d, err := daemon.ListenWith(sock, svc.Handle, daemon.Options{AllowUIDs: sa.allowUIDs, SocketMode: sa.socketMode})
	if err != nil {
		return err
	}
	defer d.Close()

	fmt.Printf("  listening on %s (%04o, owner uid %d)\n", sock, sa.socketMode, os.Getuid())
	if len(sa.allowUIDs) > 0 {
		fmt.Printf("  callers limited to uid(s) %v\n", sa.allowUIDs)
	}
	fmt.Printf("  workspace %q · %d service(s) · %d profile(s)\n", cfg.Workspace, len(cfg.Services()), len(cfg.Profiles()))
	if listen != "" {
		fmt.Printf("  proxy on %s (key required; `stk env` prints the settings)\n", sess.Addr)
	}
	fmt.Printf("  %d meta-tools exposed to agents\n", len(mcp.ToolNames))
	fmt.Println("  ctrl-C to stop")

	errc := make(chan error, 1)
	go func() { errc <- d.Serve() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	for {
		select {
		case err := <-errc:
			return err
		case <-hup:
			// The same reload `stk reload` asks for.
			res := rl.Reload()
			if res.OK {
				fmt.Println("  SIGHUP: " + res.Summary())
			} else {
				fmt.Fprintln(os.Stderr, "  SIGHUP: "+res.Summary())
			}
		case <-sig:
			fmt.Println("\n  stopping")
			return nil
		}
	}
}

// listenLocalCommands binds the local-commands socket with the given file mode. A leftover file
// from a dead process is replaced; a live socket is refused rather than taken over.
func listenLocalCommands(path string, mode os.FileMode) (net.Listener, error) {
	if _, err := os.Stat(path); err == nil {
		if c, derr := net.Dial("unix", path); derr == nil {
			c.Close()
			return nil, fmt.Errorf("%s: a local-commands proxy is already listening", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing a stale socket at %s: %w", path, err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return nil, fmt.Errorf("securing %s: %w", path, err)
	}
	return ln, nil
}

// parseProxyListen accepts only a loopback host:port. Anything reachable from
// another machine would make the broker a credential-injecting relay for the
// network, so it is refused rather than warned about.
func parseProxyListen(a string) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("--proxy-listen %q: want host:port (%v)", a, err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("--proxy-listen %q: the host must be a loopback IP address or localhost, not %q", a, host)
	}
	if !ip.IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("--proxy-listen %q: only loopback addresses (127.0.0.0/8, ::1) are accepted; %s is reachable from other machines", a, ip)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("--proxy-listen %q: %q is not a port number", a, port)
	}
	if p == 0 {
		return netip.AddrPort{}, fmt.Errorf("--proxy-listen %q: port 0 picks a random port; a fixed proxy needs a fixed one", a)
	}
	return netip.AddrPortFrom(ip, uint16(p)), nil
}
