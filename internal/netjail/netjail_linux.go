//go:build linux

package netjail

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// Command builds the confined command: self (this binary) running the shim,
// which runs name with args. The caller sets Stdin, Stdout, Env and starts it.
//
// The namespace maps the caller's uid to root inside it, because only a
// namespace root may bring loopback up; outside, the child is still the caller
// and can open nothing the caller cannot.
func (j *Jail) Command(self string, port int, name string, args ...string) *exec.Cmd {
	argv := append([]string{ShimCommand, "--sock", j.sock, "--port", strconv.Itoa(port), "--", name}, args...)
	cmd := exec.CommandContext(context.Background(), self, argv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
	return cmd
}

// Shim runs inside the namespace: loopback up, a listener relaying to the
// broker, then the real child with this process's stdio. It returns the
// child's exit code.
func Shim(args []string) (int, error) {
	var sock string
	port := 0
	i := 0
	for ; i < len(args); i++ {
		switch args[i] {
		case "--sock":
			if i+1 >= len(args) {
				return 2, usageErr()
			}
			i++
			sock = args[i]
		case "--port":
			if i+1 >= len(args) {
				return 2, usageErr()
			}
			i++
			port, _ = strconv.Atoi(args[i])
		case "--":
			i++
			goto run
		default:
			return 2, usageErr()
		}
	}
run:
	if sock == "" || port <= 0 || i >= len(args) {
		return 2, usageErr()
	}
	if err := loopbackUp(); err != nil {
		return 1, fmt.Errorf("bringing loopback up in the namespace: %w", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return 1, err
	}
	go relayTo(ln, sock)

	// The child gains nothing from this namespace's root: no new privileges.
	_ = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) // best effort, as it has always been
	cmd := exec.CommandContext(context.Background(), args[i], args[i+1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return 127, err
	}
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for s := range sig {
			_ = cmd.Process.Signal(s) // a child that has exited needs no signal
		}
	}()
	err = cmd.Wait()
	// Wait returns an *exec.ExitError itself, never wrapped, so errors.As matches the same.
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 1, err
	}
	return 0, nil
}

func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// Probe reports whether this process can create the namespaces at all, so a
// caller can refuse to start a child rather than start it unconfined.
func Probe(self string) error {
	cmd := exec.CommandContext(context.Background(), self, ShimCommand+"-probe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %v %s (on Ubuntu, kernel.apparmor_restrict_unprivileged_userns=1 needs an AppArmor profile granting userns to stk)", ErrUnsupported, err, out)
	}
	return nil
}

// ProbeChild is the probe's inside half: it proves loopback can be raised.
func ProbeChild() error { return loopbackUp() }
