//go:build !linux

package netjail

import (
	"context"
	"net/netip"
	"os/exec"
	"time"
)

// Command is unavailable off Linux; callers check Probe first.
func (j *Jail) Command(self string, port int, name string, args ...string) *exec.Cmd { return nil }

// Shim is unavailable off Linux.
func Shim(args []string) (int, error) { return 2, ErrUnsupported }

// Probe always fails off Linux.
func Probe(self string) error { return ErrUnsupported }

// ProbeChild always fails off Linux.
func ProbeChild() error { return ErrUnsupported }

// Watch is unavailable off Linux.
func Watch(ctx context.Context, pid int, allowed []netip.AddrPort, every time.Duration, report func(Violation)) {
}
