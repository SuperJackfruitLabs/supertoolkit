//go:build linux

package netjail

import (
	"bufio"
	"context"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Watch polls the sockets of pid and its descendants every interval until ctx
// ends, and reports each connected socket whose remote end is not in allowed.
// DNS (UDP to port 53) is not reported: a lookup reaches no destination, and
// most runtimes do one before they read a proxy setting.
//
// This is detection, not prevention: a connection that opens and closes
// between two polls is not seen. Confinement (Command) is the preventive form;
// Watch is for hosts where namespaces are not available.
func Watch(ctx context.Context, pid int, allowed []netip.AddrPort, every time.Duration, report func(Violation)) {
	seen := map[string]bool{}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		for _, v := range Scan(pid, allowed) {
			k := v.String()
			if !seen[k] {
				seen[k] = true
				report(v)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Scan is one pass of Watch.
func Scan(pid int, allowed []netip.AddrPort) []Violation {
	ok := map[netip.AddrPort]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	var out []Violation
	for _, p := range tree(pid) {
		inodes := socketInodes(p)
		if len(inodes) == 0 {
			continue
		}
		for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
			for inode, remote := range remotes(p, proto) {
				if !inodes[inode] || !remote.IsValid() || remote.Port() == 0 || ok[remote] {
					continue
				}
				if strings.HasPrefix(proto, "udp") && remote.Port() == 53 {
					continue
				}
				out = append(out, Violation{PID: p, Proto: proto, Remote: remote})
			}
		}
	}
	return out
}

// tree is pid and every descendant, from /proc.
func tree(root int) []int {
	children := map[int][]int{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		// The command name is in parentheses and may contain spaces.
		s := string(raw)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		children[ppid] = append(children[ppid], pid)
	}
	out := []int{root}
	for i := 0; i < len(out); i++ {
		out = append(out, children[out[i]]...)
	}
	return out
}

func socketInodes(pid int) map[string]bool {
	dir := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := map[string]bool{}
	for _, e := range ents {
		l, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err == nil && strings.HasPrefix(l, "socket:[") {
			out[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	return out
}

// remotes maps socket inode to remote address, read from the process's own
// view of the network (its namespace).
func remotes(pid int, proto string) map[string]netip.AddrPort {
	f, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "net", proto))
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]netip.AddrPort{}
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 10 {
			continue
		}
		// A listening TCP socket (state 0A) has no remote end.
		if strings.HasPrefix(proto, "tcp") && fl[3] == "0A" {
			continue
		}
		if ap, ok := parseHexAddr(fl[2]); ok {
			out[fl[9]] = ap
		}
	}
	return out
}

// parseHexAddr reads the kernel's "0100007F:1F90" form: 32-bit words in host
// (little-endian) order, then a big-endian hex port.
func parseHexAddr(s string) (netip.AddrPort, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return netip.AddrPort{}, false
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	a, _ := netip.AddrFromSlice(raw)
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), true
}
