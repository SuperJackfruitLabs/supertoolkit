package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// readProxyAddr reads proxy.addr: the address, then the owning pid.
func readProxyAddr(path string) (addr string, pid int, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	lines := strings.Fields(string(b))
	if len(lines) != 2 {
		return "", 0, fmt.Errorf("malformed %s", filepath.Base(path))
	}
	pid, err = strconv.Atoi(lines[1])
	if err != nil || pid <= 0 {
		return lines[0], 0, fmt.Errorf("malformed pid in %s", filepath.Base(path))
	}
	return lines[0], pid, nil
}

// verifyStkProxy decides whether addr is a live stk proxy, before the proxy
// key is printed to anyone.
//
// A crashed `serve` leaves proxy.addr behind, and another local process may
// since have bound the port; handing it the key would be a leak. So two checks
// must both pass: the recorded pid is alive, and a keyless CONNECT to a dummy
// host is answered 407 with stk's own realm.
//
// Residual risk: a same-host attacker who can bind the port while stk is not
// running could mimic the 407, and an unrelated process could reuse the dead
// server's pid. That is why the pid check exists too, and why the proxy key is
// not a service credential: it lets a holder use the proxy's allowed routes,
// never read a secret.
func verifyStkProxy(addr string, pid int) error {
	if kerr := syscall.Kill(pid, 0); pid <= 0 || kerr != nil && !errors.Is(kerr, syscall.EPERM) {
		return fmt.Errorf("process %d is not running", pid)
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, "CONNECT stk.invalid:443 HTTP/1.1\r\nHost: stk.invalid:443\r\n\r\n"); err != nil {
		return err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fmt.Errorf("no HTTP answer: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") != `Basic realm="stk"` {
		return fmt.Errorf("unexpected answer %q", resp.Status)
	}
	return nil
}

func cmdEnv(args []string) error { return runEnv(os.Stdout, os.Stderr, args) }

// runEnv prints the settings a client needs to use the fixed proxy that
// `stk serve --proxy-listen` is running.
//
// It prints the proxy key, inside the proxy URL, because that is its purpose:
// the operator puts it in a client's environment. It never prints a service
// credential — the variables carry placeholders, built by the same
// broker.ChildEnv a child of `stk run` gets, over an empty base so only the
// broker's own settings appear and the parent environment does not.
func runEnv(out, errw io.Writer, args []string) error {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		default:
			return fmt.Errorf("env: unknown argument %q (usage: stk env [--json])", a)
		}
	}
	cfg, err := policy.Load(configPath())
	if err != nil {
		return fmt.Errorf("%w — run `stk init` first", err)
	}
	dir, err := home()
	if err != nil {
		return err
	}
	addrPath := filepath.Join(dir, proxyAddrFile)
	addr, pid, err := readProxyAddr(addrPath)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no fixed proxy is running; start `stk serve --proxy-listen <addr>`")
	}
	if err == nil {
		err = verifyStkProxy(addr, pid)
	}
	if err != nil {
		return fmt.Errorf("the listener at %s is not a running stk proxy (%v); remove %s or start `stk serve --proxy-listen`",
			addr, err, addrPath)
	}
	// Read-only: a key minted here would be one the running broker does not
	// know, and every client would meet a 407 with no hint why.
	key, err := readProxyKey(filepath.Join(dir, proxyKeyFile))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s is missing, so the running proxy's key cannot be known; restart `stk serve --proxy-listen`",
			filepath.Join(dir, proxyKeyFile))
	}
	if err != nil {
		return err
	}
	ca, err := broker.LoadOrCreateCA(dir, "supertoolkit local CA", 365*24*time.Hour)
	if err != nil {
		return err
	}
	caPath, err := ca.WriteCert(dir)
	if err != nil {
		return err
	}
	proxyURL := broker.ProxyURL(addr, key)
	vars := map[string]string{}
	for _, kv := range childEnvFrom(nil, cfg, proxyURL, caPath) {
		k, v, _ := strings.Cut(kv, "=")
		vars[k] = v
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"proxy_url": proxyURL, "ca_path": caPath, "env": vars})
	}
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Fprintf(out, "export %s='%s'\n", k, strings.ReplaceAll(vars[k], "'", `'\''`))
	}
	return nil
}
