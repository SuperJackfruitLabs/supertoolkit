package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

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
	b, err := os.ReadFile(filepath.Join(dir, proxyAddrFile))
	addr := strings.TrimSpace(string(b))
	if err == nil && addr != "" {
		// A crashed server leaves its address behind; a dead address printed
		// as if it worked would send a client at nothing.
		var c net.Conn
		if c, err = net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
			c.Close()
		}
	}
	if err != nil || addr == "" {
		return fmt.Errorf("no fixed proxy is running; start `stk serve --proxy-listen <addr>`")
	}
	key, err := loadOrCreateProxyKey(dir)
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
