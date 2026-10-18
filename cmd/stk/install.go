package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/install"
)

const installUsage = "usage: stk install --user <name> [--group <name>] [--state-dir /var/lib/stk] [--runtime-dir /run/stk] " +
	"[--config /etc/stk/supertoolkit.yaml] [--agent-uid N]... [--proxy-port 8899] [--unit-name stk] [--dry-run]"

func parseInstallArgs(args []string) (install.Plan, bool, error) {
	p := install.Plan{StateDir: "/var/lib/stk", RuntimeDir: "/run/stk",
		ConfigPath: "/etc/stk/supertoolkit.yaml", ProxyPort: 8899}
	dry := false
	for i := 0; i < len(args); i++ {
		name, val, hasVal := strings.Cut(args[i], "=")
		if name == "--dry-run" && !hasVal {
			dry = true
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				return p, false, fmt.Errorf("%s needs a value (%s)", name, installUsage)
			}
			i++
			val = args[i]
		}
		switch name {
		case "--user":
			p.User = val
		case "--group":
			p.Group = val
		case "--state-dir":
			p.StateDir = val
		case "--runtime-dir":
			p.RuntimeDir = val
		case "--config":
			p.ConfigPath = val
		case "--agent-uid":
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 {
				return p, false, fmt.Errorf("--agent-uid wants a non-negative integer, got %q", val)
			}
			p.AgentUIDs = append(p.AgentUIDs, n)
		case "--unit-name":
			p.UnitName = val
		case "--proxy-port":
			n, err := strconv.Atoi(val)
			if err != nil {
				return p, false, fmt.Errorf("--proxy-port wants a port, got %q", val)
			}
			p.ProxyPort = n
		default:
			return p, false, fmt.Errorf("install: unknown argument %q (%s)", args[i], installUsage)
		}
	}
	if p.User == "" {
		return p, false, fmt.Errorf("--user is required (%s)", installUsage)
	}
	return p, dry, nil
}

func runInstall(args []string, goos, root string, r install.Runner, out io.Writer) error {
	if goos != "linux" {
		return fmt.Errorf("install is Linux/systemd only")
	}
	p, dry, err := parseInstallArgs(args)
	if err != nil {
		return err
	}
	if p.Binary == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if p.Binary, err = filepath.EvalSymlinks(exe); err != nil {
			return err
		}
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if dry {
		fmt.Fprint(out, install.DryRun(p))
		return nil
	}
	rep, err := install.Run(context.Background(), p, root, r)
	fmt.Fprint(out, rep.String())
	if err != nil {
		return err
	}
	return nil
}

func cmdInstall(args []string) error {
	return runInstall(args, runtime.GOOS, "/", install.ExecRunner{}, os.Stdout)
}
