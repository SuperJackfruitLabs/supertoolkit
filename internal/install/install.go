// Package install provisions stk to run as its own OS user under systemd, so
// the agent — usually the same OS user as the node — cannot read the sealed
// store, its key, or the approvals.
//
// Every filesystem path is joined under root (production "/") and every
// host-changing command goes through a Runner, so tests never touch the host.
package install

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Plan is what to provision.
type Plan struct {
	User, Group                      string
	StateDir, RuntimeDir, ConfigPath string
	AgentUIDs                        []int
	Binary                           string
	ProxyPort                        int
}

// Runner runs a host command, argv only.
type Runner interface {
	Run(name string, args ...string) error
}

// ExecRunner runs commands with os/exec, never through a shell.
type ExecRunner struct{}

// Run executes name with args and folds its output into the error.
func (ExecRunner) Run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Report lists what was done. It names paths and accounts, never a secret.
type Report struct{ Created, Changed, Unchanged, Notes []string }

func (r Report) String() string {
	var b strings.Builder
	for _, s := range []struct {
		label string
		items []string
	}{{"created", r.Created}, {"changed", r.Changed}, {"unchanged", r.Unchanged}} {
		for _, it := range s.items {
			fmt.Fprintf(&b, "  %-9s %s\n", s.label, it)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "  note      %s\n", n)
	}
	return b.String()
}

// Geteuid is injectable so the root check is testable without root.
var Geteuid = os.Geteuid

// UnitPath is where the unit is written, relative to root.
const UnitPath = "/etc/systemd/system/stk.service"

// Validate checks a plan before anything runs.
func (p Plan) Validate() error {
	if p.User == "" || strings.ContainsAny(p.User, " :/") || strings.HasPrefix(p.User, "-") {
		return fmt.Errorf("invalid --user %q", p.User)
	}
	if p.Group != "" && (strings.ContainsAny(p.Group, " :/") || strings.HasPrefix(p.Group, "-")) {
		return fmt.Errorf("invalid --group %q", p.Group)
	}
	for _, d := range []string{p.StateDir, p.RuntimeDir, p.ConfigPath, p.Binary} {
		if !filepath.IsAbs(d) || strings.ContainsAny(d, " \n") {
			return fmt.Errorf("path %q must be absolute with no spaces", d)
		}
	}
	if len(p.AgentUIDs) == 0 {
		return errors.New("stk install needs at least one --agent-uid: without it the socket allowlist is empty and any member of the group would be served")
	}
	// Only a single segment under /run gets RuntimeDirectory=; anything else
	// vanishes or keeps a stale mode after a reboot.
	if rest, ok := strings.CutPrefix(p.RuntimeDir, "/run/"); !ok || rest == "" || strings.Contains(rest, "/") {
		return fmt.Errorf("--runtime-dir %q must be directly under /run (e.g. /run/stk)", p.RuntimeDir)
	}
	if p.ProxyPort <= 0 || p.ProxyPort > 65535 {
		return fmt.Errorf("invalid proxy port %d", p.ProxyPort)
	}
	return nil
}

// DryRun describes the plan and shows the unit. It changes nothing.
func DryRun(p Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "would ensure system user %q (group %q, no home, nologin)\n", p.User, p.group())
	fmt.Fprintf(&b, "would ensure %s 0700 owned by %s\n", p.StateDir, p.User)
	fmt.Fprintf(&b, "would ensure %s %s owned by %s:%s\n", p.RuntimeDir, p.runtimeMode(), p.User, p.group())
	fmt.Fprintf(&b, "would generate %s/%s 0400 if absent (never printed)\n", p.StateDir, PassphraseFile)
	fmt.Fprintf(&b, "would ensure %s 0750; config, if present, 0640 root:%s\n", filepath.Dir(p.ConfigPath), p.group())
	if p.Group != "" {
		fmt.Fprintf(&b, "you must add each agent user to group %s (install runs no usermod)\n", p.Group)
	}
	fmt.Fprintf(&b, "would write %s:\n\n%s", UnitPath, Unit(p))
	return b.String()
}

// Run provisions the plan under root. It is idempotent and never overwrites
// anything in an existing store.
func Run(ctx context.Context, p Plan, root string, r Runner) (Report, error) {
	var rep Report
	if Geteuid() != 0 {
		return rep, errors.New("install must run as root (use --dry-run to see the plan)")
	}
	if err := p.Validate(); err != nil {
		return rep, err
	}
	at := func(path string) string { return filepath.Join(root, path) }
	owner := p.User + ":" + p.group()

	// The store check comes before any change, so a refusal leaves the host
	// as it was.
	state := at(p.StateDir)
	pass := filepath.Join(state, PassphraseFile)
	if _, err := os.Stat(pass); os.IsNotExist(err) {
		if _, err := os.Stat(filepath.Join(state, "salt")); err == nil {
			return rep, fmt.Errorf("%s holds a store but no "+PassphraseFile+"; it is sealed under another key "+
				"(machine.key or STK_PASSPHRASE) — refusing to add a new passphrase over it", p.StateDir)
		}
	}

	// Accounts.
	if p.Group != "" {
		if r.Run("getent", "group", p.Group) != nil {
			if err := r.Run("groupadd", "--system", p.Group); err != nil {
				return rep, err
			}
			rep.Created = append(rep.Created, "group "+p.Group)
		} else {
			rep.Unchanged = append(rep.Unchanged, "group "+p.Group)
		}
	}
	if r.Run("getent", "passwd", p.User) != nil {
		args := []string{"--system", "--no-create-home", "--shell", "/usr/sbin/nologin"}
		if p.Group != "" {
			args = append(args, "--gid", p.Group)
		} else {
			args = append(args, "--user-group")
		}
		if err := r.Run("useradd", append(args, p.User)...); err != nil {
			return rep, err
		}
		rep.Created = append(rep.Created, "user "+p.User)
	} else {
		rep.Unchanged = append(rep.Unchanged, "user "+p.User)
	}

	// Directories.
	runtimeMode := os.FileMode(0o700)
	if p.Group != "" {
		runtimeMode = 0o750
	}
	for _, d := range []struct {
		path  string
		mode  os.FileMode
		owner string
	}{
		{state, 0o700, owner},
		{at(p.RuntimeDir), runtimeMode, owner},
		{at(filepath.Dir(p.ConfigPath)), 0o750, "root:" + p.group()},
	} {
		if err := ensureDir(&rep, r, d.path, d.mode, d.owner); err != nil {
			return rep, err
		}
	}

	// The passphrase: generated only if absent, never read back or printed.
	if _, err := os.Stat(pass); os.IsNotExist(err) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return rep, err
		}
		f, err := os.OpenFile(pass, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
		if err != nil {
			return rep, err
		}
		_, werr := f.WriteString(base64.StdEncoding.EncodeToString(raw) + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return rep, werr
		}
		if err := os.Chmod(pass, 0o400); err != nil {
			return rep, err
		}
		if err := r.Run("chown", owner, pass); err != nil {
			return rep, err
		}
		rep.Created = append(rep.Created, pass+" (0400)")
	} else if err != nil {
		return rep, err
	} else if err := ensure(&rep, r, pass, 0o400, owner); err != nil {
		return rep, err
	}

	// The config holds no secret. It is not created here — policy is the
	// operator's — but if present its mode is tightened.
	cfg := at(p.ConfigPath)
	if _, err := os.Stat(cfg); err == nil {
		if err := ensure(&rep, r, cfg, 0o640, "root:"+p.group()); err != nil {
			return rep, err
		}
	}

	// The unit.
	unitPath := at(UnitPath)
	want := Unit(p)
	if have, err := os.ReadFile(unitPath); err == nil && string(have) == want {
		rep.Unchanged = append(rep.Unchanged, unitPath)
	} else {
		existed := err == nil
		if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
			return rep, err
		}
		if err := os.WriteFile(unitPath, []byte(want), 0o644); err != nil {
			return rep, err
		}
		if err := r.Run("systemctl", "daemon-reload"); err != nil {
			return rep, err
		}
		if existed {
			rep.Changed = append(rep.Changed, unitPath)
		} else {
			rep.Created = append(rep.Created, unitPath)
		}
	}
	if p.Group != "" {
		rep.Notes = append(rep.Notes, fmt.Sprintf("add each agent user to group %s yourself (install runs no usermod): usermod -aG %s <agent-user>", p.Group, p.Group))
	}
	return rep, ctx.Err()
}

func ensureDir(rep *Report, r Runner, path string, mode os.FileMode, owner string) error {
	fi, err := os.Stat(path)
	switch {
	case os.IsNotExist(err):
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		if err := r.Run("chown", owner, path); err != nil {
			return err
		}
		rep.Created = append(rep.Created, fmt.Sprintf("%s (%04o)", path, mode))
		return nil
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	return ensure(rep, r, path, mode, owner)
}

// ensure corrects an existing path's mode and ownership independently, and
// reports it changed if either was wrong.
func ensure(rep *Report, r Runner, path string, mode os.FileMode, owner string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	changed := false
	if fi.Mode().Perm() != mode {
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
		changed = true
	}
	u, g, err := OwnerOf(path)
	if err != nil {
		return err
	}
	if u+":"+g != owner {
		if err := r.Run("chown", owner, path); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		rep.Changed = append(rep.Changed, fmt.Sprintf("%s (%04o %s)", path, mode, owner))
	} else {
		rep.Unchanged = append(rep.Unchanged, path)
	}
	return nil
}

// PassphraseFile is the store passphrase's name inside StateDir. It is outside
// the store's "<service>.cred" namespace, so no credential write can replace it.
const PassphraseFile = "stk-passphrase.key"

// OwnerOf reports a path's owning user and group names. Injectable: tests
// fake it; production reads the inode (owner_unix.go).
var OwnerOf = ownerOf
