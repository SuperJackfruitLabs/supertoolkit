package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func knownServices() string {
	n := catalog.Names()
	sort.Strings(n)
	return strings.Join(n, ", ")
}

func cmdInit() error {
	dir, err := home()
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
	_, keySrc, err := credential.StoreKey(dir)
	if err != nil {
		return err
	}

	cfg := configPath()
	if _, err := os.Stat(cfg); os.IsNotExist(err) {
		body := "# supertoolkit policy. Safe to commit: it holds no secrets.\nworkspace: default\nservices: {}\n"
		if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
			return err
		}
		fmt.Printf("  wrote %s — safe to commit, holds no secrets\n", cfg)
	} else {
		fmt.Printf("  kept %s\n", cfg)
	}
	fmt.Printf("  local state in %s (0700)\n", dir)
	fmt.Printf("  store key from %s\n", keySrc)
	fmt.Printf("  CA certificate %s\n", caPath)
	fmt.Println()
	fmt.Println("  next: stk add github && stk connect github")
	fmt.Println("  no browser on this machine? stk connect github --device")
	fmt.Println()
	fmt.Println("  about trusting the CA:")
	switch runtime.GOOS {
	case "darwin":
		fmt.Println("    `stk run` sets the CA for curl, Python and Node automatically.")
		fmt.Println("    On macOS, Go programs ignore SSL_CERT_FILE and use the system")
		fmt.Println("    keychain, so tools like `gh` need the CA added there:")
		fmt.Printf("      sudo security add-trusted-cert -d -k /Library/Keychains/System.keychain %s\n", caPath)
	default:
		fmt.Println("    `stk run` sets SSL_CERT_FILE and friends, which covers Go, curl,")
		fmt.Println("    Python and Node on this platform. No system change needed.")
	}
	return nil
}

func cmdAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: stk add <service>...  (known: %s)", knownServices())
	}
	cfg := configPath()
	raw, err := os.ReadFile(cfg)
	if err != nil {
		return fmt.Errorf("%s: %w — run `stk init` first", cfg, err)
	}
	text := string(raw)
	for _, name := range args {
		entry, ok := catalog.Lookup(name)
		if !ok {
			return fmt.Errorf("unknown service %q: known services are %s; a git forge is defined by hand in the policy file with `kind: forge`", name, knownServices())
		}
		if strings.Contains(text, "\n  "+name+":") {
			fmt.Printf("  %s already present\n", name)
			continue
		}
		text = strings.Replace(text, "services: {}", "services:", 1)
		if !strings.Contains(text, "services:") {
			text += "\nservices:\n"
		}
		text += fmt.Sprintf("  %s:\n    scopes: []\n", name)

		reads, writes := 0, 0
		for _, c := range entry.Capabilities {
			if c.Kind == catalog.Read {
				reads++
			} else {
				writes++
			}
		}
		fmt.Printf("  %-10s %s · %d read→agent, %d write→approval\n", name, entry.Host, reads, writes)
	}
	return os.WriteFile(cfg, []byte(text), 0o644)
}

// cmdConnect reads the credential from stdin, never from a flag, so it cannot
// land in shell history or in the process table.
//
// With --device there is nothing to read: the provider hands the token straight
// to the broker, and no credential passes through a keyboard at all.
func cmdConnect(args []string) error {
	var name string
	device, browser := false, false
	for _, a := range args {
		switch a {
		case "--device":
			device = true
		case "--browser":
			browser = true
		default:
			if name != "" {
				return fmt.Errorf("usage: stk connect <service> [--device|--browser]")
			}
			name = a
		}
	}
	if name == "" {
		return fmt.Errorf("usage: stk connect <service> [--device|--browser]   (the credential is read from stdin)")
	}
	if device && browser {
		return fmt.Errorf("--device and --browser are two different flows; pick one")
	}
	if device {
		return connectDevice(name, os.Stdout)
	}
	if browser {
		return connectBrowser(name, os.Stdout, os.Stdin, openInBrowser)
	}
	entry, err := resolveEntry(name)
	if err != nil {
		return err
	}
	dir, err := home()
	if err != nil {
		return err
	}
	pass, _, err := credential.StoreKey(dir)
	if err != nil {
		return err
	}
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		return err
	}

	fields := entry.Auth.Fields()

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	m, err := parseMaterial(string(raw), fields)
	if err != nil {
		return fmt.Errorf("%w\n\n  this service needs %s. Either pipe one value per field as\n  `field=value` lines, or pipe a single value for a one-field service",
			err, strings.Join(fields, ", "))
	}
	if err := store.PutMaterial(name, m); err != nil {
		return err
	}
	fmt.Printf("  %s connected · %s\n", name, entry.Auth)
	fmt.Printf("  %d field(s) sealed in %s: %s\n", len(m), dir, strings.Join(m.Fields(), ", "))
	fmt.Printf("  never in %s\n", configPath())
	fmt.Printf("  %s\n", entry.Auth.Reassurance())
	return nil
}

// parseMaterial reads either `field=value` lines, or a single bare value for a
// service that needs exactly one field.
//
// A private key spans many lines, so a field's value continues until the next
// `field=` line — otherwise a PEM would have to be escaped, which is the sort of
// friction that gets worked around by pasting a key into a config file instead.
func parseMaterial(input string, fields []string) (credential.Material, error) {
	want := map[string]bool{}
	for _, f := range fields {
		want[f] = true
	}
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, fmt.Errorf("nothing was supplied on stdin")
	}
	if len(fields) == 1 && !strings.Contains(trimmed, "=") {
		return credential.Material{fields[0]: trimmed}, nil
	}

	m := credential.Material{}
	current := ""
	var buf []string
	flush := func() {
		if current != "" {
			m[current] = strings.TrimSpace(strings.Join(buf, "\n"))
		}
		buf = nil
	}
	for _, line := range strings.Split(input, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && want[strings.TrimSpace(k)] {
			flush()
			current = strings.TrimSpace(k)
			buf = []string{v}
			continue
		}
		if current != "" {
			buf = append(buf, line)
		}
	}
	flush()
	if err := m.Require(fields...); err != nil {
		return nil, err
	}
	return m, nil
}

// loadForRun opens everything the broker needs.
func loadForRun() (*policy.Config, *credential.Store, string, error) {
	cfg, err := policy.Load(configPath())
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w — run `stk init` first", err)
	}
	dir, err := home()
	if err != nil {
		return nil, nil, "", err
	}
	pass, _, err := credential.StoreKey(dir)
	if err != nil {
		return nil, nil, "", err
	}
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		return nil, nil, "", err
	}
	return cfg, store, dir, nil
}
