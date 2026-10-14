package main

import (
	"fmt"
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
	ca, err := broker.NewCA("supertoolkit local CA", 365*24*time.Hour)
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
			return fmt.Errorf("unknown service %q: known services are %s", name, knownServices())
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
func cmdConnect(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: stk connect <service>   (the credential is read from stdin)")
	}
	name := args[0]
	if _, ok := catalog.Lookup(name); !ok {
		return fmt.Errorf("unknown service %q: known services are %s", name, knownServices())
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

	fi, _ := os.Stdin.Stat()
	if fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprintln(os.Stderr, "  reading the credential from stdin; paste it and press ctrl-D")
	}
	buf := make([]byte, 8192)
	n, _ := os.Stdin.Read(buf)
	secret := strings.TrimSpace(string(buf[:n]))
	if secret == "" {
		return fmt.Errorf("no credential on stdin")
	}
	if err := store.Put(name, secret); err != nil {
		return err
	}
	fmt.Printf("  %s connected · credential sealed in %s · never in %s\n", name, dir, configPath())
	return nil
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
