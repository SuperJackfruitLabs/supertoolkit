package main

import (
	"os"
	"path/filepath"
)

// home is where supertoolkit keeps local state: the CA, the salt, the sealed
// credentials. Never the config file, which belongs in the project and is
// committed.
func home() (string, error) {
	if d := os.Getenv("STK_HOME"); d != "" {
		return d, os.MkdirAll(d, 0o700)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(base, "supertoolkit")
	return d, os.MkdirAll(d, 0o700)
}

// configPath is the committed policy file, looked for in the working directory.
func configPath() string {
	if p := os.Getenv("STK_CONFIG"); p != "" {
		return p
	}
	return "supertoolkit.yaml"
}

// socketPath is where the daemon listens.
func socketPath(dir string) string {
	if p := os.Getenv("STK_SOCKET"); p != "" {
		return p
	}
	return filepath.Join(dir, "stk.sock")
}
