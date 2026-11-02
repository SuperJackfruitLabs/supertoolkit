package localstate

import (
	"os"
	"path/filepath"
)

// Home is where supertoolkit keeps local state: the CA, the salt, the sealed
// credentials. Never the config file, which belongs in the project and is
// committed.
func Home() (string, error) {
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

// ConfigPath is the committed policy file, looked for in the working directory.
func ConfigPath() string {
	if p := os.Getenv("STK_CONFIG"); p != "" {
		return p
	}
	return "supertoolkit.yaml"
}

// SocketPath is where the daemon listens.
func SocketPath(dir string) string {
	if p := os.Getenv("STK_SOCKET"); p != "" {
		return p
	}
	return filepath.Join(dir, "stk.sock")
}
