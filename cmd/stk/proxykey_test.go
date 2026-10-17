package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyKeyFileIsCreated0600AndReused(t *testing.T) {
	dir := t.TempDir()
	k1, err := loadOrCreateProxyKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(k1)
	if err != nil || len(raw) != 32 {
		t.Fatalf("key %q is not 32 bytes of unpadded base64url (err %v, len %d)", k1, err, len(raw))
	}
	fi, err := os.Stat(filepath.Join(dir, "proxy.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("proxy.key mode = %v, want 0600", fi.Mode().Perm())
	}
	k2, err := loadOrCreateProxyKey(dir)
	if err != nil || k2 != k1 {
		t.Fatalf("second load = %q, %v; want the same key %q", k2, err, k1)
	}
	other, _ := loadOrCreateProxyKey(t.TempDir())
	if other == k1 {
		t.Fatal("two installs produced the same key")
	}
}

func TestProxyKeyRefusesWideMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		dir := t.TempDir()
		p := filepath.Join(dir, "proxy.key")
		if err := os.WriteFile(p, []byte("existing-key-value"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		k, err := loadOrCreateProxyKey(dir)
		if err == nil || k != "" {
			t.Fatalf("mode %v: got key %q err %v, want a refusal", mode, k, err)
		}
		if strings.Contains(err.Error(), "existing-key-value") {
			t.Fatalf("the refusal leaks the key: %v", err)
		}
	}
}

func TestServeProxyListenRejectsNonLoopback(t *testing.T) {
	for _, a := range []string{"0.0.0.0:8080", "192.168.1.5:8080", "10.0.0.1:1", "[::]:8080", "example.com:8080", ":8080", "8.8.8.8:53", "127.0.0.1", "127.0.0.1:notaport"} {
		if _, err := parseProxyListen(a); err == nil {
			t.Errorf("parseProxyListen(%q) accepted, want an error", a)
		}
	}
	for _, a := range []string{"127.0.0.1:18080", "127.1.2.3:9", "[::1]:18080", "localhost:18080"} {
		if _, err := parseProxyListen(a); err != nil {
			t.Errorf("parseProxyListen(%q) = %v, want accepted", a, err)
		}
	}
	rig(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	err := cmdServe([]string{"--proxy-listen", "0.0.0.0:8080"})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("cmdServe err = %v, want one naming loopback", err)
	}
}
