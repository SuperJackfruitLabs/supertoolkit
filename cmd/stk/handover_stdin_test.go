package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sealToken = "ZZ-seal-token-ZZ"

func publicKey(t *testing.T) string {
	t.Helper()
	var err error
	out := withStdin(t, "", func() { err = cmdHandover([]string{"key", "--json"}) })
	if err != nil {
		t.Fatalf("handover key --json: %v", err)
	}
	var k struct {
		PublicKey string `json:"public_key"`
	}
	if jerr := json.Unmarshal([]byte(out), &k); jerr != nil || !strings.HasPrefix(k.PublicKey, "stk-handover-v1:") {
		t.Fatalf("stdout = %q, want JSON with a public_key", out)
	}
	return k.PublicKey
}

func TestHandoverKeyJSON(t *testing.T) {
	forgeEnv(t)
	if k := publicKey(t); k == "" {
		t.Error("empty key")
	}
}

func TestSealFromStdinRoundTrip(t *testing.T) {
	home := forgeEnv(t)
	key := publicKey(t)
	var err error
	env := withStdin(t, sealToken+"\n", func() {
		err = cmdHandover([]string{"seal", "forge-main", "--to", key, "--stdin"})
	})
	if err != nil {
		t.Fatalf("seal --stdin: %v", err)
	}
	env = strings.TrimSpace(env)
	if !strings.HasPrefix(env, "stk-handover-v1:") || strings.Contains(env, sealToken) {
		t.Fatalf("seal output = %q, want an envelope with no plaintext", env)
	}
	out := withStdin(t, env+"\n", func() {
		err = cmdHandover([]string{"open", "forge-main", "--json"})
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var res struct {
		Service string `json:"service"`
		Stored  bool   `json:"stored"`
	}
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil || res.Service != "forge-main" || !res.Stored {
		t.Errorf("open --json stdout = %q", out)
	}
	if strings.Contains(out, sealToken) {
		t.Error("open printed the token")
	}
	got, err := openTestStore(t, home).Get("forge-main")
	if err != nil || got != sealToken {
		t.Errorf("stored credential = %q, %v", got, err)
	}
}

// The machine that seals need not run a broker, and has no business creating a
// credential store or a broker key just to produce an envelope.
func TestSealFromStdinNeedsNoLocalStore(t *testing.T) {
	forgeEnv(t)
	key := publicKey(t)
	sealHome := t.TempDir()
	t.Setenv("STK_HOME", sealHome)
	t.Setenv("STK_PASSPHRASE", "")
	var err error
	withStdin(t, sealToken+"\n", func() {
		err = cmdHandover([]string{"seal", "forge-main", "--to", key, "--stdin"})
	})
	if err != nil {
		t.Fatalf("seal --stdin: %v", err)
	}
	for _, name := range []string{"salt", "handover.key", "forge-main.cred"} {
		if _, serr := os.Stat(filepath.Join(sealHome, name)); serr == nil {
			t.Errorf("sealing created %s on the sealing machine", name)
		}
	}
}

func TestSealFromStdinRejectsAnEmptyCredential(t *testing.T) {
	forgeEnv(t)
	key := publicKey(t)
	var err error
	withStdin(t, "\n", func() {
		err = cmdHandover([]string{"seal", "forge-main", "--to", key, "--stdin"})
	})
	if err == nil {
		t.Error("sealed an empty credential")
	}
}
