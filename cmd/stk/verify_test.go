package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/verify"
)

const verifyToken = "ZZ-verify-token-ZZ"

// verifyAgainst connects a forge service and points verify at a fake provider.
func verifyAgainst(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	forgeEnv(t)
	withStdin(t, verifyToken+"\n", func() { _ = cmdConnect([]string{"forge-main"}) })
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	verifyHTTP, verifyBaseURL = s.Client(), s.URL
	t.Cleanup(func() { verifyHTTP, verifyBaseURL = nil, "" })
}

func TestVerifyCommandJSONOnSuccess(t *testing.T) {
	verifyAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+verifyToken {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"login":"chotu"}`))
	})
	var err error
	out := withStdin(t, "", func() { err = cmdVerify([]string{"forge-main", "--json"}) })
	if err != nil {
		t.Fatalf("cmdVerify() error = %v", err)
	}
	var res verify.Result
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil {
		t.Fatalf("stdout is not JSON: %q", out)
	}
	if !res.OK || res.Login != "chotu" {
		t.Errorf("Result = %+v", res)
	}
}

func TestVerifyCommandFailsWithReasonAndNeverPrintsToken(t *testing.T) {
	verifyAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("bad: " + r.Header.Get("Authorization")))
	})
	var err error
	out := withStdin(t, "", func() { err = cmdVerify([]string{"forge-main", "--json"}) })
	if err == nil || !strings.Contains(err.Error(), verify.ReasonUnauthorized) {
		t.Errorf("error = %v, want a failure naming %q", err, verify.ReasonUnauthorized)
	}
	if strings.Contains(out, verifyToken) || (err != nil && strings.Contains(err.Error(), verifyToken)) {
		t.Errorf("the token leaked: out=%q err=%v", out, err)
	}
	var res verify.Result
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil || res.OK || res.Reason != verify.ReasonUnauthorized {
		t.Errorf("stdout = %q, want JSON with reason unauthorized", out)
	}
}

func TestVerifyCommandExpectLogin(t *testing.T) {
	verifyAgainst(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"login":"chotu"}`)) })
	var err error
	withStdin(t, "", func() { err = cmdVerify([]string{"forge-main", "--expect-login", "other"}) })
	if err == nil || !strings.Contains(err.Error(), verify.ReasonWrongIdentity) {
		t.Errorf("error = %v, want wrong-identity", err)
	}
}

func TestVerifyCommandNeedsAConnectedCredential(t *testing.T) {
	forgeEnv(t)
	var err error
	withStdin(t, "", func() { err = cmdVerify([]string{"forge-main"}) })
	if err == nil {
		t.Error("verify succeeded with nothing connected")
	}
}

func TestVerifyCommandUsage(t *testing.T) {
	if err := cmdVerify(nil); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("error = %v, want usage", err)
	}
}

// ---- GitHub App grants, through the production wiring ----

const (
	verifyAppConfig = "services:\n  ghe-app:\n    kind: forge\n    provider: github\n" +
		"    host: example.com\n    auth: app\n    env_var: GH_TOKEN\n    repositories: [Corp/r, Corp/s]\n"
	verifyAppInstToken = "ghs_verify_installation_ZZ"
)

// verifyAppEnv stores an App's material and returns a fake GitHub Enterprise
// at example.com serving the exchange, /app and /installation/repositories,
// plus the private key PEM and the JWTs the fake saw.
func verifyAppEnv(t *testing.T, installed []string) (key string, jwts *[]string) {
	t.Helper()
	home := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	if err := os.WriteFile(cfgPath, []byte(verifyAppConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STK_HOME", home)
	t.Setenv("STK_CONFIG", cfgPath)
	t.Setenv("STK_PASSPHRASE", "test-passphrase")
	store := openTestStore(t, home)
	key = testAppKeyPEM(t)
	if err := store.PutMaterial("ghe-app", credential.Material{
		credential.FieldAppID: "4242", credential.FieldPrivateKey: key, credential.FieldInstallationID: "987",
	}); err != nil {
		t.Fatal(err)
	}
	seen := &[]string{}
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v3/app/installations/987/access_tokens":
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]any{"token": verifyAppInstToken, "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
		case r.URL.Path == "/api/v3/app":
			*seen = append(*seen, auth)
			if strings.Count(auth, ".") != 2 {
				w.WriteHeader(401)
				return
			}
			w.Write([]byte(`{"slug":"my-app"}`))
		case r.URL.Path == "/api/v3/installation/repositories":
			if auth != verifyAppInstToken {
				w.WriteHeader(401)
				return
			}
			var repos []map[string]string
			for _, n := range installed {
				repos = append(repos, map[string]string{"full_name": n})
			}
			json.NewEncoder(w).Encode(map[string]any{"repositories": repos})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	verifyHTTP = &http.Client{Transport: tr}
	t.Cleanup(func() { verifyHTTP, verifyBaseURL = nil, "" })
	return key, seen
}

func TestVerifyAppCommandPrintsOnlyOKLoginReason(t *testing.T) {
	key, jwts := verifyAppEnv(t, []string{"Corp/r", "Corp/s", "Corp/other"})
	var logs bytes.Buffer
	log.SetOutput(&logs) // process-global: no t.Parallel
	defer log.SetOutput(os.Stderr)
	var err error
	out := withStdin(t, "", func() { err = cmdVerify([]string{"ghe-app", "--json", "--expect-login", "my-app[bot]"}) })
	if err != nil {
		t.Fatalf("cmdVerify() error = %v", err)
	}
	var raw map[string]any
	if jerr := json.Unmarshal([]byte(out), &raw); jerr != nil {
		t.Fatalf("stdout is not JSON: %q", out)
	}
	if len(raw) != 2 || raw["ok"] != true || raw["login"] != "my-app[bot]" {
		t.Errorf("output = %v, want exactly {ok:true, login:my-app[bot]}", raw)
	}
	if len(*jwts) != 1 {
		t.Fatalf("JWTs seen = %d, want 1", len(*jwts))
	}
	// Nothing printed, logged or left on disk in the clear holds a secret.
	body := out + logs.String()
	filepath.Walk(os.Getenv("STK_HOME"), func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			body += string(b)
		}
		return nil
	})
	for name, secret := range map[string]string{"installation token": verifyAppInstToken, "jwt": (*jwts)[0], "private key": "PRIVATE KEY", "key body": strings.Split(key, "\n")[1]} {
		if strings.Contains(body, secret) {
			t.Errorf("%s appears in output, logs or the home directory", name)
		}
	}
}

func TestVerifyAppCommandRepositoryMissing(t *testing.T) {
	verifyAppEnv(t, []string{"Corp/r"})
	var err error
	out := withStdin(t, "", func() { err = cmdVerify([]string{"ghe-app", "--json"}) })
	if err == nil || !strings.Contains(err.Error(), verify.ReasonRepositoryMissing) {
		t.Errorf("error = %v, want %q", err, verify.ReasonRepositoryMissing)
	}
	var res verify.Result
	json.Unmarshal([]byte(out), &res)
	if res.OK || res.Reason != verify.ReasonRepositoryMissing || res.Login != "my-app[bot]" {
		t.Errorf("Result = %+v (%q)", res, out)
	}
	if strings.Contains(out, "Corp/") || strings.Contains(err.Error(), "Corp/") {
		t.Error("the output names a repository")
	}
}
