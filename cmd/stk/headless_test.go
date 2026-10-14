package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
)

// fakeProvider behaves the way a real one does: pending for a while, then a
// slow_down, then approval.
func fakeProvider(t *testing.T, token string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A one-second interval: the shortest a provider may honestly state,
		// and short enough that the test is not mostly waiting.
		fmt.Fprint(w, `{"device_code":"DEVICE-CODE-SECRET","user_code":"WXYZ-1234",
			"verification_uri":"https://example.invalid/device","interval":1,"expires_in":900}`)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch polls.Add(1) {
		case 1:
			fmt.Fprint(w, `{"error":"authorization_pending"}`)
		default:
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer","scope":"repo"}`, token)
		}
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s, &polls
}

// rig points stk's config and home at a temporary directory.
func rig(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "supertoolkit.yaml")
	if err := os.WriteFile(cfg, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STK_CONFIG", cfg)
	t.Setenv("STK_HOME", filepath.Join(dir, "home"))
	t.Setenv("STK_PASSPHRASE", "test-passphrase")
	return dir
}

func TestConnectDeviceStoresTheTokenAndNeverPrintsTheDeviceCode(t *testing.T) {
	const token = "gho_the_token_the_provider_issued"
	prov, polls := fakeProvider(t, token)
	rig(t, fmt.Sprintf(`workspace: test
services:
  github:
    scopes: []
    device:
      client_id: Iv1.testclientid
      authorization_url: %s/device/code
      token_url: %s/token
`, prov.URL, prov.URL))

	var out strings.Builder
	if err := connectDevice("github", &out); err != nil {
		t.Fatalf("connectDevice: %v", err)
	}
	text := out.String()

	// The token reached the store.
	dir, _ := home()
	pass, _, err := credential.StoreKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.Material("github")
	if err != nil {
		t.Fatalf("nothing was stored: %v", err)
	}
	if m.Token() != token {
		t.Errorf("stored %q, want the provider's token", m.Token())
	}

	// It polled more than once, so `authorization_pending` did not abort.
	if n := polls.Load(); n < 2 {
		t.Errorf("polled %d times; pending must not end the flow", n)
	}

	// The user code is shown — it is what the person types.
	if !strings.Contains(text, "WXYZ-1234") {
		t.Error("the user code was never shown; nobody can approve what they cannot read")
	}
	// The device code and the token are not. One is what a poll redeems, the
	// other is the credential itself.
	if strings.Contains(text, "DEVICE-CODE-SECRET") {
		t.Error("the device code was printed")
	}
	if strings.Contains(text, token) {
		t.Error("the credential was printed")
	}
	// What is about to happen is said before it happens.
	for _, want := range []string{"without a browser", "to this broker only"} {
		if !strings.Contains(text, want) {
			t.Errorf("the output never says %q:\n%s", want, text)
		}
	}
}

// Two different kinds of "no" need two different answers: a provider that does
// not offer the flow cannot be fixed by configuration, and a missing client id
// can.
func TestDeviceRefusalsSayWhichPieceIsMissing(t *testing.T) {
	rig(t, `workspace: test
services:
  github:
    scopes: []
`)
	err := connectDevice("github", &strings.Builder{})
	if err == nil {
		t.Fatal("connecting with no client id succeeded")
	}
	if !strings.Contains(err.Error(), "client_id") {
		t.Errorf("the error does not name the missing client id: %v", err)
	}

	rig(t, `workspace: test
services:
  aws-sts:
    scopes: []
`)
	err = connectDevice("aws-sts", &strings.Builder{})
	if err == nil {
		t.Fatal("connecting a provider with no device support succeeded")
	}
	if !strings.Contains(err.Error(), "does not offer") || !strings.Contains(err.Error(), "handover") {
		t.Errorf("the error does not offer the remaining paths: %v", err)
	}
}

func TestConnectDeviceNeedsTheServiceAdded(t *testing.T) {
	rig(t, "workspace: test\nservices: {}\n")
	err := connectDevice("github", &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "stk add") {
		t.Errorf("err = %v, want it to point at `stk add`", err)
	}
}

// A device endpoint pair that moves half-way would poll an address that never
// issued the code, and wait forever for an approval that cannot arrive.
func TestHalfOverriddenDeviceEndpointsAreRejected(t *testing.T) {
	rig(t, `workspace: test
services:
  github:
    scopes: []
    device:
      client_id: x
      token_url: https://example.invalid/token
`)
	if err := connectDevice("github", &strings.Builder{}); err == nil {
		t.Fatal("a half-overridden endpoint pair was accepted")
	} else if !strings.Contains(err.Error(), "authorization_url") {
		t.Errorf("err = %v, want it to name the missing endpoint", err)
	}
}
