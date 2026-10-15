package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
)

func connected(t *testing.T, service string, m credential.Material) *credential.Store {
	t.Helper()
	dir, _ := home()
	pass, _, _ := credential.StoreKey(dir)
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PutMaterial(service, m); err != nil {
		t.Fatal(err)
	}
	return store
}

// The word "revoke" promises the credential no longer works. Where we cannot
// keep that promise, the command must say so — somebody containing a leak
// would otherwise believe they had contained it.
func TestRevokeSaysWhenTheCredentialMayStillBeValid(t *testing.T) {
	rig(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	store := connected(t, "github", credential.Material{credential.FieldToken: "ghp_leaked"})

	out := captureStdout(t, func() {
		if err := cmdRevoke([]string{"github"}); err != nil {
			t.Fatal(err)
		}
	})

	if store.Has("github") {
		t.Error("the credential is still stored")
	}
	// GitHub's token deletion needs a client secret a device-flow app does not
	// have, so there is no way to revoke on the operator's behalf.
	for _, want := range []string{"forgotten here", "may still be valid", "github.com/settings/applications"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "ghp_leaked") {
		t.Error("the output contains the credential")
	}
}

// Where the provider does offer revocation, it must actually be called — and
// with the refresh token, because revoking only an access token leaves the
// grant alive and a new one a single exchange away.
func TestRevokeCallsTheProviderWithTheRefreshToken(t *testing.T) {
	var got atomic.Value
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		got.Store(r.PostForm.Encode())
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	// Point a catalogue entry at the test server.
	entry, _ := catalog.Lookup("x")
	original := entry.RevokeURL
	entry.RevokeURL = srv.URL
	t.Cleanup(func() { entry.RevokeURL = original })

	rig(t, "workspace: test\nservices:\n  x:\n    scopes: []\n")
	connected(t, "x", credential.Material{
		credential.FieldToken:        "access-token",
		credential.FieldRefreshToken: "refresh-token",
		credential.FieldClientID:     "client-id",
	})

	out := captureStdout(t, func() {
		if err := cmdRevoke([]string{"x"}); err != nil {
			t.Fatal(err)
		}
	})

	if calls.Load() != 1 {
		t.Fatalf("the provider was called %d times", calls.Load())
	}
	form := got.Load().(string)
	if !strings.Contains(form, "token=refresh-token") {
		t.Errorf("sent %q; revoking only the access token leaves the grant alive", form)
	}
	if !strings.Contains(form, "client_id=client-id") {
		t.Errorf("no client id sent: %q", form)
	}
	if !strings.Contains(out, "revoked at the provider") {
		t.Errorf("the output does not confirm the revocation:\n%s", out)
	}
	// Having revoked upstream, it must not also tell the operator to go and do
	// it themselves.
	if strings.Contains(out, "may still be valid") {
		t.Errorf("a successful revocation still warned the credential may be valid:\n%s", out)
	}
}

// A provider that refuses must not be reported as success, and the credential
// must still be forgotten here — one we failed to revoke upstream is one we
// especially do not want to keep.
func TestAFailedRevocationIsReportedAndStillForgotten(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":"unauthorized_client"}`)
	}))
	defer srv.Close()
	entry, _ := catalog.Lookup("x")
	original := entry.RevokeURL
	entry.RevokeURL = srv.URL
	t.Cleanup(func() { entry.RevokeURL = original })

	rig(t, "workspace: test\nservices:\n  x:\n    scopes: []\n")
	store := connected(t, "x", credential.Material{
		credential.FieldRefreshToken: "refresh-token", credential.FieldClientID: "c",
	})

	out := captureStdout(t, func() {
		if err := cmdRevoke([]string{"x"}); err != nil {
			t.Fatal(err)
		}
	})
	if store.Has("x") {
		t.Error("a credential we failed to revoke upstream was kept here")
	}
	if !strings.Contains(out, "NOT revoked at the provider") {
		t.Errorf("a refusal was not reported:\n%s", out)
	}
	if !strings.Contains(out, "unauthorized_client") {
		t.Errorf("the provider's reason was dropped:\n%s", out)
	}
	if !strings.Contains(out, "may still be valid") {
		t.Errorf("the operator was not told to finish the job:\n%s", out)
	}
}

// --local must not reach the provider at all.
func TestLocalOnlyNeverContactsTheProvider(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(200)
	}))
	defer srv.Close()
	entry, _ := catalog.Lookup("x")
	original := entry.RevokeURL
	entry.RevokeURL = srv.URL
	t.Cleanup(func() { entry.RevokeURL = original })

	rig(t, "workspace: test\nservices:\n  x:\n    scopes: []\n")
	connected(t, "x", credential.Material{credential.FieldRefreshToken: "r", credential.FieldClientID: "c"})

	out := captureStdout(t, func() {
		if err := cmdRevoke([]string{"x", "--local"}); err != nil {
			t.Fatal(err)
		}
	})
	if calls.Load() != 0 {
		t.Error("--local still contacted the provider")
	}
	if !strings.Contains(out, "because you asked for --local") {
		t.Errorf("the output does not say why nothing was sent:\n%s", out)
	}
	if !strings.Contains(out, "may still be valid") {
		t.Errorf("--local must still say the credential lives on:\n%s", out)
	}
}

// Revoking also drops the shared cached token, or another process would keep
// using a credential that has just been withdrawn.
func TestRevokeDropsTheCachedToken(t *testing.T) {
	rig(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	store := connected(t, "github", credential.Material{credential.FieldToken: "ghp_x"})
	if err := store.CacheToken("github", "cached-access", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := store.CachedToken("github", time.Minute); !ok {
		t.Fatal("the cache was not primed")
	}
	captureStdout(t, func() {
		if err := cmdRevoke([]string{"github"}); err != nil {
			t.Fatal(err)
		}
	})
	if _, _, ok := store.CachedToken("github", time.Minute); ok {
		t.Fatal("the cached token survived revocation; another process would keep using it")
	}
}

func TestRevokingSomethingNotConnectedSaysSo(t *testing.T) {
	rig(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	err := cmdRevoke([]string{"github"})
	if err == nil || !strings.Contains(err.Error(), "nothing to withdraw") {
		t.Errorf("err = %v", err)
	}
}

// captureStdout runs f with os.Stdout redirected, so a command that prints can
// be asserted on without changing its signature.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var b strings.Builder
		io.Copy(&b, r)
		done <- b.String()
	}()
	f()
	w.Close()
	os.Stdout = old
	return <-done
}
