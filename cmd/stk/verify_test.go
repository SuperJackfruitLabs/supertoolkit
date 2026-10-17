package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
