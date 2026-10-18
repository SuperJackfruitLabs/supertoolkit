package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// listenerRig is a state dir holding a proxy.key and a proxy.addr pointing at
// whatever the test puts there, so `stk env` has to decide whether to trust it.
func listenerRig(t *testing.T) (dir, key string) {
	t.Helper()
	rig(t, envConfig)
	dir, _ = home()
	key, err := loadOrCreateProxyKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, key
}

func expectRefused(t *testing.T, dir, key string) {
	t.Helper()
	var out, errb bytes.Buffer
	err := runEnv(&out, &errb, []string{"--json"})
	if err == nil || !strings.Contains(err.Error(), "is not a running stk proxy") {
		t.Fatalf("err = %v, want a refusal naming that it is not a running stk proxy", err)
	}
	if strings.Contains(out.String()+errb.String()+err.Error(), key) || out.Len() != 0 {
		t.Fatalf("the key (or anything) was printed to a listener that is not stk: %q", out.String())
	}
}

func serveHandler(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

func TestEnvRefusesASilentListener(t *testing.T) {
	dir, key := listenerRig(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	writeProxyAddr(dir, ln.Addr().String())
	expectRefused(t, dir, key)
}

func TestEnvRefusesAListenerThatAnswers200(t *testing.T) {
	dir, key := listenerRig(t)
	addr := serveHandler(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	writeProxyAddr(dir, addr)
	expectRefused(t, dir, key)
}

func TestEnvRefusesA407WithAnotherRealm(t *testing.T) {
	dir, key := listenerRig(t)
	addr := serveHandler(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="squid"`)
		w.WriteHeader(407)
	})
	writeProxyAddr(dir, addr)
	expectRefused(t, dir, key)
}

func TestEnvRefusesADeadPIDEvenWithALive407Listener(t *testing.T) {
	dir, key := listenerRig(t)
	sess := liveBroker(t, dir, key)
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	writeProxyAddrPID(dir, sess.addr, cmd.Process.Pid) // exited and reaped
	expectRefused(t, dir, key)
}

func TestEnvAcceptsTheGenuineBroker(t *testing.T) {
	dir, key := listenerRig(t)
	sess := liveBroker(t, dir, key)
	writeProxyAddr(dir, sess.addr)
	var out, errb bytes.Buffer
	if err := runEnv(&out, &errb, []string{"--json"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), key) {
		t.Fatal("env did not print the keyed proxy URL for a genuine broker")
	}
}

func TestEnvDoesNotMintAKeyWhenTheFileIsMissing(t *testing.T) {
	dir, key := listenerRig(t)
	sess := liveBroker(t, dir, key)
	writeProxyAddr(dir, sess.addr)
	os.Remove(filepath.Join(dir, "proxy.key"))
	var out, errb bytes.Buffer
	err := runEnv(&out, &errb, []string{"--json"})
	if err == nil || !strings.Contains(err.Error(), "proxy.key") {
		t.Fatalf("err = %v, want one naming the missing proxy.key", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "proxy.key")); serr == nil {
		t.Fatal("env created a proxy.key the running broker does not know")
	}
}

func TestEnvRejectsAnAddressOnlyProxyAddrFile(t *testing.T) {
	dir, key := listenerRig(t)
	sess := liveBroker(t, dir, key)
	// The pre-pid format: a genuine, live broker, but no owner recorded.
	os.WriteFile(filepath.Join(dir, "proxy.addr"), []byte(sess.addr+"\n"), 0o600)
	var out, errb bytes.Buffer
	err := runEnv(&out, &errb, []string{"--json"})
	if err == nil || !strings.Contains(err.Error(), "not a running stk proxy") || out.Len() != 0 {
		t.Fatalf("err = %v, out %q; want a refusal and no output", err, out.String())
	}
}
