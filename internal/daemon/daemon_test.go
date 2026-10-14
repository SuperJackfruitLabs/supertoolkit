package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func serve(t *testing.T, h Handler) *Server {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "stk.sock")
	s, err := Listen(sock, h)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSocketIsOwnerOnly(t *testing.T) {
	s := serve(t, func(int, Request) Response { return Response{} })
	fi, err := os.Stat(s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode = %o, want 600 — another OS user could open it", perm)
	}
}

func TestRequestRoundTrips(t *testing.T) {
	s := serve(t, func(uid int, r Request) Response {
		out, _ := json.Marshal(map[string]any{"method": r.Method, "profile": r.Profile})
		return Response{Result: out}
	})
	c, err := Dial(s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Call(Request{Method: "status", Profile: "writer"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	json.Unmarshal(resp.Result, &got)
	if got["method"] != "status" || got["profile"] != "writer" {
		t.Fatalf("round trip = %v, want the method and profile preserved", got)
	}
}

// The kernel's answer, not the caller's claim.
func TestPeerUIDIsTheKernelsAnswer(t *testing.T) {
	seen := make(chan int, 1)
	s := serve(t, func(uid int, r Request) Response {
		seen <- uid
		return Response{}
	})
	c, err := Dial(s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Call(Request{Method: "status"}); err != nil {
		t.Fatal(err)
	}
	got := <-seen
	if got != os.Getuid() {
		t.Fatalf("PeerUID = %d, want this process's uid %d", got, os.Getuid())
	}
}

// The invariant, enforced by making a violation break the build's tests.
// Adding a method that hands back a credential should be hard to do quietly.
func TestNoMethodReturnsACredential(t *testing.T) {
	banned := []string{"secret", "credential", "token", "password", "key", "reveal", "export", "dump"}
	for _, m := range Methods {
		lower := strings.ToLower(m)
		for _, b := range banned {
			if strings.Contains(lower, b) {
				t.Errorf("control-plane method %q looks like it returns a credential; nothing here may", m)
			}
		}
	}
	// And the set is closed: four meta-tools plus approvals plus status.
	if len(Methods) != 7 {
		t.Errorf("Methods has %d entries, want 7 — a new method needs a deliberate review, not a silent addition", len(Methods))
	}
}

// A daemon that will not start after a crash makes the operator debug a file.
func TestStaleSocketIsReplaced(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "stk.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Listen(sock, func(int, Request) Response { return Response{} })
	if err != nil {
		t.Fatalf("Listen() over a stale socket failed: %v", err)
	}
	s.Close()
}

// But a live daemon must not be displaced by a second one.
func TestSecondDaemonIsRefused(t *testing.T) {
	s := serve(t, func(int, Request) Response { return Response{} })
	if _, err := Listen(s.Addr(), func(int, Request) Response { return Response{} }); err == nil {
		t.Fatal("a second Listen() on a live socket succeeded; it must refuse")
	}
}

func TestCloseRemovesTheSocket(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "stk.sock")
	s, err := Listen(sock, func(int, Request) Response { return Response{} })
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	s.Close()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket still present after Close(): %v", err)
	}
}
