package daemon

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

func serveWith(t *testing.T, h Handler, o Options) *Server {
	t.Helper()
	// Short path: unix socket names are limited to ~104 bytes on macOS.
	dir, err := os.MkdirTemp("", "d")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	s, err := ListenWith(sock, h, o)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() { s.Close() })
	return s
}

func fakeUID(uid int, err error) func(net.Conn) (int, error) {
	return func(net.Conn) (int, error) { return uid, err }
}

func TestDaemonRefusesAnUnlistedUID(t *testing.T) {
	var calls atomic.Int32
	s := serveWith(t, func(int, Request) Response { calls.Add(1); return Response{} },
		Options{AllowUIDs: []int{501}, PeerUID: fakeUID(4242, nil)})
	c, err := Dial(s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Call(Request{Method: "status"})
	if err == nil {
		t.Fatalf("an unlisted uid got an answer: %+v", resp)
	}
	if resp.Error != "" || len(resp.Result) != 0 {
		t.Fatalf("the refusal leaked a body: %+v", resp)
	}
	if calls.Load() != 0 {
		t.Fatal("the handler ran for an unlisted uid")
	}
}

func TestDaemonAcceptsAListedUID(t *testing.T) {
	s := serveWith(t, func(int, Request) Response { return Response{Error: "ok"} },
		Options{AllowUIDs: []int{7, 4242}, PeerUID: fakeUID(4242, nil)})
	c, _ := Dial(s.Addr())
	defer c.Close()
	resp, err := c.Call(Request{Method: "status"})
	if err != nil || resp.Error != "ok" {
		t.Fatalf("listed uid: resp=%+v err=%v", resp, err)
	}
}

func TestEmptyAllowListKeepsOldBehaviour(t *testing.T) {
	s := serveWith(t, func(int, Request) Response { return Response{Error: "ok"} },
		Options{PeerUID: fakeUID(4242, nil)})
	c, _ := Dial(s.Addr())
	defer c.Close()
	resp, err := c.Call(Request{Method: "status"})
	if err != nil || resp.Error != "ok" {
		t.Fatalf("empty list: resp=%+v err=%v", resp, err)
	}
}

func TestHandleReceivesTheUID(t *testing.T) {
	seen := make(chan int, 1)
	s := serveWith(t, func(uid int, r Request) Response { seen <- uid; return Response{} },
		Options{AllowUIDs: []int{4242}, PeerUID: fakeUID(4242, nil)})
	c, _ := Dial(s.Addr())
	defer c.Close()
	if _, err := c.Call(Request{Method: "status"}); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != 4242 {
		t.Fatalf("handler saw uid %d, want 4242", got)
	}
}

// Failing to learn who is calling must never become permission to call.
func TestPeerUIDErrorRefuses(t *testing.T) {
	var calls atomic.Int32
	s := serveWith(t, func(int, Request) Response { calls.Add(1); return Response{} },
		Options{AllowUIDs: []int{501}, PeerUID: fakeUID(501, errors.New("no creds"))})
	c, _ := Dial(s.Addr())
	defer c.Close()
	if _, err := c.Call(Request{Method: "status"}); err == nil {
		t.Fatal("a caller whose uid could not be read got an answer")
	}
	if calls.Load() != 0 {
		t.Fatal("the handler ran although the uid was unknown")
	}
}
