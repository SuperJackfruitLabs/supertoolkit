package notify

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	userCode   = "WDJB-MJHT"
	deviceCode = "dev-code-never-shown-to-anyone"
	credential = "gho_a_real_credential"
)

type recorder struct {
	name string
	got  atomic.Int64
	fail error
}

func (r *recorder) Name() string { return r.name }
func (r *recorder) Send(context.Context, Message) error {
	r.got.Add(1)
	return r.fail
}

func msg() Message {
	return Message{
		Title:   "github is waiting for you to approve a sign-in",
		Body:    "Enter the code, then come back here.",
		Code:    userCode,
		URL:     "https://github.com/login/device",
		Expires: time.Now().Add(15 * time.Minute),
	}
}

func TestEverySinkReceivesTheMessage(t *testing.T) {
	a, b := &recorder{name: "a"}, &recorder{name: "b"}
	n := &Notifier{Sinks: []Sink{a, b}}
	if err := n.Notify(context.Background(), msg()); err != nil {
		t.Fatal(err)
	}
	if a.got.Load() != 1 || b.got.Load() != 1 {
		t.Fatalf("sends = %d, %d; want one each", a.got.Load(), b.got.Load())
	}
}

// A webhook that is down should not cost someone the terminal line they were
// about to read.
func TestOneFailingSinkDoesNotStopTheOthers(t *testing.T) {
	bad := &recorder{name: "bad", fail: fmt.Errorf("endpoint is down")}
	good := &recorder{name: "good"}
	n := &Notifier{Sinks: []Sink{bad, good}}
	if err := n.Notify(context.Background(), msg()); err != nil {
		t.Fatalf("a single failing sink failed the whole send: %v", err)
	}
	if good.got.Load() != 1 {
		t.Fatal("the working sink did not receive the message")
	}
}

// But if nothing reached anyone, the caller must know, because it is about to
// wait for a person who was never told.
func TestAllSinksFailingIsReported(t *testing.T) {
	a := &recorder{name: "a", fail: fmt.Errorf("down")}
	b := &recorder{name: "b", fail: fmt.Errorf("down")}
	n := &Notifier{Sinks: []Sink{a, b}}
	err := n.Notify(context.Background(), msg())
	if err == nil {
		t.Fatal("every channel failed and the caller was not told")
	}
	if !strings.Contains(err.Error(), "no channel reached you") {
		t.Errorf("error = %q", err)
	}
}

// A user code is useless without the person approving it, so it may travel.
// A device code and a credential may not, and never reach this package.
func TestTheMessageCarriesTheUserCodeAndNothingDangerous(t *testing.T) {
	var buf bytes.Buffer
	term := Terminal{W: &buf}
	if err := term.Send(context.Background(), msg()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, userCode) {
		t.Error("the user code is missing, so nobody can approve anything")
	}
	if !strings.Contains(out, "github.com/login/device") {
		t.Error("the URL is missing, so nobody knows where to go")
	}
	for _, forbidden := range []string{deviceCode, credential} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("the notification carried %q", forbidden)
		}
	}
	if !strings.Contains(out, "expires in") {
		t.Error("the person is not told how long they have")
	}
}

func TestWebhookPostsTheMessage(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 2048)
		n, _ := r.Body.Read(b)
		got = string(b[:n])
	}))
	defer srv.Close()

	h := Webhook{URL: srv.URL, Client: srv.Client()}
	if err := h.Send(context.Background(), msg()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, userCode) {
		t.Errorf("the webhook body lacks the code: %s", got)
	}
	if strings.Contains(got, deviceCode) {
		t.Fatal("the webhook body carried the device code")
	}
}

func TestWebhookReportsARefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer srv.Close()
	h := Webhook{URL: srv.URL, Client: srv.Client()}
	if err := h.Send(context.Background(), msg()); err == nil {
		t.Fatal("a 500 was treated as delivered")
	}
}

func TestFileSinkAppendsAndIsOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notices.log")
	f := File{Path: p}
	if err := f.Send(context.Background(), msg()); err != nil {
		t.Fatal(err)
	}
	if err := f.Send(context.Background(), msg()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if n := strings.Count(string(raw), userCode); n != 2 {
		t.Fatalf("the file holds %d notices, want 2 appended", n)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", fi.Mode().Perm())
	}
}

func TestNoSinksIsNotAnError(t *testing.T) {
	n := &Notifier{}
	if err := n.Notify(context.Background(), msg()); err != nil {
		t.Fatalf("an unconfigured notifier failed: %v", err)
	}
}
