package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func TestServeAllowUIDFlagParsing(t *testing.T) {
	o, err := parseServeArgs([]string{"--allow-uid", "501", "--allow-uid=0", "--proxy-listen", "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(o.allowUIDs, []int{501, 0}) || o.listen != "127.0.0.1:0" {
		t.Fatalf("parsed %+v", o)
	}
	for _, bad := range [][]string{
		{"--allow-uid", "abc"}, {"--allow-uid", "-1"}, {"--allow-uid", "1.5"},
		{"--allow-uid="}, {"--allow-uid"}, {"--allow-uid", ""},
	} {
		if _, err := parseServeArgs(bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

// A daemon-path effect is attributed to the kernel-reported caller.
func TestDaemonPathEffectRecordsTheCallerUID(t *testing.T) {
	rig(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	dir, _ := home()
	cfg, err := policy.Load(os.Getenv("STK_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(dir, "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put("github", "tok"); err != nil {
		t.Fatal(err)
	}
	svc, err := newService(cfg, store, dir, "serve")
	if err != nil {
		t.Fatal(err)
	}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer up.Close()

	do := func(ctx context.Context) {
		req, _ := http.NewRequestWithContext(ctx, "GET", up.URL+"/user", nil)
		resp, err := svc.perform(ctx, "github", req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	do(withCallerUID(context.Background(), 4242))
	do(context.Background())
	es := readAll(t, dir)
	if len(es) != 2 {
		t.Fatalf("%d entries, want 2", len(es))
	}
	if es[1].Caller != "uid:4242" {
		t.Errorf("daemon-path caller = %q, want uid:4242", es[1].Caller)
	}
	if !strings.HasPrefix(es[0].Caller, "serve") {
		t.Errorf("process-level caller = %q, want serve", es[0].Caller)
	}
}
