package managedmcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedProcessProbe(t *testing.T) {
	root := os.Getenv("STK_MANAGED_PROBE_ROOT")
	if root == "" {
		return
	}
	l, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	mode := os.Getenv("STK_MANAGED_PROBE_MODE")
	_, err = l.Execute(context.Background(), os.Getenv("STK_MANAGED_PROBE_ID"), os.Getenv("STK_MANAGED_PROBE_DIGEST"), func(context.Context, Request) error {
		if mode == "before-send" {
			fmt.Println("admission-claimed")
			for {
				time.Sleep(time.Hour)
			}
		}
		return nil
	}, func(ctx context.Context, _ Request) (string, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", os.Getenv("STK_MANAGED_PROBE_URL"), strings.NewReader(`{"effect":"fixture"}`))
		if err != nil {
			return "", err
		}
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return string(body), err
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("result-stored")
	for {
		time.Sleep(time.Hour)
	}
}

func TestRealBrokerOwnerDeathNeverReplaysTheInvocation(t *testing.T) {
	for _, mode := range []string{"before-send", "after-acceptance", "after-result"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			l := open(t, dir)
			r := request()
			r.Approval = false
			v := prepare(t, l, r)
			var calls atomic.Int32
			accepted := make(chan struct{}, 1)
			closed, release := make(chan struct{}), make(chan struct{})
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				_, _ = io.Copy(io.Discard, req.Body)
				calls.Add(1)
				accepted <- struct{}{}
				if mode == "after-acceptance" {
					select {
					case <-req.Context().Done():
						close(closed)
					case <-release:
					}
					return
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"protocol_result":"returned"}`)
			}))
			defer up.Close()
			defer close(release)
			cmd := exec.Command(os.Args[0], "-test.run=^TestManagedProcessProbe$")
			cmd.Env = []string{"STK_MANAGED_PROBE_ROOT=" + dir, "STK_MANAGED_PROBE_MODE=" + mode, "STK_MANAGED_PROBE_ID=" + v.ID, "STK_MANAGED_PROBE_DIGEST=" + v.RequestDigest, "STK_MANAGED_PROBE_URL=" + up.URL}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			ready := make(chan error, 1)
			go func() {
				if mode == "after-acceptance" {
					<-accepted
					ready <- nil
					return
				}
				line, err := bufio.NewReader(stdout).ReadString('\n')
				if err == nil {
					want := "admission-claimed\n"
					if mode == "after-result" {
						want = "result-stored\n"
					}
					if line != want {
						err = fmt.Errorf("unexpected child barrier")
					}
				}
				ready <- err
			}()
			select {
			case err := <-ready:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("child did not reach its durable barrier")
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			if cmd.ProcessState == nil {
				t.Fatal("old process was not reaped")
			}
			if mode == "after-acceptance" {
				select {
				case <-closed:
				case <-time.After(3 * time.Second):
					t.Fatal("old process HTTP connection did not close")
				}
			}
			reopened := open(t, dir)
			fenced, err := reopened.FenceInterrupted(v.ID, v.RequestDigest)
			if err != nil {
				t.Fatal(err)
			}
			wantState := OutcomeUnknown
			wantCalls := int32(1)
			if mode == "before-send" {
				wantCalls = 0
			}
			if mode == "after-result" {
				wantState = Returned
			}
			if fenced.State != wantState || calls.Load() != wantCalls {
				t.Fatal("death lost the recorded handoff/result boundary")
			}
			saved, err := reopened.Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { t.Error("recovery requested another grant"); return nil }, func(context.Context, Request) (string, error) {
				t.Error("recovery replayed an effect")
				return `{}`, nil
			})
			if err != nil || saved != fenced || calls.Load() != wantCalls {
				t.Fatal("recovery changed the original invocation")
			}
		})
	}
}
