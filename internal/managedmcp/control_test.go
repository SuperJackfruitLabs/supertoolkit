package managedmcp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func controlFixture(t *testing.T, reply func(Control) ControlReply) (*ControlAdmission, *Ledger, Request, *atomic.Int32) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "stk-control-")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ = filepath.EvalSymlinks(dir)
	t.Cleanup(func() { os.RemoveAll(dir) })
	for _, sub := range []string{"workspace", "state"} {
		if err = os.Mkdir(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	r := request()
	socket := filepath.Join(dir, "owner.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("e", 64)
	calls := new(atomic.Int32)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" || req.URL.Path != "/managed-toolkit/v1/control" || req.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(403)
			return
		}
		var c Control
		if json.NewDecoder(req.Body).Decode(&c) != nil {
			w.WriteHeader(400)
			return
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(reply(c))
	})}
	go server.Serve(l)
	t.Cleanup(func() { server.Close() })
	m := ControlManifest{Version: 1, RootDigest: r.RootDigest, ProfileDigest: r.ProfileDigest, Workspace: filepath.Join(dir, "workspace"), StateDir: filepath.Join(dir, "state"), OwnerSocket: socket, OwnerKey: key}
	body, _ := json.Marshal(m)
	path := filepath.Join(dir, "control.json")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := AdmitControl(path, byteDigest(body))
	if err != nil {
		t.Fatal(err)
	}
	ledger := open(t, m.StateDir)
	return a, ledger, r, calls
}

func allowControl(c Control) ControlReply {
	return ControlReply{Version: 1, ControlDigest: ControlFingerprint(c), Decision: "allowed"}
}
func invocationControl(r Request, action string) Control {
	return Control{Version: 1, Action: action, RootDigest: r.RootDigest, ProfileDigest: r.ProfileDigest, InvocationID: r.InvocationID, RequestDigest: RequestFingerprint(r), StopProofDigest: strings.Repeat("c", 64)}
}

func TestControlRequiresExclusiveBrokerOwnershipAndFreshExactOwner(t *testing.T) {
	a, ledger, r, calls := controlFixture(t, allowControl)
	v := prepare(t, ledger, r)
	c := invocationControl(r, "inspect")
	release, err := OwnProcess(a.Manifest.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Apply(context.Background(), c); err == nil {
		t.Fatal("live broker was treated as stopped")
	}
	if calls.Load() != 0 {
		t.Fatal("owner invoked before exclusive process ownership")
	}
	release()
	out, err := a.Apply(context.Background(), c)
	if err != nil || out.Receipt == nil || *out.Receipt != v || calls.Load() != 1 {
		t.Fatal("saved receipt unavailable after explicit owner check", err)
	}
	c.RootDigest = strings.Repeat("f", 64)
	if _, err = a.Apply(context.Background(), c); err == nil || calls.Load() != 1 {
		t.Fatal("foreign root reached owner")
	}
	c = invocationControl(r, "inspect")
	c.StopProofDigest = ""
	if _, err = a.Apply(context.Background(), c); err == nil || calls.Load() != 1 {
		t.Fatal("missing predecessor stop proof reached owner")
	}
}

func TestControlAcknowledgementIsExactDurableNonSuccessAndNeverReplays(t *testing.T) {
	a, l, r, _ := controlFixture(t, allowControl)
	r.Approval = false
	v := prepare(t, l, r)
	_, err := l.Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { return nil }, func(context.Context, Request) (string, error) { return "", refused() })
	if err != nil {
		t.Fatal(err)
	}
	ack := invocationControl(r, "acknowledge")
	ack.DecisionID = "resolution-1"
	out, err := a.Apply(context.Background(), ack)
	if err != nil || out.Receipt == nil || out.Receipt.State != OutcomeAcknowledged || out.Receipt.ResolutionID != "resolution-1" || out.Receipt.Result != "" {
		t.Fatal("unknown acknowledgement fabricated success", out, err)
	}
	// The original uncertain invocation is permanently terminal, even after reopen.
	l = open(t, a.Manifest.StateDir)
	var dispatched atomic.Int32
	got, err := l.Execute(context.Background(), v.ID, v.RequestDigest, func(context.Context, Request) error { dispatched.Add(1); return nil }, func(context.Context, Request) (string, error) { dispatched.Add(1); return "success", nil })
	if err != nil || got.State != OutcomeAcknowledged || dispatched.Load() != 0 {
		t.Fatal("acknowledged effect replayed", err)
	}
	if _, err = a.Apply(context.Background(), ack); err != nil {
		t.Fatal("same resolution not idempotent", err)
	}
	ack.DecisionID = "another-resolution"
	if _, err = a.Apply(context.Background(), ack); err == nil {
		t.Fatal("resolution binding changed")
	}
	next := r
	next.InvocationID = "next-owned-call"
	n := prepare(t, l, next)
	_, err = l.Execute(context.Background(), n.ID, n.RequestDigest, func(context.Context, Request) error { return nil }, func(context.Context, Request) (string, error) { dispatched.Add(1); return "protocol-only", nil })
	if err != nil || dispatched.Load() != 1 {
		t.Fatal("explicit resolution did not settle root fence", err)
	}
}

func TestControlDenialDriftAndWrongReplyCannotMutateJournal(t *testing.T) {
	for _, bad := range []string{"denied", "digest", "decision", "version", "drift", "foreign-record", "record-profile"} {
		t.Run(bad, func(t *testing.T) {
			a, l, r, _ := controlFixture(t, func(c Control) ControlReply {
				out := allowControl(c)
				switch bad {
				case "denied":
					out.Decision = "denied"
				case "digest":
					out.ControlDigest = strings.Repeat("f", 64)
				case "decision":
					out.Decision = "pending"
				case "version":
					out.Version = 2
				}
				return out
			})
			v := prepare(t, l, r)
			if bad == "record-profile" {
				if err := l.locked(func() error {
					record, err := l.read(v.ID)
					if err != nil {
						return err
					}
					record.Request.ProfileDigest = strings.Repeat("f", 64)
					record.Receipt.RequestDigest = RequestFingerprint(record.Request)
					return l.save(record)
				}); err != nil {
					t.Fatal(err)
				}
			}
			c := invocationControl(r, "cancel")
			if bad == "drift" {
				os.Chmod(a.Manifest.StateDir, 0755)
				defer os.Chmod(a.Manifest.StateDir, 0700)
			}
			if bad == "foreign-record" {
				c.ProfileDigest = strings.Repeat("f", 64)
			}
			if _, err := a.Apply(context.Background(), c); err == nil {
				t.Fatal("invalid control succeeded")
			}
			if bad == "drift" {
				os.Chmod(a.Manifest.StateDir, 0700)
			}
			saved, err := l.read(v.ID)
			if err != nil || saved.Receipt.State != AwaitingDecision {
				t.Fatal("failed control altered receipt", err)
			}
		})
	}
}

func TestControlFencesOnlyInterruptedStatesAndRevokedRootStillHasReceipts(t *testing.T) {
	a, l, r, _ := controlFixture(t, allowControl)
	r.Approval = false
	v := prepare(t, l, r)
	// Simulate the durable dispatch marker left by an interrupted predecessor;
	// actual compiled process/flock/SIGKILL behavior has a separate CLI proof.
	if err := l.locked(func() error {
		record, err := l.read(v.ID)
		if err != nil {
			return err
		}
		record.Receipt.State = Dispatching
		record.Claim = "stopped-predecessor"
		return l.save(record)
	}); err != nil {
		t.Fatal(err)
	}
	ack := invocationControl(r, "acknowledge")
	ack.DecisionID = "resolution"
	if _, err := a.Apply(context.Background(), ack); err == nil {
		t.Fatal("active dispatch was acknowledged before fencing")
	}
	out, err := a.Apply(context.Background(), invocationControl(r, "fence"))
	if err != nil || out.Receipt == nil || out.Receipt.State != OutcomeUnknown {
		t.Fatal("interrupted effect did not retain uncertainty", err)
	}
	next := r
	next.InvocationID = "blocked-next"
	n := prepare(t, l, next)
	_, err = l.Execute(context.Background(), n.ID, n.RequestDigest, func(context.Context, Request) error { t.Error("uncertain root reached fresh grant"); return nil }, func(context.Context, Request) (string, error) {
		t.Error("uncertain root reached executor")
		return "effect", nil
	})
	if err == nil {
		t.Fatal("unknown effect did not fence sibling invocation")
	}
	revoke := Control{Version: 1, Action: "revoke", RootDigest: r.RootDigest, ProfileDigest: r.ProfileDigest, StopProofDigest: strings.Repeat("c", 64)}
	if out, err = a.Apply(context.Background(), revoke); err != nil || !out.RootRevoked {
		t.Fatal("root revocation failed", err)
	}
	if out, err = a.Apply(context.Background(), invocationControl(r, "inspect")); err != nil || !out.RootRevoked || out.Receipt.State != OutcomeUnknown {
		t.Fatal("revocation lost inspectable uncertain receipt", err)
	}
	if out, err = a.Apply(context.Background(), ack); err != nil || !out.RootRevoked || out.Receipt.State != OutcomeAcknowledged {
		t.Fatal("revoked root could not acknowledge actual stopped predecessor", err)
	}
	next.InvocationID = "revoked-next"
	if _, err = l.Prepare(next); err == nil {
		t.Fatal("acknowledgement restored revoked work authority")
	}
}
