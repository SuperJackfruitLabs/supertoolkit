package managedmcp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ownerFixture(t *testing.T, reply func(OwnerRequest) OwnerReply) (*Admission, string, string) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "stk-owner-")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	workspace := filepath.Join(dir, "workspace")
	store := filepath.Join(dir, "store")
	state := filepath.Join(dir, "state")
	for _, p := range []string{workspace, store, state} {
		if err = os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	policy := []byte("services:\n  github: {}\n")
	policyPath := filepath.Join(dir, "policy.yaml")
	pass := filepath.Join(dir, "pass")
	if err = os.WriteFile(policyPath, policy, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(pass, []byte("fixture-only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "owner.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("e", 64)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/managed-toolkit/v1/verify" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(403)
			return
		}
		var in OwnerRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(reply(in))
	})}
	go server.Serve(l)
	t.Cleanup(func() { server.Close() })
	m := Manifest{Version: 1, RootDigest: strings.Repeat("a", 64), Workspace: workspace, PolicyPath: policyPath, PolicySHA256: byteDigest(policy), StoreDir: store, PassphraseFile: pass, StateDir: state, OwnerSocket: socket, OwnerKey: key}
	m.ProfileDigest = ProfileFingerprint(m.PolicySHA256, m.Profile)
	body, _ := json.Marshal(m)
	path := filepath.Join(dir, "manifest.json")
	if err = os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	hash := byteDigest(body)
	a, err := Admit(path, hash)
	if err != nil {
		t.Fatal(err)
	}
	return a, path, hash
}
func allowedOwner(r OwnerRequest) OwnerReply {
	return OwnerReply{Version: 1, Phase: r.Phase, RequestDigest: RequestFingerprint(r.Request), Decision: "allowed"}
}

func TestPrivateOwnerManifestAndActualUnixVerifierBindExactRequest(t *testing.T) {
	a, _, _ := ownerFixture(t, allowedOwner)
	r := request()
	r.RootDigest = a.Manifest.RootDigest
	r.ProfileDigest = a.Manifest.ProfileDigest
	if out, err := a.Verify(context.Background(), "dispatch", r); err != nil || out.Decision != "allowed" {
		t.Fatal("actual private verifier rejected its exact request")
	}
	r.RootDigest = strings.Repeat("b", 64)
	if _, err := a.Verify(context.Background(), "dispatch", r); err == nil {
		t.Fatal("foreign root reached owner")
	}
	r.RootDigest = a.Manifest.RootDigest
	r.ProfileDigest = strings.Repeat("b", 64)
	if _, err := a.Verify(context.Background(), "dispatch", r); err == nil {
		t.Fatal("foreign profile reached owner")
	}
}
func TestPrivateOwnerRefusesDriftPermissionsSymlinksAndWorkspacePlacement(t *testing.T) {
	for _, change := range []string{"policy", "manifest", "permissions", "symlink", "workspace", "passphrase"} {
		t.Run(change, func(t *testing.T) {
			a, path, hash := ownerFixture(t, allowedOwner)
			switch change {
			case "policy":
				os.WriteFile(a.Manifest.PolicyPath, []byte("services: {}\n"), 0600)
			case "passphrase":
				os.WriteFile(a.Manifest.PassphraseFile, []byte("changed-fixture\n"), 0600)
			case "manifest":
				os.WriteFile(path, []byte("{}"), 0600)
			case "permissions":
				os.Chmod(a.Manifest.PassphraseFile, 0644)
			case "symlink":
				os.Rename(a.Manifest.PassphraseFile, a.Manifest.PassphraseFile+".real")
				os.Symlink(a.Manifest.PassphraseFile+".real", a.Manifest.PassphraseFile)
			case "workspace":
				m := a.Manifest
				m.Workspace = filepath.Dir(path)
				body, _ := json.Marshal(m)
				os.WriteFile(path, body, 0600)
				hash = byteDigest(body)
			}
			if _, err := Admit(path, hash); err == nil && change != "passphrase" {
				t.Fatal("invalid private manifest admitted")
			}
			if a.Check() == nil {
				t.Fatal("active admission silently adopted drift")
			}
		})
	}
}
func TestPrivateOwnerRejectsWrongBindingsAndDecisionShapes(t *testing.T) {
	for _, bad := range []string{"digest", "phase", "version", "decision", "decision_id"} {
		t.Run(bad, func(t *testing.T) {
			a, _, _ := ownerFixture(t, func(r OwnerRequest) OwnerReply {
				out := allowedOwner(r)
				switch bad {
				case "digest":
					out.RequestDigest = strings.Repeat("b", 64)
				case "phase":
					out.Phase = "admit"
				case "version":
					out.Version = 2
				case "decision":
					out.Decision = "success"
				case "decision_id":
					out.DecisionID = "unrequested"
				}
				return out
			})
			r := request()
			r.RootDigest = a.Manifest.RootDigest
			r.ProfileDigest = a.Manifest.ProfileDigest
			if _, err := a.Verify(context.Background(), "dispatch", r); err == nil {
				t.Fatal("wrong owner reply accepted")
			}
		})
	}
}
func TestManagedProcessOwnershipIsExclusiveWithoutFakingRecovery(t *testing.T) {
	a, _, _ := ownerFixture(t, allowedOwner)
	first, err := OwnProcess(a.Manifest.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := OwnProcess(a.Manifest.StateDir); err == nil {
		other()
		t.Fatal("two live managed processes admitted")
	}
	first()
	reopened, err := OwnProcess(a.Manifest.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened()
	first() // A duplicate cleanup must not unlock an OS descriptor reused by the new owner.
	if other, err := OwnProcess(a.Manifest.StateDir); err == nil {
		other()
		t.Fatal("duplicate old cleanup released the new broker ownership")
	}
}

func TestPrivateOwnerManifestRequiresExplicitProfileEvenForDefaultView(t *testing.T) {
	for _, mode := range []string{"omitted", "null", "case-folded-workspace"} {
		t.Run(mode, func(t *testing.T) {
			_, path, _ := ownerFixture(t, allowedOwner)
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if json.Unmarshal(body, &fields) != nil {
				t.Fatal("fixture decode")
			}
			if mode == "omitted" {
				delete(fields, "profile")
			} else if mode == "case-folded-workspace" {
				fields["WORKSPACE"] = fields["workspace"]
				delete(fields, "workspace")
			} else {
				fields["profile"] = nil
			}
			body, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = Admit(path, byteDigest(body)); err == nil {
				t.Fatal("missing/null profile or case-folded manifest field was admitted")
			}
		})
	}
}
