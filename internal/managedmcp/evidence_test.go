package managedmcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEvidenceSanitizesReturnedAndAcknowledgedAfterRestart(t *testing.T) {
	for _, state := range []State{Returned, OutcomeAcknowledged} {
		t.Run(string(state), func(t *testing.T) {
			a, l, r, _ := controlFixture(t, allowControl)
			r.Args = map[string]string{"secret": "credential-in-args"}
			v := prepare(t, l, r)
			if err := l.locked(func() error {
				saved, err := l.read(v.ID)
				if err != nil {
					return err
				}
				saved.Receipt.State = state
				if state == Returned {
					saved.Receipt.Result = "private-result-credential"
				} else {
					saved.Receipt.ResolutionID = "ack-1"
					saved.Receipt.ResolutionStopDigest = strings.Repeat("d", 64)
				}
				// Historical reading remains available after the execution lease expires.
				saved.Request.ExpiresAtMS = time.Now().Add(-time.Hour).UnixMilli()
				saved.Receipt.RequestDigest = RequestFingerprint(saved.Request)
				r = saved.Request
				return l.save(saved)
			}); err != nil {
				t.Fatal(err)
			}
			l = open(t, a.Manifest.StateDir)
			if err := l.RevokeRoot(r.RootDigest); err != nil {
				t.Fatal(err)
			}
			got, err := a.Evidence(context.Background(), invocationControl(r, "inspect"))
			if err != nil || got.State != state || !got.RootRevoked || got.Authority || got.ProductEffectVerified || got.Version != 1 || got.RequestDigest != RequestFingerprint(r) || got.ReceiptID != v.ID {
				t.Fatal(got, err)
			}
			digest := got.EvidenceDigest
			got.EvidenceDigest = ""
			if !hashShape.MatchString(digest) || fingerprint(got) != digest {
				t.Fatal("evidence consistency digest mismatch")
			}
			got.EvidenceDigest = digest
			body, _ := json.Marshal(got)
			for _, secret := range []string{"credential-in-args", "private-result-credential", a.Manifest.OwnerKey, a.Manifest.StateDir, "\"args\"", "\"result\""} {
				if strings.Contains(string(body), secret) {
					t.Fatalf("projection leaked %q", secret)
				}
			}
			if state == OutcomeAcknowledged && got.ResolutionID != "ack-1" {
				t.Fatal("lost acknowledged NON-success")
			}
		})
	}
}

func TestEvidenceRejectsMutationAndForeignBindings(t *testing.T) {
	for _, bad := range []string{"cancel", "acknowledge", "root", "profile", "request", "owner"} {
		t.Run(bad, func(t *testing.T) {
			reply := allowControl
			if bad == "owner" {
				reply = func(c Control) ControlReply { r := allowControl(c); r.Decision = "denied"; return r }
			}
			a, l, r, calls := controlFixture(t, reply)
			v := prepare(t, l, r)
			c := invocationControl(r, "inspect")
			switch bad {
			case "cancel":
				c.Action = "cancel"
			case "acknowledge":
				c.Action = "acknowledge"
				c.DecisionID = "ack"
			case "root":
				c.RootDigest = strings.Repeat("f", 64)
			case "profile":
				c.ProfileDigest = strings.Repeat("f", 64)
			case "request":
				c.RequestDigest = strings.Repeat("f", 64)
			}
			if _, err := a.Evidence(context.Background(), c); err == nil {
				t.Fatal("invalid projection accepted")
			}
			if (bad == "cancel" || bad == "acknowledge") && calls.Load() != 0 {
				t.Fatal("mutation reached owner")
			}
			saved, err := l.read(v.ID)
			if err != nil || saved.Receipt != v {
				t.Fatal("projection mutated ledger", err)
			}
		})
	}
}
