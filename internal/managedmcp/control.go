package managedmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"time"
)

// ControlManifest is supervisor-only input. It deliberately carries no provider
// store, passphrase or policy path: cleanup must work after credential rotation
// or execution-root revocation, without granting any new product effect.
type ControlManifest struct {
	Version       int    `json:"version"`
	RootDigest    string `json:"root_digest"`
	ProfileDigest string `json:"profile_digest"`
	Workspace     string `json:"workspace"`
	StateDir      string `json:"state_dir"`
	OwnerSocket   string `json:"owner_socket"`
	OwnerKey      string `json:"owner_key"`
}
type ControlAdmission struct {
	Manifest ControlManifest
	path     string
	digest   string
}
type Control struct {
	Version         int    `json:"version"`
	Action          string `json:"action"`
	RootDigest      string `json:"root_digest"`
	ProfileDigest   string `json:"profile_digest"`
	InvocationID    string `json:"invocation_id"`
	RequestDigest   string `json:"request_digest"`
	StopProofDigest string `json:"stop_proof_digest"`
	DecisionID      string `json:"decision_id"`
}
type ControlReply struct {
	Version       int    `json:"version"`
	ControlDigest string `json:"control_digest"`
	Decision      string `json:"decision"`
}
type ControlResult struct {
	Version       int      `json:"version"`
	ControlDigest string   `json:"control_digest"`
	Receipt       *Receipt `json:"receipt,omitempty"`
	RootRevoked   bool     `json:"root_revoked"`
}

func ControlFingerprint(c Control) string { return fingerprint(c) }

func closedControlJSON(body []byte, value any, names ...string) bool {
	if len(body) > 4096 || !ValidJSON(body) {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || !exactFields(fields, names...) {
		return false
	}
	// All fields except version are mandatory strings. In particular JSON null
	// cannot silently become an empty invocation/decision ID through Go decoding.
	for key, raw := range fields {
		if key != "version" {
			p := bytes.TrimSpace(raw)
			if len(p) == 0 || p[0] != '"' {
				return false
			}
		}
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	return d.Decode(value) == nil && d.Decode(new(any)) == io.EOF
}
func DecodeControl(body []byte) (Control, error) {
	var c Control
	if !closedControlJSON(body, &c, "version", "action", "root_digest", "profile_digest", "invocation_id", "request_digest", "stop_proof_digest", "decision_id") || !validControl(c) {
		return Control{}, refused()
	}
	return c, nil
}
func validControl(c Control) bool {
	if c.Version != 1 || !hashShape.MatchString(c.RootDigest) || !hashShape.MatchString(c.ProfileDigest) || !hashShape.MatchString(c.StopProofDigest) {
		return false
	}
	if c.Action == "revoke" {
		return c.InvocationID == "" && c.RequestDigest == "" && c.DecisionID == ""
	}
	if !nameShape.MatchString(c.InvocationID) || !hashShape.MatchString(c.RequestDigest) {
		return false
	}
	if c.Action == "acknowledge" {
		return nameShape.MatchString(c.DecisionID)
	}
	return (c.Action == "inspect" || c.Action == "fence" || c.Action == "cancel") && c.DecisionID == ""
}

func AdmitControl(path, digest string) (*ControlAdmission, error) {
	if !canonicalPath(path) || !hashShape.MatchString(digest) {
		return nil, refused()
	}
	body, err := readPrivateFile(path, 4096)
	if err != nil || byteDigest(body) != digest {
		return nil, refused()
	}
	var m ControlManifest
	if !closedControlJSON(body, &m, "version", "root_digest", "profile_digest", "workspace", "state_dir", "owner_socket", "owner_key") || m.Version != 1 || !hashShape.MatchString(m.RootDigest) || !hashShape.MatchString(m.ProfileDigest) || !hashShape.MatchString(m.OwnerKey) || !filepath.IsAbs(m.Workspace) || filepath.Clean(m.Workspace) != m.Workspace {
		return nil, refused()
	}
	// The admitted old workspace is a path boundary, not a required live
	// directory: recovery must remain possible after its removal. Private
	// control/state/socket paths still require canonical existing owner paths.
	for _, p := range []string{path, m.StateDir, m.OwnerSocket} {
		if !canonicalPath(p) || !outside(m.Workspace, p) || privateDirectory(filepath.Dir(p)) != nil {
			return nil, refused()
		}
	}
	if privateDirectory(m.StateDir) != nil || privateSocket(m.OwnerSocket) != nil {
		return nil, refused()
	}
	return &ControlAdmission{Manifest: m, path: path, digest: digest}, nil
}
func (a *ControlAdmission) Check() error {
	current, err := AdmitControl(a.path, a.digest)
	if err != nil || current.Manifest != a.Manifest {
		return refused()
	}
	return nil
}

// Apply needs BOTH exclusive native broker ownership and the real supervisor's
// fresh confirmation of its durable predecessor-stop proof. A free flock alone
// does not establish that an unrecorded process/group/resource has stopped.
// The parent must bind cleanup role, root/profile and saved receipt access,
// including when product execution authority is already revoked or expired.
func (a *ControlAdmission) Apply(ctx context.Context, c Control) (ControlResult, error) {
	var out ControlResult
	if !validControl(c) || c.RootDigest != a.Manifest.RootDigest || c.ProfileDigest != a.Manifest.ProfileDigest || a.Check() != nil {
		return out, refused()
	}
	owned, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	release, err := OwnProcess(a.Manifest.StateDir)
	if err != nil {
		return out, refused()
	}
	defer release()
	body, err := json.Marshal(c)
	if err != nil {
		return out, refused()
	}
	data, err := privateOwnerPost(owned, a.Manifest.OwnerSocket, a.Manifest.OwnerKey, a.Check, "/managed-toolkit/v1/control", body)
	if err != nil {
		return out, refused()
	}
	var reply ControlReply
	if !closedControlJSON(data, &reply, "version", "control_digest", "decision") || reply.Version != 1 || reply.ControlDigest != ControlFingerprint(c) || reply.Decision != "allowed" || owned.Err() != nil || a.Check() != nil {
		return out, refused()
	}
	l, err := Open(a.Manifest.StateDir)
	if err != nil {
		return out, err
	}
	out = ControlResult{Version: 1, ControlDigest: ControlFingerprint(c)}
	if c.Action == "revoke" {
		err = l.RevokeRoot(c.RootDigest)
		out.RootRevoked = err == nil
		return out, err
	}
	// Inspect and check the immutable receipt before invoking any ledger mutation.
	id := requestID(Request{RootDigest: c.RootDigest, InvocationID: c.InvocationID})
	err = l.locked(func() error {
		r, err := l.read(id)
		if err != nil || r.Request.RootDigest != c.RootDigest || r.Request.ProfileDigest != c.ProfileDigest || r.Receipt.RequestDigest != c.RequestDigest {
			return refused()
		}
		out.RootRevoked, err = l.revoked(c.RootDigest)
		if err != nil {
			return err
		}
		if c.Action == "acknowledge" {
			if r.Receipt.State == OutcomeAcknowledged {
				if r.Receipt.ResolutionID != c.DecisionID || r.Receipt.ResolutionStopDigest != c.StopProofDigest {
					return refused()
				}
			} else {
				if r.Receipt.State != OutcomeUnknown {
					return refused()
				}
				r.Receipt.State = OutcomeAcknowledged
				r.Receipt.ResolutionID = c.DecisionID
				r.Receipt.ResolutionStopDigest = c.StopProofDigest
				r.Receipt.Result = ""
				if err = l.save(r); err != nil {
					return err
				}
			}
		}
		v := r.Receipt
		out.Receipt = &v
		return nil
	})
	if err != nil {
		return ControlResult{}, err
	}
	switch c.Action {
	case "fence":
		v, err := l.FenceInterrupted(id, c.RequestDigest)
		out.Receipt = &v
		return out, err
	case "cancel":
		v, err := l.Cancel(id, c.RequestDigest)
		out.Receipt = &v
		return out, err
	}
	return out, nil
}
