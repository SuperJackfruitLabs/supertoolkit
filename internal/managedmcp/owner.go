package managedmcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Manifest is private supervisor input, never an MCP tool argument or a worker
// environment value. The parent must admit its exact bytes and the executable
// before launching this versioned entry point. A digest is not execution authority.
type Manifest struct {
	Version        int    `json:"version"`
	RootDigest     string `json:"root_digest"`
	ProfileDigest  string `json:"profile_digest"`
	Workspace      string `json:"workspace"`
	PolicyPath     string `json:"policy_path"`
	PolicySHA256   string `json:"policy_sha256"`
	Profile        string `json:"profile"`
	StoreDir       string `json:"store_dir"`
	PassphraseFile string `json:"passphrase_file"`
	StateDir       string `json:"state_dir"`
	OwnerSocket    string `json:"owner_socket"`
	OwnerKey       string `json:"owner_key"`
}

type Admission struct {
	Manifest         Manifest
	Policy           []byte
	path             string
	digest           string
	passphraseDigest string
}

func byteDigest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// ProfileFingerprint is the Toolkit-owned policy/protocol pin. The supervising
// daemon must ALSO pin the binary: its compiled native catalogue is part of the
// executable revision, not something a policy hash can describe by itself.
func ProfileFingerprint(policySHA256, profile string) string {
	return fingerprint(map[string]any{"version": 1, "kind": "stk-native-managed-v1", "protocol": "2025-06-18", "policy_sha256": policySHA256, "profile": profile})
}
func RequestFingerprint(request Request) string { return fingerprint(request) }

func canonicalPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	real, err := filepath.EvalSymlinks(path)
	return err == nil && real == path
}
func outside(workspace, path string) bool {
	rel, err := filepath.Rel(workspace, path)
	return err == nil && rel != "." && (rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func Admit(path, expectedSHA256 string) (*Admission, error) {
	if !canonicalPath(path) || !hashShape.MatchString(expectedSHA256) {
		return nil, refused()
	}
	body, err := readPrivateFile(path, 65536)
	if err != nil || byteDigest(body) != expectedSHA256 {
		return nil, refused()
	}
	var fields map[string]json.RawMessage
	if !ValidJSON(body) || json.Unmarshal(body, &fields) != nil || !exactFields(fields, "version", "root_digest", "profile_digest", "workspace", "policy_path", "policy_sha256", "profile", "store_dir", "passphrase_file", "state_dir", "owner_socket", "owner_key") || len(bytes.TrimSpace(fields["profile"])) == 0 || bytes.TrimSpace(fields["profile"])[0] != '"' {
		return nil, refused()
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil || dec.Decode(new(any)) != io.EOF || m.Version != 1 || !hashShape.MatchString(m.RootDigest) || !hashShape.MatchString(m.PolicySHA256) || m.ProfileDigest != ProfileFingerprint(m.PolicySHA256, m.Profile) || (m.Profile != "" && !nameShape.MatchString(m.Profile)) || !hashShape.MatchString(m.OwnerKey) || !canonicalPath(m.Workspace) {
		return nil, refused()
	}
	workspaceInfo, err := os.Stat(m.Workspace)
	if err != nil || !workspaceInfo.IsDir() {
		return nil, refused()
	}
	for _, private := range []string{path, m.PolicyPath, m.StoreDir, m.PassphraseFile, m.StateDir, m.OwnerSocket} {
		if !canonicalPath(private) || !outside(m.Workspace, private) || privateDirectory(filepath.Dir(private)) != nil {
			return nil, refused()
		}
	}
	if privateDirectory(m.StoreDir) != nil || privateDirectory(m.StateDir) != nil || privateSocket(m.OwnerSocket) != nil {
		return nil, refused()
	}
	policy, err := readPrivateFile(m.PolicyPath, 262144)
	if err != nil || byteDigest(policy) != m.PolicySHA256 {
		return nil, refused()
	}
	passphrase, err := readPrivateFile(m.PassphraseFile, 16384)
	if err != nil {
		return nil, refused()
	}
	return &Admission{Manifest: m, Policy: policy, path: path, digest: expectedSHA256, passphraseDigest: byteDigest(passphrase)}, nil
}

// Check refuses private configuration drift; it never adopts a new key, policy,
// socket or store silently while an invocation or credential acquisition waits.
func (a *Admission) Check() error {
	current, err := Admit(a.path, a.digest)
	if err != nil || current.Manifest != a.Manifest || !bytes.Equal(current.Policy, a.Policy) || current.passphraseDigest != a.passphraseDigest {
		return refused()
	}
	return nil
}
func (a *Admission) Passphrase() (string, error) {
	if err := a.Check(); err != nil {
		return "", err
	}
	body, err := readPrivateFile(a.Manifest.PassphraseFile, 16384)
	if err != nil || len(bytes.TrimSpace(body)) == 0 {
		return "", refused()
	}
	return strings.TrimSuffix(string(body), "\n"), nil
}

type OwnerRequest struct {
	Version int     `json:"version"`
	Phase   string  `json:"phase"`
	Request Request `json:"request"`
}
type OwnerReply struct {
	Version       int    `json:"version"`
	Phase         string `json:"phase"`
	RequestDigest string `json:"request_digest"`
	// pending is valid only for review. admit and dispatch require allowed.
	Decision   string `json:"decision"`
	DecisionID string `json:"decision_id,omitempty"`
	// Durations are anchored before the IPC request, conservatively including
	// its latency. The resulting deadlines retain Go's monotonic clock reading.
	SendWithinMS      int64 `json:"send_within_ms,omitempty"`
	AuthorityForMS    int64 `json:"authority_for_ms,omitempty"`
	sendDeadline      time.Time
	authorityDeadline time.Time
}

func (r OwnerReply) SendDeadline() time.Time      { return r.sendDeadline }
func (r OwnerReply) AuthorityDeadline() time.Time { return r.authorityDeadline }

// Verify is a private local controller call. The controller must bind the exact
// request to its current root/principal/worker/attempt/call and live lease.
// admit checks without consuming an effect grant; dispatch consumes exactly one
// durable operation grant. review answers a human gate but performs no effect.
func (a *Admission) Verify(ctx context.Context, phase string, request Request) (OwnerReply, error) {
	started := time.Now()
	var out OwnerReply
	if (phase != "admit" && phase != "dispatch" && phase != "review") || request.RootDigest != a.Manifest.RootDigest || request.ProfileDigest != a.Manifest.ProfileDigest || !validRequest(request) || a.Check() != nil {
		return out, refused()
	}
	body, err := json.Marshal(OwnerRequest{1, phase, request})
	if err != nil {
		return out, refused()
	}
	data, err := privateOwnerPost(ctx, a.Manifest.OwnerSocket, a.Manifest.OwnerKey, a.Check, "/managed-toolkit/v1/verify", body)
	if err != nil {
		return out, err
	}
	var fields map[string]json.RawMessage
	if !ValidJSON(data) || json.Unmarshal(data, &fields) != nil {
		return out, refused()
	}
	names := []string{"version", "phase", "request_digest", "decision"}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&out) != nil || dec.Decode(new(any)) != io.EOF {
		return OwnerReply{}, refused()
	}
	if decision, exists := fields["decision_id"]; exists {
		names = append(names, "decision_id")
		wire := bytes.TrimSpace(decision)
		if phase != "review" || out.Decision == "pending" || len(wire) == 0 || wire[0] != '"' {
			return out, refused()
		}
	}
	if (phase == "admit" || phase == "dispatch") && out.Decision == "allowed" {
		names = append(names, "authority_for_ms")
		if out.AuthorityForMS < 1 || out.AuthorityForMS > 90000 {
			return OwnerReply{}, refused()
		}
		out.authorityDeadline = started.Add(time.Duration(out.AuthorityForMS) * time.Millisecond)
		if phase == "dispatch" {
			names = append(names, "send_within_ms")
			if out.SendWithinMS < 1 || out.SendWithinMS > 5000 || out.SendWithinMS > out.AuthorityForMS {
				return OwnerReply{}, refused()
			}
			out.sendDeadline = started.Add(time.Duration(out.SendWithinMS) * time.Millisecond)
		}
	}
	if !exactFields(fields, names...) {
		return out, refused()
	}
	if out.Version != 1 || out.Phase != phase || out.RequestDigest != fingerprint(request) || (out.Decision != "allowed" && out.Decision != "denied" && !(phase == "review" && out.Decision == "pending")) || (phase == "review" && out.Decision != "pending" && !nameShape.MatchString(out.DecisionID)) || (phase != "review" && out.DecisionID != "") || a.Check() != nil || ctx.Err() != nil || (!out.sendDeadline.IsZero() && !time.Now().Before(out.sendDeadline)) || (!out.authorityDeadline.IsZero() && !time.Now().Before(out.authorityDeadline)) {
		return OwnerReply{}, refused()
	}
	return out, nil
}

// Both private protocols share the same bounded, no-redirect/no-replay IPC.
func privateOwnerPost(ctx context.Context, socket, key string, check func() error, path string, body []byte) ([]byte, error) {
	owned, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	tr := &http.Transport{DisableKeepAlives: true, DisableCompression: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if check() != nil {
			return nil, refused()
		}
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(owned, http.MethodPost, "http://owner"+path, bytes.NewReader(body))
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		return nil, refused()
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" {
		return nil, refused()
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if err != nil || len(data) > 4096 || owned.Err() != nil || check() != nil {
		return nil, refused()
	}
	return data, nil
}
