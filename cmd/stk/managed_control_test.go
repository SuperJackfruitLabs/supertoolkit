package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/managedmcp"
)

func TestCompiledManagedControlRequiresActualBrokerDeathAndNoCredentialAccess(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "stk-control-cli-")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ = filepath.EvalSymlinks(dir)
	defer os.RemoveAll(dir)
	for _, sub := range []string{"workspace", "state", "store"} {
		if err = os.Mkdir(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	hash := func(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
	policy := []byte("services:\n  github: {}\n")
	policyPath := filepath.Join(dir, "policy.yaml")
	pass := filepath.Join(dir, "pass")
	for p, b := range map[string][]byte{policyPath: policy, pass: []byte("fixture-only")} {
		if err = os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(dir, "owner.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	root, key := strings.Repeat("a", 64), strings.Repeat("e", 64)
	var stopped atomic.Bool
	var controls atomic.Int32
	owner := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/managed-toolkit/v1/control" || r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(403)
			return
		}
		var c managedmcp.Control
		if json.NewDecoder(r.Body).Decode(&c) != nil {
			w.WriteHeader(400)
			return
		}
		controls.Add(1)
		decision := "denied"
		if stopped.Load() {
			decision = "allowed"
		}
		_ = json.NewEncoder(w).Encode(managedmcp.ControlReply{Version: 1, ControlDigest: managedmcp.ControlFingerprint(c), Decision: decision})
	})}
	go owner.Serve(listener)
	defer owner.Close()
	m := managedmcp.Manifest{Version: 1, RootDigest: root, Workspace: filepath.Join(dir, "workspace"), StateDir: filepath.Join(dir, "state"), StoreDir: filepath.Join(dir, "store"), PolicyPath: policyPath, PolicySHA256: hash(policy), PassphraseFile: pass, OwnerSocket: socket, OwnerKey: key}
	m.ProfileDigest = managedmcp.ProfileFingerprint(m.PolicySHA256, "")
	writeManifest := func(name string, value any) []string {
		t.Helper()
		body, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(dir, name)
		if e = os.WriteFile(path, body, 0600); e != nil {
			t.Fatal(e)
		}
		return []string{"--manifest", path, "--sha256", hash(body)}
	}
	brokerArgs := writeManifest("broker.json", m)
	controlArgs := writeManifest("control.json", managedmcp.ControlManifest{Version: 1, RootDigest: root, ProfileDigest: m.ProfileDigest, Workspace: m.Workspace, StateDir: m.StateDir, OwnerSocket: socket, OwnerKey: key})
	l, err := managedmcp.Open(m.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	r := managedmcp.Request{Version: 1, RootDigest: root, ProfileDigest: m.ProfileDigest, InvocationID: "saved-cli-receipt", Service: "github", Action: "get_user", Args: map[string]string{}, Approval: false, ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli()}
	v, err := l.Prepare(r)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "stk")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, out)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	broker := exec.CommandContext(ctx, bin, append([]string{"managed-mcp-v1"}, brokerArgs...)...)
	broker.Env = []string{"HOME=" + m.Workspace, "PATH=" + dir}
	input, err := broker.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := broker.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	broker.Stderr = &stderr
	if err = broker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if broker.ProcessState == nil {
			_ = broker.Process.Kill()
			_ = broker.Wait()
		}
	}()
	_, err = io.WriteString(input, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || !strings.Contains(line, `"lifecycleControl":true`) {
		t.Fatal("actual broker not ready", err, stderr.String())
	}
	c := managedmcp.Control{Version: 1, Action: "inspect", RootDigest: root, ProfileDigest: m.ProfileDigest, InvocationID: r.InvocationID, RequestDigest: v.RequestDigest, StopProofDigest: strings.Repeat("c", 64)}
	command := "managed-control-v1"
	invoke := func(c managedmcp.Control) ([]byte, error) {
		body, _ := json.Marshal(c)
		cmd := exec.CommandContext(ctx, bin, append([]string{command}, controlArgs...)...)
		cmd.Env = []string{"HOME=" + m.Workspace, "PATH=" + dir}
		cmd.Stdin = bytes.NewReader(body)
		return cmd.Output()
	}
	if out, e := invoke(c); e == nil || len(out) != 0 || controls.Load() != 0 {
		t.Fatal("live broker allowed lifecycle control")
	}
	_ = broker.Process.Kill()
	_ = broker.Wait()
	_ = input.Close()
	if broker.ProcessState == nil {
		t.Fatal("broker death not observed")
	}
	status, ok := broker.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatal("actual broker SIGKILL was not observed")
	}
	// Ownership alone is not a stop receipt. The private owner still denies.
	if out, e := invoke(c); e == nil || len(out) != 0 || controls.Load() != 1 {
		t.Fatal("free lock treated as owner stop proof")
	}
	stopped.Store(true)
	// Recovery must not need the old provider policy/store/passphrase after rotation.
	for _, p := range []string{policyPath, pass, m.StoreDir, m.Workspace} {
		if err = os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}
	out, err := invoke(c)
	if err != nil {
		t.Fatal("credential-free inspect failed", err)
	}
	var result managedmcp.ControlResult
	if json.Unmarshal(out, &result) != nil || result.Receipt == nil || *result.Receipt != v {
		t.Fatal("wrong durable receipt")
	}
	if strings.Contains(string(out), key) || strings.Contains(string(out), "fixture-only") {
		t.Fatal("private material in control output")
	}
	command = "managed-evidence-v1"
	out, err = invoke(c)
	var evidence managedmcp.Evidence
	if err != nil || json.Unmarshal(out, &evidence) != nil || evidence.ReceiptID != v.ID || evidence.State != v.State || evidence.Authority || evidence.ProductEffectVerified {
		t.Fatal("compiled credential-free evidence failed", string(out), err)
	}
	for _, forbidden := range []string{key, "fixture-only", `"args"`, `"result"`, m.StateDir} {
		if strings.Contains(string(out), forbidden) {
			t.Fatal("evidence disclosed private data")
		}
	}
	c.Action = "cancel"
	if out, err = invoke(c); err == nil || len(out) != 0 {
		t.Fatal("evidence accepted mutation")
	}
	c.Action = "inspect"
	command = "managed-control-v1"
	c.Action = "cancel"
	out, err = invoke(c)
	if err != nil || !strings.Contains(string(out), `"state":"cancelled"`) {
		t.Fatal("exact cancel failed", err)
	}
	for _, bad := range []string{"{}", strings.Repeat("x", 4097), string(out) + "{}"} {
		var reply bytes.Buffer
		if err = runManagedControl(ctx, controlArgs, strings.NewReader(bad), &reply); err == nil || reply.Len() != 0 {
			t.Fatal("malformed control input exposed a result")
		}
	}
}

func TestManagedControlRejectsUnknownFlagsBeforeReadingAnything(t *testing.T) {
	for _, args := range [][]string{nil, {"--manifest", "/not-read", "--sha256", "bad", "--unbound"}, {"--sha256", "bad", "--manifest", "/not-read"}} {
		var out bytes.Buffer
		if err := runManagedControl(context.Background(), args, strings.NewReader(""), &out); err == nil || out.Len() != 0 || strings.Contains(err.Error(), "/not-read") {
			t.Fatal("control accepted flags or disclosed private paths")
		}
	}
}
