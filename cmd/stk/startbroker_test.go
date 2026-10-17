package main

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// connectStatus sends a keyless CONNECT and returns the status line.
func connectStatus(t *testing.T, addr string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte("CONNECT stk.invalid:443 HTTP/1.1\r\nHost: stk.invalid:443\r\n\r\n"))
	line, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(line)
}

// liveBroker starts the real broker the way `stk serve --proxy-listen` does.
func liveBroker(t *testing.T, dir, key string) *session {
	t.Helper()
	cfg, store, _, err := loadForRun()
	if err != nil {
		t.Fatal(err)
	}
	sess, err := startBrokerWith(cfg, store, dir, brokerOpts{Listen: "127.0.0.1:0", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.stop)
	return sess
}

func envValue(env []string, name string) string {
	for _, kv := range env {
		if k, v, _ := strings.Cut(kv, "="); k == name {
			return v
		}
	}
	return ""
}

func TestStartBrokerWithKeyDemandsItAndHandsItToChildren(t *testing.T) {
	rig(t, envConfig)
	dir, _ := home()
	key, _ := loadOrCreateProxyKey(dir)
	sess := liveBroker(t, dir, key)
	if got := connectStatus(t, sess.addr); !strings.Contains(got, " 407") {
		t.Fatalf("keyless CONNECT = %q, want 407", got)
	}
	u, err := url.Parse(envValue(sess.env, "HTTPS_PROXY"))
	if err != nil {
		t.Fatal(err)
	}
	if pw, _ := u.User.Password(); u.User.Username() != "stk" || pw != key {
		t.Fatalf("session HTTPS_PROXY lacks the userinfo: %q", envValue(sess.env, "HTTPS_PROXY"))
	}
}

func TestStartBrokerDefaultHasNoKey(t *testing.T) {
	rig(t, envConfig)
	dir, _ := home()
	cfg, store, _, _ := loadForRun()
	sess, err := startBroker(cfg, store, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.stop()
	if got := connectStatus(t, sess.addr); strings.Contains(got, " 407") {
		t.Fatalf("the default broker demanded a key: %q", got)
	}
	if strings.Contains(envValue(sess.env, "HTTPS_PROXY"), "@") {
		t.Fatalf("default HTTPS_PROXY carries userinfo: %q", envValue(sess.env, "HTTPS_PROXY"))
	}
}

// The real binary: flag parsing, key loading, proxy.addr lifecycle, SIGTERM.
func TestServeProxyListenSubprocess(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "stk")
	if b, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, b)
	}
	// Unix socket paths are short on macOS; the temp dir name is not.
	sockDir, err := os.MkdirTemp("", "stk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)
	home := filepath.Join(dir, "home")
	cfg := filepath.Join(dir, "supertoolkit.yaml")
	os.WriteFile(cfg, []byte(envConfig), 0o600)
	env := append(os.Environ(), "STK_HOME="+home, "STK_CONFIG="+cfg,
		"STK_PASSPHRASE=test-passphrase", "STK_SOCKET="+filepath.Join(sockDir, "s"))

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()

	srv := exec.Command(bin, "serve", "--proxy-listen", addr)
	srv.Env = env
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- srv.Wait() }()
	defer srv.Process.Kill()

	addrFile := filepath.Join(home, "proxy.addr")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if b, err := os.ReadFile(addrFile); err == nil && strings.HasPrefix(string(b), addr+"\n") {
			break
		}
		select {
		case err := <-exited:
			t.Fatalf("serve exited early: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy.addr never appeared")
		}
	}
	if got := connectStatus(t, addr); !strings.Contains(got, " 407") {
		t.Fatalf("keyless CONNECT to the real serve = %q, want 407", got)
	}
	envCmd := exec.Command(bin, "env", "--json")
	envCmd.Env = env
	if out, err := envCmd.CombinedOutput(); err != nil {
		t.Fatalf("stk env: %v\n%s", err, out)
	}
	srv.Process.Signal(syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(15 * time.Second):
		t.Fatal("serve did not stop on SIGTERM")
	}
	if _, err := os.Stat(addrFile); err == nil {
		t.Fatal("proxy.addr was left behind after a clean shutdown")
	}
}
