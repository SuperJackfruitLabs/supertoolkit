package credential

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRefreshLockProcessProbe(t *testing.T) {
	path := os.Getenv("STK_REFRESH_LOCK_PROBE")
	if path == "" {
		return
	}
	release, ok := refreshFileLock(path, time.Second)
	if !ok {
		t.Fatal("child ownership unavailable")
	}
	defer release()
	fmt.Println("refresh-owned")
	for {
		time.Sleep(time.Hour)
	}
}

func TestActualRefreshOwnerDeathReleasesTheStableLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.lock")
	cmd := exec.Command(os.Args[0], "-test.run=^TestRefreshLockProcessProbe$")
	cmd.Env = []string{"STK_REFRESH_LOCK_PROBE=" + path}
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
	ready := make(chan bool, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line == "refresh-owned\n" }()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child did not hold the refresh lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("refresh owner startup timed out")
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err = os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if other, ok := refreshFileLock(path, 100*time.Millisecond); ok {
		other()
		t.Fatal("old timestamp stole a live process lock")
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if cmd.ProcessState == nil {
		t.Fatal("old owner was not reaped")
	}
	release, ok := refreshFileLock(path, time.Second)
	if !ok {
		t.Fatal("dead owner retained the lock")
	}
	defer release()
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("recovery replaced the lock inode instead of acquiring it")
	}
}

func TestKnownLiveLegacyRefreshOwnerIsNotTakenOver(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.lock")
	if err := os.WriteFile(path, []byte(fmt.Sprint(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if release, ok := refreshFileLock(path, 50*time.Millisecond); ok {
		release()
		t.Fatal("new broker ignored a known live legacy refresh owner")
	}
}
