//go:build linux || darwin

package credential

import (
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const refreshLockVersion = "STK_REFRESH_LOCK_V2\n"

// The kernel owns a stable inode for the whole exchange. Age is never evidence
// of process death, and cache invalidation must not detach a live lock's inode.
func refreshFileLock(path string, wait time.Duration) (func(), bool) {
	deadline := time.Now().Add(wait)
	for {
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
		if err != nil {
			return func() {}, false
		}
		f := os.NewFile(uintptr(fd), path)
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			f.Close()
			return func() {}, false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Getuid()) || st.Nlink != 1 {
			f.Close()
			return func() {}, false
		}
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			current, statErr := os.Lstat(path)
			stable := statErr == nil && os.SameFile(info, current)
			if stable && !legacyRefreshOwnerAlive(f, info.Size()) {
				if err = f.Truncate(0); err == nil {
					_, err = f.WriteAt([]byte(refreshLockVersion), 0)
				}
				if err == nil {
					err = f.Sync()
				}
				if err != nil {
					_ = syscall.Flock(fd, syscall.LOCK_UN)
					f.Close()
					return func() {}, false
				}
				var once sync.Once
				return func() { once.Do(func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }) }, true
			}
			_ = syscall.Flock(fd, syscall.LOCK_UN)
		} else if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			f.Close()
			return func() {}, false
		}
		f.Close()
		if !time.Now().Before(deadline) {
			return func() {}, false
		}
		pause := 25 * time.Millisecond
		if remaining := time.Until(deadline); remaining < pause {
			pause = remaining
		}
		time.Sleep(pause)
	}
}

// Migration aid only: a known live old-format PID is refused. Concurrent old and
// new broker versions are unsupported; stop old brokers before updating a store.
// Modern ownership is always the kernel lock, never a PID or timestamp heuristic.
func legacyRefreshOwnerAlive(f *os.File, size int64) bool {
	if size == 0 {
		return false
	}
	if size > 64 {
		return true
	}
	body := make([]byte, size)
	n, err := f.ReadAt(body, 0)
	if err != nil && err != io.EOF {
		return true
	}
	text := string(body[:n])
	if text == refreshLockVersion {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || pid <= 0 {
		return true
	}
	err = syscall.Kill(pid, 0)
	return !errors.Is(err, syscall.ESRCH)
}
