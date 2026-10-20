//go:build linux || darwin

package managedmcp

import (
	"os"
	"sync"
	"syscall"
)

func privateInfo(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Getuid()) && info.Mode().Perm()&0077 == 0
}
func privateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || !privateInfo(info) {
		return refused()
	}
	return nil
}
func privateSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || !privateInfo(info) {
		return refused()
	}
	return nil
}

// OwnProcess prevents two live managed brokers sharing one state directory.
// It does not replace the parent's durable process identity/stop proof and does
// not authorize FenceInterrupted on its behalf.
func OwnProcess(root string) (func(), error) {
	if !canonicalPath(root) || privateDirectory(root) != nil {
		return nil, refused()
	}
	path := root + string(os.PathSeparator) + "managed-owner-v1.lock"
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, refused()
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !privateInfo(info) || info.Sys().(*syscall.Stat_t).Nlink != 1 || syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, refused()
	}
	var once sync.Once
	return func() { once.Do(func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }) }, nil
}
func readPrivateFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !privateInfo(info) || info.Size() > limit || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, refused()
	}
	body := make([]byte, info.Size())
	n, err := f.ReadAt(body, 0)
	if err != nil || int64(n) != info.Size() {
		return nil, refused()
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || after.ModTime() != info.ModTime() || after.Sys().(*syscall.Stat_t).Nlink != 1 {
		return nil, refused()
	}
	return body, nil
}
func lockPrivateFile(path string) (func(), error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, refused()
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !privateInfo(info) || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		f.Close()
		return nil, refused()
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, refused()
	}
	return func() { _ = syscall.Flock(fd, syscall.LOCK_UN); _ = f.Close() }, nil
}
