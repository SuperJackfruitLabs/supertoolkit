//go:build linux || darwin

package approval

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockPublication serializes the complete lifecycle of one provider effect.
// The kernel releases flock when a publisher exits, so a durable "sending"
// marker is considered abandoned only after no live publisher holds this lock.
func (q *Queue) lockPublication(id string) (func() error, error) {
	path := filepath.Join(q.dir, id+".pub.lock")
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open publication lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return nil, errors.Join(fmt.Errorf("lock publication: %w", err), f.Close())
	}
	return func() error {
		return errors.Join(syscall.Flock(fd, syscall.LOCK_UN), f.Close())
	}, nil
}
