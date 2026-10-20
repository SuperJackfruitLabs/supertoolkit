//go:build !linux && !darwin

package credential

import "time"

// Shared acquisition is unsupported without a proven process-owned file lock.
func refreshFileLock(string, time.Duration) (func(), bool) { return func() {}, false }
