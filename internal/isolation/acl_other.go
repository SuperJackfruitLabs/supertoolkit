//go:build !linux

package isolation

// HasACL is nil off Linux: ACLs cannot be read here without cgo, and Check
// reports that as a reason.
var HasACL func(path string) (bool, error)
