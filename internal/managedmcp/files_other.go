//go:build !linux && !darwin

package managedmcp

func privateDirectory(string) error                 { return refused() }
func readPrivateFile(string, int64) ([]byte, error) { return nil, refused() }
func lockPrivateFile(string) (func(), error)        { return nil, refused() }
