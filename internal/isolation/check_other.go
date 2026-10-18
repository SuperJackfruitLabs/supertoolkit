//go:build !unix

package isolation

import (
	"io/fs"
	"runtime"
)

// Check cannot read Unix ownership here, so it never claims separation.
func Check(paths []string, agentUIDs []int, inspect func(path string) (fs.FileInfo, error)) Report {
	return CheckWith(paths, agentUIDs, inspect, Options{GOOS: runtime.GOOS})
}

// CheckWith: see Check.
func CheckWith(paths []string, agentUIDs []int, inspect func(path string) (fs.FileInfo, error), o Options) Report {
	if len(agentUIDs) == 0 {
		return NoAgents()
	}
	return Report{Level: SameUser, Method: MethodModeBits, Reasons: []string{"unsupported platform"}}
}
