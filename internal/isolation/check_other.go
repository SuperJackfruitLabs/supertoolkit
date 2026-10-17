//go:build !unix

package isolation

import "io/fs"

// Check cannot read Unix ownership here, so it never claims separation.
func Check(paths []string, agentUIDs []int, inspect func(path string) (fs.FileInfo, error)) Report {
	if len(agentUIDs) == 0 {
		return NoAgents()
	}
	return Report{Level: SameUser, Method: MethodModeBits, Reasons: []string{"unsupported platform"}}
}
