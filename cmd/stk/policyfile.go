package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// setPolicyInFile writes one capability's policy back to supertoolkit.yaml.
//
// The file is edited in place rather than re-serialised, so an operator's
// comments, ordering and formatting survive a change made from a screen. A
// config that gets reshuffled every time someone clicks a radio button is one
// people stop keeping in git.
func setPolicyInFile(path, category, action string, a policy.Action) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")

	svcIdx, capsIdx := -1, -1
	for i, l := range lines {
		if strings.TrimSpace(l) == category+":" && strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "    ") {
			svcIdx = i
			continue
		}
		if svcIdx >= 0 && capsIdx < 0 {
			if strings.TrimSpace(l) == "capabilities:" {
				capsIdx = i
				continue
			}
			// A new top-level or sibling key ends this service's block.
			if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "    ") {
				break
			}
		}
	}
	if svcIdx < 0 {
		return fmt.Errorf("%s: no service %q in the file", path, category)
	}

	entry := fmt.Sprintf("      %s: %s", action, a)
	if capsIdx < 0 {
		// No capabilities block yet: add one directly under the service.
		out := append([]string{}, lines[:svcIdx+1]...)
		out = append(out, "    capabilities:", entry)
		out = append(out, lines[svcIdx+1:]...)
		return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
	}
	// Replace an existing line for this action, or insert one.
	for i := capsIdx + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" {
			continue
		}
		if !strings.HasPrefix(lines[i], "      ") {
			break // left the capabilities block
		}
		if strings.HasPrefix(t, action+":") {
			lines[i] = entry
			return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	out := append([]string{}, lines[:capsIdx+1]...)
	out = append(out, entry)
	out = append(out, lines[capsIdx+1:]...)
	return os.WriteFile(path, []byte(strings.Join(out, "\n")), 0o644)
}
