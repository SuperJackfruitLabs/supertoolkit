package localstate

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveEntryWithNoConfigStillFindsBuiltins(t *testing.T) {
	t.Setenv("STK_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	if _, err := ResolveEntry("github"); err != nil {
		t.Errorf("resolveEntry(github) with no config = %v", err)
	}
}

func TestResolveEntryUnknownMentionsForgeKind(t *testing.T) {
	t.Setenv("STK_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))
	_, err := ResolveEntry("forgejo")
	if err == nil || !strings.Contains(err.Error(), "kind: forge") {
		t.Errorf("error = %v, want a hint about kind: forge", err)
	}
}
