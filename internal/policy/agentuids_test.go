package policy

import (
	"strings"
	"testing"
)

func TestAgentUIDsPolicyKey(t *testing.T) {
	cfg, err := Load(write(t, "agent_uids: [1001, 1002]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.AgentUIDs(); len(got) != 2 || got[0] != 1001 || got[1] != 1002 {
		t.Fatalf("AgentUIDs() = %v", got)
	}
	cfg, err = Load(write(t, "workspace: x\n"))
	if err != nil || len(cfg.AgentUIDs()) != 0 {
		t.Fatalf("absent key: %v %v", cfg.AgentUIDs(), err)
	}
	if _, err := Load(write(t, "agent_uids: [-1]\n")); err == nil || !strings.Contains(err.Error(), "agent_uids") {
		t.Fatalf("negative uid accepted: %v", err)
	}
	if _, err := Load(write(t, "agent_uids: [bob]\n")); err == nil {
		t.Fatal("non-integer uid accepted")
	}
}
