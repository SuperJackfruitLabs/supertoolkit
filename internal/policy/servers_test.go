package policy

import (
	"strings"
	"testing"
)

const withServer = `
workspace: test
services:
  github:
    scopes: []
servers:
  slack:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-slack"]
    host: slack.com
    env_var: SLACK_BOT_TOKEN
    capabilities:
      slack_delete_message: deny
      slack_post_message: approval
`

func TestServerBlockParses(t *testing.T) {
	cfg, err := Load(write(t, withServer))
	if err != nil {
		t.Fatal(err)
	}
	s, ok := cfg.Server("slack")
	if !ok {
		t.Fatal("server slack not found")
	}
	if s.Command != "npx" || len(s.Args) != 2 {
		t.Errorf("Command/Args = %q %v", s.Command, s.Args)
	}
	if s.Host != "slack.com" || s.EnvVar != "SLACK_BOT_TOKEN" {
		t.Errorf("Host/EnvVar = %q %q", s.Host, s.EnvVar)
	}
}

// Without interception the placeholder could not be substituted, so the server
// would need a real credential — which is the thing being prevented.
func TestServerHostIsIntercepted(t *testing.T) {
	cfg, _ := Load(write(t, withServer))
	hosts := cfg.InterceptHosts()
	if !hosts["slack.com"] {
		t.Fatalf("InterceptHosts() = %v, want slack.com", hosts)
	}
	if !hosts["api.github.com"] {
		t.Error("the native service's host should still be intercepted")
	}
}

func TestCategoriesIncludeServicesAndServers(t *testing.T) {
	cfg, _ := Load(write(t, withServer))
	cats := cfg.Categories()
	if len(cats) != 2 {
		t.Fatalf("Categories() = %v, want github and slack", cats)
	}
	if !cfg.IsServer("slack") || cfg.IsServer("github") {
		t.Error("IsServer should distinguish a fronted server from a native service")
	}
}

// The safe default for a tool we did not write.
func TestUnannotatedToolDefaultsToApproval(t *testing.T) {
	cfg, _ := Load(write(t, withServer))
	s, _ := cfg.Server("slack")

	if got := s.Policy("slack_list_channels", ToolHint{}); got != ActionApproval {
		t.Fatalf("an unannotated tool = %v, want %v — we cannot know what a tool we did not write does", got, ActionApproval)
	}
	// A read-only hint may promote it.
	if got := s.Policy("slack_list_channels", ToolHint{Known: true, ReadOnly: true}); got != ActionAgent {
		t.Fatalf("a read-only tool = %v, want %v", got, ActionAgent)
	}
	// A destructive hint never promotes, even alongside read-only.
	if got := s.Policy("slack_wipe", ToolHint{Known: true, ReadOnly: true, Destructive: true}); got != ActionApproval {
		t.Fatalf("a destructive tool = %v, want %v", got, ActionApproval)
	}
	// An explicit override wins over any hint.
	if got := s.Policy("slack_delete_message", ToolHint{Known: true, ReadOnly: true}); got != ActionDeny {
		t.Fatalf("an explicitly denied tool = %v, want %v", got, ActionDeny)
	}
}

// Both become categories, so a shared name would shadow one and an operator
// could not tell which they had configured.
func TestNameCollisionBetweenServiceAndServerIsRefused(t *testing.T) {
	_, err := Load(write(t, `
workspace: test
services:
  github:
    scopes: []
servers:
  github:
    command: npx
    host: api.github.com
`))
	if err == nil {
		t.Fatal("a service and a server sharing a name was accepted")
	}
	if !strings.Contains(err.Error(), "unique") {
		t.Errorf("error = %q, want it to explain the collision", err)
	}
}

func TestServerWithoutCommandIsRefused(t *testing.T) {
	_, err := Load(write(t, `
workspace: test
servers:
  slack:
    host: slack.com
`))
	if err == nil || !strings.Contains(err.Error(), "command") {
		t.Fatalf("want a refusal naming the missing command, got %v", err)
	}
}

// A server with no host cannot be brokered at all, so accepting it would mean
// silently requiring a real credential in the child's environment.
func TestServerWithoutHostIsRefused(t *testing.T) {
	_, err := Load(write(t, `
workspace: test
servers:
  slack:
    command: npx
`))
	if err == nil {
		t.Fatal("a server with no host was accepted")
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("error = %q, want it to name the missing host", err)
	}
}

func TestProfileMayNameAServer(t *testing.T) {
	cfg, err := Load(write(t, withServer+`
profiles:
  poster:
    slack: [slack_post_message]
`))
	if err != nil {
		t.Fatalf("a profile naming a server was refused: %v", err)
	}
	if _, ok := cfg.Profile("poster"); !ok {
		t.Fatal("profile poster not found")
	}
}
