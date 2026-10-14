package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
)

// cmdMCP speaks MCP on stdio.
//
// It runs its own broker rather than requiring `stk serve`, so an agent host can
// launch it directly with no daemon to manage. The credential still never
// leaves this process.
func cmdMCP(args []string) error {
	profile := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--profile", "-p":
			if i+1 >= len(args) {
				return fmt.Errorf("--profile needs a value")
			}
			profile = args[i+1]
			i++
		case "install":
			return mcpInstall(args[i+1:], profile)
		}
	}
	cfg, store, dir, err := loadForRun()
	if err != nil {
		return err
	}
	prof, ok := cfg.Profile(profile)
	if !ok {
		return fmt.Errorf("unknown profile %q; declared: %s", profile, strings.Join(cfg.Profiles(), ", "))
	}
	svc, err := newService(cfg, store, dir, "mcp")
	if err != nil {
		return err
	}
	defer svc.closeHosts()
	// A fronted child needs the broker's address, so the broker starts here too.
	if sess, serr := startBroker(cfg, store, dir); serr == nil {
		defer sess.stop()
		svc.childEnvFor = sess.childEnvFor
	}
	srv, err := mcp.NewServer(mcp.Options{
		Config: cfg, Profile: prof, Queue: svc.queue, Exec: svc.perform,
		Servers: svc.frontedServer,
		// An agent waiting on stdio cannot be left blocked indefinitely, but a
		// short wait lets a human approve in time to keep the turn alive.
		ApprovalWait: 90 * time.Second,
	})
	if err != nil {
		return err
	}
	return srv.Serve(context.Background(), os.Stdin, os.Stdout)
}

// mcpInstall prints the client configuration. It contains a command and a
// profile name, and no secret — which is the point.
func mcpInstall(args []string, profile string) error {
	host := "generic"
	if len(args) > 0 {
		host = args[0]
	}
	exe, err := os.Executable()
	if err != nil {
		exe = "stk"
	}
	cmdArgs := []any{"mcp"}
	if profile != "" {
		cmdArgs = append(cmdArgs, "--profile", profile)
	}
	entry := map[string]any{
		"mcpServers": map[string]any{
			"supertoolkit": map[string]any{"command": exe, "args": cmdArgs},
		},
	}
	out, _ := json.MarshalIndent(entry, "", "  ")
	fmt.Printf("  configuration for %s — note there is no secret in it:\n\n%s\n\n", host, out)
	switch host {
	case "claude-code":
		fmt.Println("  add it to ~/.claude.json under mcpServers")
	case "cursor":
		fmt.Println("  add it to ~/.cursor/mcp.json")
	default:
		fmt.Println("  add it wherever your agent host keeps MCP servers")
	}
	return nil
}

func cmdApprovals(args []string) error {
	cfg, store, dir, err := loadForRun()
	if err != nil {
		return err
	}
	_ = cfg
	_ = store
	c, err := dialDaemon(dir)
	if err != nil {
		return err
	}
	defer c.Close()

	if len(args) == 0 {
		return listApprovals(c)
	}
	switch args[0] {
	case "allow", "approve":
		if len(args) < 2 {
			return fmt.Errorf("usage: stk approvals allow <id>")
		}
		return decideApproval(c, args[1], true)
	case "refuse", "deny":
		if len(args) < 2 {
			return fmt.Errorf("usage: stk approvals refuse <id>")
		}
		return decideApproval(c, args[1], false)
	}
	return fmt.Errorf("usage: stk approvals [allow|refuse <id>]")
}

func listApprovals(c daemonClient) error {
	resp, err := c.Call("approvals.list", nil, "")
	if err != nil {
		return err
	}
	var effects []approval.Effect
	if err := json.Unmarshal(resp, &effects); err != nil {
		return err
	}
	pending := 0
	for _, e := range effects {
		if e.State != approval.Pending {
			continue
		}
		pending++
		fmt.Printf("  %s  %s/%s\n     %s\n     waiting %s, expires in %s\n",
			e.ID, e.Service, e.Capability, e.Summary,
			time.Since(e.Submitted).Round(time.Second), time.Until(e.Expires).Round(time.Second))
	}
	if pending == 0 {
		fmt.Println("  nothing is waiting on you.")
	} else {
		fmt.Printf("\n  stk approvals allow <id>   ·   stk approvals refuse <id>\n")
	}
	return nil
}

func decideApproval(c daemonClient, id string, allow bool) error {
	who := os.Getenv("USER")
	if who == "" {
		who = "operator"
	}
	params, _ := json.Marshal(map[string]any{"id": id, "allow": allow, "who": who})
	resp, err := c.Call("approvals.decide", params, "")
	if err != nil {
		return err
	}
	var out map[string]string
	json.Unmarshal(resp, &out)
	fmt.Printf("  %s %s by %s\n", out["id"], out["state"], who)
	return nil
}
