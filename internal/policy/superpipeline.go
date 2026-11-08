package policy

import (
	"fmt"
	"regexp"
)

// superPipelineFile mirrors a top-level `superpipeline:` block.
type superPipelineFile struct {
	// ApprovalsBoard names the board that hosts every approval this broker
	// raises. Unset, approvals stay local and an operator uid decides them.
	ApprovalsBoard string `yaml:"approvals_board"`
}

// Hosting needs both stk-owned service credentials: the write one creates the
// approval request and the read one reads the decision back.
const (
	ApprovalsReadService  = "superpipeline-approvals-read"
	ApprovalsWriteService = "superpipeline-approvals-write"
)

var boardIDRE = regexp.MustCompile(`^brd_[A-Za-z0-9_-]{1,124}$`)

func (c *Config) applySuperPipeline(f superPipelineFile) error {
	if f.ApprovalsBoard == "" {
		return nil
	}
	if !boardIDRE.MatchString(f.ApprovalsBoard) {
		return fmt.Errorf("superpipeline.approvals_board %q is not a board id (brd_…)", f.ApprovalsBoard)
	}
	// Refused rather than quietly local: a board named without the means to
	// reach it would otherwise look hosted and never be decided.
	for _, name := range []string{ApprovalsWriteService, ApprovalsReadService} {
		if _, ok := c.services[name]; !ok {
			return fmt.Errorf("superpipeline.approvals_board needs service %q declared (and connected): it is how stk reaches the board", name)
		}
	}
	c.approvalsBoard = f.ApprovalsBoard
	return nil
}

// ApprovalsBoard is the SuperPipeline board that hosts approvals, or "" when
// approvals are local.
func (c *Config) ApprovalsBoard() string { return c.approvalsBoard }
