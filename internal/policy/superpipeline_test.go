package policy

import (
	"strings"
	"testing"
)

func TestApprovalsBoardNeedsBothServiceCredentials(t *testing.T) {
	base := "workspace: t\nservices:\n  github:\n    scopes: []\n"
	both := base + "  superpipeline-approvals-read:\n    scopes: []\n  superpipeline-approvals-write:\n    scopes: []\n"
	cfg, err := Parse("t.yaml", []byte(both+"superpipeline:\n  approvals_board: brd_abc123\n"))
	if err != nil || cfg.ApprovalsBoard() != "brd_abc123" {
		t.Fatalf("board=%q err=%v", cfg.ApprovalsBoard(), err)
	}
	if cfg, err := Parse("t.yaml", []byte(both)); err != nil || cfg.ApprovalsBoard() != "" {
		t.Fatalf("no board: %q %v; want local approvals", cfg.ApprovalsBoard(), err)
	}
	// A board with no way to reach it would look hosted and never be decided.
	if _, err := Parse("t.yaml", []byte(base+"superpipeline:\n  approvals_board: brd_abc123\n")); err == nil ||
		!strings.Contains(err.Error(), "superpipeline-approvals-write") {
		t.Fatalf("board without credentials: err=%v", err)
	}
	// The form the README documents.
	readme := base + "  superpipeline-approvals-write: {}\n  superpipeline-approvals-read: {}\nsuperpipeline:\n  approvals_board: brd_abc123\n"
	if cfg, err := Parse("t.yaml", []byte(readme)); err != nil || cfg.ApprovalsBoard() != "brd_abc123" {
		t.Fatalf("README form: %v", err)
	}
	if _, err := Parse("t.yaml", []byte(both+"superpipeline:\n  approvals_board: ../x\n")); err == nil {
		t.Fatal("a non-board id was accepted")
	}
}
