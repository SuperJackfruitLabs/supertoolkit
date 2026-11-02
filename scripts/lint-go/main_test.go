package main

import (
	"strings"
	"testing"
)

// The ratchet must see both directions: a count above the baseline (or a linter the baseline
// does not list) fails, and a count below it asks for the baseline to be lowered.
func TestCompareSeesRisesAndFalls(t *testing.T) {
	raised, lowered := compare(
		map[string]int{"held": 5, "rose": 4, "fell": 1, "new": 1},
		map[string]int{"held": 5, "rose": 3, "fell": 2, "gone": 7},
	)
	if strings.Join(raised, ",") != "new,rose" {
		t.Errorf("raised = %v, want [new rose]", raised)
	}
	if strings.Join(lowered, ",") != "fell,gone" {
		t.Errorf("lowered = %v, want [fell gone]", lowered)
	}
}

func TestCompareIsQuietWhenEverythingIsHeld(t *testing.T) {
	raised, lowered := compare(map[string]int{"a": 2}, map[string]int{"a": 2})
	if len(raised)+len(lowered) != 0 {
		t.Errorf("raised %v lowered %v, want neither", raised, lowered)
	}
}
