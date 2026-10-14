package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

type fakeCfg struct{ names []string }

func (f fakeCfg) Services() []string { return f.names }

type fakeStore struct{ secrets map[string]string }

func (f fakeStore) Get(name string) (string, error) {
	s, ok := f.secrets[name]
	if !ok {
		return "", fmt.Errorf("no credential for %q", name)
	}
	return s, nil
}

// The leak check is the product's promise expressed as a test, so it must
// actually detect a leak rather than always reporting success.
func TestLeakCheckDetectsACredentialInTheEnvironment(t *testing.T) {
	const secret = "ghp_leaked_into_the_environment"
	t.Setenv("STK_LEAK_CANARY", secret)

	got := leakCheckAgainst(
		fakeCfg{names: []string{"github"}},
		fakeStore{secrets: map[string]string{"github": secret}},
		os.Environ(),
	)
	if got.ok {
		t.Fatalf("leak check passed while %s held the credential: %+v", "STK_LEAK_CANARY", got)
	}
	if !strings.Contains(got.note, "STK_LEAK_CANARY") {
		t.Errorf("note = %q, want it to name the variable holding the credential", got.note)
	}
}

func TestLeakCheckPassesWhenNothingHoldsTheCredential(t *testing.T) {
	got := leakCheckAgainst(
		fakeCfg{names: []string{"github"}},
		fakeStore{secrets: map[string]string{"github": "ghp_safely_in_the_broker"}},
		[]string{"PATH=/usr/bin", "GH_TOKEN=stk:ref:github:v1"},
	)
	if !got.ok {
		t.Fatalf("leak check failed with no credential present: %+v", got)
	}
}

func TestLeakCheckIsHonestWithNoCredentialsStored(t *testing.T) {
	got := leakCheckAgainst(fakeCfg{names: []string{"github"}}, fakeStore{secrets: nil}, []string{"PATH=/usr/bin"})
	if !got.ok {
		t.Fatalf("want a pass when nothing is stored, got %+v", got)
	}
	if !strings.Contains(got.note, "no credentials") {
		t.Errorf("note = %q, want it to say nothing is stored rather than implying a proof", got.note)
	}
}
