package treatytest

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
)

// fatalRecorder stands in for a test so a check that must fail the test can be watched failing.
type fatalRecorder struct {
	testing.TB
	msg string
}

func (f *fatalRecorder) Helper() {}
func (f *fatalRecorder) Fatalf(format string, args ...any) {
	f.msg = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

func fails(fn func(testing.TB)) string {
	r := &fatalRecorder{}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); fn(r) }()
	wg.Wait()
	return r.msg
}

// A contract test that iterates zero cases proves nothing, so a part with no valid case, or one
// the file does not have, fails the test rather than returning an empty set.
func TestLoadCasesRefusesAnEmptyOrMissingPart(t *testing.T) {
	for name, raw := range map[string]string{
		"no valid case":     `{"operations":{"op":{"request":{"valid":{},"invalid":[{"why":"x","body":{}}]}}}}`,
		"no such part":      `{"operations":{"op":{"responses":{"200":{"valid":{"a":{}}}}}}}`,
		"no such operation": `{"operations":{}}`,
	} {
		if msg := fails(func(tb testing.TB) { parseCases(tb, "cases.json", []byte(raw), "op", "request") }); msg == "" {
			t.Errorf("%s: parseCases returned without failing the test", name)
		}
	}
	got := parseCases(t, "cases.json", []byte(`{"operations":{"op":{"responses":{"200":{"valid":{"b":{},"a":{}},"invalid":[{"why":"x","body":1}]}}}}}`), "op", "200")
	if len(got.Valid) != 2 || got.Valid[0].Name != "a" || len(got.Invalid) != 1 || got.Invalid[0].Name != "x" {
		t.Fatalf("parsed %+v", got)
	}
}

// The approvals contract compiles and its corpus reads as treaty says, so the schemas the
// product tests trust are the vendored ones.
func TestVendoredApprovalsContractReadsItsCorpus(t *testing.T) {
	api := Load(t, "schemas/http/superpipeline/approvals.v1.openapi.json")
	c := LoadCases(t, "fixtures/http/superpipeline/approvals.v1.cases.json", "createApprovalRequest", "request")
	if len(c.Invalid) == 0 {
		t.Fatal("no invalid case: the control cannot fail")
	}
	CheckCorpus(t, api.Request(t, "createApprovalRequest"), c)
	if err := api.Request(t, "createApprovalRequest").Validate([]byte(`{}`)); err == nil {
		t.Fatal("an empty body validated")
	}
}
