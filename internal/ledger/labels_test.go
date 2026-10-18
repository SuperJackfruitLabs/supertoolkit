package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLabelsRoundTripAndOldRowsStillParse(t *testing.T) {
	dir := t.TempDir()
	old := `{"when":"2026-10-01T00:00:00Z","service":"forge-main","capability":"x","method":"GET","path":"/","host":"h"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "audit.log"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	l, _ := Open(dir)
	if err := l.Append(Entry{Service: "forge-main", Labels: map[string]string{"station": "st-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := l.Append(Entry{Service: "github"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(l.Path())
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if strings.Contains(lines[2], "labels") {
		t.Errorf("unlabelled row carries a labels key: %s", lines[2])
	}
	es, err := l.Read(10)
	if err != nil || len(es) != 3 {
		t.Fatalf("Read = %d entries, %v", len(es), err)
	}
	if es[1].Labels["station"] != "st-1" {
		t.Errorf("labels lost: %+v", es[1])
	}
	if es[2].Labels != nil || es[2].Service != "forge-main" {
		t.Errorf("old row: %+v", es[2])
	}
}
