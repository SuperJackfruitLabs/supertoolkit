package policy

import (
	"strings"
	"testing"
)

func TestLabelsLoadOnAForgeService(t *testing.T) {
	svc := loadForge(t, forgeWith("read", "    labels: {station: st-1, principal: lyra, grant: g-7}\n"))
	got := svc.Labels()
	if len(got) != 3 || got["station"] != "st-1" || got["principal"] != "lyra" || got["grant"] != "g-7" {
		t.Fatalf("Labels() = %v", got)
	}
	got["station"] = "mutated"
	if svc.Labels()["station"] != "st-1" {
		t.Fatal("Labels() returned the service's own map, not a copy")
	}
	if l := loadForge(t, forgeWith("read", "")).Labels(); l != nil {
		t.Fatalf("no labels: Labels() = %v, want nil", l)
	}
	cfg, err := Load(write(t, "services:\n  github:\n    scopes: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	gh, _ := cfg.Service("github")
	if gh.Labels() != nil {
		t.Fatalf("built-in Labels() = %v, want nil", gh.Labels())
	}
}

func TestLabelsRejectControlCharsAndOversize(t *testing.T) {
	for name, body := range map[string]string{
		"control":   "    labels: {station: \"a\\x1bb\"}\n",
		"newline":   "    labels: {principal: \"a\\nb\"}\n",
		"c1":        "    labels: {grant: \"a\\u0085b\"}\n",
		"del":       "    labels: {grant: \"a\\x7fb\"}\n",
		"oversize":  "    labels: {station: " + strings.Repeat("x", 129) + "}\n",
		"unknown":   "    labels: {team: blue}\n",
		"non-str":   "    labels: {station: [a, b]}\n",
		"not-a-map": "    labels: [station]\n",
	} {
		_, err := Load(write(t, forgeWith("read", body)))
		if err == nil || !strings.Contains(err.Error(), `"forge-main"`) || !strings.Contains(err.Error(), "labels") {
			t.Errorf("%s: error = %v, want a labels error naming forge-main", name, err)
		}
	}
	if _, err := Load(write(t, forgeWith("read", "    labels: {station: "+strings.Repeat("x", 128)+"}\n"))); err != nil {
		t.Errorf("128 chars rejected: %v", err)
	}
	_, err := Load(write(t, "services:\n  github:\n    scopes: []\n    labels: {station: a}\n"))
	if err == nil || !strings.Contains(err.Error(), "github") {
		t.Errorf("labels on a built-in: error = %v", err)
	}
}
