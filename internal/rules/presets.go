package rules

import "fmt"

const repoBase = "/repos/{owner}/{repo}"

type presetLine struct{ method, pattern string }

// Preset tiers, each added on top of the previous one. Merge differs by
// provider and is added to the maintain tier in Preset.
var presetTiers = []struct {
	name  string
	lines []presetLine
}{
	{"read", []presetLine{
		{"GET", "/user"},
		{"GET", repoBase + "/**"},
	}},
	{"issues", []presetLine{
		{"POST", repoBase + "/issues"},
		{"PATCH", repoBase + "/issues/*"},
		{"POST", repoBase + "/issues/*/comments"},
		{"PATCH", repoBase + "/issues/comments/*"},
		{"POST", repoBase + "/issues/*/labels"},
		{"PUT", repoBase + "/issues/*/labels"},
	}},
	{"pull-requests", []presetLine{
		{"POST", repoBase + "/pulls"},
		{"PATCH", repoBase + "/pulls/*"},
		{"POST", repoBase + "/pulls/*/reviews"},
		{"POST", repoBase + "/pulls/*/requested_reviewers"},
	}},
	{"maintain", []presetLine{
		{"MERGE", repoBase + "/pulls/*/merge"}, // method set per provider
		{"POST", repoBase + "/releases"},
		{"PATCH", repoBase + "/releases/*"},
		{"POST", repoBase + "/labels"},
	}},
}

// Preset returns the starting rule list for a provider and preset name.
// Presets are cumulative (read < issues < pull-requests < maintain); "none"
// is empty. No preset allows DELETE. Unknown providers and names are errors.
func Preset(provider, name string) ([]Rule, error) {
	var mergeMethod string
	switch provider {
	case "forgejo", "gitea":
		mergeMethod = "POST"
	case "github":
		mergeMethod = "PUT"
	case "bitbucket":
		return nil, fmt.Errorf("no presets for bitbucket yet; use preset: none and write rules")
	default:
		return nil, fmt.Errorf("unknown provider %q for presets", provider)
	}
	if name == "none" {
		return []Rule{}, nil
	}
	var out []Rule
	found := false
	for _, tier := range presetTiers {
		for _, l := range tier.lines {
			m := l.method
			if m == "MERGE" {
				m = mergeMethod
			}
			id := fmt.Sprintf("preset:%s#%d", name, len(out)+1)
			r, err := ParseRule(id, m+" "+l.pattern, nil, true)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		if tier.name == name {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("unknown preset %q (want read, issues, pull-requests, maintain or none)", name)
	}
	return out, nil
}
