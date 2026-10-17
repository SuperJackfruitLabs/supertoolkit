package rules

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Decision reasons.
const (
	ReasonAllowed        = "allowed"
	ReasonDenyRule       = "deny-rule"
	ReasonNoRule         = "no-rule"
	ReasonOutsidePrefix  = "outside-api-prefix"
	ReasonMethodOverride = "method-override"
	ReasonBadPath        = "bad-path"
	ReasonNoRuleSet      = "no-rule-set"
)

// Built-in rule ids for denials no named rule decided. A denial always
// carries a rule id, so the audit record can always name one.
const (
	IDDefaultDeny    = "builtin:default-deny"
	IDOutsidePrefix  = "builtin:outside-prefix"
	IDMethodOverride = "builtin:method-override"
	IDBadPath        = "builtin:bad-path"
	IDNoRuleSet      = "builtin:no-rule-set"
)

var knownMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
	http.MethodOptions: true,
}

var overrideHeaders = []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"}

// Rule allows or denies one method on one path pattern, optionally only when
// body conditions hold.
type Rule struct {
	ID      string
	Allow   bool
	Method  string
	Pattern string
	When    []Cond
}

// Request is what Evaluate needs from an HTTP request. Body holds at most
// MaxBody bytes; BodyTruncated is set when more were available.
type Request struct {
	Method, EscapedPath string
	Header              http.Header
	Body                []byte
	BodyTruncated       bool
	ContentType         string
}

// Decision is the outcome of Evaluate. RuleID names the deciding rule, if any.
type Decision struct {
	Allowed bool
	RuleID  string
	Reason  string
}

// ParseRule parses "METHOD /pattern" plus an optional `when:` map.
func ParseRule(id, line string, when map[string]any, allow bool) (Rule, error) {
	f := strings.Fields(line)
	if len(f) != 2 {
		return Rule{}, fmt.Errorf("rule %q: want \"METHOD /path\", got %q", id, line)
	}
	r := Rule{ID: id, Allow: allow, Method: f[0], Pattern: f[1]}
	conds, err := parseWhen(when)
	if err != nil {
		return Rule{}, fmt.Errorf("rule %q: %w", id, err)
	}
	r.When = conds
	if err := validRule(r); err != nil {
		return Rule{}, err
	}
	return r, nil
}

func validRule(r Rule) error {
	if r.ID == "" {
		return errors.New("rule has no id")
	}
	if !knownMethods[r.Method] {
		return fmt.Errorf("rule %q: unknown method %q", r.ID, r.Method)
	}
	if err := validPattern(r.Pattern); err != nil {
		return fmt.Errorf("rule %q: %w", r.ID, err)
	}
	for _, c := range r.When {
		if err := validCond(c); err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
	}
	return nil
}

func validPattern(p string) error {
	if p == "" || p[0] != '/' {
		return errors.New("pattern must start with /")
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		last := i == len(segs)-1
		switch {
		case s == "":
			if !last {
				return errors.New("empty segment in pattern")
			}
		case s == "**":
			if !last {
				return errors.New("** must be the last segment")
			}
		case strings.ContainsAny(s, "{}"):
			if len(s) < 3 || s[0] != '{' || s[len(s)-1] != '}' || strings.ContainsAny(s[1:len(s)-1], "{}") {
				return fmt.Errorf("bad placeholder %q", s)
			}
		case strings.Contains(s, "**"):
			return fmt.Errorf("bad segment %q", s)
		}
	}
	return nil
}

// Set is a validated rule list bound to the granted repositories.
type Set struct {
	repos map[string]bool // lowercase "owner/name"
	deny  []Rule
	allow []Rule
}

// NewSet validates rs and binds {owner}/{repo} to repos ("owner/name").
func NewSet(repos []string, rs []Rule) (*Set, error) {
	s := &Set{repos: map[string]bool{}}
	for _, r := range repos {
		parts := strings.Split(r, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("repository %q: want owner/name", r)
		}
		s.repos[strings.ToLower(r)] = true
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if err := validRule(r); err != nil {
			return nil, err
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Allow {
			s.allow = append(s.allow, r)
		} else {
			s.deny = append(s.deny, r)
		}
	}
	return s, nil
}

// Evaluate decides r: deny rules first (a deny wins), then allow rules, and
// deny by default. prefix is the service's api_prefix; a path outside it is
// denied. Matching uses the normalised path, which is for matching only:
// callers must forward the ORIGINAL escaped path upstream, never the
// normalised one. Any error is a deny.
func (s *Set) Evaluate(prefix string, r Request) Decision {
	if s == nil {
		return Decision{RuleID: IDNoRuleSet, Reason: ReasonNoRuleSet}
	}
	for k := range r.Header {
		for _, h := range overrideHeaders {
			if strings.EqualFold(k, h) {
				return Decision{RuleID: IDMethodOverride, Reason: ReasonMethodOverride}
			}
		}
	}
	full, err := NormalizePath(r.EscapedPath)
	if err != nil {
		return Decision{RuleID: IDBadPath, Reason: ReasonBadPath}
	}
	path, ok := StripPrefix(prefix, full)
	if !ok {
		return Decision{RuleID: IDOutsidePrefix, Reason: ReasonOutsidePrefix}
	}

	// Deny: method and literals case-insensitive, one trailing slash
	// tolerated, no repository binding (a broader deny is safer). A deny
	// with conditions that cannot be evaluated is treated as matched.
	lp := strings.ToLower(path)
	cands := []string{lp}
	if len(lp) > 1 && strings.HasSuffix(lp, "/") {
		cands = append(cands, lp[:len(lp)-1])
	}
	for _, d := range s.deny {
		if !strings.EqualFold(d.Method, r.Method) {
			continue
		}
		pat := lowerLiterals(d.Pattern)
		matched := false
		for _, c := range cands {
			if MatchPath(pat, c, nil) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if len(d.When) > 0 {
			if hold, err := condsHold(d.When, r); err == nil && !hold {
				continue
			}
		}
		return Decision{RuleID: d.ID, Reason: ReasonDenyRule}
	}

	// Allow: exact method and path, repository binding, conditions must
	// evaluate and hold.
	for _, a := range s.allow {
		if a.Method != r.Method {
			continue
		}
		vars := map[string]string{}
		if !MatchPath(a.Pattern, path, vars) || !s.bound(vars) {
			continue
		}
		if len(a.When) > 0 {
			if hold, err := condsHold(a.When, r); err != nil || !hold {
				continue
			}
		}
		return Decision{Allowed: true, RuleID: a.ID, Reason: ReasonAllowed}
	}
	return Decision{RuleID: IDDefaultDeny, Reason: ReasonNoRule}
}

// bound reports whether {owner}/{repo} captures name a granted repository,
// case-insensitively. Other captures are unrestricted.
func (s *Set) bound(vars map[string]string) bool {
	owner, hasO := vars["owner"]
	repo, hasR := vars["repo"]
	switch {
	case hasO && hasR:
		return s.repos[strings.ToLower(owner+"/"+repo)]
	case hasO:
		for k := range s.repos {
			if strings.HasPrefix(k, strings.ToLower(owner)+"/") {
				return true
			}
		}
		return false
	case hasR:
		for k := range s.repos {
			if strings.HasSuffix(k, "/"+strings.ToLower(repo)) {
				return true
			}
		}
		return false
	}
	return true
}

// StripPrefix removes the API prefix from a normalised path. ok is false when
// the path lies outside the prefix.
func StripPrefix(prefix, path string) (string, bool) {
	prefix = strings.TrimRight(prefix, "/")
	if prefix == "" {
		return path, true
	}
	if path == prefix {
		return "/", true
	}
	if strings.HasPrefix(path, prefix+"/") {
		return path[len(prefix):], true
	}
	return "", false
}

// lowerLiterals lowercases literal pattern segments, leaving {name} intact.
func lowerLiterals(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if !strings.HasPrefix(s, "{") {
			segs[i] = strings.ToLower(s)
		}
	}
	return strings.Join(segs, "/")
}
