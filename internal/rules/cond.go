package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxBody is the most request-body bytes a body condition reads. A body over
// the limit cannot be evaluated, which fails the condition closed.
const MaxBody = 64 << 10

// Condition operators.
const (
	OpAbsent  = "absent"
	OpPresent = "present"
	OpEquals  = "equals"
	OpOneOf   = "oneof"
)

// Cond is one body condition. Key is a dotted path through JSON objects
// ("state", "a.b"); array indexing is not supported. Values hold the JSON
// encoding of each comparison value (`"closed"`, `true`, `3`), so a string
// "true" and the boolean true never compare equal.
type Cond struct {
	Key    string
	Op     string
	Values []string
}

var errUnevaluable = errors.New("body cannot be evaluated")

// parseWhen turns a config `when:` map into conditions. Keys may carry a
// "body." prefix. A value of "absent" or "present" is that operator; any
// other scalar is equality; a non-empty list of scalars is one-of.
func parseWhen(when map[string]any) ([]Cond, error) {
	var out []Cond
	for k, v := range when {
		key := strings.TrimPrefix(k, "body.")
		if err := validKey(key); err != nil {
			return nil, fmt.Errorf("when key %q: %w", k, err)
		}
		switch x := v.(type) {
		case string:
			if x == OpAbsent || x == OpPresent {
				out = append(out, Cond{Key: key, Op: x})
				continue
			}
		case []any:
			if len(x) == 0 {
				return nil, fmt.Errorf("when key %q: empty list", k)
			}
			vals := make([]string, 0, len(x))
			for _, e := range x {
				s, err := scalarJSON(e)
				if err != nil {
					return nil, fmt.Errorf("when key %q: %w", k, err)
				}
				vals = append(vals, s)
			}
			out = append(out, Cond{Key: key, Op: OpOneOf, Values: vals})
			continue
		}
		s, err := scalarJSON(v)
		if err != nil {
			return nil, fmt.Errorf("when key %q: %w", k, err)
		}
		out = append(out, Cond{Key: key, Op: OpEquals, Values: []string{s}})
	}
	return out, nil
}

func validKey(key string) error {
	if key == "" {
		return errors.New("empty key")
	}
	for _, p := range strings.Split(key, ".") {
		if p == "" {
			return errors.New("empty key segment")
		}
	}
	return nil
}

func scalarJSON(v any) (string, error) {
	switch x := v.(type) {
	case string:
		b, err := json.Marshal(x)
		return string(b), err
	case bool:
		return strconv.FormatBool(x), nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case uint64:
		return strconv.FormatUint(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	}
	return "", fmt.Errorf("unsupported value type %T", v)
}

func validCond(c Cond) error {
	if err := validKey(c.Key); err != nil {
		return err
	}
	switch c.Op {
	case OpAbsent, OpPresent:
		if len(c.Values) != 0 {
			return fmt.Errorf("%s takes no values", c.Op)
		}
	case OpEquals:
		if len(c.Values) != 1 {
			return errors.New("equals takes one value")
		}
	case OpOneOf:
		if len(c.Values) == 0 {
			return errors.New("oneof needs values")
		}
	default:
		return fmt.Errorf("unknown op %q", c.Op)
	}
	return nil
}

// object is a decoded JSON object that remembers duplicated keys.
type object struct {
	m   map[string]any
	dup map[string]bool
}

// parseBody decodes a request body for condition evaluation. Anything other
// than a single, complete, valid-UTF-8 JSON object under MaxBody with a JSON
// content type is unevaluable.
func parseBody(r Request) (*object, error) {
	if r.BodyTruncated || len(r.Body) > MaxBody || !utf8.Valid(r.Body) || !jsonContentType(r.ContentType) {
		return nil, errUnevaluable
	}
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, errUnevaluable
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errUnevaluable
	}
	o, ok := v.(*object)
	if !ok {
		return nil, errUnevaluable
	}
	return o, nil
}

func jsonContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json" || (strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
}

// decodeValue reads one JSON value by token streaming, so duplicate object
// keys are seen rather than silently overwritten.
func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := &object{m: map[string]any{}, dup: map[string]bool{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errUnevaluable
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				k = foldKey(k)
				if _, seen := o.m[k]; seen {
					o.dup[k] = true
				}
				o.m[k] = v
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return o, nil
		case '[':
			var a []any
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return a, nil
		}
		return nil, errUnevaluable
	default:
		return t, nil // string, json.Number, bool, nil
	}
}

// lookup walks a dotted key. found reports presence; a duplicated key at any
// level is present but its value is ambiguous (dup=true). Walking through a
// non-object is unevaluable.
func (o *object) lookup(key string) (v any, found, dup bool, err error) {
	parts := strings.Split(foldKey(key), ".")
	cur := o
	for i, p := range parts {
		val, ok := cur.m[p]
		if !ok {
			return nil, false, false, nil
		}
		if cur.dup[p] {
			return nil, true, true, nil
		}
		if i == len(parts)-1 {
			return val, true, false, nil
		}
		next, ok := val.(*object)
		if !ok {
			return nil, false, false, errUnevaluable
		}
		cur = next
	}
	return nil, false, false, errUnevaluable
}

// eval reports whether c holds for body; an error means it cannot be decided.
func (c Cond) eval(o *object) (bool, error) {
	v, found, dup, err := o.lookup(c.Key)
	if err != nil {
		return false, err
	}
	switch c.Op {
	case OpAbsent:
		return !found, nil
	case OpPresent:
		return found, nil
	}
	if dup {
		return false, errUnevaluable
	}
	if !found {
		return false, nil
	}
	enc, ok := encodeScalar(v)
	if !ok {
		return false, nil
	}
	for _, want := range c.Values {
		eq, err := scalarEqual(enc, want)
		if err != nil {
			return false, err
		}
		if eq {
			return true, nil
		}
	}
	return false, nil
}

// foldKey folds an object key exactly as Go's encoding/json matches field
// names: each rune maps to the smallest rune of its unicode.SimpleFold orbit
// (so "State", "STATE", Kelvin sign and long s fold, but U+0130 does not).
// A broader fold would let the rule see a key the origin does not. Case
// variants of one key become duplicates, which count as present.
func foldKey(k string) string { return strings.Map(foldRune, k) }

func foldRune(r rune) rune {
	for {
		r2 := unicode.SimpleFold(r)
		if r2 <= r {
			return r2
		}
		r = r2
	}
}

// maxExponent bounds number exponents so a pathological literal cannot make
// exact comparison expensive; beyond it the value is unevaluable.
const maxExponent = 400

// scalarEqual compares two JSON-encoded scalars. Numbers compare by exact
// value (3 == 3.0 == 30e-1); a string never equals a number.
func scalarEqual(a, b string) (bool, error) {
	ra, aNum, err := jsonNumber(a)
	if err != nil {
		return false, err
	}
	rb, bNum, err := jsonNumber(b)
	if err != nil {
		return false, err
	}
	if aNum && bNum {
		return ra.Cmp(rb) == 0, nil
	}
	if aNum || bNum {
		return false, nil
	}
	return a == b, nil
}

func jsonNumber(s string) (*big.Rat, bool, error) {
	if s == "" || !(s[0] == '-' || (s[0] >= '0' && s[0] <= '9')) {
		return nil, false, nil
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(strings.TrimPrefix(s[i+1:], "+"))
		if err != nil || e > maxExponent || e < -maxExponent {
			return nil, true, errUnevaluable
		}
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, true, errUnevaluable
	}
	return r, true, nil
}

func encodeScalar(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		b, err := json.Marshal(x)
		return string(b), err == nil
	case bool:
		return strconv.FormatBool(x), true
	case json.Number:
		return x.String(), true
	}
	return "", false
}

// condsHold evaluates every condition (logical AND).
func condsHold(cs []Cond, r Request) (bool, error) {
	o, err := parseBody(r)
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		ok, err := c.eval(o)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}
