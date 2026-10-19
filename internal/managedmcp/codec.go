package managedmcp

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

// DecodeRequest validates shape only. Fresh execution authority is a separate
// owner check at dispatch; a well-formed root fingerprint does not grant it.
func DecodeRequest(body []byte) (Request, error) {
	var out Request
	if len(body) > 65536 || !wireScalars(body) {
		return out, refused()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || len(fields) != 9 {
		return out, refused()
	}
	// Alias avoids recursively invoking Request.UnmarshalJSON below.
	type wireRequest Request
	var wire wireRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || decoder.Decode(new(any)) != io.EOF {
		return Request{}, refused()
	}
	out = Request(wire)
	if !validRequest(out) {
		return Request{}, refused()
	}
	return out, nil
}

func (r *Request) UnmarshalJSON(body []byte) error {
	value, err := DecodeRequest(body)
	if err != nil {
		return err
	}
	*r = value
	return nil
}

// Go's JSON decoder replaces lone surrogates/invalid UTF-8. Reject them instead,
// so fingerprints cannot differ from a JavaScript consumer's retained code units.
func wireScalars(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for i := 0; i < len(body); i++ {
		if body[i] != '\\' {
			continue
		}
		if i+1 >= len(body) {
			return false
		}
		if body[i+1] != 'u' {
			i++
			continue
		}
		if i+6 > len(body) {
			return false
		}
		u, err := strconv.ParseUint(string(body[i+2:i+6]), 16, 16)
		if err != nil {
			return false
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+12 > len(body) || body[i+6] != '\\' || body[i+7] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(body[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 11
		} else if u >= 0xdc00 && u <= 0xdfff {
			return false
		} else {
			i += 5
		}
	}
	return true
}

// All request keys, including argument names, are ASCII. Sorted object keys and
// scalar values therefore match Salaam's canonical JSON, including U+2028/U+2029.
func canonicalBytes(value any) []byte {
	body, _ := json.Marshal(value)
	var object any
	_ = json.Unmarshal(body, &object)
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(object)
	data := bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
	var wire bytes.Buffer
	for i := 0; i < len(data); {
		if data[i] == '\\' && i+1 < len(data) {
			if bytes.HasPrefix(data[i:], []byte(`\u2028`)) {
				wire.WriteRune('\u2028')
				i += 6
				continue
			}
			if bytes.HasPrefix(data[i:], []byte(`\u2029`)) {
				wire.WriteRune('\u2029')
				i += 6
				continue
			}
			wire.Write(data[i : i+2])
			i += 2
			continue
		}
		wire.WriteByte(data[i])
		i++
	}
	return wire.Bytes()
}
