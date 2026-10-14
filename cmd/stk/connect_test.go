package main

import (
	"strings"
	"testing"
)

func TestParseMaterialAcceptsABareValueForASingleField(t *testing.T) {
	m, err := parseMaterial("  ghp_a_token\n", []string{"token"})
	if err != nil {
		t.Fatal(err)
	}
	if m["token"] != "ghp_a_token" {
		t.Fatalf("token = %q", m["token"])
	}
}

func TestParseMaterialReadsFieldLines(t *testing.T) {
	in := "access_key_id=AKIAEXAMPLE\nsecret_access_key=shhh\n"
	m, err := parseMaterial(in, []string{"access_key_id", "secret_access_key"})
	if err != nil {
		t.Fatal(err)
	}
	if m["access_key_id"] != "AKIAEXAMPLE" || m["secret_access_key"] != "shhh" {
		t.Fatalf("parsed = %v", m.Fields())
	}
}

// A PEM private key spans many lines. If a value could not continue across
// lines, an operator would have to escape it — and the usual workaround for
// that friction is pasting the key into a config file instead, which is the
// exact thing this product exists to avoid.
func TestParseMaterialKeepsAMultiLinePrivateKey(t *testing.T) {
	key := "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\ndefghi\n-----END RSA PRIVATE KEY-----"
	in := "app_id=123456\ninstallation_id=987\nprivate_key=" + key + "\n"
	m, err := parseMaterial(in, []string{"app_id", "installation_id", "private_key"})
	if err != nil {
		t.Fatal(err)
	}
	if m["app_id"] != "123456" || m["installation_id"] != "987" {
		t.Errorf("scalars wrong: %v", m)
	}
	if m["private_key"] != key {
		t.Fatalf("private_key did not survive:\n got %q\nwant %q", m["private_key"], key)
	}
}

// Field order must not matter, since an operator pastes in whatever order.
func TestParseMaterialIgnoresFieldOrder(t *testing.T) {
	key := "-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----"
	in := "private_key=" + key + "\ninstallation_id=987\napp_id=1\n"
	m, err := parseMaterial(in, []string{"app_id", "installation_id", "private_key"})
	if err != nil {
		t.Fatal(err)
	}
	if m["private_key"] != key {
		t.Fatalf("private_key = %q", m["private_key"])
	}
	if m["app_id"] != "1" {
		t.Fatalf("app_id = %q", m["app_id"])
	}
}

func TestParseMaterialNamesWhatIsMissing(t *testing.T) {
	_, err := parseMaterial("app_id=1\n", []string{"app_id", "installation_id", "private_key"})
	if err == nil {
		t.Fatal("parseMaterial() accepted incomplete input")
	}
	for _, want := range []string{"installation_id", "private_key"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

func TestParseMaterialRefusesEmptyInput(t *testing.T) {
	if _, err := parseMaterial("   \n ", []string{"token"}); err == nil {
		t.Fatal("parseMaterial() accepted empty input")
	}
}

// A bare value must not be accepted for a multi-field service: it would store
// one field and leave the rest missing, failing later at signing time.
func TestParseMaterialRefusesABareValueForMultipleFields(t *testing.T) {
	if _, err := parseMaterial("just-one-value", []string{"access_key_id", "secret_access_key"}); err == nil {
		t.Fatal("a bare value was accepted for a two-field service")
	}
}
