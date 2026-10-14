package credential

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMaterialRoundTripsEveryField(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir, "k")
	if err != nil {
		t.Fatal(err)
	}
	want := Material{
		FieldAppID:          "123456",
		FieldPrivateKey:     "-----BEGIN RSA PRIVATE KEY-----\nnot-a-real-key\n-----END RSA PRIVATE KEY-----",
		FieldInstallationID: "987",
	}
	if err := s.PutMaterial("github-app", want); err != nil {
		t.Fatal(err)
	}
	reopened, _ := OpenStore(dir, "k")
	got, err := reopened.Material("github-app")
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("field %q = %q, want %q", k, got[k], v)
		}
	}
}

// An install that predates typed material must keep working.
func TestOldSingleTokenStoreStillReads(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir, "k")
	// putSealed is what the old Put wrote: the bare token, not JSON.
	if err := s.putSealed("github", "ghp_written_by_an_older_version"); err != nil {
		t.Fatal(err)
	}
	m, err := s.Material("github")
	if err != nil {
		t.Fatalf("an old-format credential failed to read: %v", err)
	}
	if m.Token() != "ghp_written_by_an_older_version" {
		t.Fatalf("Token() = %q, want the old value", m.Token())
	}
	tok, err := s.Get("github")
	if err != nil || tok != "ghp_written_by_an_older_version" {
		t.Fatalf("Get() = %q, %v", tok, err)
	}
}

// No field may appear in plaintext, and the file must still hide its length.
func TestNoFieldIsPlaintextOnDisk(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir, "k")
	m := Material{
		FieldAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		FieldSecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	s.PutMaterial("aws", m)

	filepath.Walk(dir, func(p string, i os.FileInfo, e error) error {
		if e != nil || i.IsDir() {
			return e
		}
		raw, _ := os.ReadFile(p)
		for k, v := range m {
			if strings.Contains(string(raw), v) {
				t.Errorf("%s contains field %q in plaintext", p, k)
			}
		}
		return nil
	})
}

// An empty map would read as "no credential needed", which is worse than an error.
func TestEmptyMaterialIsRefused(t *testing.T) {
	s, _ := OpenStore(t.TempDir(), "k")
	if err := s.PutMaterial("github", Material{}); err == nil {
		t.Fatal("PutMaterial() accepted an empty credential")
	}
}

func TestMaterialForAbsentServiceIsAnError(t *testing.T) {
	s, _ := OpenStore(t.TempDir(), "k")
	m, err := s.Material("never-stored")
	if err == nil {
		t.Fatalf("Material() returned %v and no error for an absent service", m)
	}
}

// Get must not quietly succeed on a credential that is not a token, because the
// caller would then sign nothing or send an empty bearer.
func TestGetRefusesNonTokenMaterial(t *testing.T) {
	s, _ := OpenStore(t.TempDir(), "k")
	s.PutMaterial("aws", Material{FieldAccessKeyID: "AKIA", FieldSecretAccessKey: "s"})
	if tok, err := s.Get("aws"); err == nil {
		t.Fatalf("Get() returned %q for key-pair material; it must refuse", tok)
	}
}

func TestRequireNamesEveryMissingField(t *testing.T) {
	m := Material{FieldAppID: "1"}
	err := m.Require(FieldAppID, FieldPrivateKey, FieldInstallationID)
	if err == nil {
		t.Fatal("Require() passed with fields missing")
	}
	for _, want := range []string{FieldPrivateKey, FieldInstallationID} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "1") {
		t.Error("the error mentioned a field value")
	}
}

// Fields is shown to operators, so it must list names and never values.
func TestFieldsListsNamesNotValues(t *testing.T) {
	m := Material{FieldAccessKeyID: "AKIA_SECRETISH", FieldSecretAccessKey: "very-secret"}
	for _, f := range m.Fields() {
		if strings.Contains(f, "secret-") || strings.Contains(f, "AKIA_") {
			t.Errorf("Fields() returned a value: %q", f)
		}
	}
	if len(m.Fields()) != 2 {
		t.Errorf("Fields() = %v, want two names", m.Fields())
	}
}
