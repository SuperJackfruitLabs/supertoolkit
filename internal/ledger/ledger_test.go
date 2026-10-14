package ledger

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppendAndReadNewestFirst(t *testing.T) {
	l, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := l.Append(Entry{Service: "github", Capability: fmt.Sprintf("cap-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := l.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d entries, want 3", len(got))
	}
	// Newest first: the question is nearly always "what just happened".
	if got[0].Capability != "cap-2" {
		t.Errorf("first entry is %q, want the most recent", got[0].Capability)
	}
	if got[0].When.IsZero() {
		t.Error("the entry has no timestamp")
	}
}

func TestLedgerIsOwnerOnlyAndCreatedLazily(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir)
	if _, err := os.Stat(l.Path()); !os.IsNotExist(err) {
		t.Error("opening the ledger created a file before anything was written")
	}
	if err := l.Append(Entry{Service: "github"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 600", fi.Mode().Perm())
	}
}

// A process killed mid-write leaves one incomplete record. Losing the whole
// history over it would be the worse failure by far.
func TestTruncatedFinalLineDoesNotLoseTheHistory(t *testing.T) {
	l, _ := Open(t.TempDir())
	for i := 0; i < 3; i++ {
		l.Append(Entry{Service: "github", Capability: fmt.Sprintf("cap-%d", i)})
	}
	f, err := os.OpenFile(l.Path(), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"service":"github","capab`) // killed here
	f.Close()

	got, err := l.Read(10)
	if err != nil {
		t.Fatalf("a truncated line made the ledger unreadable: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d entries, want the 3 complete ones", len(got))
	}
	if got[0].Capability != "cap-2" {
		t.Errorf("first entry is %q", got[0].Capability)
	}
}

// Several processes write this file and none coordinates with the others.
func TestConcurrentWritersDoNotInterleave(t *testing.T) {
	l, _ := Open(t.TempDir())
	var wg sync.WaitGroup
	const writers, each = 8, 25
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := l.Append(Entry{Service: "github", Caller: fmt.Sprintf("w%d-%d", w, i)}); err != nil {
					t.Error(err)
				}
			}
		}(w)
	}
	wg.Wait()

	got, err := l.Read(writers * each * 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != writers*each {
		t.Fatalf("read %d entries, want %d — a write was torn or lost", len(got), writers*each)
	}
	seen := map[string]bool{}
	for _, e := range got {
		if seen[e.Caller] {
			t.Fatalf("duplicate entry %q", e.Caller)
		}
		seen[e.Caller] = true
	}
}

func TestRotationKeepsOneGenerationAndStillReadsIt(t *testing.T) {
	l, _ := Open(t.TempDir())
	// A path long enough that a few hundred entries pass the rotation size.
	big := strings.Repeat("p", 64*1024)
	for i := 0; i < 200; i++ {
		if err := l.Append(Entry{Service: "github", Path: big, Caller: fmt.Sprintf("n%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(l.Path() + ".1"); err != nil {
		t.Fatalf("the ledger never rotated: %v", err)
	}
	fi, _ := os.Stat(l.Path())
	if fi.Size() > maxBytes {
		t.Errorf("the live file is %d bytes, above the %d bound", fi.Size(), maxBytes)
	}
	// The previous generation is still readable, so a rotation does not hide
	// what happened just before it.
	got, err := l.Read(500)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 200 {
		t.Errorf("read %d entries after rotation, want all 200 across both generations", len(got))
	}
}

// The one assertion this package exists to make: whatever the auth scheme, the
// ledger holds no credential. A fingerprint, an operation name, a status — never
// the secret.
func TestNoSchemeEverWritesACredential(t *testing.T) {
	l, _ := Open(t.TempDir())
	secrets := map[string]string{
		"token":             "ghp_the_bearer_token",
		"secret_access_key": "the_sigv4_secret_access_key",
		"private_key":       "-----BEGIN RSA PRIVATE KEY-----MIIEow",
		"consumer_secret":   "the_oauth1_consumer_secret",
		"token_secret":      "the_oauth1_token_secret",
		"client_secret":     "the_client_credentials_secret",
	}
	// Each entry is shaped the way its scheme's call site shapes it.
	entries := []Entry{
		{Service: "github", Capability: "list_repos", Credential: "sha256:1a2b3c4d", Outcome: "200"},
		{Service: "aws-sts", Capability: "get_caller_identity", Credential: "signature (AWS SigV4)", Outcome: "200"},
		{Service: "github-app", Capability: "create_issue", Credential: "installation token, minted, expires in 60m", Outcome: "201"},
		{Service: "x", Capability: "post_tweet", Credential: "signature (OAuth1 HMAC-SHA1)", Outcome: "201"},
		{Service: "stripe", Capability: "list_charges", Credential: "sha256:9f8e7d6c", Outcome: "200"},
	}
	for _, e := range entries {
		if err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(l.Path())
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for field, secret := range secrets {
		if strings.Contains(body, secret) {
			t.Errorf("the ledger contains the %s", field)
		}
	}
	// And it is still useful: it says which operation ran and what came back.
	for _, want := range []string{"post_tweet", "OAuth1", "SigV4", "201"} {
		if !strings.Contains(body, want) {
			t.Errorf("the ledger does not record %q, so it answers nothing", want)
		}
	}
}

func TestReadOfAnAbsentLedgerIsEmptyNotAnError(t *testing.T) {
	l, _ := Open(t.TempDir())
	got, err := l.Read(10)
	if err != nil {
		t.Fatalf("reading a ledger nothing has written failed: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("read %d entries from nothing", len(got))
	}
}

func TestLimitIsHonoured(t *testing.T) {
	l, _ := Open(t.TempDir())
	for i := 0; i < 50; i++ {
		l.Append(Entry{Service: "github", Caller: fmt.Sprintf("n%d", i), When: time.Now().UTC()})
	}
	got, _ := l.Read(5)
	if len(got) != 5 {
		t.Fatalf("read %d, want 5", len(got))
	}
	if got[0].Caller != "n49" {
		t.Errorf("the limit dropped the newest: first is %q", got[0].Caller)
	}
}
