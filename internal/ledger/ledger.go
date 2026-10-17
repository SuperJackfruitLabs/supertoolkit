// Package ledger is the durable record of what the broker did.
//
// "What did the agent do with my credentials?" is the question this product
// exists to answer, and until this existed the answer was lost when the process
// exited. The broker's in-memory records serve its own counters; this serves the
// operator, who is usually looking at a different process on a different day.
//
// What it is not: a log. It holds effects — a capability, a caller, a policy
// decision, an outcome — and never a credential. A signed request's entry says
// a signature was computed; a substituted one says a fingerprint. Neither says
// the secret, and there is a test for every scheme.
package ledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxBytes is where the file rotates. An unbounded audit log on a small VPS is
// an outage, and one generation is enough to answer "what just happened"
// without becoming the thing that fills the disk.
const maxBytes = 8 << 20

// Entry is one effect.
type Entry struct {
	When    time.Time `json:"when"`
	Service string    `json:"service"`
	// Capability is the catalogue name where one is known, and the method and
	// path otherwise: the proxy sees requests a connector never named.
	Capability string `json:"capability"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Host       string `json:"host"`
	// Policy is what the decision was: agent, approval or deny.
	Policy string `json:"policy,omitempty"`
	// Caller identifies who asked — a profile, a pid, a fronted server.
	Caller string `json:"caller,omitempty"`
	// Credential describes what was sent without being it: a fingerprint, or
	// the name of the operation that replaced it.
	Credential string `json:"credential,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	// Rule is the id of the rule that denied the request, when one did.
	Rule string `json:"rule,omitempty"`
}

// Ledger appends effects to a file and reads them back.
type Ledger struct {
	path string
	mu   sync.Mutex
}

// Open prepares the ledger. The file is created on first write, so opening one
// that will never be written leaves nothing behind.
func Open(dir string) (*Ledger, error) {
	if dir == "" {
		return nil, fmt.Errorf("ledger: no directory")
	}
	return &Ledger{path: filepath.Join(dir, "audit.log")}, nil
}

// Path is where the ledger lives, which `stk doctor` reports.
func (l *Ledger) Path() string { return l.path }

// Append writes one entry.
//
// Several processes write this file — a broker, a daemon, an MCP server — and
// none coordinates with the others. Each entry is therefore marshalled whole
// and written with a single `Write` to a descriptor opened O_APPEND, which is
// the one case POSIX guarantees will not interleave. A mutex would only order
// this process's own writes, so it guards rotation rather than the write.
func (l *Ledger) Append(e Entry) error {
	if e.When.IsZero() {
		e.When = time.Now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.rotateIfLarge(len(line)); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}

// rotateIfLarge keeps one generation. Called with the mutex held.
func (l *Ledger) rotateIfLarge(incoming int) error {
	fi, err := os.Stat(l.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Size()+int64(incoming) <= maxBytes {
		return nil
	}
	return os.Rename(l.path, l.path+".1")
}

// Read returns the most recent entries, newest first.
//
// A truncated final line is skipped rather than fatal. A process killed
// mid-write leaves one incomplete record, and a ledger that refuses to open
// because of its last line is a ledger that has lost everything before it.
func (l *Ledger) Read(limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = 200
	}
	// Read the previous generation first so a rotation does not hide what came
	// just before it.
	var all []Entry
	for _, p := range []string{l.path + ".1", l.path} {
		es, err := readFile(p)
		if err != nil {
			return nil, err
		}
		all = append(all, es...)
	}
	// Newest first: the question is nearly always "what just happened".
	out := make([]Entry, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}

func readFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Entry
	// A single entry can carry a long path; 1 MB is well above anything real
	// and still bounded.
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			// A line we cannot parse is a line we skip: the alternative is
			// discarding the whole history over one bad record.
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	return out, nil
}
