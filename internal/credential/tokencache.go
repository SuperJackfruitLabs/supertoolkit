package credential

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// The short-lived token cache, shared by every process on this machine.
//
// # Why it has to be shared
//
// A short-lived access token used to live only in one process's memory, and
// `stk run` is a fresh process per invocation. So every invocation began by
// exchanging the refresh token for a new access token.
//
// That is merely wasteful against a provider that reuses its refresh token. It
// is broken against one that rotates: X issues a new refresh token on every
// exchange and invalidates the old one immediately. Four agents starting
// together all read the same stored refresh token, all exchange it at once,
// one wins and three are refused a token that was valid when they read it —
// observed as 502, 502, 401, 200.
//
// With the access token on disk, a process that finds a valid one does not
// exchange at all, so refreshing becomes rare rather than per-invocation. The
// rare case takes a lock, so only one process exchanges while the others wait
// and re-read what it stored.
//
// The marginal exposure is small: the refresh token is already on disk and is
// strictly more powerful than the access token it mints.

// cacheDir is where cached tokens and their locks live.
func (s *Store) cacheDir() string { return filepath.Join(s.dir, "cache") }

func (s *Store) cachePath(service string) string {
	return filepath.Join(s.cacheDir(), filepath.Base(service)+".tok")
}

func (s *Store) lockPath(service string) string {
	return filepath.Join(s.cacheDir(), filepath.Base(service)+".lock")
}

// cacheAAD binds a cached token to its own purpose, so one cannot be moved
// into a credential file and opened as the long-lived secret.
func cacheAAD(service string) string { return service + "#cache" }

type cachedToken struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// CacheToken stores a short-lived token for other processes to reuse.
//
// It is sealed with the same key as the credentials beside it: a cached access
// token is a working credential until it expires, and storing it in the clear
// would undo the point of sealing the thing that minted it.
func (s *Store) CacheToken(service, token string, expires time.Time) error {
	if token == "" {
		return fmt.Errorf("refusing to cache an empty token for %q", service)
	}
	if err := os.MkdirAll(s.cacheDir(), 0o700); err != nil {
		return err
	}
	blob, err := json.Marshal(cachedToken{Token: token, Expires: expires})
	if err != nil {
		return err
	}
	ct, err := s.seal(cacheAAD(service), string(blob))
	if err != nil {
		return err
	}
	// Written whole to a temporary name and renamed, so a reader never sees a
	// half-written token: rename is atomic within a directory.
	tmp, err := os.CreateTemp(s.cacheDir(), ".tok-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(ct); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.cachePath(service))
}

// CachedToken returns a cached token that is still comfortably valid.
//
// `early` is how long before expiry a token stops counting, so a call never
// goes out with one that expires mid-flight.
func (s *Store) CachedToken(service string, early time.Duration) (string, time.Time, bool) {
	raw, err := os.ReadFile(s.cachePath(service))
	if err != nil {
		return "", time.Time{}, false
	}
	plain, err := s.open(cacheAAD(service), string(raw))
	if err != nil {
		// A cache we cannot read is a cache miss, not a failure: the worst it
		// costs is one exchange.
		return "", time.Time{}, false
	}
	var c cachedToken
	if err := json.Unmarshal([]byte(plain), &c); err != nil {
		return "", time.Time{}, false
	}
	if c.Token == "" || !time.Now().Add(early).Before(c.Expires) {
		return "", time.Time{}, false
	}
	return c.Token, c.Expires, true
}

// ForgetCachedToken drops the one cached token stored under exactly this key,
// used when it turns out not to work. To drop everything a service owns,
// every scope included, use ForgetCachedTokens.
func (s *Store) ForgetCachedToken(service string) error {
	err := os.Remove(s.cachePath(service))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// LockRefresh serializes acquisition with a stable OS-owned file lock. Process
// death releases ownership; timeout/unavailable locking fails closed. Lock files
// must not be removed while another process may still hold their inode.
func (s *Store) LockRefresh(service string, wait time.Duration) (func(), bool) {
	if err := os.MkdirAll(s.cacheDir(), 0700); err != nil {
		return func() {}, false
	}
	return refreshFileLock(s.lockPath(service), wait)
}

// ForgetCachedTokens drops every cached token a service owns, preserving stable locks: the
// bare-name token and each scoped token (`<service>.scope-<16 hex>`), including
// scopes no longer in the config. The match is exact, so another service's
// files never qualify; a forge name may not contain ".scope-", which keeps a
// lookalike name from posing as a scope.
func (s *Store) ForgetCachedTokens(service string) error {
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(filepath.Base(service)) + `(\.scope-[0-9a-f]{16})?\.tok$`)
	ents, err := os.ReadDir(s.cacheDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var first error
	for _, e := range ents {
		if !re.MatchString(e.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(s.cacheDir(), e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = err
		}
	}
	return first
}
