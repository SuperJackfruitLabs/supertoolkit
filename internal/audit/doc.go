// Package audit is the durable record of what the broker did: the observer that turns a wire
// record into a ledger entry, the caller each entry is attributed to, `stk audit`, and the feed
// the web UI reads. No credential is ever written here, only a fingerprint or the operation that
// replaced it.
package audit
