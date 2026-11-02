// Package native performs one direct request with a credential attached, outside the egress
// proxy: preparing may acquire a credential, sending does not, and every send is audited. It also
// holds the managed Toolkit's owned HTTP client and its redaction of what comes back.
package native
