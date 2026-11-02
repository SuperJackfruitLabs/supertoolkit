// Package secrets is where a stored credential becomes what goes on the wire: one acquirer per
// scheme that needs an exchange, the egress proxy's secret source, Authorize for a direct request,
// and what a stored credential actually does. Three of the five schemes never put a long-lived
// secret on the wire.
package secrets
