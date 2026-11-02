// Package livepolicy is the policy in force in a running process: one holder shared by the
// daemon path, the audit observer and the proxy's secret source, replaced whole when
// supertoolkit.yaml is reloaded, and `stk reload`, which asks a running serve to do that.
package livepolicy
