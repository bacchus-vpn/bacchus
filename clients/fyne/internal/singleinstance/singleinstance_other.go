//go:build !windows && !linux

package singleinstance

// acquire is a no-op wherever there is no guard yet.
//
// It returns success rather than an error, and that is a deliberate reading of
// what #185 is about. The defect is a machine-wide kill-switch being disarmed
// by a peer, and a platform with no enforcement.Enforcer has no machine-wide
// kill-switch to disarm — [E9] macOS is the only such platform in the tree and
// 1.0 does not ship it (see the release scope). Refusing to start there would
// be a refusal over a hazard that does not exist on it.
//
// The moment macOS gains an Enforcer (bacchus#36, ADR-0050) this stops being
// true and this file becomes a real implementation, not a stub. That is stated
// here because the failure it would otherwise produce is silent: everything
// compiles, everything runs, and two clients quietly share a lockdown.
func acquire(string) (func(), error) {
	return func() {}, nil
}
