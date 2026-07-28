//go:build linux

package enforcement

// New returns a Linux Enforcer. None exists yet — [E10], bacchus-vpn/bacchus#37,
// is the card that writes one, and bacchus#35's ADR-0039 amendment is what it
// implements against.
func New() (Enforcer, error) {
	return nil, NotImplementedError{GOOS: "linux", Issue: "bacchus-vpn/bacchus#37"}
}
