//go:build darwin

package enforcement

// New returns a macOS Enforcer. None exists yet — [E9], bacchus-vpn/bacchus#36,
// is the card that writes one, and bacchus#35's ADR-0039 amendment is what it
// implements against. Unlike Linux, macOS has no client code of any kind
// today (no clients/macos, no CI job, no build target — the only darwin-
// tagged files in this repo are vendored pion), so [E9] is a start, not a
// port, and this stub is the first darwin-tagged file clients/ has ever had.
func New() (Enforcer, error) {
	return nil, NotImplementedError{GOOS: "darwin", Issue: "bacchus-vpn/bacchus#36"}
}
