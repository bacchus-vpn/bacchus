//go:build darwin

package enforcement

// New returns a macOS Enforcer. None exists yet — [E9], bacchus-vpn/bacchus#36,
// is the card that writes one, against ADR-0039's eight-point parity bar.
// Unlike Linux, macOS has no client code of any kind today (no clients/macos,
// no CI job, no build target — the only other darwin-tagged files in this
// repo are vendored pion), so [E9] is a start, not a port.
//
// Its scope is the same shape as [E10]'s: implement osNet (osnet.go) and
// inherit the rest, which bacchus#59 made portable when it implemented
// Windows. The from-scratch half is a BSD routing socket or
// `route`/`networksetup`, plus `pf`/`pfctl` for the kill-switch, and parity
// item 8's traffic test as an acceptance criterion. See
// enforcement_linux.go's doc — the two cards differ only in which OS API
// they write against.
func New() (Enforcer, error) {
	return nil, NotImplementedError{GOOS: "darwin", Issue: "bacchus-vpn/bacchus#36"}
}
