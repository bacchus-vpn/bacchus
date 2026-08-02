//go:build darwin

package enforcement

// New returns a macOS Enforcer. None exists yet — [E9], bacchus-vpn/bacchus#36,
// is the card that writes one, against ADR-0039's eight-point parity bar.
// Unlike Linux, macOS has no client code of any kind today (no clients/macos,
// no CI job, no build target — the only other darwin-tagged files in this
// repo are vendored pion), so [E9] is a start, not a port.
//
// Its scope is NOT the same shape as [E10]'s, and an earlier version of this
// comment said it was. It described macOS as implementing osNet (osnet.go)
// over a BSD routing socket plus `pf`/`pfctl` for the kill-switch — the Linux
// design with the OS names swapped. ADR-0050 rejected that: macOS enforcement
// is a NetworkExtension packet tunnel in a system extension, where the OS owns
// the routing table, the DNS settings and the on-demand rules, and the client
// declares what it wants rather than installing it. `pf` was ruled out because
// it has no arbitration scheme between writers — two products editing the same
// anchor set is a corruption the platform does not resolve — which is the one
// respect in which nftables and `pf` are not analogous.
//
// So macOS does not implement osNet at all: there is no osnet_darwin.go, and
// there is not meant to be one. The primitives that interface is a seam over
// are precisely the ones NetworkExtension does not expose. See ADR-0050 §5,
// and osnet.go's package doc, which lists this as the macOS entry rather than
// inventing a mechanism to fill the column (bacchus#110).
//
// The parity bar still applies in full; what changes is what satisfies it.
// Notarization is required on both routes, the entitlement is self-serve, and
// enrollment is the only real lead time — ADR-0050 prices all three.
func New() (Enforcer, error) {
	return nil, NotImplementedError{GOOS: "darwin", Issue: "bacchus-vpn/bacchus#36"}
}
