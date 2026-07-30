//go:build linux

package enforcement

// New returns a Linux Enforcer. None exists yet — [E10], bacchus-vpn/bacchus#37,
// is the card that writes one, against ADR-0039's eight-point parity bar.
//
// What #37 has to write is now much smaller than when this stub was added:
// bacchus#59 implemented Windows, and everything that turned out to be
// portable moved with it. A Linux backend implements osNet (osnet.go) — read
// the default route, add/remove a route, create a TUN device, block IPv6,
// arm/lift a firewall lockdown — and inherits tunnel.go's bring-up ordering,
// poolroutes.go's underlay-exclusion state machine, splittunnel.go,
// tun2socks.go, addrs.go and redact.go unchanged. tunnel_test.go runs against
// any osNet, so the orderings this has to satisfy are executable rather than
// prose.
//
// What is genuinely from scratch is what ADR-0039 said it was: netlink or
// `ip route` for the routing half, nftables or iptables for the firewall
// half, and parity item 8's traffic test as an acceptance criterion rather
// than a nice-to-have. Returning a working Enforcer that clears only some of
// the eight items is the one outcome the bar exists to forbid.
func New() (Enforcer, error) {
	return nil, NotImplementedError{GOOS: "linux", Issue: "bacchus-vpn/bacchus#37"}
}
