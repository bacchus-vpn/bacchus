// The per-platform primitive set the portable half of this package calls.
//
// tunnel.go's bring-up/teardown sequencing, poolroutes.go's underlay-exclusion
// state machine, splittunnel.go's matching and tun2socks.go's netstack bridge
// are all platform-independent — 1,317 of the 1,969 lines clients/windows
// carried, per ADR-0039's 2026-07-28 file-by-file costing. What is not
// portable is the handful of primitives underneath them: read the default
// route, add/remove a route, create a TUN device, block IPv6 on the physical
// adapter, arm/lift a firewall lockdown, point the machine's resolver at the
// tunnel. Per platform:
//
//   - Windows: `NetTCPIP`/`NetSecurity` cmdlets (routes_windows.go,
//     killswitch_windows.go).
//   - Linux: netlink and the nftables netlink subsystem, spoken directly by a
//     root helper across a socket ([E10], bacchus#37, ADR-0049); the DNS
//     primitive additionally speaks to systemd-resolved (ADR-0051).
//   - macOS: does not implement this interface. ADR-0050 §5 rules the macOS
//     tunnel to a NetworkExtension packet tunnel in a system extension, where
//     the OS owns routing, DNS and the on-demand rules outright, so there is
//     no set of primitives for a macOS osNet to be the seam over. `pf` plus a
//     helper — the shape an earlier draft assumed by analogy with Linux — was
//     rejected there because `pf` has no arbitration scheme between writers.
//     enforcement_darwin.go returns NotImplementedError and there is no
//     osnet_darwin.go; [E9], bacchus#36, is the card that builds the
//     NetworkExtension client, and it will not be an osNet implementation.
//
// osNet is where that line falls. It is deliberately not exported: it is this
// package's internal porting surface, not a contract for callers — callers get
// Enforcer/Session/Policy (enforcement.go), which is the whole point of the
// seam. A new platform implements osNet and an New() returning an enforcer
// wired to it; nothing else in this package changes.
//
// This is not a new pattern for this repo. poolroutes.go's poolExcluder has
// always taken its four OS-facing primitives as injected functions
// (excludeFn/allowFn/gatewayFn/removeFn) rather than calling them by name,
// precisely so its ordering logic could be tested without a real Windows
// route table; osNet generalizes that same idea to the rest of the surface,
// which is what let tunnel.go stop calling routes.go/killswitch.go functions
// by name. See ADR-0039's "The enforcement seam" section, which names
// poolExcluder as the precedent this follows rather than a third invention.
package enforcement

import "golang.zx2c4.com/wireguard/tun"

// gatewayInfo describes the default route in place before the tunnel comes
// up, so it can be restored / used for exclusion routes and so IPv6 can be
// disabled on the right physical adapter.
//
// Portable by shape, not by accident: every field is a concept each of the
// three target platforms has (Windows reads them from Get-NetRoute; Linux
// from netlink/`ip route`'s via + dev; macOS from a routing-socket lookup),
// which is why it lives here rather than in routes_windows.go where it
// started. poolroutes.go and tunnel.go both hold one, and both are portable.
type gatewayInfo struct {
	nextHop string
	ifIndex int
	ifAlias string

	// nextHopV6 is the IPv6 default-gateway next hop on the same interface, if
	// any (issue #117) — "" when this interface has no IPv6 default route
	// (common: physical IPv6 is disabled for most of the tunnel's lifetime via
	// disablePhysicalIPv6, and many networks have no IPv6 at all). Populated
	// best-effort by defaultGateway; addExclusionRoutesV6 is a no-op without
	// it, since there is then nothing to route an IPv6 exclusion via.
	nextHopV6 string
}

// osNet is one platform's implementation of the primitives above. Every
// method keeps the exact name, signature and failure posture the
// clients/windows free function it came from had, so tunnel.go's sequencing
// reads the same after re-pointing as before it — the seam moved, the
// ordering did not.
//
// Note which methods return an error and which do not: that split is load
// bearing and was inherited deliberately rather than tidied. The route
// mutators are best-effort and silent (a missing exclusion route fails safe —
// the dial loops into the tunnel or is blocked, it does not leak), while
// createTUN, configureTunInterface, addSplitDefaultRoute, enableKillSwitch and
// captureDNS return errors because a failure there means the tunnel is not
// actually carrying traffic — or is carrying it while the resolver is not —
// and bring-up must unwind rather than continue. An
// implementation that turns one of the silent ones into a hard failure, or a
// hard one into a best-effort no-op, changes the fail-closed posture ADR-0014
// and parity items 2 and 5 depend on.
type osNet interface {
	// defaultGateway reads the current best (lowest-metric) IPv4 default
	// route, plus that same interface's IPv6 default route if it has one
	// (issue #117). Only the IPv4 lookup is required to succeed.
	defaultGateway() (gatewayInfo, error)

	// addExclusionRoutes routes each prefix via the physical default gateway,
	// carving it out of the tunnel's capture. addExclusionRoutesV6 is its
	// IPv6 counterpart (issue #117) and must be a no-op when gw has no IPv6
	// next hop. Both are best-effort: see the type doc.
	addExclusionRoutes(prefixes []string, gw gatewayInfo)
	addExclusionRoutesV6(prefixes []string, gw gatewayInfo)

	// addInclusionRoutes is the mirror for split-tunnel "include" mode (issue
	// #64): routes each prefix *into* the tunnel adapter. Requires the TUN
	// device to already exist, unlike addExclusionRoutes.
	addInclusionRoutes(prefixes []string, tunNextHop string)

	// removeRoutes deletes each prefix's route regardless of which of the
	// three added it.
	removeRoutes(prefixes []string)

	// createTUN brings up the OS TUN device the netstack bridges to.
	createTUN() (tun.Device, error)

	// configureTunInterface assigns addr/prefixLen to that device.
	configureTunInterface(addr string, prefixLen int) error

	// addSplitDefaultRoute overrides the default route without removing it
	// (0.0.0.0/1 + 128.0.0.0/1 via addr, the standard approach). Exclude mode
	// only — include mode must never call this (issue #64).
	addSplitDefaultRoute(addr string) error

	// disablePhysicalIPv6 / enablePhysicalIPv6 are parity item 6: the tunnel
	// is IPv4-only, so IPv6 is turned off on the physical adapter for its
	// lifetime rather than left as an uncovered egress path.
	disablePhysicalIPv6(ifAlias string)
	enablePhysicalIPv6(ifAlias string)

	// enableKillSwitch flips the machine to fail-closed with a narrow
	// allowlist (ADR-0014, parity item 2). It must be an OS-level filter that
	// outlives this process, not process-lifetime state. disableKillSwitch
	// lifts it; recoverKillSwitch lifts one a *crashed prior session* left
	// behind (parity item 3) and must be idempotent.
	enableKillSwitch(control, bypass []string) error
	disableKillSwitch()
	recoverKillSwitch()

	// refreshKillSwitchAllowIP folds one late-learned bypass address into the
	// live allowlist (parity item 4). Best-effort by contract: a no-op when
	// the kill-switch is not armed.
	refreshKillSwitchAllowIP(ip string)

	// captureDNS points the machine's resolver at the tunnel, so that every
	// query reaches tun2socks.go's handleDNSUDP rather than leaving by some
	// path the TUN never sees. releaseDNS puts the resolver back.
	//
	// It takes no arguments, and that is deliberate rather than incidental.
	// The interceptor rewrites every query's destination to the configured
	// upstream anyway (tun2socks.go), so the address a resolver is pointed at
	// only has to be one that lands in the TUN — which makes it something the
	// implementation derives rather than something a caller supplies. On Linux
	// that keeps ADR-0049 §2's inward vocabulary closed: no interface name and
	// no file path crosses the privilege boundary for this, because nothing
	// crosses at all.
	//
	// captureDNS returns an error and releaseDNS does not, which is the same
	// split the rest of this interface uses and for the same reason. A failed
	// capture is not a degraded tunnel, it is an unprotected resolver: on a
	// systemd-resolved machine the queries either leave in the clear or are
	// dropped by the kill-switch, and both are ADR-0039 parity item 7's
	// "silently degrading to unprotected". So bring-up unwinds. A failed
	// release is best-effort like the other teardown primitives.
	//
	// Restoring is NOT only Close's job. Whatever an implementation changes
	// must also come back when the client dies without calling anything —
	// the property recoverKillSwitch has, and the opposite of the choice the
	// kill-switch makes. A lockdown held past a crash fails closed; a resolver
	// left pointing into a dead tunnel fails to a machine with no DNS, so it
	// is restored rather than held. On Linux that recovery is the helper's own
	// (ADR-0051), which is why there is no third method here for it.
	//
	// The three platforms answer this differently and the difference is real:
	//
	//   - Linux implements it. See ADR-0051 and osnet_linux.go.
	//   - Windows does not need it, and its implementation says so and does
	//     nothing. A Windows resolver's servers are ordinary routable
	//     addresses, so its queries already meet the split-default route and
	//     enter the TUN. See routes_windows.go.
	//   - macOS does not implement this interface at all (see the package doc
	//     and ADR-0050 §5), so there is nothing to stub.
	captureDNS() error
	releaseDNS()
}
