// Orchestrates full-device routing: brings up a TUN device, points the OS
// default route at it (split-default, so the physical default route is
// preserved rather than replaced), excludes the coordinator/STUN/TURN
// endpoints — and the pool's own reality underlay addresses, learned late via
// the excluder (poolroutes.go, issue #109) — so the session's own transport
// doesn't loop into the tunnel, and bridges the adapter to the existing local
// SOCKS5 server via tun2socks.go.
//
// Split-tunnel "include" mode (splittunnel.go) inverts the middle part: no
// split-default is installed at all, and the bypass/include set gets routed
// into the tunnel adapter instead of out of it (issue #64).
//
// This is ADR-0039's "Orchestration only" row: the sequencing below is
// portable, but it used to call routes.go/killswitch.go's functions directly
// by name, which is what pinned it to Windows. It now calls them through
// osNet (osnet.go), the way poolroutes.go has always called its four injected
// primitives. Nothing about the order changed in that re-pointing, and the
// order is the part that matters — every step's rollback is deferred in
// reverse, and the defers run LIFO, so read the deferred cleanup next to the
// step it undoes rather than top to bottom.
package enforcement

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// tunIP is the client's own address on the tunnel adapter. Fixed for v1 —
// there's exactly one tunnel interface per running client, so no allocation
// scheme is needed.
const tunIP = "10.66.0.2"

type tunnel struct {
	os          osNet
	logf        func(string, ...any)
	dev         tun.Device
	nt          *netTun
	gw          gatewayInfo
	excludedIPs []string
	policy      *bypassPolicy
	excluder    *poolExcluder
	killSwitch  bool
}

func (t *tunnel) log(format string, args ...any) {
	if t.logf != nil {
		t.logf(format, args...)
	}
}

// startTunnel brings the full-device tunnel up. socksAddr is the client's
// own already-running local SOCKS5 server (core.Engine.Connect started it);
// every coordinator pool member plus cfg.STUNURL/cfg.TURNURL are excluded from
// the tunnel's route so the underlying signalling/relay session keeps flowing
// over the physical interface — the client can rotate to any pool member, so
// all of them must stay reachable outside the tunnel (issue #6), regardless of
// split-tunnel mode. cfg.DNSUpstream is the plain-DNS server queried (over
// DNS-over-TCP, through the tunnel) for every intercepted DNS query. policy is
// the destination-based split-tunnelling decision (splittunnel.go): its
// static CIDR/IP entries get a route right away and its domain entries are
// seeded with a one-time resolution now, but which *direction* that route
// goes — carved out of the tunnel, or pulled into it — depends on policy.mode
// (see the mode-branches below and splittunnel.go's file doc comment).
// pe carries the pool's dynamically-dialled reality underlay addresses (issue
// #109): any reserved before now (during the initial pooled Connect) are
// excluded here alongside the control plane, and the excluder is switched live
// so a mid-session failover excludes its new address as it dials.
// cfg.KillSwitch arms the fail-closed lockdown once the tunnel is up.
func startTunnel(osn osNet, logf func(string, ...any), cfg Policy, policy *bypassPolicy, pe *poolExcluder, socksAddr string) (_ *tunnel, err error) {
	log := func(format string, args ...any) {
		if logf != nil {
			logf(format, args...)
		}
	}
	log("[tun] bring-up start")
	gw, err := osn.defaultGateway()
	if err != nil {
		return nil, fmt.Errorf("read default route: %w", err)
	}

	// Exclude every pool member plus STUN/TURN. A fresh slice avoids appending
	// into the caller's Coordinators backing array. Always via the physical
	// gateway, in both modes — the tunnel's own signalling must never be
	// captured by its own route.
	endpoints := append([]string{}, cfg.Coordinators...)
	endpoints = append(endpoints, cfg.STUNURL, cfg.TURNURL)
	excluded := resolveExclusions(endpoints...)
	osn.addExclusionRoutes(excluded, gw)
	ok := false
	defer func() {
		if !ok {
			osn.removeRoutes(excluded)
		}
	}()

	// Exclude the pool's already-dialled reality underlays (issue #109) the same
	// way and at the same point as the control plane — before the split-default
	// route flips further down — and switch the excluder live so any failover
	// from here on excludes its own new address on the dial path. Teardown
	// re-derives the set (reserved()) rather than snapshotting now, so an address
	// a failover adds during the rest of bring-up is cleaned up too.
	pe.goLive(gw)
	defer func() {
		if !ok {
			// disable() first (issue #117): a concurrent failover reserve()
			// that races past this point self-reaps instead of installing a
			// route after this snapshot already ran and missed it.
			pe.disable()
			osn.removeRoutes(pe.reserved())
		}
	}()

	// Seed bypass domains with their current address(es) via the OS's own
	// resolver — safe here, since bypass destinations are explicitly meant to
	// be reached with the real IP rather than hidden behind the tunnel — so
	// they already have a route on the very first connection instead of
	// waiting on the DNS interceptor to observe a fresh query for them.
	for _, ip := range resolveDomains(policy.domains) {
		policy.seed(ip)
	}
	bypassEntries := append(policy.staticEntries(), policy.dynamicSnapshot()...)

	// Exclude mode's bypass set is routed via the gateway, same as the
	// control-plane endpoints above — and, like them, this must happen before
	// the split-default route exists (further down) so there's never a
	// window where bypass traffic could get captured before its exclusion
	// does. Include mode can't route its (include) set here: inclusion routes
	// bind to the tun adapter, which needs that adapter to already exist —
	// that happens later, once osn.createTUN below has run.
	if policy.mode != modeInclude {
		osn.addExclusionRoutes(bypassEntries, gw)
		defer func() {
			if !ok {
				// Re-derived rather than reusing bypassEntries: onLearn
				// (wired below) can add more dynamic entries during the rest
				// of bring-up, and dynamicSnapshot() here runs at unwind
				// time, so it picks those up too.
				osn.removeRoutes(policy.staticEntries())
				osn.removeRoutes(policy.dynamicSnapshot())
			}
		}()
	}

	// Wired before the netstack starts (rather than after) so there is no
	// window where a live DNS answer for a bypass domain could be learned
	// without its route getting installed. armed is read by learn() under the
	// same lock as the dynamic-set mutation that triggers this call, atomically
	// with respect to policy.arm() below — see splittunnel.go's arm()/learn()
	// doc comments (issue #73): this is what closes the race a plain post-hoc
	// atomic.Bool check would leave open. The route direction depends on mode:
	// include pulls the IP into the tun adapter, exclude carves it out via the
	// gateway.
	policy.onLearn = func(ip string, armed bool) {
		if policy.mode == modeInclude {
			osn.addInclusionRoutes([]string{ip}, tunIP)
		} else {
			osn.addExclusionRoutes([]string{ip}, gw)
		}
		if cfg.KillSwitch && armed {
			osn.refreshKillSwitchAllowIP(ip)
		}
	}

	log("[tun] creating tun device")
	dev, err := osn.createTUN()
	if err != nil {
		return nil, err
	}
	log("[tun] tun device created")
	defer func() {
		if !ok {
			_ = dev.Close()
		}
	}()

	if err := osn.configureTunInterface(tunIP, 24); err != nil {
		return nil, err
	}

	// Exclude mode captures everything into the tunnel and relies on the
	// gw-routed exclusions above to carve the bypass set back out. Include
	// mode does the opposite (issue #64): no split-default at all, so the
	// real default route stays authoritative for "direct" traffic, and the
	// bypass/include set is pulled in via its own tun-adapter-bound routes —
	// without this, include mode's "direct" traffic (everything not in the
	// include set) would have nothing excluding it from a split-default that
	// was still being installed unconditionally, and would loop straight back
	// into the tunnel it was supposed to avoid.
	if policy.mode == modeInclude {
		osn.addInclusionRoutes(bypassEntries, tunIP)
		// Deliberately doesn't lean on "the adapter's own teardown removes
		// its routes" here: this defer is registered *after* dev.Close()'s
		// (above), so on unwind it runs first (defers are LIFO) and removes
		// these routes explicitly while the adapter still exists — a failed
		// bring-up in include mode never depends on Windows adapter-deletion
		// semantics at all. That assumption is only actually load-bearing in
		// the success path (Close(), below, is straight-line code where
		// dev.Close() genuinely does run before the equivalent removeRoutes
		// call) — see removeRoutes' doc comment for that caveat.
		defer func() {
			if !ok {
				osn.removeRoutes(policy.staticEntries())
				osn.removeRoutes(policy.dynamicSnapshot())
			}
		}()
	} else if err := osn.addSplitDefaultRoute(tunIP); err != nil {
		return nil, err
	}

	osn.disablePhysicalIPv6(gw.ifAlias)
	defer func() {
		if !ok {
			osn.enablePhysicalIPv6(gw.ifAlias)
		}
	}()

	addr, err := v4Address(tunIP)
	if err != nil {
		return nil, err
	}
	log("[tun] starting netstack")
	nt, err := startNetstack(dev, addr, socksAddr, cfg.DNSUpstream, policy)
	if err != nil {
		return nil, err
	}
	log("[tun] netstack up")
	defer func() {
		if !ok {
			nt.Close()
		}
	}()

	// Arm the kill-switch last: only once the tunnel is actually carrying
	// traffic do we flip the machine to fail-closed. Do it before returning so
	// there is no window where routes point at the tunnel but the lockdown
	// isn't in force. policy.arm() takes a *fresh* dynamic snapshot atomically
	// with the actual arming (not the stale early bypassEntries computed above,
	// which is only safe for the earlier route-adding step) — issue #73:
	// reusing that early snapshot here left a window where a bypass IP learned
	// between startNetstack going live and this point could miss both the
	// initial allowlist and the live refresh.
	//
	// Note for include mode specifically: this still allow-lists only the
	// control-plane + bypass/include set (plus the tunnel adapter and
	// loopback) — "direct" traffic (everything else, the majority in include
	// mode) is not allow-listed, so arming the kill-switch in include mode
	// blocks it while connected, rather than leaving it alone as never-tunnelled
	// traffic. Fails safe (no leak), but is a real, undecided UX question for
	// include+kill-switch together; flagged, not solved here.
	if cfg.KillSwitch {
		// Nest the pool-allowlist arming inside the bypass arming so the pool's
		// reserved underlays and the bypass dynamic set are both snapshotted
		// atomically with the single enableKillSwitch call — each excluder's own
		// lock is held across it, so an address either lands in this snapshot or
		// is live-refreshed afterwards, never dropped (issue #73 / #109). The
		// pool underlays join the control-plane allow-list (they are as
		// load-bearing as coordinator/STUN/TURN — the session rides them), while
		// the bypass set stays in the bypass allow-list argument.
		if err := policy.arm(func(dynamicSnapshot []string) error {
			return pe.armAllowlist(func(poolIPs []string) error {
				control := append(append([]string{}, excluded...), poolIPs...)
				return osn.enableKillSwitch(control, append(policy.staticEntries(), dynamicSnapshot...))
			})
		}); err != nil {
			return nil, err
		}
	}

	ok = true
	log("[tun] bring-up complete")
	return &tunnel{
		os: osn, logf: logf, dev: dev, nt: nt, gw: gw,
		excludedIPs: excluded, policy: policy, excluder: pe, killSwitch: cfg.KillSwitch,
	}, nil
}

// Close tears the tunnel down and restores the machine's normal networking.
// The kill-switch is lifted first so egress is restored before the adapter
// and routes go away; then the netstack stops, the TUN adapter is deleted
// (expected to remove its own addresses/routes along with it — including any
// include-mode inclusion routes and, in exclude mode, the split-default
// route, all bound to the adapter — per standard Windows adapter-deletion
// semantics; see removeRoutes' doc comment for the caveat that this is an
// assumption, not verified against a live device here), IPv6 is re-enabled on
// the physical adapter, and the remaining gateway-bound routes are dropped —
// the control-plane exclusions plus, in exclude mode, the bypass set
// (including any bypass-domain routes learned after startup, not just the
// ones present when it came up). In include mode the policy's routes should
// already be gone by this point (tun-adapter-bound, removed above with the
// adapter itself), so removeRoutes is expected to be a harmless no-op for
// them — it isn't worth branching on mode just to skip it, and if the
// assumption above ever turns out wrong, this call is also the fallback that
// actually cleans them up.
func (t *tunnel) Close() {
	if t == nil {
		return
	}
	if t.killSwitch {
		t.os.disableKillSwitch()
	}
	if t.nt != nil {
		t.nt.Close()
	}
	if t.dev != nil {
		_ = t.dev.Close()
	}
	t.os.enablePhysicalIPv6(t.gw.ifAlias)
	t.os.removeRoutes(t.excludedIPs)
	if t.excluder != nil {
		// The pool's underlay exclusions (issue #109) are gateway-bound host
		// routes like the control-plane ones, so they need explicit removal too;
		// reserved() re-derives the full set, including any a failover added
		// mid-session. Kill-switch allowlist entries need no separate cleanup —
		// disableKillSwitch above removes the whole rule group. disable() first
		// (issue #117), same reasoning as startTunnel's failure-cleanup defer:
		// a failover reserve() racing this Close self-reaps if it lands after
		// the reserved() snapshot below.
		t.excluder.disable()
		t.os.removeRoutes(t.excluder.reserved())
	}
	if t.policy != nil {
		t.os.removeRoutes(t.policy.staticEntries())
		t.os.removeRoutes(t.policy.dynamicSnapshot())
	}
	t.log("[tun] torn down")
}

func v4Address(s string) (tcpip.Address, error) {
	ip := net.ParseIP(s)
	v4 := ip.To4()
	if v4 == nil {
		return tcpip.Address{}, fmt.Errorf("not an IPv4 address: %q", s)
	}
	return tcpip.AddrFrom4([4]byte(v4)), nil
}
