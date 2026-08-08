// Late underlay-address exclusion for the transport pool (old #109).
//
// The full-device tunnel keeps its own control plane reachable by excluding a
// fixed, known-ahead-of-time set of addresses (coordinator/STUN/TURN) from the
// split-default route before that route flips (tunnel.go / routes.go). WebRTC
// fits that model for free: ForceRelay pins every pooled candidate to the one
// configured TURN server, whose address is already in that set. Reality does
// not — its exit dial address arrives only in the per-session coordinator
// answer, at Dial time (core/transport_reality.go), so there is nothing fixed
// to exclude in advance. Without an exclusion, a reality underlay connection
// would follow the split-default straight back into the tunnel it is carrying
// (a loop, and — once the kill-switch is armed — a Block), which is exactly why
// old #75 shipped webrtc-only.
//
// poolExcluder closes that gap. core.Config.OnUnderlayDial hands it each
// reality underlay address the instant the transport has learned it but BEFORE
// the underlay connection is opened; poolExcluder makes that address
// tunnel-safe (a host-route exclusion via the physical gateway, plus a
// kill-switch allowlist entry) before returning, so the connection below rides
// the physical interface instead of the tunnel. Because that happens on the
// dial path — not after the pool commits a winner — a mid-session failover to a
// new exit excludes its address as it dials it, never after, so the "route flip
// races the real address" leak never reopens.
//
// The arm/allowlist timing mirrors splittunnel.go's arm()/learn() (old #73):
// a reserve() that lands in the narrow window around kill-switch arming must end
// up either in the initial allowlist snapshot or on the live-refresh path, never
// neither. reserve() and armAllowlist() take the same lock across their whole
// critical section for exactly that reason.
//
// Hardening (old #117), all fail-closed before this change and additive now:
//
//   - reserve()'s live-install path keeps the physical gateway fresh via a
//     background refresh (triggerGatewayRefresh) rather than trusting the
//     snapshot goLive cached forever, so a mid-session physical-network
//     change (the laptop roams to a new Wi-Fi network) doesn't route a new
//     exclusion via a gateway that no longer exists indefinitely. goLive's
//     own initial batch install is unaffected: its gw parameter is already
//     fresh, resolved instead by startTunnel moments before calling it. (This
//     bullet originally had reserve() re-resolve synchronously on every live
//     install; old #123c moved that off the dial path itself — see
//     triggerGatewayRefresh's doc comment.)
//   - reserve() no longer holds mu across the excludeFn/allowFn shell-outs
//     (mirroring the old #73 single-lock discipline for the *recording*, not the
//     I/O): a slow PowerShell call must not stall a concurrent reserve() or
//     the arm/teardown snapshot.
//   - Narrowing that lock reopens a race the old whole-call lock incidentally
//     closed: startTunnel's failure cleanup (or tunnel.Close()) can snapshot
//     reserved() and remove those routes while a concurrent reserve()'s
//     install — already past its own recording step, now unlocked — is still
//     in flight, landing after the snapshot and orphaning a route nothing is
//     tracking. disable() plus reserve()'s post-install closed check close
//     that window: any install that lands after teardown's snapshot self-reaps
//     — and (old #123b) that same post-lock closed read now also gates
//     allowFn, so a kill-switch allow rule is never installed for an address
//     whose route install we already know raced past teardown.
//   - reserve() also resolves IPv6 addresses (resolveExclusionsV6) and dispatches
//     to addExclusionRoutesV6 for one, defense in depth against physical IPv6
//     ever being reachable while the tunnel is up (today it is not —
//     disablePhysicalIPv6 — so this closes a gap that would otherwise open the
//     day that changes, not a currently reachable leak).
package enforcement

import (
	"sync"
)

// poolExcluder tracks the pool's dynamically-dialled underlay addresses and
// keeps each one excluded from the full-device tunnel. All state transitions
// hold mu so reserve() is atomic with respect to goLive()/armAllowlist() —
// specifically, the *recording* of which IPs are reserved/armed/closed; the
// actual route/firewall I/O for a live install runs unlocked (old #117).
type poolExcluder struct {
	mu           sync.Mutex
	gw           gatewayInfo     // physical default gateway; set by goLive, kept fresh in the background by triggerGatewayRefresh (old #117/#123c)
	routesLive   bool            // gateway known — reserve() installs routes immediately
	armed        bool            // kill-switch armed — reserve() live-refreshes the allowlist
	closed       bool            // bring-up failed, or the tunnel is tearing down — reserve() self-reaps any install racing past that cleanup (old #117)
	seen         map[string]bool // dialled underlay IPs already excluded (dedup)
	gwRefreshing bool            // a background gatewayFn call is already in flight — dedups triggerGatewayRefresh (old #123c)

	// excludeFn / allowFn are the actual route + kill-switch-allowlist side
	// effects, injected so the ordering logic here is testable without shelling
	// out to real routes/firewall (the same reason bypassPolicy takes onLearn).
	// gatewayFn re-resolves the physical gateway, called only from the
	// background triggerGatewayRefresh (old #123c), never synchronously from
	// reserve(); removeFn reaps a route reserve() installed into a
	// since-disabled excluder (old #117). All four injected for the same
	// reason: testable ordering/self-reap logic without a real Windows route
	// table. newPoolExcluder wires them to the platform's osNet (osnet.go).
	excludeFn func(gw gatewayInfo, ip string)
	allowFn   func(ip string)
	gatewayFn func() (gatewayInfo, error)
	removeFn  func(ips []string)
}

// newPoolExcluder wires the four injected primitives to osn. This is the
// "only the wiring changes per platform" half of ADR-0039's poolroutes.go row
// — the state machine above it is untouched, and every one of the four still
// arrives as a function value rather than being called by name, so the
// existing tests that drive the old #109/#117/#123b/#123c orderings keep working
// against fakes with no osNet at all.
func newPoolExcluder(osn osNet) *poolExcluder {
	return &poolExcluder{
		seen: map[string]bool{},
		excludeFn: func(gw gatewayInfo, ip string) {
			if isIPv6Literal(ip) {
				osn.addExclusionRoutesV6([]string{ip}, gw)
			} else {
				osn.addExclusionRoutes([]string{ip}, gw)
			}
		},
		allowFn:   osn.refreshKillSwitchAllowIP,
		gatewayFn: osn.defaultGateway,
		removeFn:  osn.removeRoutes,
	}
}

// reserve is wired as core.Config.OnUnderlayDial: called synchronously on the
// client dial path with the exit's underlay host:port, just before the pool
// opens a connection to it. It makes each resolved address tunnel-safe before
// returning — a host-route exclusion via the physical gateway and, when the
// kill-switch is armed, an allowlist entry — so the dial that follows this call
// can't loop into or be blocked by the tunnel. Idempotent per IP: a reality
// session re-dials the same address for every stream, and this must stay cheap
// after the first time.
//
// Before the tunnel is up (routesLive still false — the initial pooled Connect
// dials reality before startTunnel runs) it only records the address; goLive
// installs those routes, and armAllowlist folds them into the initial allowlist,
// as part of bring-up. After bring-up (a failover) it installs live.
func (p *poolExcluder) reserve(addr string) {
	// Resolve before taking the lock: a hostname answer would need DNS, which
	// must not stall a concurrent reserve() or the arm snapshot. Real exits
	// advertise a literal IP, so in practice this parses rather than looks up
	// (resolveExclusions returns the IP unchanged). A hostname that can't be
	// resolved — e.g. under an armed kill-switch, where DNS itself is blocked —
	// yields nothing here, so the dial proceeds unexcluded and simply fails into
	// the tunnel (fail-safe: it never leaks), the same posture the control-plane
	// exclusions already take when one fails to resolve. Both address families
	// are resolved (old #117); in practice a real exit's address is one or
	// the other, never both.
	ips := append(resolveExclusions(addr), resolveExclusionsV6(addr)...)
	if len(ips) == 0 {
		return
	}

	p.mu.Lock()
	var toInstall []string
	for _, ip := range ips {
		if p.seen[ip] {
			continue
		}
		p.seen[ip] = true
		if p.routesLive {
			toInstall = append(toInstall, ip)
		} // else pre-tunnel: goLive() installs this IP's route
	}
	gw, armed, closed := p.gw, p.armed, p.closed
	p.mu.Unlock()
	if closed || len(toInstall) == 0 {
		return
	}

	// Keep p.gw current for whoever reserves next, without this call waiting
	// on it (old #123c): a live install uses whatever gw the snapshot above
	// just read — goLive's seed, or a prior background refresh — rather than
	// shelling out to PowerShell itself on the dial path. See
	// triggerGatewayRefresh's doc comment for the staleness trade-off this
	// makes.
	p.triggerGatewayRefresh()

	for _, ip := range toInstall {
		// Route first: fails safe either way (a missing route loops the dial
		// into the tunnel), so this only has to land before returning, not in
		// a particular order relative to the allowlist below. Doesn't hold mu
		// (old #117): a slow PowerShell call must not stall a concurrent
		// reserve() or the arm/teardown snapshot it could otherwise block.
		p.excludeFn(gw, ip)

		p.mu.Lock()
		closedNow := p.closed
		p.mu.Unlock()
		if closedNow {
			// Bring-up already failed (or the tunnel already tore down) and
			// took its final removeRoutes(reserved()) snapshot before this
			// install landed — reap the route now instead of leaving an
			// orphaned one nothing is tracking (old #117), and skip the
			// allowlist entry below entirely: installing a firewall rule for
			// an address we already know raced past teardown just leaves a
			// duplicate-DisplayName rule for the next teardown's group sweep
			// to clean up, with no self-reap of its own (old #123b).
			p.removeFn([]string{ip})
			continue
		}
		if armed {
			p.allowFn(ip)
		}
	}
}

// triggerGatewayRefresh kicks off a background re-resolve of the physical
// gateway if one isn't already in flight, and returns immediately either way
// — reserve() never blocks on it (old #123c). A successful refresh updates
// p.gw for the next reserve() to read; a failed one (a transient PowerShell
// hiccup) leaves p.gw exactly as it was, the same last-known-good fallback
// reserve()'s old synchronous re-resolve used (old #117).
//
// This trades reserve()'s previous "always fresh, synchronously, on every
// live install" guarantee for "fresh as of the most recent reserve() call
// before this one" — at most one live install after a physical-network
// change (the laptop roams to a new Wi-Fi network) can still route via the
// stale gateway. That one dial fails exactly like any other missed exclusion
// (fail-closed, not a leak — see reserve()'s doc comment), and the pool's own
// failover retries moments later, by which point this refresh has landed.
// What old #117 actually protected against — an indefinitely stale gateway,
// never re-resolved for the rest of the session — is unchanged: every live
// install still triggers a refresh, so staleness never persists past one
// call.
func (p *poolExcluder) triggerGatewayRefresh() {
	p.mu.Lock()
	if p.gwRefreshing {
		p.mu.Unlock()
		return
	}
	p.gwRefreshing = true
	p.mu.Unlock()

	go func() {
		fresh, err := p.gatewayFn()
		p.mu.Lock()
		if err == nil {
			p.gw = fresh
		}
		p.gwRefreshing = false
		p.mu.Unlock()
	}()
}

// disable marks the excluder torn down: called once bring-up has failed, or
// the tunnel is closing, right before that path takes its final
// removeRoutes(reserved()) snapshot (old #117). Any reserve() install
// already past its recording step and in flight, unlocked, at that moment
// self-reaps via the closed check at the end of reserve()'s install loop,
// instead of leaving an orphaned route the snapshot missed. Idempotent (a
// plain flag under the lock); safe to call at most once per real teardown in
// practice, since a poolExcluder is created fresh per connect() and torn down
// on exactly one of the failure or Close paths, never both.
func (p *poolExcluder) disable() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
}

// goLive records the physical gateway, installs exclusion routes for every
// address reserved so far, and switches reserve() into live-install mode. It is
// called from startTunnel once the gateway is known and BEFORE the split-default
// route flips, so the pool's already-dialled underlays are carved out before the
// tunnel can capture them — exactly like the control-plane exclusions alongside
// it. Holding mu across the installs keeps a concurrent failover reserve() from
// observing routesLive before these routes exist.
func (p *poolExcluder) goLive(gw gatewayInfo) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gw = gw
	p.routesLive = true
	for ip := range p.seen {
		p.excludeFn(gw, ip)
	}
}

// armAllowlist snapshots the reserved addresses and hands them to install (which
// builds them into the kill-switch's initial allowlist), then marks the excluder
// armed so any address reserved afterwards is live-refreshed into the allowlist
// instead. install runs while mu is held, so — mirroring bypassPolicy.arm
// (old #73) — no reserve() can slip between "the snapshot install sees" and "armed
// becomes true": a racing reserve() either already added its IP to p.seen (so
// it's in this snapshot) or observes armed already true and refreshes live. It is
// nested inside bypassPolicy.arm at the call site so both dynamic sets feed one
// enableKillSwitch call atomically. Only called when the kill-switch is enabled.
func (p *poolExcluder) armAllowlist(install func(poolIPs []string) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := install(p.ipsLocked()); err != nil {
		return err
	}
	p.armed = true
	return nil
}

// reserved returns a snapshot of every underlay IP excluded so far, for
// teardown (removeRoutes) — both the clean-up on a failed bring-up and Close.
// Re-derived at call time so it picks up addresses a failover added after
// bring-up, not just the ones present when the tunnel came up.
func (p *poolExcluder) reserved() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.ipsLocked()
}

// ipsLocked returns the reserved IP set as a slice. Caller holds mu.
func (p *poolExcluder) ipsLocked() []string {
	out := make([]string, 0, len(p.seen))
	for ip := range p.seen {
		out = append(out, ip)
	}
	return out
}
