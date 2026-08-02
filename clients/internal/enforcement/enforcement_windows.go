//go:build windows

package enforcement

import "sync"

// New returns the Windows Enforcer. This is the enforcement the Windows tray
// client shipped from ADR-0036 until bacchus#138 retired it, and bacchus#59
// folded in here rather than rewriting. routes_windows.go and
// killswitch_windows.go are that code, near-verbatim, with their free
// functions turned into winOS methods so tunnel.go can reach them through
// osNet instead of by name; the hardening comments came across with them,
// because the reason a fix exists is the part a port drops first.
//
// It had two callers between bacchus#59 and bacchus#138 — one implementation,
// never two — and has one now. The retirement waited on evidence rather than
// on taste: enforcement folded behind this interface (bacchus#59), the two
// OS-level guarantees no Go test can assert confirmed on hardware
// (bacchus#88), and clients/fyne built for Windows by CI and driven through
// the full lifecycle on a real machine (bacchus#115). See ADR-0039.
func New() (Enforcer, error) {
	e := &windowsEnforcer{}
	// One winOS for the enforcer's whole life, built here rather than per
	// Start: the poolExcluder below binds its four primitives to it at
	// construction, and that construction happens on the first underlay dial,
	// which is before Start. Rebuilding it per session would leave the
	// excluder holding the previous one.
	e.os = &winOS{logf: e.logf}
	return e, nil
}

// newWindowsEnforcerWith is New with the OS backend supplied, so the session
// lifecycle here — which excluder a session gets, when it is released, what a
// second connect inherits — can be tested without a live route table. The
// production path is New; nothing else calls this.
func newWindowsEnforcerWith(osn osNet) *windowsEnforcer {
	return &windowsEnforcer{os: osn}
}

// windowsEnforcer is one client's enforcement across one app lifetime, not
// one tunnel. It outlives each Session because the transport pool dials its
// first reality underlay before the tunnel exists (Enforcer.ReserveUnderlay),
// so the poolExcluder that address lands in has to be owned here and handed
// down into the session, not created by it.
type windowsEnforcer struct {
	os osNet

	mu sync.Mutex
	pe *poolExcluder // current session's excluder, or the one accumulating for the next

	// logMu guards sink alone, deliberately separate from mu. winOS calls
	// logf from inside PowerShell failure paths, which run on the dial path
	// and on background gateway refreshes — taking the same lock those paths
	// might already hold would be a deadlock waiting to be discovered in the
	// field. Nothing holds logMu across an OS call.
	logMu sync.Mutex
	sink  func(string, ...any)
}

// logf is the stable method value winOS holds. It reads the current sink
// under logMu, so Start can re-point logging at a new client's logger without
// racing a live session's background refresh.
func (e *windowsEnforcer) logf(format string, args ...any) {
	e.logMu.Lock()
	sink := e.sink
	e.logMu.Unlock()
	if sink != nil {
		sink(format, args...)
	}
}

func (e *windowsEnforcer) setSink(sink func(string, ...any)) {
	e.logMu.Lock()
	e.sink = sink
	e.logMu.Unlock()
}

// excluder returns the live poolExcluder, creating one if this is the first
// underlay dial since the last teardown. Caller holds mu.
func (e *windowsEnforcer) excluderLocked() *poolExcluder {
	if e.pe == nil {
		e.pe = newPoolExcluder(e.os)
	}
	return e.pe
}

// Recover implements parity item 3. See Enforcer.Recover for why this is a
// launch-time call rather than something folded into Start.
func (e *windowsEnforcer) Recover() { e.os.recoverKillSwitch() }

// ReserveUnderlay is wired to core.Config.OnUnderlayDial for the whole app
// lifetime and forwards to the current excluder — the same one Start hands
// down to the session, so a dial before bring-up and a failover dial after it
// land in one set rather than two.
//
// Issue #109's ordering guarantee — the address is excluded *before* the dial
// that uses it, never after — comes from reserve() being synchronous on the
// dial path. That is preserved here: no queue, no goroutine, no deferred
// install, and mu is released before the call so a slow PowerShell shell-out
// cannot stall an unrelated Start or Close.
func (e *windowsEnforcer) ReserveUnderlay(addr string) {
	e.mu.Lock()
	pe := e.excluderLocked()
	e.mu.Unlock()
	pe.reserve(addr)
}

// ServesWhileRouted is false on Windows. routes_windows.go's allowServedEgress
// carries the argument: the Linux mechanism's routing half has no Windows
// equivalent, IP_UNICAST_IF is the lever that would, and bacchus#109's
// traffic-level bar is not something the Windows CI job can reach. Returning
// false keeps ErrVolunteerWhileRouted in force here rather than offering a
// checkbox whose disclosure this platform cannot yet make true.
func (e *windowsEnforcer) ServesWhileRouted() bool { return false }

// ServedSource is therefore always empty: nothing can start a serving session
// on this platform, so there is never a carve-out for core to bind to.
func (e *windowsEnforcer) ServedSource() string { return "" }

// Start brings up device-wide enforcement for one session.
func (e *windowsEnforcer) Start(policy Policy, socksAddr string) (Session, error) {
	e.setSink(policy.Logf)

	e.mu.Lock()
	pe := e.excluderLocked()
	e.mu.Unlock()

	bypass := newBypassPolicy(policy.BypassMode, policy.Bypass)
	t, err := startTunnel(e.os, e.logf, policy, bypass, pe, socksAddr)
	if err != nil {
		// Bring-up already unwound its own routes and disabled the excluder.
		// Drop it so the next connect starts from an empty set rather than
		// re-arming a kill-switch allowlist with addresses whose routes are
		// gone.
		e.mu.Lock()
		e.pe = nil
		e.mu.Unlock()
		return nil, err
	}
	return &windowsSession{enf: e, t: t, pe: pe}, nil
}

// windowsSession is one running tunnel. ReserveUnderlay and Close are the
// only two calls it needs from outside, per the seam.
type windowsSession struct {
	enf  *windowsEnforcer
	t    *tunnel
	pe   *poolExcluder
	once sync.Once
}

func (s *windowsSession) ReserveUnderlay(addr string) { s.pe.reserve(addr) }

// Close tears the tunnel down and releases the excluder, so a reconnect
// builds a fresh one instead of inheriting a set whose routes this call just
// removed. Idempotent: tunnel.Close is not, and a double Close would
// re-remove routes and re-lift a kill-switch a *newer* session may have
// armed in between.
func (s *windowsSession) Close() {
	s.once.Do(func() {
		s.t.Close()
		s.enf.mu.Lock()
		if s.enf.pe == s.pe {
			s.enf.pe = nil
		}
		s.enf.mu.Unlock()
	})
}
