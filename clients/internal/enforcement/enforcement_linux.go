//go:build linux

package enforcement

import (
	"errors"
	"fmt"
	"sync"

	"github.com/bacchus-vpn/bacchus/cmd/bacchus-netd/netdwire"
)

// ErrHelperUnreachable is what every path returns when bacchus-netd cannot be
// reached. It is a distinct error rather than a wrapped dial failure because
// clients/fyne shows the user a different sentence for it: "not installed" is
// something they can fix, and it is by far the most likely way for enforcement
// to fail on Linux.
var ErrHelperUnreachable = errors.New("bacchus-netd is not reachable")

// ErrHelperBusy is a second client trying to enforce while one already is
// (ADR-0049 §3.2). A separate error for the same reason: the user's action is
// to close the other Bacchus, not to install anything.
var ErrHelperBusy = errors.New("another Bacchus session already holds device-wide enforcement")

// ErrHelperVersion is a helper and a GUI that disagree on the protocol.
// ADR-0049's Consequences require this to be a refusal rather than a
// negotiation: "a client that silently loses the kill-switch because the helper
// is old is parity item 7's failure mode wearing a version skew."
var ErrHelperVersion = errors.New("bacchus-netd and this client speak different protocol versions")

// translateRefusal maps a protocol refusal onto the errors above, so callers
// branch on a value instead of matching message text.
func translateRefusal(err error) error {
	var perr *netdwire.ProtocolError
	if !errors.As(err, &perr) {
		return err
	}
	switch perr.Code {
	case netdwire.CodeBusy:
		return fmt.Errorf("%w: %s", ErrHelperBusy, perr.Message)
	case netdwire.CodeVersion:
		return fmt.Errorf("%w: %s", ErrHelperVersion, perr.Message)
	case netdwire.CodeDenied:
		return fmt.Errorf("%w: %s", ErrHelperUnreachable, perr.Message)
	default:
		return err
	}
}

// New returns the Linux Enforcer. As of bacchus#37 this is real: ADR-0049's
// root helper (cmd/bacchus-netd) owns the privileged half, osnet_linux.go is
// the client for it, and everything between them — tunnel.go's bring-up
// ordering, poolroutes.go's underlay-exclusion state machine, splittunnel.go,
// tun2socks.go, addrs.go and redact.go — is portable code Linux inherits rather
// than reimplements.
//
// # Why this does not probe for the helper
//
// New succeeds whether or not bacchus-netd is installed, and Start is where an
// unreachable helper surfaces. That is deliberate, and it is the opposite of
// what a "fail early" instinct suggests.
//
// Controller.DeviceEnforced() is `c.enf != nil`, and its doc calls it "a
// property of the platform, not of the moment" — which is what makes it safe to
// call from an OnState callback. Probing a socket here would make it a property
// of the moment: the same build would report device-wide enforcement or not
// depending on whether a socket-activated unit happened to answer during
// startup. Worse, it would fail in the direction the parity bar exists to
// forbid — a probe that failed would leave DeviceEnforced() false, the UI
// saying "Proxy ready", and the user quietly unprotected on a machine that was
// supposed to route everything.
//
// So the platform's answer is fixed at build time and the session's answer is
// decided by Start, which fails loudly. ADR-0049's Consequences require exactly
// that: clients/fyne must fail the connect when the helper is unreachable,
// never fall back to a working SOCKS proxy under a "Protected" banner.
func New() (Enforcer, error) {
	e := &linuxEnforcer{}
	// One linuxOS for the enforcer's whole life, built here rather than per
	// Start, for the reason the Windows enforcer does the same: the
	// poolExcluder binds its four primitives to it at construction, and that
	// construction happens on the first underlay dial, which is before Start.
	e.os = &linuxOS{logf: e.logf}
	return e, nil
}

// newLinuxEnforcerWith is New with the OS backend supplied, so the session
// lifecycle here can be tested without a live helper. The production path is
// New; nothing else calls this.
func newLinuxEnforcerWith(os *linuxOS) *linuxEnforcer {
	return &linuxEnforcer{os: os}
}

// linuxEnforcer is one client's enforcement across one app lifetime, not one
// tunnel — the same shape as windowsEnforcer, and for the same reason: the
// transport pool dials its first reality underlay before the tunnel exists, so
// the poolExcluder that address lands in has to outlive each session.
type linuxEnforcer struct {
	os *linuxOS

	mu sync.Mutex
	pe *poolExcluder

	// servedSrc is the current serving session's carve-out source, guarded by
	// mu and read from core's dial path (ServedSource). Held on the enforcer
	// rather than the session because that is where core.Config's hook is
	// wired, one connect earlier than any session exists.
	servedSrc string

	// logMu guards sink alone, deliberately separate from mu. linuxOS calls
	// logf from silent-method failure paths, which run on the dial path and on
	// background gateway refreshes; taking the same lock those paths might hold
	// would be a deadlock waiting to be found in the field.
	logMu sync.Mutex
	sink  func(string, ...any)
}

func (e *linuxEnforcer) logf(format string, args ...any) {
	e.logMu.Lock()
	sink := e.sink
	e.logMu.Unlock()
	if sink != nil {
		sink(format, args...)
	}
}

func (e *linuxEnforcer) setSink(sink func(string, ...any)) {
	e.logMu.Lock()
	e.sink = sink
	e.logMu.Unlock()
}

func (e *linuxEnforcer) excluderLocked() *poolExcluder {
	if e.pe == nil {
		e.pe = newPoolExcluder(e.os)
	}
	return e.pe
}

// Recover implements parity item 3. Unlike Windows this needs a connection, so
// it opens one, asks, and closes it again — a launch-time call on a machine
// where the helper may not be installed at all must not be the thing that fails
// the launch, so an unreachable helper here is silent. A stale lockdown that
// goes unlifted because the helper is missing is not a state this client could
// have created in the first place.
func (e *linuxEnforcer) Recover() {
	if err := e.os.connect(); err != nil {
		return
	}
	defer e.os.close()
	e.os.recoverKillSwitch()
}

// ReserveUnderlay forwards to the current excluder. Old #109's ordering
// guarantee — the address is excluded BEFORE the dial that uses it — comes from
// reserve() being synchronous on the dial path, and that is preserved here: no
// queue, no goroutine, and mu is released before the call so a slow socket
// round trip cannot stall an unrelated Start or Close.
func (e *linuxEnforcer) ReserveUnderlay(addr string) {
	e.mu.Lock()
	pe := e.excluderLocked()
	e.mu.Unlock()
	pe.reserve(addr)
}

// Start brings up device-wide enforcement for one session.
func (e *linuxEnforcer) Start(policy Policy, socksAddr string) (Session, error) {
	e.setSink(policy.Logf)

	// The session with the helper opens here and closes with the tunnel. An
	// unreachable helper fails the whole call — there is no degraded mode to
	// fall into, by design.
	if err := e.os.connect(); err != nil {
		return nil, err
	}

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
		// End the helper session too, or the next attempt meets our own
		// abandoned session as EBUSY and can never succeed.
		e.os.close()
		return nil, err
	}
	e.mu.Lock()
	e.servedSrc = t.servedSource
	e.mu.Unlock()
	return &linuxSession{enf: e, t: t, pe: pe}, nil
}

// ServesWhileRouted is true on Linux as of bacchus#109: ADR-0053's carve-out is
// a fib rule and an nftables allowance, both installed by bacchus-netd from
// values it derives itself, and the helper's protocol version gates a client
// that expects them against one that cannot do them.
func (e *linuxEnforcer) ServesWhileRouted() bool { return true }

func (e *linuxEnforcer) ServedSource() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.servedSrc
}

type linuxSession struct {
	enf  *linuxEnforcer
	t    *tunnel
	pe   *poolExcluder
	once sync.Once
}

func (s *linuxSession) ReserveUnderlay(addr string) { s.pe.reserve(addr) }

// Close tears the tunnel down and then ends the helper session.
//
// The order matters and it is not interchangeable. tunnel.Close lifts the
// kill-switch, removes routes and restores IPv6 — every one of which is a
// request to the helper — so the helper session must still be open while it
// runs. Closing the connection first would leave the helper reading EOF as a
// crash and HOLDING the lockdown, which is exactly right for a crash and
// exactly wrong for a clean disconnect.
func (s *linuxSession) Close() {
	s.once.Do(func() {
		s.t.Close()
		s.enf.os.close()
		s.enf.mu.Lock()
		if s.enf.pe == s.pe {
			s.enf.pe = nil
		}
		// Cleared unconditionally, unlike the excluder above: a stale source
		// here would have core bind an address whose carve-out no longer
		// exists, which is the failure this whole change is about, one
		// disconnect late.
		s.enf.servedSrc = ""
		s.enf.mu.Unlock()
	})
}
