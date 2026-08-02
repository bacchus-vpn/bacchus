// Package enforcement names the device-wide enforcement seam: bringing up a
// TUN device, routing the OS default route through it (or specific
// destinations, for split-tunnel "include" mode), and optionally arming a
// fail-closed kill-switch — everything clients/windows's tunnel.go,
// routes.go, killswitch.go, splittunnel.go, poolroutes.go and tun2socks.go
// (~1970 lines total) do for Windows today, as one contract instead of three
// unrelated implementations.
//
// This package is deliberately internal to clients/ (Go's internal-import
// rule: importable from clients/fyne or clients/windows, not from core/ or
// cmd/), and deliberately has no import of Fyne, walk, or appstate — the same
// "no toolkit dependency" discipline clients/fyne/internal/appstate already
// holds for connection state, one level further out: this seam is UI-neutral
// as well as OS-neutral, so whichever client eventually calls it does so
// without pulling a GUI toolchain into a routing decision.
//
// Windows is implemented (enforcement_windows.go, routes_windows.go,
// killswitch_windows.go): bacchus#35 chose "Fyne everywhere", and bacchus#59
// folded clients/windows's working, hardened enforcement in behind this
// interface. It clears all eight of ADR-0039's parity items — see that ADR's
// 2026-07-30 amendment, which records them one by one. Linux and macOS are
// still honest NotImplementedErrors (enforcement_linux.go,
// enforcement_darwin.go); writing them is [E10] (bacchus-vpn/bacchus#37) and
// [E9] (bacchus-vpn/bacchus#36), each its own card against the same bar.
//
// The bulk of what a new platform needs is already here and portable: the
// bring-up/teardown sequencing (tunnel.go), the underlay-exclusion state
// machine (poolroutes.go), split-tunnel matching and DNS learning
// (splittunnel.go), the netstack/SOCKS bridge (tun2socks.go, udprelay.go),
// address handling (addrs.go) and log redaction (redact.go). What is left is
// osNet (osnet.go) — read that file first.
package enforcement

import "fmt"

// Enforcer is the per-platform enforcement backend. New returns whichever one
// this build's GOOS has, or a NotImplementedError.
type Enforcer interface {
	// Start brings up device-wide enforcement for one session and returns a
	// Session to manage it — TUN device, OS routing per policy, and (if
	// policy.KillSwitch) a fail-closed kill-switch — mirroring
	// clients/windows/tunnel.go's startTunnel. socksAddr is the caller's
	// already-running local SOCKS5 server (core.Engine.Connect) to bridge
	// into the tunnel; Start does not start or own that server.
	//
	// An implementation that cannot honor part of policy (e.g. a platform
	// with routing but no kill-switch primitive) must fail the whole call
	// rather than silently ignore the field — the same "an honest error
	// beats a silent no-op" rule NotImplementedError follows at the package
	// level, applied to one policy field instead of the whole package.
	Start(policy Policy, socksAddr string) (Session, error)

	// Recover lifts a fail-closed lockdown left behind by a *crashed prior
	// session*, and is safe to call when there is none. This is parity item 3,
	// and it is a separate call rather than something Start does because the
	// bar says "detected and lifted on next launch" — a user whose last
	// session was killed is offline before they touch anything, so waiting
	// until they next press Connect (which is all Start could do) leaves them
	// with no network and no way to discover why. Callers run it at startup;
	// Start also runs it defensively before arming, which is a different
	// moment and does not replace this one.
	Recover()

	// ReserveUnderlay is Session.ReserveUnderlay's pre-Start half, and it
	// exists because of when core actually calls it. The transport pool dials
	// its first reality underlay during the initial Connect — before the
	// tunnel is up, so before there is a Session to hand it to (see
	// poolroutes.go: "the initial pooled Connect dials reality before
	// startTunnel runs"). A caller that wired core.Config.OnUnderlayDial to
	// the Session it does not have yet would silently drop that first
	// address, which is precisely the leak issue #109 closed. So the wiring
	// point is the Enforcer, once, for the whole session lifetime: addresses
	// reserved before Start are recorded and installed by bring-up, and
	// addresses reserved after it install live.
	ReserveUnderlay(addr string)

	// ServesWhileRouted reports whether this platform can honor
	// Policy.ServeEgress — whether a volunteered relay or exit can serve from
	// a machine this Enforcer is routing (ADR-0053, bacchus#109).
	//
	// A property of the platform, not of the moment, exactly like
	// Controller.DeviceEnforced(): it must be answerable before anything has
	// been started, because clients/fyne asks it to decide whether the
	// volunteer checkboxes are even offered, and it must give the same answer
	// when the settings window asks and when the connect path re-asks. A probe
	// would make it a property of the moment and could disagree with itself
	// across those two calls, which is how a user ticks a box that the connect
	// then refuses.
	//
	// False is the safe answer and the default for a new platform. It leaves
	// ErrVolunteerWhileRouted in force, which is where every platform started.
	ServesWhileRouted() bool

	// ServedSource is the local address a served role's own sockets must bind
	// for the carve-out to apply to them, or "" when no serving session is up.
	//
	// It is read at DIAL time rather than passed in at Start, and the ordering
	// is why: clients/fyne builds core.Config and connects the engine before it
	// starts enforcement at all, so at the moment core needs a value there is
	// no Session and no tunnel to have derived one. The engine holds this as a
	// function and asks when it opens a served socket, by which point bring-up
	// has run. Wired to the Enforcer rather than the Session for the same
	// reason ReserveUnderlay is.
	ServedSource() string
}

// Session is one running enforcement session: one TUN device, one set of OS
// routes, and — if the Policy that started it set KillSwitch — one armed
// kill-switch. Mirrors clients/windows/tunnel.go's *tunnel type plus
// poolroutes.go's *poolExcluder, which today are two separate types wired
// together by hand in tunnel.go; here they are one seam because every caller
// needs both for the life of a session.
type Session interface {
	// ReserveUnderlay excludes addr — a transport-pool underlay address the
	// client is about to dial (core.Config.OnUnderlayDial) — from the
	// tunnel's route before the dial completes, so the dial rides the
	// physical interface instead of looping into the tunnel it is carrying.
	// See clients/windows/poolroutes.go's poolExcluder and issue #109: the
	// Reality transport's exit address is only known at dial time, not in
	// advance like the WebRTC/TURN control-plane endpoints Policy already
	// carries, so it cannot be excluded up front in Start and needs this
	// separate, synchronous, dial-path hook instead. An implementation for
	// a transport pool with no such late-arriving address is free to make
	// this a no-op, but the method has to exist on the interface, or a port
	// of poolroutes.go's hardening (issues #109/#117/#123b/#123c — several
	// rounds of closing races in exactly this path) has nowhere to attach.
	ReserveUnderlay(addr string)

	// Close tears the session down: kill-switch lifted first if armed, then
	// routes removed and IPv6 restored, then the TUN device itself — the
	// same order clients/windows/tunnel.go's Close uses, and for the same
	// reason: egress must be restored before whatever was blocking it goes
	// away, not after (ADR-0014).
	Close()
}

// Policy is the platform-independent configuration one Start call carries.
// Every field mirrors an existing clients/windows concept; see routes.go,
// killswitch.go and splittunnel.go for the semantics each is expected to
// have when a real Enforcer implements this.
type Policy struct {
	// Coordinators, STUNURL and TURNURL are not dialled here — they are
	// excluded. An Enforcer must keep every pool member plus STUN/TURN
	// reachable outside the tunnel's own route (clients/windows/tunnel.go's
	// startTunnel, issue #6), the same set core.Config uses to actually
	// dial, for an unrelated reason: whichever of them the session ends up
	// using, the tunnel's own signalling must never be captured by the
	// route the tunnel itself just installed.
	Coordinators     []string
	STUNURL, TURNURL string

	// DNSUpstream is the plain-DNS server queried over DNS-over-TCP through
	// the tunnel for every intercepted DNS query (clients/windows/
	// tun2socks.go's handleDNSUDP). Deliberately never resolved in the
	// clear: see killswitch.go's file doc on why there is no plaintext-DNS
	// kill-switch allowance either.
	DNSUpstream string

	// Bypass and BypassMode are destination-based split tunnelling
	// (clients/windows/splittunnel.go). BypassMode is "exclude" (listed
	// destinations go direct, default) or "include" (listed destinations
	// are the only thing tunnelled) — see BypassModeExclude/BypassModeInclude.
	// Entries are IPs, CIDRs, or domain names, exactly as splittunnel.go's
	// newBypassPolicy classifies them; this package does not itself define a
	// shared bypass-mode type with clients/fyne/internal/appstate.Config
	// (which has its own BypassModeExclude/BypassModeInclude for the same
	// string values) or with clients/windows/splittunnel.go's own unexported
	// modeExclude/modeInclude — three independent definitions of the same two
	// strings today, and unifying them is a naming cleanup this decision does
	// not need to make.
	Bypass     []string
	BypassMode string

	// KillSwitch requests a fail-closed lockdown (ADR-0014): if the tunnel —
	// or the whole process — dies, nothing egresses in the clear until it is
	// explicitly restored. See killswitch_windows.go.
	KillSwitch bool

	// ServeEgress asks for a volunteered relay or exit's OWN egress to be
	// carved out of the tunnel this session installs, so the machine can serve
	// other people while routing itself (ADR-0053, bacchus#109).
	//
	// It is the one field here that widens what the machine may do rather than
	// narrowing it, and Start must fail rather than ignore it — the rule this
	// interface already states, with more than usual riding on it. Ignoring
	// KillSwitch would leave a user less protected than they asked; ignoring
	// this leaves other people's traffic egressing through the tunnel under the
	// UPSTREAM exit's address while the exit checkbox in the settings window
	// says "under YOUR own IP and jurisdiction". A volunteer would be accepting
	// a legal exposure they do not have, and somebody else's traffic would be
	// laundering through an exit its operator never agreed to carry it for.
	// That is worse than the feature being unavailable, which is why
	// clients/fyne refuses to offer it at all where this cannot be honored.
	ServeEgress bool

	// Logf, if set, receives this package's own bring-up/teardown progress
	// and any OS-command failure. Injected rather than called by name because
	// the two clients log to different places — clients/windows to
	// bacchus.log (eventlog.go), clients/fyne to its own sink — and neither
	// is importable from here. Nil is fine and means "discard".
	//
	// Whatever this points at, an implementation must redact addresses out of
	// what it passes (redact.go): a client's log is a disk file a user may
	// hand over for support, and this package's messages carry coordinator,
	// exit and relay addresses as literal command arguments (issue #140).
	Logf func(format string, args ...any)
}

// BypassMode values — see Policy.BypassMode.
const (
	BypassModeExclude = "exclude"
	BypassModeInclude = "include"
)

// NotImplementedError is what New returns on a platform with no Enforcer
// yet: an honest, typed refusal rather than a silent no-op or a
// missing-symbol build break, matching
// clients/fyne/internal/appstate.ErrLaunchOnBootUnsupported's convention
// (autostart_other.go) one level up, with the tracking issue attached since
// there are two of these rather than one catch-all.
type NotImplementedError struct {
	GOOS  string // runtime.GOOS of the build this was returned from
	Issue string // tracking issue for the missing implementation
}

func (e NotImplementedError) Error() string {
	return fmt.Sprintf("device-wide enforcement is not implemented on %s yet (see %s)", e.GOOS, e.Issue)
}
