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
// It exists to be implemented, not to be complete. New returns an honest
// NotImplementedError on every platform today (see enforcement_linux.go,
// enforcement_darwin.go) — writing a real implementation is [E9] (macOS,
// bacchus-vpn/bacchus#36) and [E10] (Linux, bacchus-vpn/bacchus#37), each
// its own card, not this package. See docs/adr/0039-cross-platform-fyne-
// client-in-process-core.md's 2026-07-28 amendment for the parity bar an
// implementation has to clear before clients/windows retires in favor of
// one, if it ever does — that is still an open question this package does
// not answer, and Windows deliberately has no stub here: clients/windows
// already has a complete, hardened, working implementation of this shape
// outside this interface, so "not implemented" would be false for it, and
// which of Fyne's two options folds it in behind this seam or leaves it
// exactly where it is is the amendment's decision to make, not this file's.
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
	// explicitly restored. See clients/windows/killswitch.go.
	KillSwitch bool
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
