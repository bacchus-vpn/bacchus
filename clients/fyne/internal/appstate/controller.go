package appstate

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/bacchus-vpn/bacchus/clients/internal/enforcement"
	"github.com/bacchus-vpn/bacchus/core"
)

// Controller drives one core.Engine across a connect/disconnect lifecycle and
// republishes state as it changes, via OnState/OnDetail. It has no Fyne
// dependency at all - the outer package is the only place that touches widgets,
// and main.go wires OnState/OnDetail through fyne.Do (never fyne.DoAndWait) so
// updates always land on Fyne's UI goroutine regardless of which goroutine called
// them from here. That split is the seam issues
// #148/#149 spiked: it is what makes the state machine itself unit- and
// integration-testable with no display driver at all (controller_test.go
// exercises a real core.Engine over a loopback fake coordinator, driven
// exactly the way ui.go drives it).
//
// OnState/OnDetail are always invoked from a goroutine Controller itself
// spawned (Connect and Disconnect each start one), never synchronously from
// the caller's own stack - so a caller on the UI goroutine (a button's
// OnTapped) never re-enters itself through these callbacks.
type Controller struct {
	cfg Config

	OnState  func(ConnState)
	OnDetail func(string)

	// Logf, if set, receives this client's own diagnostics and everything the
	// enforcement layer logs (route installs that failed, kill-switch
	// arming). Not the detail line: that is one calm user-facing sentence,
	// and OS-command failures are neither calm nor actionable by a user.
	// Whatever this points at, enforcement redacts addresses before writing
	// (issue #140).
	Logf func(format string, args ...any)

	// enf is this client's OS enforcement backend, or nil on a platform that
	// has none yet. Set once in NewController and never written again, so it
	// is safe to read without the lock — which matters, because the UI reads
	// it from inside an OnState callback that runs with c.mu held.
	enf enforcement.Enforcer

	mu     sync.Mutex
	eng    *core.Engine
	cancel context.CancelFunc
	sess   enforcement.Session
	state  ConnState

	// gen identifies the current connect attempt. Connect and Disconnect each bump
	// it, and an attempt may only install or abandon shared state while its own
	// generation is still current.
	//
	// It does not CANCEL an in-flight connect — nothing does; c.cancel is nil until an
	// attempt installs, so Disconnect has nothing to cancel yet and connectAsync runs
	// to completion regardless. What gen does is make that attempt's OUTCOME inert:
	// it finishes, finds itself stale, stops its own engine, and touches nothing.
	// That was survivable while SocksAddr was an ephemeral port, because two
	// attempts got two ports and never met. Pinning the port (see SocksAddr, and it
	// had to be pinned) made them collide: Connect -> Disconnect -> Connect leaves
	// two attempts racing to bind 1080, the loser's Start fails, and its abort would
	// nil out c.eng — orphaning the WINNER's live engine. The UI then reads
	// Disconnected with eng == nil, Disconnect is a no-op, 1080 is held forever by a
	// tunnel nothing is tracking, and every later Connect fails. Bricked until
	// restart, with a live session the user cannot see or stop.
	//
	// So the rule is: a stale attempt cleans up after ITSELF and touches nothing
	// else.
	gen uint64
}

func NewController(cfg Config) *Controller {
	c := &Controller{cfg: cfg}
	// A platform with no Enforcer yet returns a NotImplementedError, and that
	// is not a failure to report — it is this client's pre-bacchus#59 posture,
	// which is proxy-only and says so (see DeviceEnforced). Windows has one
	// (bacchus#59); Linux has one as of bacchus#37; [E9] (macOS, bacchus#36) is
	// what gives the last platform theirs.
	if enf, err := enforcement.New(); err == nil {
		c.enf = enf
		// Parity item 3, at the only moment it works: a lockdown left behind by
		// a killed prior session has the user offline before they touch
		// anything, so this cannot wait until they press Connect.
		enf.Recover()
	}
	return c
}

// newProxyOnlyController is NewController with no Enforcer, which is the
// posture of a platform that has none — macOS today ([E9], bacchus#36).
//
// It exists because the tests that assert what "Protected" MEANS have to reach
// Protected, and on a platform with an Enforcer that now requires enforcement
// to actually come up. Before bacchus#37 those tests got this posture on Linux
// for free; the Linux Enforcer is exactly what took it away, so the seam that
// replaces it belongs in the same change.
//
// It is a narrowing, and the honest statement of what it costs is: these tests
// no longer exercise the enforced connect path on Linux. What they still
// exercise is the half they were written for — that reaching Protected means
// the SOCKS tunnel genuinely carries bytes — which is a real configuration on
// every platform and the only one on macOS. The enforced path is covered
// instead where it can be covered against a real kernel, in
// cmd/bacchus-netd's namespace tests — and, as of issue #112, at this seam by
// newEnforcedController below, which supplies a fake Enforcer. A
// controller-level test of the FULL enforced connect would still need a live
// helper, a network namespace and a real coordinator in one process; that is
// not built here and is named in the PR rather than implied.
func newProxyOnlyController(cfg Config) *Controller {
	return &Controller{cfg: cfg}
}

// newEnforcedController is NewController with the Enforcer supplied, so the
// enforced connect path — the one bacchus#37 gave Linux, and the one
// the Windows tray client had from bacchus#59 — can be driven at this seam with
// no live bacchus-netd. It mirrors NewController exactly, Recover() included,
// so what a test drives is the object production builds rather than a
// near-miss of it. The production path is NewController; nothing else calls
// this.
//
// It is the other half of newProxyOnlyController, and it is a narrowing too.
// The honest statement of what it costs is: the Enforcer is a fake, so nothing
// BELOW this seam is checked by it — no TUN, no routes, no kill-switch, and no
// evidence that a packet goes anywhere. That half is covered where it can be:
// against a real kernel in cmd/bacchus-netd's namespace tests, and against the
// real cmdlet sequences in clients/internal/enforcement.
//
// What this reaches that neither of those can is the CONTROLLER's own
// behaviour on the enforced path — a failed Start aborting the connect instead
// of leaving a working proxy under a banner (parity item 7), each helper
// failure keeping its own sentence, disconnect and reconnect unwinding and
// re-arming through here, and DeviceEnforced staying a property of the
// platform across a session that failed.
//
// Still not built, and named rather than implied: the FULL enforced connect,
// which needs a live helper, a network namespace and a real coordinator
// co-resident in one process. Issue #112 holds that as a separate judgement.
func newEnforcedController(cfg Config, enf enforcement.Enforcer) *Controller {
	c := &Controller{cfg: cfg, enf: enf}
	enf.Recover()
	return c
}

// DeviceEnforced reports whether a Protected session on this build routes the
// whole device, or only what is pointed at SocksAddr.
//
// It is a property of the platform, not of the moment, which is what makes it
// safe to call from an OnState callback (the caller holds c.mu; this touches
// no locked state). The per-session question collapses into it: when an
// Enforcer exists, connectAsync refuses to reach Protected unless enforcement
// actually came up — a failed Start aborts rather than falling back to
// proxy-only. That refusal is parity item 7. Silently degrading to
// unprotected is the single failure mode the whole bar exists to rule out,
// and "the user gets a working proxy instead" is exactly what that failure
// would look like from the inside.
//
// So: false means the UI must keep saying "Proxy ready" and naming what is
// and is not covered (ADR-0039's Scope). True means it has earned the word
// "Protected" — the same word the Windows tray client was always entitled to,
// through the same code.
func (c *Controller) DeviceEnforced() bool { return c.enf != nil }

// VolunteeringRefused reports whether the volunteer opt-ins must be refused on
// this build: it routes the whole device AND cannot carve a served role's own
// egress back out of the tunnel it installs (bacchus#109, ADR-0053).
//
// The two halves are asked separately because as of #109 they have different
// answers. Before it, "routes the device" implied "cannot serve", so
// DeviceEnforced() was the whole question — and once #37 gave Linux an
// Enforcer, that made the GUI volunteer toggles reachable on no platform that
// ships. Now Linux carves the egress out and Windows does not, so the question
// that decides the toggles is the second half, not the first.
//
// Like DeviceEnforced this is a property of the platform rather than of the
// moment, and for the same reason: the settings window asks it to decide
// whether to offer the checkboxes at all, and connectAsync asks it again
// against whatever is on disk. Two different answers to one user's one choice
// is how a box gets ticked that the connect then refuses.
func (c *Controller) VolunteeringRefused() bool {
	return c.enf != nil && !c.enf.ServesWhileRouted()
}

// servedSourceHook is what core asks, per served socket, for the local address
// to bind (core.Config.ServedSource). nil on a platform with no Enforcer, which
// core treats as "bind nothing" — the proxy-only case, where there is no tunnel
// for served traffic to be caught by and nothing to carve out of it.
func (c *Controller) servedSourceHook() func() string {
	if c.enf == nil {
		return nil
	}
	return c.enf.ServedSource
}

func (c *Controller) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// SocksAddr is where this client's SOCKS5 proxy listens, and it is FIXED rather
// than OS-assigned because the whole value of the tunnel is that something can
// reach it. This client does no OS-level routing — no TUN, no route flip, no
// system proxy configuration (see the ADR's Scope) — so the proxy address is the
// entire interface between the tunnel and the user's traffic. An ephemeral port
// (":0") would be unknowable: core exposes no accessor for the bound address, and
// even its own log line reports the *requested* address, so nothing and nobody
// could ever point an application at it. The engine would come up, the UI would
// say Protected, and every byte the user sent would leave in the clear.
//
// 1080 mirrors the Windows tray client (its socksAddr) deliberately: it is the
// conventional SOCKS port, it is what the Windows client's tun2socks already
// expects, and keeping both clients on one number means one sentence of
// documentation covers both. Loopback-only, so nothing off the machine can use it.
const SocksAddr = "127.0.0.1:1080"

var (
	errNoCoordinators = errors.New("no coordinators configured — copy bacchus-fyne.config.example.json into place and set at least one")
)

// Connect resolves an exit and brings up a session, entirely off the calling
// goroutine. A no-op if a connect/connected session is already in flight. The
// re-entrancy guard below runs synchronously (so a rapid double-click is
// rejected immediately) but never itself invokes OnState/OnDetail - only the
// spawned goroutine does, preserving the "never from the caller's stack"
// contract documented on the Controller type.
func (c *Controller) Connect() {
	c.mu.Lock()
	if c.state != Disconnected {
		c.mu.Unlock()
		return
	}
	c.gen++
	gen := c.gen
	c.state = Connecting
	c.mu.Unlock()

	go func() {
		// Re-check under the lock rather than publishing Connecting unconditionally:
		// Disconnect may already have run and published Disconnected, and announcing
		// a stale Connecting on top of it strands the UI on "Connecting…" with
		// nothing connecting. See publishLocked.
		c.mu.Lock()
		if c.gen == gen && c.state == Connecting {
			c.publishLocked(Connecting)
		}
		c.mu.Unlock()
		c.connectAsync(gen)
	}()
}

func (c *Controller) connectAsync(gen uint64) {
	if len(c.cfg.Coordinators) == 0 {
		c.abort(gen, errNoCoordinators)
		return
	}

	// Read the relay directory before anything is built: a missing file or a
	// non-hex key is the user's to fix, and naming it here — as its own
	// message, from the field that caused it — is the whole reason this is not
	// left to core's construction-time refusal. Nothing is read at all below 2
	// hops, which is the default (see LoadRelayDirectory).
	relayDir, relayDirKey, err := LoadRelayDirectory(c.cfg.RelayHops, c.cfg.RelayDirectoryPath, c.cfg.RelayDirectoryKey)
	if err != nil {
		c.abort(gen, err)
		return
	}
	// Re-sanitized here and not only on save (settings.go), so a hand-edited
	// config file cannot put a transport into the pool that this client's
	// tunnel could not make safe. SelectionDir is meaningful only with a pool,
	// so it stays empty without one rather than creating a directory nothing
	// writes to.
	pool := SanitizePoolOrder(c.cfg.TransportPool)
	var selectionDir string
	if len(pool) > 0 {
		selectionDir = DefaultSelectionDir()
	}

	// Volunteering (issue #12). Re-validated here and not only on save
	// (settings.go), for the reason SanitizePoolOrder is: a hand-edited config
	// file must not reach core through a dialog it never opened. That matters
	// more here than for the pool, because the check this repeats is the one
	// that cannot be recovered from afterwards — a serving role on a build that
	// routes the whole device would carry other people's traffic out through
	// this machine's own tunnel while the settings window's disclosure claimed
	// it left under this machine's address (ErrVolunteerWhileRouted).
	//
	// VolunteeringRefused() is the same answer settings.go was given when the
	// user ticked the box, so the two agree by construction rather than by
	// comment. A refusal aborts the connect with its own sentence, exactly as
	// LoadRelayDirectory's does, rather than surfacing later as one of core's
	// construction errors naming a field the user never saw.
	volunteer, err := PlanVolunteer(c.cfg, c.VolunteeringRefused())
	if err != nil {
		c.abort(gen, err)
		return
	}
	// Warn-and-serve findings go to the log, not to the detail line: the detail
	// line is one calm user-facing sentence about the connection they are
	// waiting on, and "your advertised address is carrier-NAT" is neither about
	// that nor actionable in the moment. The settings window is where these are
	// shown to the user, at the point of choosing.
	for _, w := range volunteer.Warnings {
		c.logf("volunteer: %s", w)
	}

	ctx, cancel := context.WithCancel(context.Background())
	eng, err := core.New(core.Config{
		Coordinators: c.cfg.Coordinators,
		// The client role, plus whichever serve roles were volunteered (issue
		// #12). Always includes RoleClient: a volunteer donates its connection
		// ALONGSIDE using it, so the serve roles add to the client role rather
		// than replacing it — the same shape cmd/node's volunteer flags have
		// against -role. The default, all-off plan is []string{RoleClient}
		// exactly, which is what this line said literally before #12.
		Roles:     volunteer.Roles,
		SocksAddr: SocksAddr,
		// Advertise/ListenAddr/ExitKeyHex are empty unless the EXIT opt-in is
		// on, and core reads all three only for the roles that need them.
		// ListenAddr is derived from Advertise's port rather than separately
		// configured, so the two cannot disagree; see VolunteerPlan.
		Advertise:  volunteer.Advertise,
		ListenAddr: volunteer.ListenAddr,
		ExitKeyHex: volunteer.ExitKeyHex,
		// No exit is named. Country-only assignment (issue #146, ADR-0042) means the
		// coordinator picks the exit; leaving Geo unset lets core take the first
		// country the coordinator reports as available, which is what the throwaway
		// list-and-pick-the-first engine here used to do by hand. The country picker
		// this unblocks is #150, in the client's own lane.
		STUNURL:  c.cfg.STUN,
		TURNURL:  c.cfg.TURN,
		TURNUser: c.cfg.TURNUser,
		TURNPass: c.cfg.TURNPass,
		// Passed through, not defaulted: unset means core verifies no exit
		// credential and checks no revocation (fail-open), so an operator with an
		// admission anchor loses ADR-0026/#60's backstop against a hostile
		// coordinator unless these actually reach the engine. See Config's doc.
		AdmissionPubKey:  c.cfg.AdmissionPubKey,
		AdmissionCRLPath: c.cfg.AdmissionCRLPath,
		// Transport pool (issue #93). Empty reproduces the pre-#93
		// single-transport Connect exactly, so the default path is unchanged.
		TransportPool: pool,
		SelectionDir:  selectionDir,
		// ForceRelay pins every WebRTC candidate to the configured TURN server
		// — an address enforcement.Policy already excludes from the tunnel's
		// own default route — instead of letting ICE pick a direct P2P
		// candidate whose address is learned only after the fact.
		//
		// It is set only where this platform actually routes the whole device,
		// and that gate is the whole point. A full-device tunnel must be able
		// to exclude an underlay address BEFORE dialing it, or the underlay
		// follows the split-default back into the tunnel it is carrying (a
		// loop, and a Block once the kill-switch arms — clients/internal/
		// enforcement/poolroutes.go's file doc). reality is handled late, on
		// the dial path, by OnUnderlayDial below; webrtc has no such hook
		// because it is not supposed to need one — it is supposed to be pinned
		// here. The Windows tray client set this from issue #75 for exactly that
		// reason. This client did not, which left its webrtc underlay
		// unexcluded on the one platform where it enforces; #93 surfaced it
		// while wiring TransportPool, since a pool whose first member is
		// webrtc makes the omission load-bearing rather than latent.
		//
		// Not unconditional, unlike the Windows tray client: on a platform with no
		// Enforcer this client is proxy-only, there is no tunnel to loop into,
		// and forcing every session through TURN would spend an operator's
		// relay bandwidth and a round trip to fix a problem that platform does
		// not have.
		ForceRelay: c.enf != nil,
		// Relay chaining (ADR-0038, issue #93). RelayHops 0/1 with a nil
		// directory is pre-#93 behaviour exactly. RelayDirectoryPath is passed
		// alongside the bytes so the engine keeps the directory fresh for the
		// rest of the session rather than pinning the snapshot read above
		// (issue #27).
		RelayHops:          c.cfg.RelayHops,
		RelayDirectory:     relayDir,
		RelayDirectoryKey:  relayDirKey,
		RelayDirectoryPath: c.cfg.RelayDirectoryPath,
		OnEvent:            func(ev core.Event) { c.onEvent(gen, ev) },
		// Wired to the Enforcer, not to a Session: the transport pool's first
		// reality underlay is dialled inside Connect below, before enforcement
		// starts, so there is no Session yet to hand it to. The Enforcer
		// records it and bring-up installs it (issue #109). nil when this
		// platform has no Enforcer, which core treats as "no hook".
		OnUnderlayDial: c.underlayDialHook(),
		// The local address a served role's own sockets bind, so other
		// people's traffic leaves under THIS machine's address instead of
		// through the tunnel this machine is also using (bacchus#109,
		// ADR-0053). Wired to the Enforcer rather than the Session for the
		// same reason OnUnderlayDial is, and asked lazily rather than passed
		// as a value for a stronger version of it: enforcement has not started
		// yet on this line, so the address does not exist yet. nil when this
		// platform has no Enforcer, which core treats as "bind nothing".
		ServedSource: c.servedSourceHook(),
	})
	if err != nil {
		cancel()
		c.abort(gen, err)
		return
	}
	if err := eng.Start(ctx); err != nil {
		cancel()
		c.abort(gen, err)
		return
	}
	if err := eng.Connect(ctx); err != nil {
		eng.Stop()
		cancel()
		c.abort(gen, err)
		return
	}

	// Device-wide enforcement, once the SOCKS server it bridges into is
	// actually up (core.Engine.Connect started it). This is the step that
	// makes "Protected" mean the device rather than one proxy port.
	//
	// A failure here aborts the whole connect. It deliberately does NOT fall
	// back to leaving the engine running as a working SOCKS proxy, even
	// though that would look like the friendlier outcome and would leave the
	// user with something that works: the user asked to be protected, the app
	// would be unable to protect them, and a green banner over a proxy that
	// covers nothing they configured is this ADR's own Scope-section lie in
	// its original form. Parity item 7 names this exact failure — "silently
	// degrading to unprotected is the one failure mode this whole bar exists
	// to rule out" — and the overwhelmingly common cause is running
	// unelevated, which is fixable, but only by a user who is told.
	sess, err := c.startEnforcement(volunteer.Serving())
	if err != nil {
		eng.Stop()
		cancel()
		c.abort(gen, err)
		return
	}

	c.mu.Lock()
	// Disconnect (or a newer Connect) may have run while the above was in flight;
	// honor it rather than resurrecting a session nothing wants, or trampling an
	// engine a later attempt already installed. A stale attempt tears down only what
	// it built itself.
	if c.gen != gen || c.state != Connecting {
		c.mu.Unlock()
		if sess != nil {
			// Before eng.Stop(), mirroring the teardown order Disconnect uses
			// and tunnel.Close documents: the kill-switch is lifted and the
			// routes come out first, so egress is restored before the tunnel
			// carrying it goes away rather than after.
			sess.Close()
		}
		eng.Stop()
		cancel()
		return
	}
	c.eng, c.cancel, c.sess, c.state = eng, cancel, sess, Protected
	c.publishLocked(Protected)
	c.mu.Unlock()
}

// underlayDialHook returns the OnUnderlayDial callback, or nil when this
// platform has no Enforcer — core reads a nil hook as "no hook", and handing
// it a closure that dereferences a nil Enforcer would panic on the dial path.
func (c *Controller) underlayDialHook() func(string) {
	if c.enf == nil {
		return nil
	}
	return c.enf.ReserveUnderlay
}

// startEnforcement brings up device-wide routing for the session that just
// connected. Returns (nil, nil) — no session, no error — on a platform with
// no Enforcer, which is this client's documented proxy-only posture rather
// than a failure; see DeviceEnforced.
//
// serving is VolunteerPlan.Serving(): whether this session carries anybody
// else's traffic. It is passed in rather than re-derived from c.cfg because
// the plan is the validated answer and the config is only the request — a
// stored opt-in that PlanVolunteer refused must not turn into a carve-out
// here.
func (c *Controller) startEnforcement(serving bool) (enforcement.Session, error) {
	if c.enf == nil {
		return nil, nil
	}
	dns := c.cfg.DNS
	if dns == "" {
		dns = DefaultDNSUpstream
	}
	sess, err := c.enf.Start(enforcement.Policy{
		Coordinators: c.cfg.Coordinators,
		STUNURL:      c.cfg.STUN,
		TURNURL:      c.cfg.TURN,
		DNSUpstream:  dns,
		Bypass:       c.cfg.Bypass,
		BypassMode:   NormalizeBypassMode(c.cfg.BypassMode),
		KillSwitch:   !c.cfg.DisableKillSwitch,
		// Carve this node's own served egress out of the tunnel about to be
		// installed, when the volunteer plan says it is serving (bacchus#109).
		// PlanVolunteer has already refused this combination on a platform
		// that cannot honor it, so a true here is a platform that can — and
		// enforcement.Policy's contract makes Start fail rather than ignore
		// it if that is ever wrong.
		ServeEgress: serving,
		Logf:        c.logf,
	}, SocksAddr)
	if err != nil {
		return nil, fmt.Errorf("could not route this device: %w", err)
	}
	return sess, nil
}

// Disconnect tears the active session down, entirely off the calling
// goroutine. Safe to call with nothing connected (including mid-Connect, or
// twice in a row) - each is a harmless no-op past the first.
func (c *Controller) Disconnect() {
	go func() {
		c.mu.Lock()
		eng, cancel, sess := c.eng, c.cancel, c.sess
		c.eng, c.cancel, c.sess, c.state = nil, nil, nil, Disconnected
		// Any connect in flight is now stale and must not install its engine on top
		// of this: the user asked to be disconnected, and an attempt that finishes a
		// second later does not get to overrule them.
		c.gen++
		// Announced here — under the lock, and BEFORE the teardown below — rather
		// than after the engine is actually down. Both halves of that are load-bearing.
		//
		// Under the lock, because that is what stops a concurrent ICE event from
		// publishing Protected after this (publishLocked).
		//
		// Before the teardown, because Stop() is slow and must not run under the lock:
		// onEvent takes the same mutex, and the dying engine emits into it. Publishing
		// first is safe precisely because the state is already Disconnected: StateFor
		// only moves out of Protected/Blocked, so every event the engine emits on its
		// way down is inert by construction. Telling the user "disconnected" the
		// instant they asked, rather than when the last goroutine winds up, is also
		// simply the truth — the session is already unreachable.
		c.publishLocked(Disconnected)
		c.mu.Unlock()

		// Enforcement first, engine second (tunnel.Close's own order, and
		// ADR-0014's): the kill-switch is lifted and the routes come out
		// before the tunnel that was carrying traffic goes away. Reversed,
		// the machine spends the length of an engine teardown fail-closed
		// over a tunnel that is already gone — which is not a leak, but is
		// the user watching their network die for no reason they can see.
		if sess != nil {
			sess.Close()
		}
		if cancel != nil {
			cancel()
		}
		if eng != nil {
			eng.Stop()
		}
	}()
}

// onEvent is core.Config.OnEvent: called from whichever engine goroutine observed
// something (readLoop, the reconnect driver, pion's ICE callback, ...), never the
// goroutine that called Connect. See StateFor/DetailFor (state.go) for the pure
// decision logic this just applies and republishes.
//
// gen is the attempt whose engine emitted this, and an event from a stale one is
// DROPPED. Every attempt wires its own engine's OnEvent here, and a stale attempt's
// engine keeps running until it notices — Connect -> Disconnect -> Connect really does
// run two engines at once, briefly, and they both emit. Without this check a zombie's
// ICE ": closed", fired as it shuts down, moves the WINNER's state to Blocked, where
// it stays: the healthy engine has no reason to re-emit "connected", so no later event
// corrects it.
//
// It fails safe — a false Blocked over a live tunnel is the inverse of this app's
// defect, and it is not reachable over loopback, where a zombie always finishes before
// the winner starts. On a real network ICE timings swing enough to invert that, and
// "we could not make it happen locally" is not a guarantee.
func (c *Controller) onEvent(gen uint64, ev core.Event) {
	c.mu.Lock()
	if c.gen != gen {
		c.mu.Unlock()
		return
	}
	cur := c.state
	if next := StateFor(cur, ev); next != cur {
		c.state = next
		c.publishLocked(next)
	}
	c.mu.Unlock()

	// The detail line stays outside the lock: it is cosmetic prose, it makes no
	// safety claim, and a stale one costs a confusing sentence rather than a false
	// "you are protected".
	if text, show := DetailFor(ev, cur); show {
		c.notifyDetail(text)
	}
}

// abort ends a failed connect attempt: drop back to Disconnected and surface
// why. Never called once a session is up (past that point a drop is Blocked,
// not a failure - see onEvent/StateFor).
func (c *Controller) abort(gen uint64, err error) {
	// A stale attempt reports nothing and touches nothing. It lost a race it does not
	// know it was in — most concretely, it lost the bind on SocksAddr to the attempt
	// the user actually wants — and the state it would clear belongs to the winner.
	// Clearing it anyway is what orphans a live engine (see Controller.gen).
	c.mu.Lock()
	stale := c.gen != gen
	c.mu.Unlock()
	if stale {
		return
	}

	c.notifyDetail(err.Error()) // before the state, so the reason is on screen when it lands

	c.mu.Lock()
	// Re-checked: gen can move while the detail is being delivered, and the check
	// that matters is the one that guards the write.
	if c.gen == gen {
		// c.sess is nil here in every reachable path — abort is never called
		// once a session is up (see this function's doc), and enforcement is
		// installed in the same locked step as the engine. Cleared anyway so
		// the invariant is the code's, not a comment's.
		c.eng, c.cancel, c.sess, c.state = nil, nil, nil, Disconnected
		c.publishLocked(Disconnected)
	}
	c.mu.Unlock()
}

// publishLocked hands s to OnState. THE CALLER MUST HOLD c.mu, AND MUST STILL HOLD
// IT WHEN THIS RETURNS — that is the entire point, not an accident of where the
// call sits.
//
// Publishing outside the lock is a false-Protected bug, and this app's whole job is
// to not have one. Every mutator here used to set c.state under the lock and then
// publish after releasing it, which orders neither against the other: two goroutines
// could set A then B, and publish B then A, leaving the UI on A forever. That is not
// hypothetical — a reconnect (ADR-0030) fires ICE "connected" from a goroutine pion
// owns, which Engine.Stop's wg.Wait does not track, so it can be preempted between
// setting Protected and publishing it. The user presses Disconnect, the engine dies,
// Disconnected is published, and then the preempted goroutine publishes Protected on
// top of it. No further event can ever correct it, because the engine is gone. The
// band stays green on "you are protected" over a dead tunnel.
//
// Holding the lock across the callback makes the state change and its announcement
// one atomic step, so the last publish always carries the last state. A generation
// counter cannot do this: checking the counter and calling OnState are two steps, and
// a preemption between them reintroduces the same reorder.
//
// THE CONTRACT THIS REQUIRES: OnState must not block, and must not call back into
// Controller. main.go satisfies it — it wires OnState through fyne.Do, which queues
// onto Fyne's unbounded func channel and returns immediately, and its callback only
// assigns widget state. Never fyne.DoAndWait
// (that blocks until the UI goroutine runs the callback, and if the UI goroutine is
// itself inside a Connect/Disconnect button handler waiting on c.mu, that deadlocks).
// The Controller doc's "never from the caller's own stack" rule still holds: every
// publish happens on a goroutine Controller spawned.
func (c *Controller) publishLocked(s ConnState) {
	if c.OnState != nil {
		c.OnState(s)
	}
}

func (c *Controller) notifyDetail(s string) {
	if c.OnDetail != nil {
		c.OnDetail(s)
	}
}
