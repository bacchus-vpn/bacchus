package appstate

import (
	"context"
	"errors"
	"sync"

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

	mu     sync.Mutex
	eng    *core.Engine
	cancel context.CancelFunc
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
	return &Controller{cfg: cfg}
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
// 1080 mirrors clients/windows (main.go's socksAddr) deliberately: it is the
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

	ctx, cancel := context.WithCancel(context.Background())
	eng, err := core.New(core.Config{
		Coordinators: c.cfg.Coordinators,
		Roles:        []string{core.RoleClient},
		SocksAddr:    SocksAddr,
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
		OnEvent:          func(ev core.Event) { c.onEvent(gen, ev) },
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

	c.mu.Lock()
	// Disconnect (or a newer Connect) may have run while the above was in flight;
	// honor it rather than resurrecting a session nothing wants, or trampling an
	// engine a later attempt already installed. A stale attempt tears down only what
	// it built itself.
	if c.gen != gen || c.state != Connecting {
		c.mu.Unlock()
		eng.Stop()
		cancel()
		return
	}
	c.eng, c.cancel, c.state = eng, cancel, Protected
	c.publishLocked(Protected)
	c.mu.Unlock()
}

// Disconnect tears the active session down, entirely off the calling
// goroutine. Safe to call with nothing connected (including mid-Connect, or
// twice in a row) - each is a harmless no-op past the first.
func (c *Controller) Disconnect() {
	go func() {
		c.mu.Lock()
		eng, cancel := c.eng, c.cancel
		c.eng, c.cancel, c.state = nil, nil, Disconnected
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
		c.eng, c.cancel, c.state = nil, nil, Disconnected
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
