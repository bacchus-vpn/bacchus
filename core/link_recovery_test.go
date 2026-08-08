package core

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/rendezvous"
)

// A client that survives its coordinator (issue #225).
//
// Nothing in this repository had ever taken a coordinator away from a LIVE client,
// which is how a client that never reconnects after a coordinator restart shipped
// past every test here, both PR CI runs and a combination build, and was found by a
// person on real hardware a hundred minutes into an outage. Every test in this file
// exists to make that condition reachable in-process: establish a link, take the far
// end away underneath it, and require the client to come back on its own.
//
// The premise the whole file rests on is asserted rather than assumed — see
// TestARestartedCoordinatorForgetsTheAssociation. A fixture whose "restart" left the
// far end still holding the association would make every case below pass for the
// wrong reason.

// ---------------------------------------------------------------------------
// A coordinator that can be restarted underneath a running client
// ---------------------------------------------------------------------------

// restartableCoordinator is the minimum coordinator a connect leg needs, plus the one
// thing no fake in this package could do before: restart.
//
// It answers a connect with a REFUSAL rather than a session, deliberately. A refusal
// is a full round trip — the client sends, the coordinator answers, the client reads
// it off the link — which is all these tests measure, and it stops before the
// transport dial, so nothing here depends on a WebRTC stack coming up. What separates
// a healthy link from a wedged one is then unambiguous: a healthy one is REFUSED and
// a wedged one is SILENT.
type restartableCoordinator struct {
	pc *net.UDPConn

	mu       sync.Mutex
	peer     *rendezvous.Peer
	seen     map[string]int
	silent   bool
	restarts int
}

// briskLegs shrinks a client's per-mode budgets so a failed pass costs a couple of
// seconds instead of the shipped thirty. The bound this fix claims is stated in
// PASSES, not in seconds, precisely so it survives that: what a test can show is that
// recovery takes one failed pass and the next, and the wall-clock number is whatever
// the deployed ladder makes it (12s direct + 18s relay + a backoff step, today).
func briskLegs(e *Engine) {
	e.directTimeout = 900 * time.Millisecond
	e.relayTimeout = 900 * time.Millisecond
	e.listTimeout = 900 * time.Millisecond
}

func newRestartableCoordinator(t *testing.T) *restartableCoordinator {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	c := &restartableCoordinator{pc: pc, seen: map[string]int{}}
	c.peer = servePeer(t, pc)
	go c.serve(c.peer)
	return c
}

func (c *restartableCoordinator) addr() string { return c.pc.LocalAddr().String() }

// restart is the process restart the deploy pin performs and the card is about
// (ADR-0064 restarts the coordinator LAST, so every node is brought up against the
// outgoing one and then has it removed a second later). The socket and its address
// survive — systemd rebinds the same port — and everything the old process knew about
// who was talking to it does not.
func (c *restartableCoordinator) restart(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	old := c.peer
	c.mu.Unlock()
	_ = old.Close()

	p, err := rendezvous.Serve(c.pc)
	if err != nil {
		t.Fatalf("rendezvous.Serve: %v", err)
	}
	c.mu.Lock()
	c.peer = p
	c.restarts++
	c.mu.Unlock()
	t.Cleanup(func() { _ = p.Close() })
	go c.serve(p)
}

// goSilent makes this coordinator stop ANSWERING without losing its association — a
// live coordinator that drops a reply, which is the condition a link rebuild must not
// mistake for its own staleness any more often than it has to.
func (c *restartableCoordinator) goSilent() {
	c.mu.Lock()
	c.silent = true
	c.mu.Unlock()
}

func (c *restartableCoordinator) count(msgType string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen[msgType]
}

func (c *restartableCoordinator) serve(peer *rendezvous.Peer) {
	for {
		raw, src, err := peer.ReadFrom()
		if err != nil {
			return
		}
		var m wire
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		c.mu.Lock()
		c.seen[m.Type]++
		silent := c.silent
		c.mu.Unlock()
		if silent {
			continue
		}
		switch m.Type {
		case "connect":
			c.send(peer, src, wire{Type: "error", Reason: "country-busy"})
		case "list":
			c.send(peer, src, wire{Type: "countries"})
		}
	}
}

func (c *restartableCoordinator) send(peer *rendezvous.Peer, to *net.UDPAddr, m wire) {
	b, _ := json.Marshal(m)
	_, _ = peer.WriteTo(b, to)
}

// ---------------------------------------------------------------------------
// The premise
// ---------------------------------------------------------------------------

// TestARestartedCoordinatorForgetsTheAssociation asserts the fixture's own premise,
// because every case below is meaningless without it and none of them would fail if
// it were wrong.
//
// A restarted coordinator holds no association for a source it was mid-conversation
// with, so the records a running client keeps sending land nowhere — its mux will not
// create state for a record that is not a handshake, precisely so a spoofed source
// cannot mint associations. That is what makes the client's side of the conversation
// a conversation with nobody: every write succeeds, because a UDP send into a dead
// association is a local success forever, and no reply ever comes.
func TestARestartedCoordinatorForgetsTheAssociation(t *testing.T) {
	coord := newRestartableCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)
	if coord.count("connect") == 0 {
		t.Fatal("the first attempt reached nothing — the fixture is not a working coordinator")
	}
	before := coord.count("connect")

	coord.restart(t)

	// The same association, used exactly as it was a moment ago.
	heard := link.heardMark()
	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)

	if got := coord.count("connect"); got != before {
		t.Fatalf("the restarted coordinator decoded %d connects (was %d); this fixture does not forget on restart and every test in this file would pass for the wrong reason", got, before)
	}
	if link.heardSince(heard) {
		t.Fatal("the client heard something back through an association the far end has forgotten")
	}
	// And the writes succeeded throughout, which is the whole trap: there is no error
	// anywhere for the client to notice.
	if !link.holdsAssociation() {
		t.Fatal("the client's association died on its own; the bug is that it does NOT, so nothing retires it")
	}
}

// ---------------------------------------------------------------------------
// The card
// ---------------------------------------------------------------------------

// TestAClientRecoversWhenItsCoordinatorRestartsUnderIt is issue #225 written as an
// assertion, and it is the test this change exists for.
//
// On real hardware this ran for a hundred minutes: 112 consecutive
// "reconnect attempt N failed (core: no coordinator reachable)" from a process using
// 1.6 seconds of CPU in 1h39m — idle, waiting on a link it never rebuilt — while that
// same coordinator connected a fresh `-role client` from the SAME BOX in under a
// second. It ended when a person restarted the service.
//
// It drives establish, not attemptWith, because establish is where the decision is:
// the leg below it cannot tell a stale link from an unreachable member, and the leg
// above it never asked.
func TestAClientRecoversWhenItsCoordinatorRestartsUnderIt(t *testing.T) {
	coord := newRestartableCoordinator(t)
	eng, _ := newTestClientEngine(t, coord.addr())
	eng.connectCountry = "NL"
	briskLegs(eng)
	ctx := context.Background()

	// A working link: the coordinator refuses, which means it was reached.
	if _, err := eng.establish(ctx, modeDirect); errors.Is(err, ErrNoCoordinatorReachable) {
		t.Fatalf("the first pass could not reach the coordinator at all: %v", err)
	}
	refusals := coord.count("connect")
	if refusals == 0 {
		t.Fatal("the first pass reached nothing")
	}

	coord.restart(t)

	// From here on the client is on its own. No restart, no user, no reconfiguration —
	// exactly the hundred minutes.
	const maxPasses = 4
	for pass := 1; pass <= maxPasses; pass++ {
		_, err := eng.establish(ctx, modeDirect)
		if coord.count("connect") > refusals {
			if pass > 2 {
				t.Errorf("recovery took %d passes; the bound this fix claims is one failed pass plus the next", pass)
			}
			return
		}
		if pass == 1 && !errors.Is(err, ErrCoordinatorLinkStale) {
			t.Errorf("the pass that found the wedge reported %v; it should name the link, not the network", err)
		}
	}
	t.Fatalf("the client never reached its coordinator again in %d passes, though that coordinator is up and answering — this is issue #225", maxPasses)
}

// TestAVolunteersRegistrationsComeBackWithTheLink is the half of the card that is not
// about the user's own connection.
//
// A volunteer's serve-side registration rides its CLIENT link — one process, one
// coordinator connection, and the client role is what shapes it (ADR-0053 lets a
// routed machine serve; a link cannot be half shaped). So the moment that link wedged,
// the box stopped being an exit and a relay as well, and the coordinator did not
// notice anything at all: it simply never heard from it again, and the capacity left
// the pool silently. A fix that restores the client and not the registrations is half
// a fix, and the missing half is the one nobody is watching.
func TestAVolunteersRegistrationsComeBackWithTheLink(t *testing.T) {
	coord := newRestartableCoordinator(t)
	eng, err := New(Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{RoleClient, "relay"},
		SocksAddr:    "127.0.0.1:0",
		Geo:          "NL",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)
	briskLegs(eng)

	if !waitFor(5*time.Second, func() bool { return coord.count("register") > 0 }) {
		t.Fatal("the volunteer never registered at all")
	}

	coord.restart(t)
	// Registers keep going out on their ten-second ticker and land nowhere; nothing
	// on this side errors, which is why the coordinator sees an empty registry and the
	// node sees a healthy one.
	after := coord.count("register")

	// The client half is what notices, and the registrations ride back on what it
	// rebuilds. This is the join: nothing here touches the register loop.
	for pass := 1; pass <= 4 && coord.count("register") <= after; pass++ {
		_, _ = eng.establish(ctx, modeDirect)
	}

	if !waitFor(15*time.Second, func() bool { return coord.count("register") > after }) {
		t.Fatal("the volunteer's registrations never came back, so its exit and relay capacity left the pool silently and stayed out")
	}
}

// ---------------------------------------------------------------------------
// The message
// ---------------------------------------------------------------------------

// TestAStaleLinkIsNotReportedAsAnUnreachableNetwork. coordpool's own comment on
// refusedForSize calls "no coordinator reachable" the sentence a user on a censored
// network will believe and report, and was written to stop a LOCAL fault wearing it.
// This is a local fault, from a different cause, and it wore that sentence 112 times.
//
// A user must be able to tell "the link I held is gone" from "nothing is reachable":
// the second is a reason to change networks and the first is not.
func TestAStaleLinkIsNotReportedAsAnUnreachableNetwork(t *testing.T) {
	coord := newRestartableCoordinator(t)
	var mu sync.Mutex
	var msgs []string
	eng, err := New(Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{RoleClient},
		Geo:          "NL",
		OnEvent: func(ev Event) {
			mu.Lock()
			msgs = append(msgs, ev.Message)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)
	briskLegs(eng)

	if _, err := eng.establish(ctx, modeDirect); errors.Is(err, ErrNoCoordinatorReachable) {
		t.Fatalf("the first pass could not reach the coordinator: %v", err)
	}
	coord.restart(t)

	_, err = eng.establish(ctx, modeDirect)
	if !errors.Is(err, ErrCoordinatorLinkStale) {
		t.Fatalf("a wedged link reported %v", err)
	}
	if errors.Is(err, ErrNoCoordinatorReachable) {
		t.Fatal("a stale link still unwraps to ErrNoCoordinatorReachable — it would trigger mesh-walk, which rediscovers coordinator ADDRESSES and cannot help a link whose address was never in doubt")
	}

	mu.Lock()
	got := strings.Join(msgs, "\n")
	mu.Unlock()
	for _, want := range []string{"LOCAL fault", "NOT the network", "restarting underneath a running client", "fresh socket"} {
		if !strings.Contains(got, want) {
			t.Errorf("the diagnosis does not say %q, so a reader cannot tell this from a censored network:\n%s", want, got)
		}
	}
}

// ---------------------------------------------------------------------------
// What must NOT be rebuilt
// ---------------------------------------------------------------------------

// TestAnUnreachableCoordinatorIsNotAStaleLink is the guard that keeps mesh-walk alive.
//
// Silence from a member this client never had a conversation with is silence about the
// MEMBER, and it is exactly what ErrNoCoordinatorReachable is for — the mesh-walk
// trigger (issue #31). If a rebuilt socket claimed the local diagnosis here, a client
// whose coordinators had genuinely moved would report a local fault forever and never
// walk for the directory that would have saved it.
func TestAnUnreachableCoordinatorIsNotAStaleLink(t *testing.T) {
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = dead.Close() })

	eng, err := New(Config{
		Coordinators: []string{dead.LocalAddr().String()},
		Roles:        []string{RoleClient},
		Geo:          "NL",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)
	briskLegs(eng)

	for pass := 1; pass <= 2; pass++ {
		_, err := eng.establish(ctx, modeDirect)
		if !errors.Is(err, ErrNoCoordinatorReachable) {
			t.Fatalf("pass %d against a black hole returned %v, want ErrNoCoordinatorReachable — mesh-walk keys on it", pass, err)
		}
	}
}

// TestAMemberThatAnsweredKeepsItsLink. Any byte off the far end is proof the link is a
// link, so a member that answered — even with a refusal, even unintelligibly — must
// keep the association it answered on. Rebuilding one that works costs a handshake for
// nothing and, worse, teaches the failure that the cure is indiscriminate.
func TestAMemberThatAnsweredKeepsItsLink(t *testing.T) {
	coord := newRestartableCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())
	eng.connectCountry = "NL"
	briskLegs(eng)
	ctx := context.Background()

	if _, err := eng.establish(ctx, modeDirect); errors.Is(err, ErrNoCoordinatorReachable) {
		t.Fatalf("the first pass could not reach the coordinator: %v", err)
	}
	_, _, gen := link.transport()

	// A second pass against the same, healthy coordinator: refused again, so heard.
	if _, err := eng.establish(ctx, modeDirect); errors.Is(err, ErrCoordinatorLinkStale) {
		t.Fatal("a member that answered was called stale")
	}
	if _, _, now := link.transport(); now != gen {
		t.Fatalf("the link was rebuilt (generation %d -> %d) though the coordinator answered every request", gen, now)
	}
}

// TestALinkWithNoAssociationIsNotRebuilt pins the other half of the test: a link this
// client is not HOLDING anything on cannot have gone stale. A cleartext link — every
// pure forwarder's — holds no association at all, so this is also what keeps the
// recovery out of a role it was not designed for.
func TestALinkWithNoAssociationIsNotRebuilt(t *testing.T) {
	coord := fakeCoordinator(t)
	eng, err := New(Config{Coordinators: []string{coord.LocalAddr().String()}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)

	l := eng.links[0]
	if l.holdsAssociation() {
		t.Fatal("a forwarder's cleartext link reports holding an association")
	}
	if eng.relinkIfStale(l, l.heardMark(), l.holdsAssociation()) {
		t.Fatal("a link holding no association was rebuilt; there was nothing to go stale")
	}
}

// ---------------------------------------------------------------------------
// The rebuild itself
// ---------------------------------------------------------------------------

// TestARebuiltLinkLeavesTheSocketBehind. The whole reason a rebuild is a new SOCKET
// and not a new association on the old one: a re-handshake on the same 5-tuple is
// swallowed while the far end still holds the old association — its mux finds the
// source in its table before it looks at the record type — and, because every datagram
// from that source refreshes the entry, a client retrying in place holds its own wedge
// open indefinitely.
func TestARebuiltLinkLeavesTheSocketBehind(t *testing.T) {
	coord := newRestartableCoordinator(t)
	_, link := newTestClientEngine(t, coord.addr())

	conn, shaped, gen := link.transport()
	before := conn.LocalAddr().String()

	if err := link.relink(); err != nil {
		t.Fatalf("relink: %v", err)
	}
	newConn, newShaped, newGen := link.transport()
	if newConn.LocalAddr().String() == before {
		t.Fatalf("the rebuilt link kept source address %s; a re-handshake from it is swallowed by any far end still holding the old association", before)
	}
	if newGen == gen {
		t.Fatal("the rebuild did not move the link's generation, so a parked reader cannot tell it happened")
	}
	if newShaped == shaped {
		t.Fatal("the rebuilt link kept its old transport, which still owns the closed socket")
	}
	if newShaped == nil {
		t.Fatal("a shaped link came back unshaped — the rebuilt one would send plaintext, which ADR-0062 rules out entirely")
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("the old socket is still open after a rebuild")
	}
}

// TestARebuildAfterStopIsRefused. A leg can decide to rebuild a link and land after
// Stop has already torn it down. Installing a socket at that point leaves the read
// loop parked on something closeLinks is already past — and Stop waits on that loop,
// so the engine would hang on shutdown for a link it had just repaired.
func TestARebuildAfterStopIsRefused(t *testing.T) {
	coord := newRestartableCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	eng.Stop() // idempotent; t.Cleanup calls it again
	_, _, gen := link.transport()

	if err := link.relink(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("relink after Stop returned %v, want net.ErrClosed", err)
	}
	if _, _, now := link.transport(); now != gen {
		t.Fatal("a link torn down by Stop was given a new socket; nothing will ever close it and Stop waits on its reader")
	}
	// And the leg says nothing about it, because there is nothing left to repair.
	if eng.relinkIfStale(link, link.heardMark(), true) {
		t.Fatal("relinkIfStale reported a rebuild of a link that is gone")
	}
}

// TestStopReturnsWhileLinksAreBeingRebuilt is the same hazard from the other side and
// the one that would actually be felt: shutdown must not wait on a read loop parked on
// a socket a concurrent rebuild installed.
func TestStopReturnsWhileLinksAreBeingRebuilt(t *testing.T) {
	coord := newRestartableCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	rebuilding := make(chan struct{})
	go func() {
		close(rebuilding)
		for i := 0; i < 50; i++ {
			if err := link.relink(); err != nil {
				return // refused once the link is closed, which is the point
			}
			time.Sleep(time.Millisecond)
		}
	}()
	<-rebuilding
	time.Sleep(20 * time.Millisecond)

	done := make(chan struct{})
	go func() { eng.Stop(); eng.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return while links were being rebuilt; a read loop is parked on a socket nothing closed")
	}
}

// TestTheReadLoopSurvivesARebuild is the failure a rebuild could quietly introduce and
// nothing else in this file would catch: the link comes back and nothing is listening
// to it. Closing the old socket fails whatever read was parked on it, and a read loop
// that treated that as the link ending would leave the rebuilt link mute — a quieter
// version of the bug being fixed.
func TestTheReadLoopSurvivesARebuild(t *testing.T) {
	coord := newRestartableCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())
	eng.connectCountry = "NL"
	briskLegs(eng)
	ctx := context.Background()

	if _, err := eng.establish(ctx, modeDirect); errors.Is(err, ErrNoCoordinatorReachable) {
		t.Fatalf("the first pass could not reach the coordinator: %v", err)
	}
	if err := link.relink(); err != nil {
		t.Fatalf("relink: %v", err)
	}

	// The read loop is the only reader of this link; if the rebuild ended it, nothing
	// will ever put a reply on msgCh again and every future attempt reads as silence.
	heard := link.heardMark()
	eng.attemptWith(ctx, link, connectReq{country: "NL", mode: modeDirect}, eng.transport, 3*time.Second, nil)
	if !link.heardSince(heard) {
		t.Fatal("nothing was read off the rebuilt link; the read loop did not survive the rebuild")
	}
}

// TestConcurrentSendsAndRebuildsDoNotRace drives the two things that touch a link's
// socket from different goroutines — the sends every role makes and the rebuild a
// client leg performs — against each other, because this is a lifecycle bug and the
// half of it that is not lifecycle is concurrency. Run under -race, which is where it
// means anything.
func TestConcurrentSendsAndRebuildsDoNotRace(t *testing.T) {
	coord := newRestartableCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var sends atomic.Int64

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				link.send(eng, helloWire())
				sends.Add(1)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if err := link.relink(); err != nil {
				t.Errorf("relink: %v", err)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()
	if sends.Load() == 0 {
		t.Fatal("no sends ran, so nothing was raced against the rebuilds")
	}
}

// ---------------------------------------------------------------------------
// What a rebuild costs when it was not needed
// ---------------------------------------------------------------------------

// TestALiveCoordinatorThatStopsAnsweringIsRecoveredAnyway is the false-positive case
// priced honestly. A coordinator that is up and still holds this client's association
// but drops its replies looks exactly like one that restarted, and the rebuild fires.
//
// It has to be survivable, and it is only survivable because the rebuild moves the
// socket: re-handshaking in place against a far end that still holds the association
// draws nothing, and every attempt refreshes the entry that is swallowing it, so a
// client that recovered "in place" would wedge itself for as long as it kept trying.
// This is the measurement that decided the design.
func TestALiveCoordinatorThatStopsAnsweringIsRecoveredAnyway(t *testing.T) {
	coord := newRestartableCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())
	eng.connectCountry = "NL"
	briskLegs(eng)
	ctx := context.Background()

	if _, err := eng.establish(ctx, modeDirect); errors.Is(err, ErrNoCoordinatorReachable) {
		t.Fatalf("the first pass could not reach the coordinator: %v", err)
	}
	coord.goSilent() // still holding our association, simply not replying

	_, _, gen := link.transport()
	if _, err := eng.establish(ctx, modeDirect); !errors.Is(err, ErrCoordinatorLinkStale) {
		t.Fatalf("a live coordinator that stopped answering reported %v", err)
	}
	if _, _, now := link.transport(); now == gen {
		t.Fatal("the link was not rebuilt, so the next handshake would go out on the 5-tuple the far end is already holding and be swallowed")
	}
	// And the rebuilt link reaches it — the far end's stale association cannot swallow
	// a handshake from a source it has never seen.
	reached := coord.count("connect")
	eng.attemptWith(ctx, link, connectReq{country: "NL", mode: modeDirect}, eng.transport, 3*time.Second, nil)
	if coord.count("connect") <= reached {
		t.Fatal("the rebuilt link did not reach the coordinator; a same-5-tuple re-handshake is exactly what this rebuild exists to avoid")
	}
}

// ---------------------------------------------------------------------------
// Recovery must not cost the recovery that already existed
// ---------------------------------------------------------------------------

// TestAStaleLinkDoesNotResetTheMeshWalkStreak. Mesh-walk fires after a run of
// consecutive all-silent passes (issue #31/#115). A stale-link pass is neither
// evidence that rendezvous is down nor evidence that it is up, so it must not COUNT —
// a walk would rediscover the address this client is already dialling — and it must
// not RESET, or a client whose coordinators really had moved would have its recovery
// postponed indefinitely by a link that wedges once per pass.
//
// The passes are silent, STALE, silent, against meshRecoveryAfter of two. If the stale
// pass resets, the streak never reaches two and the walk never happens.
func TestAStaleLinkDoesNotResetTheMeshWalkStreak(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	cache := coldstart.NewSnapshotCache()
	cache.Store(signedCoordSnapshot(t, priv, "203.0.113.9:3478")) // a genuinely different coordinator
	courier := startCoreCourier(t, pub, cache)

	e := newReconnectEngine(t, nil)
	t.Cleanup(e.Stop)
	e.meshPeers = []string{courier}
	e.meshProof = signedCoordSnapshot(t, priv, "203.0.113.1:3478")
	e.meshPubKey = pub
	e.meshRecoveryAfter = 2
	e.relayTimeout = 700 * time.Millisecond

	var passes atomic.Int64
	e.establishFn = func(context.Context, string) (connPath, error) {
		if passes.Add(1) == 2 {
			return connPath{}, ErrCoordinatorLinkStale
		}
		return connPath{}, ErrNoCoordinatorReachable
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := e.reconnect(ctx, modeDirect)
	if !errors.Is(err, errRecovering) {
		t.Fatalf("reconnect returned %v after %d passes; a stale pass in the middle of a genuine outage swallowed the mesh-walk streak", err, passes.Load())
	}
	if got := passes.Load(); got != 3 {
		t.Errorf("mesh-walk fired after %d passes, want 3 (silent, stale, silent) — the stale pass either counted toward the streak or reset it", got)
	}
}
