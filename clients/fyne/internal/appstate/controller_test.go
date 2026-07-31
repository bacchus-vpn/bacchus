package appstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
)

// TestController_RealLoopback is the issues #148/#149 acceptance test: a
// Controller - exactly the seam the outer package's ui.go drives, through
// fyne.Do - brings a real client-role core.Engine up to Protected against a
// real exit-role core.Engine, rendezvoused through a minimal fake coordinator
// (fakecoordinator_test.go) over loopback. Nothing below core.Engine itself
// is mocked: this is the empirical proof the spike set out to get, that
// Fyne's controller layer can drive core in-process end to end, not just in
// theory - see the ADR.
func TestController_RealLoopback(t *testing.T) {
	coord := newFakeCoordinator(t)

	exitEng, err := core.New(core.Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{core.RoleExit},
		ListenAddr:   "127.0.0.1:0",
		Advertise:    "127.0.0.1:1", // unused in direct mode; New only requires it non-empty
		Country:      "zz",
	})
	if err != nil {
		t.Fatalf("exit New: %v", err)
	}
	if err := exitEng.Start(context.Background()); err != nil {
		t.Fatalf("exit Start: %v", err)
	}
	t.Cleanup(exitEng.Stop)

	if !waitFor(5*time.Second, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return coord.exit != nil
	}) {
		t.Fatal("exit never registered with the fake coordinator")
	}

	ctrl := newProxyOnlyController(Config{Coordinators: []string{coord.addr()}})
	rec := newStateRecorderFor(ctrl)
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 20*time.Second); s != Protected {
		t.Fatalf("state = %v, want Protected (details so far: %v)", s, rec.detailsSnapshot())
	}

	// A real transport-level drop (issue #149's "Blocked (kill-switch)"
	// signal, appstate.StateFor's ICE branch): kill the exit's session and
	// confirm the headline state reacts to a genuine ICE disconnect, not just
	// the synthetic string match already covered by state_test.go. ICE
	// disconnect detection isn't instant, hence the generous timeout.
	exitEng.Stop()
	if s := rec.next(t, 45*time.Second); s != Blocked {
		t.Fatalf("state after the exit died = %v, want Blocked", s)
	}

	ctrl.Disconnect()
	if s := rec.next(t, 5*time.Second); s != Disconnected {
		t.Fatalf("state after Disconnect = %v, want Disconnected", s)
	}

	// Covers connectAsync's Protected announcement, which nothing else reaches: it
	// needs a real engine, so it cannot be driven synthetically.
	rec.assertPublishesWereLocked(t)
}

// TestController_NoCoordinators is the common failure path a censored user
// hits far more often than the happy path: Connect must fail cleanly back to
// Disconnected with an actionable detail line, never hang in Connecting.
func TestController_NoCoordinators(t *testing.T) {
	ctrl := NewController(Config{})
	rec := newStateRecorder()
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 2*time.Second); s != Disconnected {
		t.Fatalf("state = %v, want Disconnected", s)
	}
	if got := rec.detailsSnapshot(); len(got) == 0 || got[len(got)-1] != errNoCoordinators.Error() {
		t.Fatalf("details = %v, want the last entry to explain the missing config", got)
	}
}

// stateRecorder captures every OnState/OnDetail callback a Controller makes,
// exposing them to a test goroutine via a channel (next) and, for failure
// messages, a locked snapshot (detailsSnapshot).
type stateRecorder struct {
	states chan ConnState
	ctrl   *Controller // when set, every announcement is checked for lock discipline

	mu      sync.Mutex
	details []string
	escaped []ConnState
}

func newStateRecorder() *stateRecorder {
	return &stateRecorder{states: make(chan ConnState, 16)}
}

// watching returns a recorder that also asserts c publishes under its own lock.
func newStateRecorderFor(c *Controller) *stateRecorder {
	return &stateRecorder{states: make(chan ConnState, 16), ctrl: c}
}

// onState doubles as a lock-discipline check on every announcement any test drives.
// TestStatePublishHappensUnderTheLock drives the paths it can reach synthetically;
// connectAsync's Protected — the happy path, and the single most important
// announcement in the app — is reachable only through a real engine, so it had no
// coverage at all and a mutant moving it outside the lock survived the whole suite.
// Checking here means every test that reaches Protected pins it, for free. See
// publishLocked for why the lock is the invariant.
func (r *stateRecorder) onState(s ConnState) {
	if r.ctrl != nil && r.ctrl.mu.TryLock() {
		r.ctrl.mu.Unlock()
		r.mu.Lock()
		r.escaped = append(r.escaped, s)
		r.mu.Unlock()
	}
	r.states <- s
}

// assertPublishesWereLocked fails if any announcement escaped its critical section.
func (r *stateRecorder) assertPublishesWereLocked(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.escaped) > 0 {
		t.Errorf("%d state announcement(s) published with c.mu unheld (%v): a publish outside the lock is not ordered against the state change it describes, so a stale one can outlive the session it claims", len(r.escaped), r.escaped)
	}
}

func (r *stateRecorder) onDetail(text string) {
	r.mu.Lock()
	r.details = append(r.details, text)
	r.mu.Unlock()
}

func (r *stateRecorder) detailsSnapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.details...)
}

func (r *stateRecorder) next(t *testing.T, timeout time.Duration) ConnState {
	t.Helper()
	select {
	case s := <-r.states:
		return s
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for a state change", timeout)
		return Disconnected
	}
}

// waitFor polls cond until it reports true or timeout elapses, mirroring
// core's own test helper of the same name (core/reconnect_smoke_test.go) -
// duplicated here since it is unexported there too.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

// TestStatePublishHappensUnderTheLock pins the invariant that prevents the worst
// class of bug this app can have: the band reading "protected" over a tunnel that is
// gone.
//
// The bug it guards is real, not theoretical. A reconnect (ADR-0030) recovers and
// pion fires ICE "connected" from a goroutine pion owns — one that Engine.Stop's
// wg.Wait() does not track — so onEvent can be preempted between recording Protected
// and announcing it. If the user presses Disconnect in that window, the engine dies,
// Disconnected is announced, and then the preempted goroutine announces Protected on
// top of it. Nothing corrects it afterwards: the engine is stopped, so no further
// event will ever arrive. Silent, sticky, and failing toward "you are safe" in a
// country where believing that is the risk.
//
// This does NOT race two goroutines and hope. That interleaving reproduces about 3
// times in 200,000, which is useless as a gate and flaky as a signal — a test that
// samples a probability tests nothing you can rely on. So it checks the property that
// makes the interleaving impossible instead: a publish must be atomic with the state
// change it announces, i.e. it must happen with c.mu HELD. TryLock answers that
// exactly — if the lock can be acquired from inside OnState, it was not held, and the
// announcement has escaped its critical section. Deterministic, first call, every run.
//
// Single-goroutine on purpose: with no contention, a failed TryLock can only mean
// this goroutine already holds it.
func TestStatePublishHappensUnderTheLock(t *testing.T) {
	var escaped []ConnState
	c := NewController(Config{}) // no coordinators: Connect aborts, exercising that path too
	c.OnState = func(s ConnState) {
		if c.mu.TryLock() {
			c.mu.Unlock()
			escaped = append(escaped, s)
		}
	}
	c.OnDetail = func(string) {}

	// Every path that announces a state. Connect+abort covers Connecting and the
	// abort-to-Disconnected path; onEvent covers the reconnect edge that the bug
	// actually rides in on; Disconnect covers the user teardown racing it.
	c.Connect()
	waitForState(t, c, Disconnected) // errNoCoordinators -> abort

	c.mu.Lock()
	c.state = Blocked
	c.mu.Unlock()
	c.onEvent(c.gen, core.Event{Kind: core.EventICE, Message: "peer1 ICE: connected"}) // -> Protected

	c.Disconnect()
	waitForState(t, c, Disconnected)

	if len(escaped) > 0 {
		t.Fatalf("%d state announcement(s) were published with c.mu unheld (%v): a publish outside the lock is not ordered against the state change it describes, so a stale one can outlive the session it claims — and the user is told they are protected over a dead tunnel, permanently", len(escaped), escaped)
	}
}

// waitForState blocks until the controller settles, since Connect/Disconnect do their
// work on goroutines they spawn.
func waitForState(t *testing.T, c *Controller, want ConnState) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		got := c.state
		c.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("controller never reached %v (stuck at %v)", want, got)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestAdmissionAnchorRejectsAnUncredentialedExit pins that admission verification
// actually happens on the engine that connects.
//
// Admission is the client's END-TO-END backstop against a HOSTILE COORDINATOR
// (ADR-0026/#60): the one check that does not trust the party doing the matchmaking.
// core reads an unset AdmissionPubKey as fail-open, so a client that never passes the
// field accepts any exit it can complete a handshake with — and a coordinator handing
// out an exit it controls is precisely the attack the check exists to catch. This
// client had no config field at all, so the check was not merely off, it was
// unreachable.
//
// The first attempt at this test fed a MALFORMED key and asserted the resulting
// construction error. It was vacuous, and worse, exactly inverted: pickExit runs
// first, so ITS core.New rejected the bad key and connectAsync was never reached.
// Deleting the fields from connectAsync — restoring the original defect verbatim —
// left it passing; deleting them from pickExit, which the code itself calls "inert…
// nothing here verifies an exit credential", made it fail. It tested the engine that
// does not matter.
//
// So this uses a WELL-FORMED anchor for an authority nothing here is signed by.
// pickExit then succeeds (a valid key really is inert there), and the assertion falls
// on the connecting engine, where the exit presents no admission credential and must
// be refused. That is the actual claim of #60 — a client with an anchor does not take
// the coordinator's word for which exit it got — rather than a claim about hex
// parsing.
func TestAdmissionAnchorRejectsAnUncredentialedExit(t *testing.T) {
	coord := newFakeCoordinator(t)
	echoAddr := startEchoServer(t)

	// An exit with no admission credential: it presents none, which an anchored
	// client must refuse and an unanchored one accepts (fail-open, pre-#60).
	exitEng, err := core.New(core.Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{core.RoleExit},
		ListenAddr:   "127.0.0.1:0",
		Advertise:    "127.0.0.1:1",
		Country:      "zz",
	})
	if err != nil {
		t.Fatalf("exit New: %v", err)
	}
	if err := exitEng.Start(context.Background()); err != nil {
		t.Fatalf("exit Start: %v", err)
	}
	t.Cleanup(exitEng.Stop)
	if !waitFor(5*time.Second, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return coord.exit != nil
	}) {
		t.Fatal("exit never registered with the fake coordinator")
	}

	anchorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate anchor: %v", err)
	}

	ctrl := newProxyOnlyController(Config{
		Coordinators:    []string{coord.addr()},
		AdmissionPubKey: hex.EncodeToString(anchorPub),
	})
	rec := newStateRecorderFor(ctrl)
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail
	t.Cleanup(ctrl.Disconnect)

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	// Protected is expected, and is NOT the assertion. core checks the exit's
	// credential inside clientHandshake (core/client.go), which runs per SOCKS
	// stream — the credential rides in msg2 of the end-to-end Noise handshake, and
	// there is no such handshake until traffic wants one. So the transport session
	// legitimately comes up before any admission check has happened.
	if s := rec.next(t, 20*time.Second); s != Protected {
		t.Fatalf("state = %v, want Protected (details: %v)", s, rec.detailsSnapshot())
	}

	// THE assertion: the moment traffic actually asks for the exit, the anchor must
	// refuse it. Nothing reaches the internet through an exit that proved nothing.
	if _, err := socksEchoRoundTrip(SocksAddr, echoAddr, []byte("this must not arrive")); err == nil {
		t.Fatal("an anchored client round-tripped traffic through an exit that presented no admission credential: " +
			"ADR-0026/#60's end-to-end backstop is not running on the engine that connects, so a hostile coordinator's exit is accepted on the client's own authority")
	}
}

// TestStaleAttemptCannotClearTheWinnersState is the regression test for a defect the
// SocksAddr fix INTRODUCED, which is the interesting part.
//
// With an ephemeral port, two connect attempts got two ports and never met, so
// Disconnect's inability to cancel an in-flight connectAsync was invisible. Pinning
// the port — which had to happen, or nothing could reach the tunnel at all — made
// them contend for 1080. Connect -> Disconnect -> Connect leaves two attempts racing
// to bind; the loser's Start fails; and abort used to clear c.eng/c.state
// unconditionally. That is not the loser's state to clear. It orphans the WINNER's
// live engine: the UI reads Disconnected with eng == nil, Disconnect becomes a no-op,
// 1080 stays held by a tunnel nothing tracks, and every later Connect fails on the
// bind. Bricked until restart, with a live session the user can neither see nor stop.
//
// This does NOT race two connects and hope. Tried that: over loopback an attempt
// completes in ~30ms, so the second Connect is simply rejected by the state guard and
// the two never overlap — the mutant survived every run. Racing tests what the
// scheduler felt like, not what the code guarantees.
//
// So it drives the invariant instead: **an attempt may only clear state while its own
// generation is current.** abort is called directly at a stale generation, which is
// exactly what the losing goroutine does, minus the scheduling lottery.
func TestStaleAttemptCannotClearTheWinnersState(t *testing.T) {
	c := NewController(Config{})
	c.OnState = func(ConnState) {}
	c.OnDetail = func(string) {}

	// Stand in for a winning attempt that has installed a live session.
	c.mu.Lock()
	c.gen, c.state = 7, Protected
	c.mu.Unlock()

	// A loser from an earlier generation reports the failure it just hit — in
	// production, losing the bind on SocksAddr to the attempt the user actually wants.
	c.abort(3, errors.New("listen tcp 127.0.0.1:1080: bind: address already in use"))

	c.mu.Lock()
	got := c.state
	c.mu.Unlock()
	if got != Protected {
		t.Fatalf("a stale attempt's failure moved the controller to %v: it cleared state belonging to the attempt that WON, "+
			"orphaning a live engine that still holds %s — Disconnect is now a no-op and every future Connect fails on that bind", got, SocksAddr)
	}

	// And the guard must not be "abort never works": the CURRENT generation's failure
	// still has to land, or a failed connect hangs the UI on Connecting forever.
	c.mu.Lock()
	c.gen, c.state = 8, Connecting
	c.mu.Unlock()
	c.abort(8, errors.New("no exits are available right now"))
	c.mu.Lock()
	got = c.state
	c.mu.Unlock()
	if got != Disconnected {
		t.Fatalf("the current attempt's failure left the controller at %v, want Disconnected — a failed connect must not strand the UI", got)
	}
}

// TestProtectedMeansTrafficActuallyFlows is the test whose absence let this client
// ship a green "you are protected" banner over a tunnel that carried nothing.
//
// TestController_RealLoopback proves the state machine reaches Protected. It cannot
// prove Protected is TRUE, because it never sends a byte — and the state really was
// correct: the tunnel came up, the engine was healthy, the ICE events were genuine.
// What was false was the sentence the UI showed about it. The client asked core for
// SocksAddr "127.0.0.1:0", an OS-assigned ephemeral port; core exposes no accessor
// for the bound address (and its own log line prints the REQUESTED one), and this
// client does no OS routing at all — no TUN, no route flip, no system proxy. So the
// proxy listened on a port that nothing, and nobody, could ever discover. Every
// "Protected" it displayed was false, on the only path there is, and no test noticed
// because every test asked the state machine rather than the network.
//
// So this asks the network: once the UI says Protected, a real SOCKS5 CONNECT to the
// address the user is told to configure must round-trip a real byte through a real
// exit. That is the claim ui.go makes, tested the way the claim is made. It fails
// against port 0 — nothing is listening on 1080 — which is the point.
func TestProtectedMeansTrafficActuallyFlows(t *testing.T) {
	coord := newFakeCoordinator(t)
	echoAddr := startEchoServer(t) // stands in for the internet, reached by the exit

	exitEng, err := core.New(core.Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{core.RoleExit},
		ListenAddr:   "127.0.0.1:0",
		Advertise:    "127.0.0.1:1",
		Country:      "zz",
	})
	if err != nil {
		t.Fatalf("exit New: %v", err)
	}
	if err := exitEng.Start(context.Background()); err != nil {
		t.Fatalf("exit Start: %v", err)
	}
	t.Cleanup(exitEng.Stop)

	if !waitFor(5*time.Second, func() bool {
		coord.mu.Lock()
		defer coord.mu.Unlock()
		return coord.exit != nil
	}) {
		t.Fatal("exit never registered with the fake coordinator")
	}

	ctrl := newProxyOnlyController(Config{Coordinators: []string{coord.addr()}})
	rec := newStateRecorderFor(ctrl)
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail
	t.Cleanup(ctrl.Disconnect)

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 20*time.Second); s != Protected {
		t.Fatalf("state = %v, want Protected (details so far: %v)", s, rec.detailsSnapshot())
	}

	// The UI now says "Apps set to use the proxy at 127.0.0.1:1080 are protected."
	// Take it at its word.
	payload := []byte("bacchus carries this or the banner is a lie")
	got, err := socksEchoRoundTrip(SocksAddr, echoAddr, payload)
	if err != nil {
		t.Fatalf("the UI says Protected, but nothing can use the tunnel: SOCKS5 through %s failed: %v\n"+
			"That is the false-Protected defect: a user in a censored country is told they are safe while every byte leaves in the clear.", SocksAddr, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip through the tunnel returned %q, want %q", got, payload)
	}
	rec.assertPublishesWereLocked(t)
}

// startEchoServer is a TCP echo the exit can dial: the "internet" end of the round
// trip. Mirrors cmd/node's helper of the same name (that one lives in package main
// and cannot be imported here).
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// socksEchoRoundTrip drives one real SOCKS5 CONNECT through socksAddr to target,
// writes payload, and returns the echoed bytes — proving the tunnel is genuinely
// usable end to end (real transport handshake, real E2E Noise handshake, real exit
// egress), not merely that some internal call returned no error. Mirrors cmd/node's
// helper of the same name.
func socksEchoRoundTrip(socksAddr, target string, payload []byte) ([]byte, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial socks: %w", err)
	}
	defer c.Close()
	if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}

	if _, err := c.Write([]byte{5, 1, 0}); err != nil { // VER 5, 1 method, no-auth
		return nil, fmt.Errorf("write greeting: %w", err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(c, greet); err != nil {
		return nil, fmt.Errorf("read greeting reply: %w", err)
	}
	if greet[0] != 5 || greet[1] != 0 {
		return nil, fmt.Errorf("socks greeting rejected: %v", greet)
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("split target: %w", err)
	}
	ip4 := net.ParseIP(host).To4()
	if ip4 == nil {
		return nil, fmt.Errorf("target must be an IPv4 literal, got %q", host)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return nil, fmt.Errorf("parse port %q: %w", portStr, err)
	}
	req := []byte{5, 1, 0, 1, ip4[0], ip4[1], ip4[2], ip4[3], byte(port >> 8), byte(port)}
	if _, err := c.Write(req); err != nil {
		return nil, fmt.Errorf("write connect: %w", err)
	}
	connReply := make([]byte, 10)
	if _, err := io.ReadFull(c, connReply); err != nil {
		return nil, fmt.Errorf("read connect reply: %w", err)
	}
	if connReply[1] != 0 {
		return nil, fmt.Errorf("socks connect failed, rep=%d", connReply[1])
	}

	if _, err := c.Write(payload); err != nil {
		return nil, fmt.Errorf("write payload: %w", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return nil, fmt.Errorf("read echo: %w", err)
	}
	return got, nil
}

// TestSocksAddrMatchesWhatTheUserIsTold couples the constant to the text users act
// on, by reading that text.
//
// The address is a literal in three files: ui.go's Protected description,
// translations/state.ru.json's Russian of it, and README.md. Nothing in Go couples
// them, so changing SocksAddr alone leaves every test here passing — including
// TestProtectedMeansTrafficActuallyFlows, which follows the constant rather than the
// claim — while the app, the translation and the documentation all go on telling
// users to configure a port nothing is listening on. A user in a censored country
// points their browser at 1080, gets connection refused, and has no way to discover
// why.
//
// The first version of this was a tripwire that asserted the constant equalled a
// literal and listed where else to look. It was wrong twice over: its list named the
// wrong README section (renamed in the very commit that added it — a tripwire whose
// only deliverable is its map, shipped with a broken map), and its premise, that a
// test here "cannot reach" those files, was simply untrue. They are three relative
// paths away. So it reads them.
func TestSocksAddrMatchesWhatTheUserIsTold(t *testing.T) {
	for _, f := range []string{
		"../../ui.go",
		"../../translations/state.ru.json",
		"../../README.md",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v (this test exists to couple SocksAddr to the text users read; if the file moved, re-point it rather than deleting it)", f, err)
		}
		if !strings.Contains(string(b), SocksAddr) {
			t.Errorf("%s does not mention %s. This client does no OS routing, so that address is the ONLY way a user can send traffic through the tunnel — "+
				"if the app, the Russian translation, or the docs name a different port, they are instructing users to configure something that is not listening.", f, SocksAddr)
		}
	}
}

// TestStaleEngineEventsAreDropped pins onEvent's generation gate, which was correct
// and untested — removing it left all nine tests passing.
//
// Every attempt wires its OWN engine's OnEvent to onEvent, and Connect -> Disconnect
// -> Connect genuinely runs two engines at once for a moment. A zombie's ICE ": closed",
// fired as it shuts down, would move the WINNER's state to Blocked and leave it there:
// the healthy engine has no reason to re-emit "connected", so nothing corrects it.
//
// The end-to-end race does not reproduce over loopback, where the zombie always
// finishes before the winner starts. The property needs no scheduling lottery at all —
// it is just "an event from generation N does not move generation M". Drive that
// directly, exactly as TestStatePublishHappensUnderTheLock argues.
func TestStaleEngineEventsAreDropped(t *testing.T) {
	c := NewController(Config{})
	c.OnState = func(ConnState) {}

	// A live session, installed by attempt 7.
	c.mu.Lock()
	c.gen, c.state = 7, Protected
	c.mu.Unlock()

	// Attempt 3's engine — long since abandoned — notices it is shutting down.
	c.onEvent(3, core.Event{Kind: core.EventICE, Message: "peer1 ICE: closed"})

	c.mu.Lock()
	got := c.state
	c.mu.Unlock()
	if got != Protected {
		t.Fatalf("a stale engine's shutdown moved the live session to %v: the UI now reports a dead path over a healthy tunnel, and the working engine will never re-emit anything to correct it", got)
	}

	// And the gate must not be "onEvent never works": the LIVE engine's identical event
	// still has to land, or the app stops reporting real path failures — which is the
	// far worse direction.
	c.onEvent(7, core.Event{Kind: core.EventICE, Message: "peer1 ICE: closed"})
	c.mu.Lock()
	got = c.state
	c.mu.Unlock()
	if got != Blocked {
		t.Fatalf("the live engine's ICE close left the state at %v, want Blocked — the gate is dropping events it must deliver, so a dead path would keep reading as protected", got)
	}
}
