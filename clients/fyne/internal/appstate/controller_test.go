package appstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/clients/internal/enforcement"
	"github.com/bacchus-vpn/bacchus/core"
	"github.com/pion/turn/v4"
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
	coord, exitEng := startLoopbackExit(t)

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
	if got := rec.detailsSnapshot(); len(got) == 0 || got[len(got)-1] != noCoordinatorsError().Error() {
		t.Fatalf("details = %v, want the last entry to explain the missing config", got)
	}
}

// TestController_BlankCoordinatorIsNoCoordinator is the near miss of the
// release bundle's empty template: `"coordinators": [""]`, which is what
// deleting a host from between the quotes leaves behind. Its length is 1 and
// it names nothing, so a length check waves it through to core, which drops
// blanks itself and then refuses - correctly, but with a sentence that names
// no file, no key and no window. The client's own refusal is the one worth
// getting, so this must abort here.
//
// Mutation check: put `len(c.cfg.Coordinators) == 0` back in connectAsync and
// this hangs on a real dial attempt instead of landing on Disconnected with an
// actionable line.
func TestController_BlankCoordinatorIsNoCoordinator(t *testing.T) {
	ctrl := NewController(Config{Coordinators: []string{"", "   "}})
	rec := newStateRecorder()
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail

	ctrl.Connect()
	if s := rec.next(t, 2*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 2*time.Second); s != Disconnected {
		t.Fatalf("state = %v, want Disconnected", s)
	}
	if got := rec.detailsSnapshot(); len(got) == 0 || got[len(got)-1] != noCoordinatorsError().Error() {
		t.Fatalf("details = %v, want this client's own no-coordinators message, not core's", got)
	}
}

// TestHasCoordinator pins the counting rule itself, including the two entries
// that look like addresses to len() and are not.
func TestHasCoordinator(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{""}, false},
		{[]string{" \t\n"}, false},
		{[]string{"", ""}, false},
		{[]string{"203.0.113.10:8080"}, true}, // TEST-NET-3 (RFC 5737)
		{[]string{"", "203.0.113.10:8080"}, true},

		// An untouched template is nothing configured. Both entries the
		// example ships, with and without a port, and a half-edited pair
		// where only the second was replaced.
		{[]string{"COORDINATOR_HOST:8080"}, false},
		{[]string{"COORDINATOR_HOST:8080", "COORDINATOR_HOST_2:8080"}, false},
		{[]string{"COORDINATOR_HOST"}, false},
		{[]string{" COORDINATOR_HOST:8080 "}, false},
		{[]string{"COORDINATOR_HOST:8080", "203.0.113.10:8080"}, true},

		// Matched in the HOST POSITION and EXACTLY, so a real deployment is
		// never refused for a name that merely resembles a placeholder.
		{[]string{"coordinator_host:8080"}, true},
		{[]string{"COORDINATOR_HOST.example.net:8080"}, true},
		{[]string{"my-COORDINATOR_HOST:8080"}, true},
		{[]string{"203.0.113.10:COORDINATOR_HOST"}, true},
	} {
		if got := hasCoordinator(tc.in); got != tc.want {
			t.Errorf("hasCoordinator(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestTemplatePlaceholdersMatchTheExampleFile is what keeps the hard-coded set
// in controller.go honest. hasCoordinator refuses the example's placeholder
// hostnames by name, which is only safe while those names are what the example
// actually ships — rename a placeholder there and the client silently goes
// back to treating an untouched template as configured, which is bacchus#134
// returning by the same route it arrived.
//
// So this reads the real file rather than a copy: every host in its
// "coordinators" array must be in templatePlaceholderHosts, and every entry in
// templatePlaceholderHosts must appear in the file. Neither direction is
// optional — the first catches a rename, the second catches a stale leftover.
func TestTemplatePlaceholdersMatchTheExampleFile(t *testing.T) {
	const example = "../../bacchus-fyne.config.example.json"
	b, err := os.ReadFile(example)
	if err != nil {
		t.Fatalf("read %s: %v", example, err)
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("parse %s: %v", example, err)
	}
	if len(cfg.Coordinators) == 0 {
		t.Fatalf("%s names no coordinators; this test cannot mean anything", example)
	}

	seen := map[string]bool{}
	for _, a := range cfg.Coordinators {
		host := a
		if h, _, err := net.SplitHostPort(a); err == nil {
			host = h
		}
		if !templatePlaceholderHosts[host] {
			t.Errorf("%s ships coordinator host %q, which templatePlaceholderHosts does not list — "+
				"an untouched template would be treated as configured (bacchus#134)", example, host)
		}
		seen[host] = true
	}
	for host := range templatePlaceholderHosts {
		if !seen[host] {
			t.Errorf("templatePlaceholderHosts lists %q, which %s no longer ships — "+
				"a real host by that name would be refused", host, example)
		}
	}

	// The whole point, end to end: the file as shipped must read as
	// unconfigured.
	if hasCoordinator(cfg.Coordinators) {
		t.Errorf("hasCoordinator(%q) = true for the untouched example; "+
			"a fresh user would get a DNS failure instead of the refusal that names the file",
			cfg.Coordinators)
	}
}

// TestNoCoordinatorsErrorNamesTheFileToCreate is bacchus#134's first half: the
// message must name a path the user can act on. It used to say to copy
// bacchus-fyne.config.example.json "into place" — a file that is in the
// repository and in no artifact, at a path it did not name.
//
// The per-user branch is the one a fresh binary with no config anywhere lands
// on, which is what a #115-style download does before anybody has saved
// anything.
func TestNoCoordinatorsErrorNamesTheFileToCreate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	want := DefaultConfigPath()
	if _, err := os.Stat(want); err == nil {
		t.Fatalf("%s already exists; this test needs the no-config-anywhere case", want)
	}

	got := noCoordinatorsError().Error()
	if !strings.Contains(got, want) {
		t.Errorf("message %q does not name %q — a path the user can act on is the whole point of bacchus#134", got, want)
	}
	if !strings.Contains(got, "create") {
		t.Errorf("message %q does not tell the user to create the file, which is what has to happen when it is not there: %q", got, want)
	}
}

// TestNoCoordinatorsErrorNamesAnExistingConfig is the case the release bundle
// creates and the reason bacchus#136's third ruling is enough on the client
// side: the bundle ships bacchus-fyne.config.json beside the exe with the
// endpoint keys present and empty, so the file the user must edit already
// exists and the message has to say "add to" rather than "create".
func TestNoCoordinatorsErrorNamesAnExistingConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	exePath := writeExeAdjacentConfig(t, Config{})

	got := noCoordinatorsError().Error()
	if !strings.Contains(got, exePath) {
		t.Errorf("message %q does not name the config that exists (%q)", got, exePath)
	}
	if strings.Contains(got, "create") {
		t.Errorf("message %q tells the user to create a file that is already there (%q)", got, exePath)
	}
}

// TestNoCoordinatorsErrorHasNoDeadEnds is the regression guard for the two
// pieces of advice bacchus#134 found unactionable, kept separate because each
// was independently a dead end: a file that ships in no artifact, and a
// Settings window with no widget for the field in question.
//
// The second is asserted as a REQUIREMENT to mention Settings, not a ban on
// it. Saying nothing sends the user hunting through that window for a control
// that is not in it — which is what bacchus#134's own reporter did within
// minutes. Naming it in order to rule it out is what stops the hunt. If the
// endpoint fields ever gain widgets, this test is where that shows up.
func TestNoCoordinatorsErrorHasNoDeadEnds(t *testing.T) {
	got := noCoordinatorsError().Error()
	if strings.Contains(got, "bacchus-fyne.config.example.json") {
		t.Errorf("message %q still points at the example file, which is in the repository and in no artifact", got)
	}
	if !strings.Contains(got, settingsMenuPath) {
		t.Errorf("message %q does not mention %s, so nothing tells the user that window cannot set this field", got, settingsMenuPath)
	}
	if !strings.Contains(got, "coordinators") {
		t.Errorf("message %q does not name the config key to set, which is the one token a user hand-editing JSON needs", got)
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

// startLoopbackExit brings up the two-engine rig every end-to-end test in this
// file needs: a fake coordinator (fakecoordinator_test.go) and one registered
// exit-role core.Engine, both on loopback, with the exit stopped on cleanup.
// It returns both because a test that wants a genuine ICE drop kills the exit
// by hand.
//
// # turnAddr, and why the enforced path needs it on Windows
//
// Callers that leave turnAddr empty get an exit with no STUN and no TURN, which
// gathers HOST candidates. pion excludes loopback from host gathering by
// default and nothing here calls SetIncludeLoopbackCandidate, so those
// candidates carry the machine's real interface addresses.
//
// That is fine while the other side also has host candidates. It is not fine on
// the enforced path, where the client is relay-ONLY: connectAsync sets
// ForceRelay whenever an Enforcer exists, so the client's only candidate is the
// TURN allocation at 127.0.0.1. The connectivity check then runs from a socket
// bound to a real interface TO loopback — which Linux delivers and **Windows
// does not**, because Windows will not carry a datagram from a non-loopback
// socket to 127.0.0.1. The symptom is ICE sitting in `checking` until the
// transport gives up, on Windows only, with every assertion here otherwise
// sound.
//
// Passing turnAddr puts the exit on the same TURN server and makes it
// relay-only too. Then neither side ever asks an interface-bound socket to
// reach loopback: both talk to the TURN server from unspecified-bound sockets,
// and relaying between the two allocations is internal to that server. The
// three callers that pass nothing keep exactly today's behaviour.
func startLoopbackExit(t *testing.T, turnAddr ...string) (*fakeCoordinator, *core.Engine) {
	t.Helper()
	coord := newFakeCoordinator(t)

	cfg := core.Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{core.RoleExit},
		ListenAddr:   "127.0.0.1:0",
		Advertise:    "127.0.0.1:1", // unused in direct mode; New only requires it non-empty
		Country:      "zz",
	}
	if len(turnAddr) > 0 && turnAddr[0] != "" {
		cfg.TURNURL = "turn:" + turnAddr[0]
		cfg.TURNUser = turnTestUser
		cfg.TURNPass = turnTestPass
		cfg.ForceRelay = true
	}

	exitEng, err := core.New(cfg)
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
	return coord, exitEng
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
	// The rig's exit carries no admission credential: it presents none, which an
	// anchored client must refuse and an unanchored one accepts (fail-open, pre-#60).
	coord, _ := startLoopbackExit(t)
	echoAddr := startEchoServer(t)

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
	coord, _ := startLoopbackExit(t)
	echoAddr := startEchoServer(t) // stands in for the internet, reached by the exit

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

// --- the enforced connect path (issue #112) -------------------------------
//
// Everything below drives a Controller that HAS an Enforcer, which is what
// the Windows tray client had from bacchus#59 and what Linux gained in
// bacchus#37. The Enforcer is a fake (fakeEnforcer), so nothing below the seam
// is checked here — see newEnforcedController for the full statement of what
// that costs and where the other half is covered.
//
// One thing had to be discovered rather than assumed, and it is why these
// tests need a TURN server when the proxy-only ones above do not.
// connectAsync sets core.Config.ForceRelay from `c.enf != nil`, so the moment
// an Enforcer exists every WebRTC candidate is pinned to the configured TURN
// server (ICETransportPolicyRelay). With no TURN configured, relay-only ICE
// gathers nothing at all: the rig above sits in Connecting until the test
// times out, having never reached Enforcer.Start. Confirmed by running it.
// So an enforced-path test is not the proxy-only rig plus a fake — it is that
// rig plus a real STUN/TURN server, and startLoopbackTURN is it.

// fakeEnforcer is an enforcement.Enforcer that answers from the test instead
// of from the OS: no helper, no TUN, no routes, no kill-switch, and no
// privilege of any kind.
//
// It records rather than asserts, so each test states its own expectation. All
// state is mutex-guarded because Start is called from the goroutine Connect
// spawned while the test reads it from its own — under -race, anything less is
// a data race rather than a test.
type fakeEnforcer struct {
	mu sync.Mutex

	// startErrs is consumed one entry per Start call. A nil entry (or running
	// off the end of the slice) is a Start that succeeds, so
	// []error{errSomething} is "fail the first attempt, succeed after".
	startErrs []error

	// servesWhileRouted is what ServesWhileRouted answers, i.e. whether this
	// fake platform can carve a served role's egress out of the tunnel
	// (bacchus#109). The zero value is false — the safe answer, and the one a
	// platform that has not built the carve-out gives — so every test written
	// before #109 keeps the posture it was written against.
	servesWhileRouted bool
	servedSource      string

	starts     int
	recovers   int
	policies   []enforcement.Policy
	socksAddrs []string
	reserved   []string
	sessions   []*fakeSession
}

func (f *fakeEnforcer) Start(policy enforcement.Policy, socksAddr string) (enforcement.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies = append(f.policies, policy)
	f.socksAddrs = append(f.socksAddrs, socksAddr)
	i := f.starts
	f.starts++
	if i < len(f.startErrs) && f.startErrs[i] != nil {
		return nil, f.startErrs[i]
	}
	s := &fakeSession{}
	f.sessions = append(f.sessions, s)
	return s, nil
}

func (f *fakeEnforcer) Recover() {
	f.mu.Lock()
	f.recovers++
	f.mu.Unlock()
}

func (f *fakeEnforcer) ReserveUnderlay(addr string) {
	f.mu.Lock()
	f.reserved = append(f.reserved, addr)
	f.mu.Unlock()
}

func (f *fakeEnforcer) ServesWhileRouted() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.servesWhileRouted
}

func (f *fakeEnforcer) ServedSource() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.servedSource
}

func (f *fakeEnforcer) startCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts
}

func (f *fakeEnforcer) recoverCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.recovers
}

func (f *fakeEnforcer) reservedUnderlays() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reserved...)
}

// sessionsOpened returns every Session Start handed back, in order.
func (f *fakeEnforcer) sessionsOpened() []*fakeSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeSession(nil), f.sessions...)
}

// lastPolicy is the Policy of the most recent Start, for the tests that check
// what the controller translated Config into.
func (f *fakeEnforcer) lastPolicy(t *testing.T) (enforcement.Policy, string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.policies) == 0 {
		t.Fatal("Enforcer.Start was never called, so there is no policy to inspect")
	}
	return f.policies[len(f.policies)-1], f.socksAddrs[len(f.socksAddrs)-1]
}

// fakeSession is one enforcement session. It deliberately has NO sync.Once
// around Close, unlike the real linuxSession — a second Close is exactly what
// this wants to catch, and a Once in the fake would hide the controller
// double-closing a session it had already torn down.
type fakeSession struct {
	mu sync.Mutex

	closes int
	// socksUpAtClose records, per Close call, whether the client's SOCKS
	// listener was still accepting connections at that instant. That is the
	// only way this seam can observe Disconnect's teardown ORDER, which is
	// documented as load-bearing: enforcement is closed FIRST and the engine
	// stopped second, so egress is restored before the tunnel carrying it goes
	// away (ADR-0014, tunnel.Close). Reversed, the port is already gone by the
	// time Close runs and this reads false.
	socksUpAtClose []bool
}

// ReserveUnderlay is a no-op and records nothing, because the controller never
// calls it: connectAsync wires core.Config.OnUnderlayDial to the ENFORCER's
// method, not to a Session's, and the Enforcer is where the recording happens
// (see TestUnderlayDialHookIsWiredToTheEnforcer). The method exists here only
// to satisfy enforcement.Session.
func (s *fakeSession) ReserveUnderlay(string) {}

func (s *fakeSession) Close() {
	up := socksIsListening()
	s.mu.Lock()
	s.closes++
	s.socksUpAtClose = append(s.socksUpAtClose, up)
	s.mu.Unlock()
}

func (s *fakeSession) closeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closes
}

func (s *fakeSession) engineWasStillUpAtClose() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.socksUpAtClose) > 0 && s.socksUpAtClose[0]
}

// socksIsListening reports whether anything is accepting on SocksAddr. Used
// both to prove the engine is DOWN after a failed or torn-down session — the
// half-state a failed enforcement must never leave behind is a working SOCKS
// proxy nobody is tracking — and to observe teardown order from inside
// fakeSession.Close.
func socksIsListening() bool {
	c, err := net.DialTimeout("tcp", SocksAddr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TURN credentials for the in-process server below. Loopback-only, generated
// nowhere, valid for nothing: the server is started by the test and dies with
// it, and both ends of the pair are these two literals.
const (
	turnTestRealm = "bacchus-test"
	turnTestUser  = "testuser"
	turnTestPass  = "testpass"
)

// startLoopbackTURN runs a real pion/turn server on loopback and returns its
// address, because ForceRelay makes one mandatory on the enforced path (see
// this section's opening note). Same shape as the one cmd/coordinator actually
// ships (startTurnAndBootstrap), minus the cold-start bootstrap demux this has
// no use for.
func startLoopbackTURN(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("TURN listen: %v", err)
	}
	key := turn.GenerateAuthKey(turnTestUser, turnTestRealm, turnTestPass)
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: turnTestRealm,
		AuthHandler: func(username, realm string, src net.Addr) ([]byte, bool) {
			return key, username == turnTestUser
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"), // what peers are told to use
				Address:      "127.0.0.1",
			},
		}},
	})
	if err != nil {
		t.Fatalf("turn.NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return conn.LocalAddr().String()
}

// enforcedRig is the whole fixture one enforced-path test needs: the loopback
// coordinator+exit, a TURN server, and a Controller wired to enf. Cleanup
// disconnects and waits for SocksAddr to come free, since the port is pinned
// (see SocksAddr) and a test that left it held would fail the next one.
func enforcedRig(t *testing.T, enf enforcement.Enforcer) (*Controller, *stateRecorder) {
	t.Helper()
	// One TURN server for both ends. The exit has to be on it too, or the
	// enforced path cannot connect on Windows — see startLoopbackExit's doc.
	turnAddr := startLoopbackTURN(t)
	coord, _ := startLoopbackExit(t, turnAddr)
	ctrl := newEnforcedController(Config{
		Coordinators: []string{coord.addr()},
		TURN:         "turn:" + turnAddr,
		TURNUser:     turnTestUser,
		TURNPass:     turnTestPass,
	}, enf)
	rec := newStateRecorderFor(ctrl)
	ctrl.OnState, ctrl.OnDetail = rec.onState, rec.onDetail
	t.Cleanup(func() {
		ctrl.Disconnect()
		if !waitFor(10*time.Second, func() bool { return !socksIsListening() }) {
			t.Errorf("%s is still held after Disconnect — a later test will fail on the bind", SocksAddr)
		}
	})
	return ctrl, rec
}

// lastDetail is the sentence currently on screen under the headline state.
func lastDetail(t *testing.T, rec *stateRecorder) string {
	t.Helper()
	got := rec.detailsSnapshot()
	if len(got) == 0 {
		t.Fatal("the controller published no detail line at all")
	}
	return got[len(got)-1]
}

// TestEnforcementFailureAbortsTheConnect is the branch bacchus#37 created and
// nothing covered: core.Engine.Connect SUCCEEDS and Enforcer.Start FAILS.
//
// It is not a hypothetical. On Linux the overwhelmingly likely way to get here
// is a machine with no bacchus-netd installed, which is every machine until the
// user installs one, and ADR-0049's Consequences call it out by name.
//
// What must happen is that the whole connect aborts. What must NOT happen is
// the friendlier-looking outcome: leaving the engine running as a working SOCKS
// proxy and calling it Protected. connectAsync's own comment names that as
// "this ADR's own Scope-section lie in its original form", and parity item 7
// exists to rule it out. So this asserts the terminal state, the sentence the
// user is given, and — the part a state assertion cannot reach — that nothing
// is still accepting on SocksAddr, by asking the network. A half-state here is
// a proxy port held open by a session nothing is tracking.
//
// The limit of that last check, found by running the mutation rather than
// assuming it: deleting eng.Stop() from the failure branch and leaving cancel()
// SURVIVES, because cancelling the engine's context already closes the
// listener. So the probe catches "the abort tore nothing down", not "the abort
// tore down less than it should have" — Stop's other work (sessions closed,
// goroutines joined, the quota checkpoint flushed) leaves no mark this seam can
// see, and inventing one is not worth an accessor on core.Engine.
func TestEnforcementFailureAbortsTheConnect(t *testing.T) {
	helperMissing := errors.New("bacchus-netd is not reachable")
	enf := &fakeEnforcer{startErrs: []error{helperMissing}}
	ctrl, rec := enforcedRig(t, enf)

	ctrl.Connect()
	if s := rec.next(t, 5*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 30*time.Second); s != Disconnected {
		t.Fatalf("state = %v, want Disconnected — enforcement failed, so the connect must abort rather than arrive anywhere else (details: %v)", s, rec.detailsSnapshot())
	}

	// Without this the test is vacuous: any connect that failed EARLIER — no
	// exit, no ICE, a TURN server that never came up — also lands on
	// Disconnected, and would pass every assertion here while never reaching
	// the branch under test.
	if got := enf.startCount(); got != 1 {
		t.Fatalf("Enforcer.Start was called %d times, want 1: the engine never got far enough to attempt enforcement, so this test proved nothing about the enforced path (details: %v)", got, rec.detailsSnapshot())
	}

	want := "could not route this device: " + helperMissing.Error()
	if got := lastDetail(t, rec); got != want {
		t.Errorf("detail line = %q, want %q — the user is told the connection failed but not that routing was what failed, which is the one part they can act on", got, want)
	}

	if waitFor(2*time.Second, socksIsListening) {
		t.Errorf("%s is still accepting connections after enforcement failed. The connect aborted on paper and left a working, untracked SOCKS proxy behind it — "+
			"which is the silent degradation to unprotected that parity item 7 exists to rule out, plus a pinned port no later Connect can bind", SocksAddr)
	}

	// c.sess must be nil too, or Disconnect would later close a session that
	// was never installed. abort clears it; this pins that it does.
	ctrl.mu.Lock()
	sess := ctrl.sess
	ctrl.mu.Unlock()
	if sess != nil {
		t.Errorf("the controller kept an enforcement session (%v) from a connect that failed to start one", sess)
	}
}

// TestDeviceEnforcedSurvivesAFailedSession is the one that matters most, and
// the reason is that DeviceEnforced() is not a status line — it is a decision
// input, read in three places (main.go's indicator, settings.go's volunteer
// disclosure, connectAsync's own ForceRelay and PlanVolunteer calls).
//
// It answers a question about the PLATFORM, not about the moment (see its own
// doc and enforcement_linux.go's "why this does not probe for the helper"),
// and a session that failed to enforce does not change what the platform is.
// If it did flip to false, the failure is not a wrong pixel: c.enf would be
// gone, so the NEXT connect would take startEnforcement's proxy-only branch,
// succeed, and reach Protected having enforced nothing — with the UI rendering
// "Proxy ready" over a machine the user asked to have routed in full.
//
// So the assertion is not only the boolean. It is that a second connect after
// a failed one still ATTEMPTS enforcement and still installs a session, which
// is what the boolean is for.
func TestDeviceEnforcedSurvivesAFailedSession(t *testing.T) {
	enf := &fakeEnforcer{startErrs: []error{errors.New("bacchus-netd is not reachable")}}
	ctrl, rec := enforcedRig(t, enf)

	if !ctrl.DeviceEnforced() {
		t.Fatal("DeviceEnforced() is false on a controller built with an Enforcer")
	}

	ctrl.Connect()
	if s := rec.next(t, 5*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 30*time.Second); s != Disconnected {
		t.Fatalf("state = %v, want Disconnected after the failed Start (details: %v)", s, rec.detailsSnapshot())
	}
	if got := enf.startCount(); got != 1 {
		t.Fatalf("Enforcer.Start was called %d times, want 1 — the connect failed before enforcement was attempted", got)
	}

	if !ctrl.DeviceEnforced() {
		t.Fatal("DeviceEnforced() went false after a session failed to enforce. It answers what this BUILD does, not what the last attempt managed: " +
			"with it false the UI headline becomes \"Proxy ready\", ForceRelay stops pinning the underlay, and a serving role stops being refused — " +
			"all decided by one attempt that did not work")
	}

	// The behavioural half. If the failure had cleared c.enf, this connect
	// would succeed proxy-only: Protected, one Start ever, no session.
	ctrl.Connect()
	if s := rec.next(t, 5*time.Second); s != Connecting {
		t.Fatalf("second connect: first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 30*time.Second); s != Protected {
		t.Fatalf("second connect: state = %v, want Protected (details: %v)", s, rec.detailsSnapshot())
	}
	if got := enf.startCount(); got != 2 {
		t.Fatalf("Enforcer.Start was called %d times across two connects, want 2: the connect after a failed one reached Protected WITHOUT enforcing anything, "+
			"which is a green banner over an unrouted device", got)
	}
	if got := len(enf.sessionsOpened()); got != 1 {
		t.Fatalf("%d enforcement sessions were opened, want 1 (the second connect's)", got)
	}
	ctrl.mu.Lock()
	sess := ctrl.sess
	ctrl.mu.Unlock()
	if sess == nil {
		t.Fatal("the controller reached Protected with no enforcement session installed")
	}
	rec.assertPublishesWereLocked(t)
}

// TestDisconnectUnwindsAndReconnectRearmsEnforcement drives the lifecycle
// through the Controller rather than through the Enforcer, which is where the
// mistakes live: the Enforcer's own Close is covered next door, but whether
// Disconnect CALLS it — once, in the right order, and whether the connect after
// it arms a fresh session — is this seam's job and nothing asserted it.
//
// The teardown order is checked too, and it is not decoration. Disconnect
// closes enforcement first and stops the engine second, so egress is restored
// before the tunnel carrying it disappears (ADR-0014, and tunnel.Close's own
// documented order). Reversed, the machine spends a whole engine teardown
// fail-closed over a tunnel that is already gone. fakeSession.Close observes it
// by asking whether the SOCKS listener is still up at that instant.
func TestDisconnectUnwindsAndReconnectRearmsEnforcement(t *testing.T) {
	enf := &fakeEnforcer{}
	ctrl, rec := enforcedRig(t, enf)

	// NewController runs Recover() at startup — parity item 3, lifting a
	// lockdown a killed prior session left behind — and newEnforcedController
	// mirrors it, so this also pins that the test constructor has not quietly
	// dropped a production step.
	if got := enf.recoverCount(); got != 1 {
		t.Fatalf("Recover() was called %d times at construction, want 1: a lockdown left by a killed session stays armed and the user is offline before they touch anything", got)
	}

	ctrl.Connect()
	if s := rec.next(t, 5*time.Second); s != Connecting {
		t.Fatalf("first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 30*time.Second); s != Protected {
		t.Fatalf("state = %v, want Protected (details: %v)", s, rec.detailsSnapshot())
	}
	first := enf.sessionsOpened()
	if len(first) != 1 {
		t.Fatalf("%d enforcement sessions after one connect, want 1", len(first))
	}

	ctrl.Disconnect()
	if s := rec.next(t, 10*time.Second); s != Disconnected {
		t.Fatalf("state after Disconnect = %v, want Disconnected", s)
	}
	if !waitFor(10*time.Second, func() bool { return first[0].closeCount() > 0 }) {
		t.Fatal("Disconnect returned the UI to Disconnected without closing the enforcement session: the routes, the TUN and the kill-switch all outlive the session that installed them, " +
			"so the user is told they are disconnected while the device is still fail-closed over a tunnel that is gone")
	}
	if got := first[0].closeCount(); got != 1 {
		t.Errorf("the enforcement session was closed %d times, want exactly 1 — the real Session swallows the extra with a sync.Once, but a controller that closes twice is tearing down state it no longer owns", got)
	}
	if !first[0].engineWasStillUpAtClose() {
		t.Errorf("the engine was already stopped when the enforcement session was closed. Disconnect must lift the kill-switch and pull the routes FIRST and stop the engine second (ADR-0014): " +
			"reversed, the machine stays fail-closed for the length of an engine teardown over a tunnel that no longer exists, which the user sees as their network dying for no visible reason")
	}
	ctrl.mu.Lock()
	sess := ctrl.sess
	ctrl.mu.Unlock()
	if sess != nil {
		t.Errorf("the controller still holds an enforcement session after Disconnect")
	}

	// Re-arm. A disconnect that tore enforcement down but left the controller
	// unable to bring it back is the same defect one press later.
	ctrl.Connect()
	if s := rec.next(t, 5*time.Second); s != Connecting {
		t.Fatalf("reconnect: first state = %v, want Connecting", s)
	}
	if s := rec.next(t, 30*time.Second); s != Protected {
		t.Fatalf("reconnect: state = %v, want Protected (details: %v)", s, rec.detailsSnapshot())
	}
	if got := enf.startCount(); got != 2 {
		t.Fatalf("Enforcer.Start was called %d times across connect/disconnect/connect, want 2: the second session reached Protected without arming enforcement", got)
	}
	second := enf.sessionsOpened()
	if len(second) != 2 || second[1] == first[0] {
		t.Fatalf("the reconnect did not install a fresh enforcement session (%d sessions opened)", len(second))
	}
	if second[1].closeCount() != 0 {
		t.Errorf("the live session has already been closed %d times", second[1].closeCount())
	}
	rec.assertPublishesWereLocked(t)
}

// TestEnforcementPolicyCarriesTheUsersConfiguration checks the translation
// startEnforcement does from Config into enforcement.Policy, which nothing else
// in the repo exercises — the enforcement package's own tests start from a
// Policy that a test wrote by hand.
//
// Two fields are worth the test on their own. KillSwitch is a NEGATION of the
// config field (`!DisableKillSwitch`), and inverting it silently disarms
// ADR-0014's lockdown for every user who never touched the setting. DNSUpstream
// falls back to a default when unset, and an empty one reaching a real Enforcer
// is a DNS path with no server behind it. socksAddr is checked for the reason
// SocksAddr is a constant at all: it is the address the tunnel bridges into,
// and a mismatch means enforcement routes the device into a port nothing serves.
//
// Driven through startEnforcement directly rather than a full connect: this is
// a pure translation, no engine can make it more true, and three more ICE
// negotiations to read back a struct is not a trade worth making.
func TestEnforcementPolicyCarriesTheUsersConfiguration(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		enf := &fakeEnforcer{}
		c := newEnforcedController(Config{Coordinators: []string{"127.0.0.1:9"}}, enf)
		if _, err := c.startEnforcement(false); err != nil {
			t.Fatalf("startEnforcement: %v", err)
		}
		p, socksAddr := enf.lastPolicy(t)
		if !p.KillSwitch {
			t.Error("KillSwitch is off in the default policy: DisableKillSwitch defaults to false, so every user who never opened Settings would be running unprotected against a tunnel drop (ADR-0014)")
		}
		if p.DNSUpstream != DefaultDNSUpstream {
			t.Errorf("DNSUpstream = %q, want the %q fallback — an empty upstream is a DNS path with nothing behind it", p.DNSUpstream, DefaultDNSUpstream)
		}
		if p.BypassMode != BypassModeExclude {
			t.Errorf("BypassMode = %q, want the normalized default %q", p.BypassMode, BypassModeExclude)
		}
		if socksAddr != SocksAddr {
			t.Errorf("Start was given socksAddr %q, want %q: enforcement bridges the device into that address, so a mismatch routes everything into a port nothing is serving", socksAddr, SocksAddr)
		}
	})

	t.Run("configured", func(t *testing.T) {
		enf := &fakeEnforcer{}
		cfg := Config{
			Coordinators:      []string{"127.0.0.1:9", "127.0.0.1:10"},
			STUN:              "stun:127.0.0.1:3478",
			TURN:              "turn:127.0.0.1:3479",
			DNS:               "192.0.2.53:53",
			Bypass:            []string{"198.51.100.0/24"},
			BypassMode:        BypassModeInclude,
			DisableKillSwitch: true,
		}
		c := newEnforcedController(cfg, enf)
		var logged []string
		c.Logf = func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }

		if _, err := c.startEnforcement(false); err != nil {
			t.Fatalf("startEnforcement: %v", err)
		}
		p, _ := enf.lastPolicy(t)
		if p.KillSwitch {
			t.Error("KillSwitch is on despite DisableKillSwitch: the negation is inverted, and a user who deliberately turned the lockdown off gets it anyway")
		}
		if p.DNSUpstream != cfg.DNS {
			t.Errorf("DNSUpstream = %q, want the configured %q", p.DNSUpstream, cfg.DNS)
		}
		if p.BypassMode != BypassModeInclude {
			t.Errorf("BypassMode = %q, want %q — an include list applied as an exclude list tunnels precisely the destinations the user asked to keep out of the tunnel, and vice versa", p.BypassMode, BypassModeInclude)
		}
		if len(p.Bypass) != 1 || p.Bypass[0] != cfg.Bypass[0] {
			t.Errorf("Bypass = %v, want %v", p.Bypass, cfg.Bypass)
		}
		if len(p.Coordinators) != 2 || p.STUNURL != cfg.STUN || p.TURNURL != cfg.TURN {
			t.Errorf("control-plane addresses = %v/%q/%q, want %v/%q/%q — an Enforcer excludes exactly these from the tunnel's own route, so one that does not arrive is signalling captured by the route it installed",
				p.Coordinators, p.STUNURL, p.TURNURL, cfg.Coordinators, cfg.STUN, cfg.TURN)
		}

		// The enforcement layer's diagnostics have to reach this client's log
		// sink, or a route install that failed is written to nothing.
		if p.Logf == nil {
			t.Fatal("Policy.Logf is nil: everything the enforcement layer reports about failed route installs and kill-switch arming goes nowhere")
		}
		p.Logf("route add %s failed", "203.0.113.1")
		if len(logged) != 1 || !strings.Contains(logged[0], "203.0.113.1") {
			t.Errorf("Controller.Logf received %v, want the enforcement layer's line", logged)
		}
	})
}

// TestUnderlayDialHookIsWiredToTheEnforcer pins the two things
// underlayDialHook exists to get right, both of which only matter on the
// enforced path and neither of which any test reached.
//
// Nil on a platform with no Enforcer, because core reads a nil hook as "no
// hook" and a closure that dereferenced a nil Enforcer would panic on the dial
// path — a crash in the middle of a connect, not a failed connect.
//
// Wired to the ENFORCER and not to a Session when there is one, which is issue
// #109 itself: the transport pool dials its first reality underlay during the
// initial Connect, BEFORE startEnforcement has run, so there is no Session to
// hand it to. A hook pointing at a Session would silently drop that first
// address, and the underlay it names would ride the tunnel it is carrying.
func TestUnderlayDialHookIsWiredToTheEnforcer(t *testing.T) {
	if hook := newProxyOnlyController(Config{}).underlayDialHook(); hook != nil {
		t.Error("a controller with no Enforcer handed core a non-nil OnUnderlayDial: core calls it on the dial path, where it would dereference a nil Enforcer and take the process down mid-connect")
	}

	enf := &fakeEnforcer{}
	hook := newEnforcedController(Config{}, enf).underlayDialHook()
	if hook == nil {
		t.Fatal("a controller WITH an Enforcer handed core no OnUnderlayDial: the pool's first reality underlay is never excluded, which is the leak issue #109 closed")
	}
	hook("192.0.2.10:443")
	if got := enf.reservedUnderlays(); len(got) != 1 || got[0] != "192.0.2.10:443" {
		t.Errorf("the Enforcer was told to reserve %v, want [192.0.2.10:443] — the hook is pointed somewhere else, and an underlay dialled before enforcement starts is excluded by nothing", got)
	}
}
