package main

import (
	"bytes"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
)

// Issue #114: a node running a diverged build registers cleanly, re-announces every
// 10s, is never pruned, is offered to clients and is assigned work it silently drops.
// Everything this coordinator can say about that is said to the operator log, so
// these tests read the log — that IS the behaviour, not a proxy for it.

// logSink is a race-safe io.Writer for capturing what the coordinator logs. It is
// synchronized because this package's other tests leave background goroutines
// (startTurnAndBootstrap's reload and sign loops) running for the rest of the
// process, and any of them may log while a later test holds the writer.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// captureLog redirects the standard logger into a sink for one test, restoring it
// afterwards. It returns the sink so a test can read what has been written so far —
// several of these assert on what was logged BETWEEN two points, not only at the end.
func captureLog(t *testing.T) *logSink {
	t.Helper()
	sink := &logSink{}
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(sink)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return sink
}

// countLines counts log lines containing sub.
func countLines(logged, sub string) int {
	n := 0
	for _, line := range strings.Split(logged, "\n") {
		if strings.Contains(line, sub) {
			n++
		}
	}
	return n
}

// docAddr is an exit's advertised data-plane endpoint in RFC 5737 documentation
// space. Nothing here resolves it; it only has to be a plausible endpoint.
const docAddr = "192.0.2.10:20000"

// A node's release is on the line an operator reads first. Before this, the
// coordinator received the field, fenced on it, and never printed it.
//
// MUTATION: drop releaseOrUnknown(m.Release) from either "registered" line (revert
// it to its pre-#114 format) — that role's subtest goes red.
func TestRegisterLogsNodeRelease(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	peer := fakePeer(t)

	t.Run("exit", func(t *testing.T) {
		resetRegistry(t)
		sink := captureLog(t)
		handle(wire{Type: "register", Role: "exit", ID: "e1", Country: "rs", Addr: docAddr, Release: "0.4.1"},
			peer.LocalAddr().(*net.UDPAddr))
		if got := sink.String(); !strings.Contains(got, "exit registered:") || !strings.Contains(got, "release=0.4.1") {
			t.Fatalf("the exit registration line must carry the node's release, got:\n%s", got)
		}
	})

	t.Run("relay", func(t *testing.T) {
		resetRegistry(t)
		sink := captureLog(t)
		handle(wire{Type: "register", Role: "relay", ID: "r1", Country: "rs", Release: "0.4.1"},
			peer.LocalAddr().(*net.UDPAddr))
		if got := sink.String(); !strings.Contains(got, "relay registered:") || !strings.Contains(got, "release=0.4.1") {
			t.Fatalf("the relay registration line must carry the node's release, got:\n%s", got)
		}
	})
}

// A node predating ADR-0015 sends no release at all, and with the fence at its
// default 0.0.0 it still serves — so the empty case is a state an operator really
// looks at, and it must be named rather than printed as a blank.
//
// MUTATION: make releaseOrUnknown return release unchanged — goes red on the
// "release=unknown" assertion (the line renders "release= " instead).
func TestRegisterLogsUnknownReleaseForLegacyNode(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	peer := fakePeer(t)

	handle(wire{Type: "register", Role: "exit", ID: "legacy", Country: "rs", Addr: docAddr},
		peer.LocalAddr().(*net.UDPAddr))

	if got := sink.String(); !strings.Contains(got, "release=unknown") {
		t.Fatalf("a node reporting no release must log release=unknown, got:\n%s", got)
	}
}

// The skew warning fires once for a node, not on all 8,640 registers it sends in a
// day. A forwarder re-announces every 10s and this coordinator replaces its registry
// entry wholesale each time, so the dedupe has to survive that replacement.
//
// MUTATION 1: delete the `if prior.release == release { return }` early return in
// noteRelease — red, four warnings instead of one.
// MUTATION 2: make carryHealth ignore prior and return forwarderHealth{release:
// release} — red the same way: the stored release is rebuilt but the comparison
// still holds, so drop the release from carryHealth instead and every register looks
// like a change.
func TestReleaseMismatchWarnsOncePerNode(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	peer := fakePeer(t)

	reg := wire{Type: "register", Role: "exit", ID: "stale", Country: "rs", Addr: docAddr, Release: "0.4.1"}
	for i := 0; i < 4; i++ {
		handle(reg, peer.LocalAddr().(*net.UDPAddr))
	}

	logged := sink.String()
	if n := countLines(logged, "reports release 0.4.1"); n != 1 {
		t.Fatalf("a diverged node must be warned about exactly once across repeated registers, got %d:\n%s", n, logged)
	}
	if !strings.Contains(logged, "this coordinator is 0.9.0") {
		t.Fatalf("the warning must name both sides of the comparison, got:\n%s", logged)
	}
	if !strings.Contains(logged, "NOT refused") {
		t.Fatalf("the warning must say it is not a refusal — -min-serving-version is the fence, got:\n%s", logged)
	}
}

// A node on the coordinator's own build is not news.
//
// MUTATION: delete the `if release == coordRelease { return }` guard in noteRelease
// — red, every matching node is warned about.
func TestMatchingReleaseIsSilent(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	peer := fakePeer(t)

	handle(wire{Type: "register", Role: "exit", ID: "current", Country: "rs", Addr: docAddr, Release: "0.9.0"},
		peer.LocalAddr().(*net.UDPAddr))

	if logged := sink.String(); strings.Contains(logged, "WARNING") {
		t.Fatalf("a node on the coordinator's own release must produce no warning, got:\n%s", logged)
	}
}

// The staged-rollout hole, and the reason the release is STORED rather than only
// logged: the "registered" line fires only for a node that is not already in the
// registry, an update restarts a node in about a second, and its entry survives 35s
// — so without this, every binary in the fleet can be swapped under a running
// coordinator without one line being printed.
//
// MUTATION: delete the `log.Printf("%s %s changed release: ...")` branch in
// noteRelease — red on the "changed release" assertion.
func TestReleaseChangeUnderARunningCoordinatorIsLogged(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	peer := fakePeer(t)
	addr := peer.LocalAddr().(*net.UDPAddr)

	// First sight, on the coordinator's own build: silent past the registration line.
	handle(wire{Type: "register", Role: "exit", ID: "rolling", Country: "rs", Addr: docAddr, Release: "0.9.0"}, addr)

	// Now the node is rebuilt and restarted. It is still in the registry, so the
	// "registered" line does not fire for it again.
	sink := captureLog(t)
	handle(wire{Type: "register", Role: "exit", ID: "rolling", Country: "rs", Addr: docAddr, Release: "0.4.1"}, addr)

	logged := sink.String()
	if strings.Contains(logged, "exit registered:") {
		t.Fatalf("precondition failed: the registration line fired for an already-registered node, so this test proves nothing:\n%s", logged)
	}
	if !strings.Contains(logged, "changed release: 0.9.0 -> 0.4.1") {
		t.Fatalf("a node that changes build under a running coordinator must be logged, got:\n%s", logged)
	}
	if !strings.Contains(logged, "reports release 0.4.1") {
		t.Fatalf("the new release must be re-checked against the coordinator's own, got:\n%s", logged)
	}
}

// unanswered builds a session a client tried to bring up and the assigned node never
// answered, quiet for longer than answerGrace.
func unanswered(client, peer *net.UDPAddr, exitID, relayID string) *session {
	return &session{
		client: client, peer: peer, exitID: exitID, relayID: relayID,
		signaled: true, answered: false,
		lastSeen: time.Now().Add(-answerGrace - time.Second),
	}
}

// putExit puts an exit in the registry directly, bypassing the register handler so a
// sweep test does not depend on admission, policy or country derivation.
func putExit(id, release string) {
	exits[id] = &exitNode{
		forwarderHealth: forwarderHealth{release: release},
		id:              id, tcpAddr: docAddr, lastSeen: time.Now(), country: "rs",
	}
}

// putRelay is putExit's relay half. addr must be the address the sessions naming
// this relay carry as their peer: reselectDeadRelays, which runs in the same sweep,
// retires a peer-relay session whose relay has moved (issue #105), and a relay
// registered at some other address would have its session swept out from under the
// check being tested.
func putRelay(id, release string, addr *net.UDPAddr) {
	relays[id] = &relayNode{
		forwarderHealth: forwarderHealth{release: release},
		id:              id, addr: addr, lastSeen: time.Now(), country: "rs",
	}
}

// runSweep runs one full timer pass exactly as reselectLoop does. It goes through
// sweepTick rather than calling reportUnansweredNodes directly so that dropping the
// call from the tick is caught here — the check is only worth anything if it is
// actually wired to the timer — and so each of these exercises the real composition
// with prune and reselectDeadRelays rather than the new pass in isolation.
func runSweep() {
	mu.Lock()
	defer mu.Unlock()
	sweepTick(time.Now())
}

// The incident this card comes from, reduced: a client posted its candidates, the
// coordinator relayed them, and the exit — three weeks behind on its binary — never
// answered. Nothing said so.
//
// MUTATION 1: delete the `t.unanswered++` arm from the sweep — red.
// MUTATION 2: delete the reportUnansweredNodes(now) call from sweepTick — red too;
// runSweep goes through the tick, so a check that is not wired to the timer fails
// here rather than passing on a direct call nothing in production makes.
func TestUnansweredNodeIsReported(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	client, node := loopback(t), loopback(t)

	mu.Lock()
	putExit("silent-exit", "0.4.1")
	sessions["s1"] = unanswered(client, node, "silent-exit", "")
	mu.Unlock()

	runSweep()

	logged := sink.String()
	if !strings.Contains(logged, "exit silent-exit") || !strings.Contains(logged, "answered NONE") {
		t.Fatalf("an exit that answers nothing must be named, got:\n%s", logged)
	}
	if !strings.Contains(logged, "release 0.4.1") {
		t.Fatalf("the report must carry the node's release so the two diagnoses meet on one line, got:\n%s", logged)
	}
}

// One answered session clears the node: it is serving somebody, and one client
// hitting a snag against a working exit is not a fault report.
//
// MUTATION: delete the `case s.answered: t.answered++` arm (so an answered session
// falls through to the default and is simply not counted) — red, the working exit is
// reported.
func TestNodeWithAnyAnsweredSessionIsNotReported(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	client, node := loopback(t), loopback(t)

	mu.Lock()
	putExit("busy-exit", "0.9.0")
	sessions["bad"] = unanswered(client, node, "busy-exit", "")
	good := unanswered(client, node, "busy-exit", "")
	good.answered = true
	sessions["good"] = good
	mu.Unlock()

	runSweep()

	if logged := sink.String(); strings.Contains(logged, "busy-exit") {
		t.Fatalf("an exit that answered another session must not be reported, got:\n%s", logged)
	}
}

// The false-positive class the issue worried about, and the reason this is quiet
// enough to ship: a client that walked away before it ever spoke leaves a session
// nobody was asked to answer. Not a node fault, and distinguishable rather than
// merely rare — a node answers off its ASSIGN, so a client that never spoke has not
// stopped it answering.
//
// MUTATION: drop `s.signaled &&` from the unanswered arm — red, every abandoned
// connect is blamed on the exit it was assigned.
func TestSessionTheClientNeverSpokeOnIsNotReported(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	client, node := loopback(t), loopback(t)

	mu.Lock()
	putExit("fine-exit", "0.9.0")
	abandoned := unanswered(client, node, "fine-exit", "")
	abandoned.signaled = false
	sessions["walked-away"] = abandoned
	mu.Unlock()

	runSweep()

	if logged := sink.String(); strings.Contains(logged, "fine-exit") {
		t.Fatalf("a session the client never spoke on must not be blamed on the node, got:\n%s", logged)
	}
}

// A session still inside answerGrace is a session in flight, not a fault.
//
// MUTATION: drop the `now.Sub(s.lastSeen) > answerGrace` condition — red, a
// connect is reported the moment it is minted.
func TestUnansweredWithinGraceIsNotReported(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	client, node := loopback(t), loopback(t)

	mu.Lock()
	putExit("new-exit", "0.9.0")
	fresh := unanswered(client, node, "new-exit", "")
	fresh.lastSeen = time.Now()
	sessions["in-flight"] = fresh
	mu.Unlock()

	runSweep()

	if logged := sink.String(); strings.Contains(logged, "new-exit") {
		t.Fatalf("a session still inside the answer grace window must not be reported, got:\n%s", logged)
	}
}

// Said once per episode, not once per 10s sweep — and re-armed when the node
// recovers, so a second outage is reported too. This is what keeps a genuinely dead
// exit from burying every other line in the log.
//
// MUTATION 1: delete `h.silentWarned = true` — red, one line per sweep.
// MUTATION 2: delete the `h.silentWarned = false` re-arm — red, the recovery is
// latched forever and the second outage is silent.
func TestUnansweredIsReportedOncePerEpisode(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	client, node := loopback(t), loopback(t)

	mu.Lock()
	putExit("flapping", "0.9.0")
	sessions["s1"] = unanswered(client, node, "flapping", "")
	mu.Unlock()

	runSweep()
	runSweep()
	runSweep()
	if n := countLines(sink.String(), "flapping"); n != 1 {
		t.Fatalf("repeated sweeps of the same outage must log once, got %d:\n%s", n, sink.String())
	}

	// The node recovers: an answered session re-arms the warning.
	mu.Lock()
	recovered := unanswered(client, node, "flapping", "")
	recovered.answered = true
	sessions["s2"] = recovered
	mu.Unlock()
	runSweep()

	// And fails again.
	mu.Lock()
	delete(sessions, "s2")
	sessions["s3"] = unanswered(client, node, "flapping", "")
	mu.Unlock()
	runSweep()

	if n := countLines(sink.String(), "flapping"); n != 2 {
		t.Fatalf("a second outage after a recovery must be reported again, got %d line(s):\n%s", n, sink.String())
	}
}

// A peer-relayed session is answered by the RELAY — the relay is the node the
// assignment went to and the party that dials the exit. Blaming the exit for a relay
// that never acted would point an operator at the wrong box.
//
// This is also the case a reap-time check could not make: prune exempts a signaled
// peer-relay session from the idle sweep (issue #96/#105), so this session is never
// reaped while its relay keeps heartbeating — which is exactly the state a diverged
// relay is in.
//
// MUTATION: swap the two branches of assignedNode so exitID is preferred — red, the
// exit is named and the relay is not.
func TestPeerRelaySessionIsAttributedToTheRelay(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.9.0")
	resetRegistry(t)
	sink := captureLog(t)
	client, node := loopback(t), loopback(t)

	mu.Lock()
	putRelay("silent-relay", "0.4.1", node)
	putExit("innocent-exit", "0.9.0")
	sessions["s1"] = unanswered(client, node, "innocent-exit", "silent-relay")
	mu.Unlock()

	runSweep()

	logged := sink.String()
	if !strings.Contains(logged, "relay silent-relay") {
		t.Fatalf("a peer-relayed session must be attributed to the relay that was assigned it, got:\n%s", logged)
	}
	if strings.Contains(logged, "innocent-exit") {
		t.Fatalf("the exit behind a silent relay must not be blamed, got:\n%s", logged)
	}
}

// The distinction the whole check rests on: signaled is set by EITHER side, and the
// client speaks first on every path, so a session the assigned node never received is
// signaled. Only a frame from the assigned node marks it answered.
//
// MUTATION: move `s.answered = true` out of the `src == s.peer` branch so any frame
// sets it — the client-frame subtest goes red.
func TestOnlyTheAssignedNodeMarksASessionAnswered(t *testing.T) {
	setPC(t)
	client, node := fakePeer(t), fakePeer(t)
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	nodeAddr := node.LocalAddr().(*net.UDPAddr)

	fresh := func() {
		mu.Lock()
		sessions = map[string]*session{
			"s": {client: clientAddr, peer: nodeAddr, exitID: "e", lastSeen: time.Now()},
		}
		mu.Unlock()
	}
	t.Cleanup(func() {
		mu.Lock()
		sessions = map[string]*session{}
		mu.Unlock()
	})

	t.Run("client frame does not answer", func(t *testing.T) {
		fresh()
		handle(wire{Type: "offer", Session: "s"}, clientAddr)
		mu.Lock()
		defer mu.Unlock()
		if !sessions["s"].signaled {
			t.Fatal("a client frame must still mark the session signaled")
		}
		if sessions["s"].answered {
			t.Fatal("a frame from the CLIENT must not count as the assigned node answering")
		}
	})

	t.Run("node frame answers", func(t *testing.T) {
		fresh()
		handle(wire{Type: "answer", Session: "s"}, nodeAddr)
		mu.Lock()
		defer mu.Unlock()
		if !sessions["s"].answered {
			t.Fatal("a frame from the assigned node must mark the session answered")
		}
	})
}

// The coordinator's startup line has to identify the build it is, because the
// release cannot: nothing in this repository stamps core/version.current, so every
// binary ever built here reports the same one and two builds three weeks apart are
// indistinguishable by it. The revision is what differs.
//
// MUTATION 1: return release unchanged from describeBuild — red on the first two
// subtests.
// MUTATION 2: drop the vcs.modified arm — red on "uncommitted changes".
// MUTATION 3: drop the `revision == ""` branch and return the bare release — red on
// the third subtest, which is the case every worktree and every `go test` build is
// in, and which must say so rather than look like a clean stamped build.
func TestDescribeBuildNamesTheBuild(t *testing.T) {
	rev := debug.BuildSetting{Key: "vcs.revision", Value: "b2f75452973be9c296887220cb8829930a88099d"}
	clean := debug.BuildSetting{Key: "vcs.modified", Value: "false"}
	dirty := debug.BuildSetting{Key: "vcs.modified", Value: "true"}

	t.Run("stamped", func(t *testing.T) {
		got := describeBuild("0.1.0", []debug.BuildSetting{rev, clean})
		if got != "0.1.0 (revision b2f75452973b)" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("stamped with uncommitted changes", func(t *testing.T) {
		got := describeBuild("0.1.0", []debug.BuildSetting{rev, dirty})
		if !strings.Contains(got, "b2f75452973b") || !strings.Contains(got, "uncommitted changes") {
			t.Fatalf("a build made over a dirty tree must say so, got %q", got)
		}
	})

	t.Run("unstamped", func(t *testing.T) {
		got := describeBuild("0.1.0", []debug.BuildSetting{{Key: "-compiler", Value: "gc"}})
		if !strings.HasPrefix(got, "0.1.0 ") || !strings.Contains(got, "no build revision") {
			t.Fatalf("a build with no VCS data must name the absence rather than look stamped, got %q", got)
		}
	})
}

// loopback returns a distinct loopback UDP address for a test session's endpoints.
// It binds a real socket so the ports are genuinely distinct, and closes it at the
// end of the test — nothing here sends to these addresses.
func loopback(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().(*net.UDPAddr)
}
