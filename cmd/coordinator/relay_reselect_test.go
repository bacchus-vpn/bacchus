package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// In-session peer-relay liveness and reselection (issue #96), the counterpart to
// connect-time pickRelay (relay_test.go). These drive reselectDeadRelays() and the
// re-establish that follows directly, with fake UDP peers — the same style as
// relay_test.go / main_test.go's prune test. The invariant under test: a relay that
// dies while carrying a session is noticed within one sweep, its client nudged to
// re-establish, and the re-establish lands on a fresh live relay (the dead one
// excluded) or the TURN fallback — never on the dead relay, never silently stuck.
//
// setPC/resetRegistry/fakePeer/recvWire/registerExit/registerRelay/connectRelay come
// from main_test.go, admission_test.go and relay_test.go; expectSilence from
// version_fence_test.go. Admission and the version fence are nil/zero by default, so
// these inherit an open, unfenced coordinator.

const reExitID, reExitTCP = "exit-1", "10.0.0.9:20000"

// startPeerRelaySession drives a relay-mode connect that lands on the single
// registered relay relayP, drains the relay's assign and the client's session reply
// so the sockets are clean for what follows, and returns the minted session id. It
// requires relayP to be the only registered relay so pickRelay is deterministic.
func startPeerRelaySession(t *testing.T, client, relayP *net.UDPConn, exitID string) string {
	t.Helper()
	connectRelay(exitID, client)
	if asg := recvWire(t, relayP, time.Second); asg.Type != "assign" || asg.ExitAddr == "" {
		t.Fatalf("session setup: relay got %+v, want a peer-relay assign", asg)
	}
	sess := recvWire(t, client, time.Second)
	if sess.Type != "session" || sess.Relay != relayPeer {
		t.Fatalf("session setup: client got %+v, want a peer-relay session", sess)
	}
	return sess.Session
}

// killRelay ages relayID past the ttl/2 in-session liveness bound so the next sweep
// treats it as dead — a relay that stopped heartbeating.
func killRelay(relayID string) {
	mu.Lock()
	defer mu.Unlock()
	if r, ok := relays[relayID]; ok {
		r.lastSeen = time.Now().Add(-ttl/2 - time.Second)
	}
}

// sweep runs one liveness pass, as reselectLoop's ticker would.
func sweep() {
	mu.Lock()
	defer mu.Unlock()
	reselectDeadRelays(time.Now())
}

func sessionExists(sid string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, ok := sessions[sid]
	return ok
}

// recvWireOrNil reads one datagram sent to peer within d, returning ok=false if none
// arrives — for asserting which of several candidate relays received a reselected
// assign when the pick among live relays is random (ADR-0033).
func recvWireOrNil(peer *net.UDPConn, d time.Duration) (wire, bool) {
	_ = peer.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 65535)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		return wire{}, false
	}
	var m wire
	if json.Unmarshal(buf[:n], &m) != nil {
		return wire{}, false
	}
	return m, true
}

// TestReselectNudgesClientWhenAssignedRelayDies is the assigned-relay-failure case:
// a session's peer relay stops heartbeating, and one sweep must nudge the client to
// re-establish and retire the now-dead session so the nudge fires exactly once.
func TestReselectNudgesClientWhenAssignedRelayDies(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)
	registerRelay("relay-1", relayP)
	sid := startPeerRelaySession(t, client, relayP, reExitID)

	killRelay("relay-1")
	sweep()

	got := recvWire(t, client, time.Second)
	if got.Type != "reselect" || got.Session != sid {
		t.Fatalf("client got %+v, want a reselect for session %q", got, sid)
	}
	if sessionExists(sid) {
		t.Fatalf("session %q must be reaped after the reselect nudge (else the sweep re-nudges a dead path)", sid)
	}
}

// TestReselectLeavesLiveRelaySessionAlone pins the threshold: a session whose relay
// is still heartbeating (fresh) must never be nudged — no false-positive reselect
// that would churn a healthy path.
func TestReselectLeavesLiveRelaySessionAlone(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)
	registerRelay("relay-1", relayP)
	sid := startPeerRelaySession(t, client, relayP, reExitID)

	sweep() // relay is fresh — nothing should happen

	expectSilence(t, client)
	if !sessionExists(sid) {
		t.Fatalf("session %q with a live relay must survive the sweep", sid)
	}
}

// TestReselectPicksLiveRelayExcludingDead is the multi-eligible-relay-selection
// case: with the assigned relay dead and two other live relays available, the
// client's re-establish must land on one of the live relays — never the dead one —
// and be tagged a peer relay, not the TURN fallback.
func TestReselectPicksLiveRelayExcludingDead(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP := fakePeer(t), fakePeer(t)
	relayA, relayB, relayC := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)
	registerRelay("relay-a", relayA)
	sid := startPeerRelaySession(t, client, relayA, reExitID)

	// Two more live relays join; then the assigned relay A dies.
	registerRelay("relay-b", relayB)
	registerRelay("relay-c", relayC)
	killRelay("relay-a")
	sweep()

	if got := recvWire(t, client, time.Second); got.Type != "reselect" || got.Session != sid {
		t.Fatalf("client got %+v, want a reselect for %q", got, sid)
	}

	// The client re-establishes (a fresh relay-mode connect). It must be handed one
	// of the live relays B/C — the pick among live relays is random — and told peer.
	connectRelay(reExitID, client)
	asgB, okB := recvWireOrNil(relayB, time.Second)
	asgC, okC := recvWireOrNil(relayC, time.Second)
	if okB == okC {
		t.Fatalf("exactly one live relay should get the reselected assign (B=%v C=%v)", okB, okC)
	}
	asg := asgB
	if okC {
		asg = asgC
	}
	if asg.Type != "assign" || asg.ExitAddr != reExitTCP {
		t.Fatalf("reselected relay got %+v, want a peer-relay assign carrying %q", asg, reExitTCP)
	}
	sess := recvWire(t, client, time.Second)
	if sess.Relay != relayPeer {
		t.Fatalf("client relay = %q, want %q (a live relay was available)", sess.Relay, relayPeer)
	}
	expectSilence(t, relayA) // the dead relay is never reselected
}

// TestReselectReconnectFallsBackToTURNWhenNoLiveRelay is the reselect-or-TURN case:
// the assigned relay dies and no other relay is live, so the re-establish degrades
// to the TURN fallback — a direct assign to the exit (no exitAddr), tagged turn.
func TestReselectReconnectFallsBackToTURNWhenNoLiveRelay(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)
	registerRelay("relay-1", relayP)
	sid := startPeerRelaySession(t, client, relayP, reExitID)

	killRelay("relay-1")
	sweep()
	if got := recvWire(t, client, time.Second); got.Type != "reselect" || got.Session != sid {
		t.Fatalf("client got %+v, want a reselect for %q", got, sid)
	}

	// Re-establish with no live relay left: wired straight to the exit, tagged turn.
	connectRelay(reExitID, client)
	asg := recvWire(t, exitP, time.Second)
	if asg.Type != "assign" || asg.ExitAddr != "" {
		t.Fatalf("exit got %+v, want a direct (TURN-fallback) assign", asg)
	}
	sess := recvWire(t, client, time.Second)
	if sess.Relay != relayTURN {
		t.Fatalf("client relay = %q, want %q (no live relay -> TURN)", sess.Relay, relayTURN)
	}
}

// TestReselectIgnoresDirectAndTurnSessions guards the relayID=="" scoping: sessions
// with no peer relay (direct pairing, and the TURN fallback that pairs straight to
// the exit) carry no relay to monitor, so a sweep must never nudge them even when no
// relay is registered at all.
func TestReselectIgnoresDirectAndTurnSessions(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP := fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)

	// Direct-mode session: peer is the exit, relayID is empty.
	handle(wire{Type: "connect", Country: countryOf(reExitID), Mode: "direct"}, client.LocalAddr().(*net.UDPAddr))
	recvWire(t, exitP, time.Second) // assign
	dsess := recvWire(t, client, time.Second)

	// TURN-fallback session: relay-mode connect with no relay registered.
	handle(wire{Type: "connect", Country: countryOf(reExitID), Mode: "relay"}, client.LocalAddr().(*net.UDPAddr))
	recvWire(t, exitP, time.Second) // assign
	tsess := recvWire(t, client, time.Second)
	if tsess.Relay != relayTURN {
		t.Fatalf("setup: expected a TURN-fallback session, got relay=%q", tsess.Relay)
	}

	sweep()

	expectSilence(t, client) // neither session has a peer relay to reselect
	if !sessionExists(dsess.Session) || !sessionExists(tsess.Session) {
		t.Fatal("direct and TURN-fallback sessions must survive the sweep untouched")
	}
}

// ageSession backdates a session's lastSeen so a prune sweep sees it as though that
// long has passed since its last signaling — used to reach the >sessionTTL regime a
// real session spends almost all its life in, since no offer/answer/candidate flows
// once the data plane is up (issue #105).
func ageSession(sid string, d time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	if s, ok := sessions[sid]; ok {
		s.lastSeen = time.Now().Add(-d)
	}
}

// sweepWithPrune runs one full timer sweep exactly as reselectLoop does — prune then
// reselectDeadRelays, under the lock — so a test exercises their interaction, not
// reselectDeadRelays alone (which sweep() covers). The pre-#105 gap lived precisely
// in that interaction: prune reaped the session entry reselectDeadRelays needed.
func sweepWithPrune() {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	prune(now)
	reselectDeadRelays(now)
}

// expireRelay ages relayID past ttl (not just ttl/2 as killRelay does) so a prune
// pass drops it from the relays map entirely — the "relay dead long enough to be
// evicted while a peer-relay session still names it" case (issue #105).
func expireRelay(relayID string) {
	mu.Lock()
	defer mu.Unlock()
	if r, ok := relays[relayID]; ok {
		r.lastSeen = time.Now().Add(-ttl - time.Second)
	}
}

func relayRegistered(relayID string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, ok := relays[relayID]
	return ok
}

// TestReselectMonitorsPeerRelaySessionPastSessionTTL is the #105 regression guard: a
// peer-relay session whose relay keeps heartbeating must survive prune well past
// sessionTTL — its liveness is the relay's, not setup-time signaling silence — so
// reselectDeadRelays can still catch the relay dying minutes into the session, not
// only in its first sessionTTL. Before #105, prune reaped the session entry at
// sessionTTL and the sweep went blind to any later relay death.
func TestReselectMonitorsPeerRelaySessionPastSessionTTL(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)
	registerRelay("relay-1", relayP)
	sid := startPeerRelaySession(t, client, relayP, reExitID)

	// Minutes into the session: no signaling has flowed since setup, so lastSeen is
	// now far older than sessionTTL.
	ageSession(sid, sessionTTL+time.Minute)

	// A full sweep (prune + reselect) with the relay still fresh must NOT reap the
	// session — the pre-#105 signaling-silence prune would have.
	sweepWithPrune()
	expectSilence(t, client)
	if !sessionExists(sid) {
		t.Fatal("a long-lived peer-relay session whose relay is alive must survive prune (regression #105)")
	}

	// The relay now dies this late in the session; the next sweep must still see it
	// and nudge — the whole point of keeping the session monitorable.
	killRelay("relay-1")
	sweepWithPrune()
	if got := recvWire(t, client, time.Second); got.Type != "reselect" || got.Session != sid {
		t.Fatalf("client got %+v, want a reselect after a late relay death", got)
	}
	if sessionExists(sid) {
		t.Fatal("session must be reaped after the late relay-death nudge")
	}
}

// TestPruneStillReapsDirectSessionOnSilence guards that #105's prune exemption is
// scoped to peer-relay sessions only: a direct session (relayID=="") has no relay to
// tie liveness to, so signaling silence past sessionTTL must still reap it.
func TestPruneStillReapsDirectSessionOnSilence(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP := fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)
	handle(wire{Type: "connect", Country: countryOf(reExitID), Mode: "direct"}, client.LocalAddr().(*net.UDPAddr))
	recvWire(t, exitP, time.Second) // assign
	dsess := recvWire(t, client, time.Second)

	ageSession(dsess.Session, sessionTTL+time.Minute)
	sweepWithPrune()

	if sessionExists(dsess.Session) {
		t.Fatal("a direct session silent past sessionTTL must still be reaped by prune (the exemption is peer-relay only)")
	}
}

// TestReselectReapsRelayRestartedUnderSameID is the #105 MINOR guard: a relay that
// dies and restarts under the same admission-bound id but a new address is a
// different incarnation than the one the session's splice was built on, so a fresh
// lastSeen alone must not mask it — the address must match too, or the client is
// nudged onto the live incarnation.
func TestReselectReapsRelayRestartedUnderSameID(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayOld, relayNew := fakePeer(t), fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)
	registerRelay("relay-1", relayOld)
	sid := startPeerRelaySession(t, client, relayOld, reExitID)

	// relay-1 restarts under the same id at a new socket: fresh lastSeen, new addr.
	registerRelay("relay-1", relayNew)

	// Fresh lastSeen would say "live", but the address no longer matches the splice
	// the session was built on, so the sweep must treat it as dead and nudge.
	sweepWithPrune()
	if got := recvWire(t, client, time.Second); got.Type != "reselect" || got.Session != sid {
		t.Fatalf("client got %+v, want a reselect after a same-id relay restart at a new address", got)
	}
	if sessionExists(sid) {
		t.Fatal("session must be reaped after the restart-under-same-id nudge")
	}
}

// TestReselectReapsSessionWhenRelayFullyPruned covers the relays[relayID] ok==false
// branch (issue #105): a peer-relay session outlives sessionTTL (it is exempt from
// prune), but its relay goes stale long enough that prune evicts it from the relays
// map. The sweep must still nudge the client and reap the now-orphaned session — it
// must not linger just because the relay entry it keyed liveness on is gone. This is
// exactly the "relay dead long enough to be pruned while a session still points at
// it" interaction the prune exemption creates, so it is asserted, not just inspected.
func TestReselectReapsSessionWhenRelayFullyPruned(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(reExitID, "RU", reExitTCP, exitP)
	registerRelay("relay-1", relayP)
	sid := startPeerRelaySession(t, client, relayP, reExitID)

	// The relay has been gone long enough for prune to evict it, while the peer-relay
	// session (exempt from prune) is still present — the ok==false path.
	expireRelay("relay-1")
	sweepWithPrune()

	if relayRegistered("relay-1") {
		t.Fatal("test setup: prune should have evicted the relay aged past ttl (exercising the ok==false path)")
	}
	if got := recvWire(t, client, time.Second); got.Type != "reselect" || got.Session != sid {
		t.Fatalf("client got %+v, want a reselect when the assigned relay was fully pruned", got)
	}
	if sessionExists(sid) {
		t.Fatal("an orphaned peer-relay session must be reaped when its relay is gone from the map, not left to linger")
	}
}
