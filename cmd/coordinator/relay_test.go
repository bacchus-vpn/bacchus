package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// Peer-relay-preferred matchmaking with a TURN fallback (issue #17, ADR-0033).
// These drive handle() directly with fake UDP peers — the same style as
// main_test.go's hello/prune tests — and assert what the coordinator wires for a
// relay-mode connect: the preferred Bacchus peer relay when one is available,
// the TURN fallback (a direct assignment to the exit, tagged relayTURN) when not.
//
// resetRegistry (admission_test.go) clears the registry maps; admission and the
// version fence are both nil/zero by default and restored by the tests that set
// them (admission_test.go, version_fence_test.go), so these tests inherit an
// open, unfenced coordinator without touching those globals. expectSilence
// (version_fence_test.go) asserts a peer received nothing.

// recvWire reads one datagram sent to peer and unmarshals it, failing the test
// if none arrives within d. It is how these tests read what handle() sent back
// to a fake client / exit / relay.
func recvWire(t *testing.T, peer *net.UDPConn, d time.Duration) wire {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 65535)
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected a datagram, got none: %v", err)
	}
	var m wire
	if err := json.Unmarshal(buf[:n], &m); err != nil {
		t.Fatalf("unmarshal reply: %v", err)
	}
	return m
}

// registerExit / registerRelay drive a register through handle() from a node's
// fake socket, so the registry is populated exactly as the wire path would.
func registerExit(id, country, tcpAddr string, from *net.UDPConn) {
	handle(wire{Type: "register", Role: "exit", ID: id, Country: country, Addr: tcpAddr}, from.LocalAddr().(*net.UDPAddr))
}
func registerRelay(id string, from *net.UDPConn) {
	handle(wire{Type: "register", Role: "relay", ID: id}, from.LocalAddr().(*net.UDPAddr))
}

// connectRelay drives a relay-mode connect for the COUNTRY of the named exit. A
// client can no longer name an exit (issue #146), so a test whose subject is one
// specific exit asks for its country — which in these single-exit-per-country
// fixtures selects exactly that exit. See countryOf.
func connectRelay(exitID string, from *net.UDPConn) {
	dialConnect(wire{Country: countryOf(exitID), Mode: "relay"}, from.LocalAddr().(*net.UDPAddr))
}

// TestConnectRelayPrefersPeerRelay: with a distinct relay registered, a
// relay-mode connect is wired through that peer relay — it is assigned the splice
// (the exit's advertised TCP address) and the client is told relay=peer.
func TestConnectRelayPrefersPeerRelay(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	const exitID, exitTCP = "exit-1", "10.0.0.9:20000"
	registerExit(exitID, "RU", exitTCP, exitP)
	registerRelay("relay-1", relayP)

	connectRelay(exitID, client)

	asg := recvWire(t, relayP, time.Second)
	if asg.Type != "assign" || asg.ExitAddr != exitTCP {
		t.Fatalf("relay got %+v, want an assign carrying the exit's TCP addr %q", asg, exitTCP)
	}
	sess := recvWire(t, client, time.Second)
	if sess.Type != "session" || sess.Relay != relayPeer {
		t.Fatalf("client got %+v, want a session tagged relay=%q", sess, relayPeer)
	}
	if asg.Session == "" || asg.Session != sess.Session {
		t.Fatalf("relay and client must share the session id: relay=%q client=%q", asg.Session, sess.Session)
	}
	// The exit is not signaled directly on the peer-relay path — the relay dials
	// its TCP ingress instead.
	expectSilence(t, exitP)
}

// TestConnectRelayFallsBackToTURNWhenNoRelay: with no relay registered, a
// relay-mode connect falls back to TURN — the client is wired straight to the
// exit (a direct assignment, no exitAddr) and told relay=turn so it knows the
// preferred peer relay was unavailable.
func TestConnectRelayFallsBackToTURNWhenNoRelay(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP := fakePeer(t), fakePeer(t)

	const exitID, exitTCP = "exit-1", "10.0.0.9:20000"
	registerExit(exitID, "RU", exitTCP, exitP)

	connectRelay(exitID, client)

	asg := recvWire(t, exitP, time.Second)
	if asg.Type != "assign" || asg.ExitAddr != "" {
		t.Fatalf("exit got %+v, want a direct assign (no exitAddr) for the TURN fallback", asg)
	}
	sess := recvWire(t, client, time.Second)
	if sess.Type != "session" || sess.Relay != relayTURN {
		t.Fatalf("client got %+v, want a session tagged relay=%q (TURN fallback)", sess, relayTURN)
	}
	if asg.Session == "" || asg.Session != sess.Session {
		t.Fatalf("exit and client must share the session id: exit=%q client=%q", asg.Session, sess.Session)
	}
}

// TestConnectRelayExcludesExitFromRelaySelection: a node registered as both the
// exit AND a relay under one id must never be picked to relay to itself. With no
// other relay available, the coordinator falls back to TURN rather than assign
// the exit a splice to its own ingress.
func TestConnectRelayExcludesExitFromRelaySelection(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, node := fakePeer(t), fakePeer(t)

	const id, exitTCP = "dual-1", "10.0.0.9:20000"
	registerExit(id, "RU", exitTCP, node)
	registerRelay(id, node) // same node also advertises relay capability

	connectRelay(id, client)

	// The only relay is the exit itself (excluded) -> TURN fallback: a direct
	// assign to the exit, never a self-relay splice.
	asg := recvWire(t, node, time.Second)
	if asg.Type != "assign" || asg.ExitAddr != "" {
		t.Fatalf("node got %+v, want a direct (no-exitAddr) assign — the exit must not relay to itself", asg)
	}
	sess := recvWire(t, client, time.Second)
	if sess.Relay != relayTURN {
		t.Fatalf("client relay = %q, want %q (only relay is the exit, excluded)", sess.Relay, relayTURN)
	}
}

// TestConnectRelayPicksDistinctRelayNotExit: when a node is both exit+relay (id
// X) and a separate relay Y also exists, the exit-as-relay X is excluded and the
// distinct relay Y is chosen — even though X registered its relay role later (so
// freshest-first would pick X if exclusion were broken). This isolates the
// exclusion from the freshness tiebreak.
func TestConnectRelayPicksDistinctRelayNotExit(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, dual, other := fakePeer(t), fakePeer(t), fakePeer(t)

	const x, exitTCP = "exit-x", "10.0.0.9:20000"
	registerRelay("relay-y", other) // Y first (staler)
	registerExit(x, "RU", exitTCP, dual)
	registerRelay(x, dual) // X's relay role last (fresher) — must still be excluded

	connectRelay(x, client)

	asg := recvWire(t, other, time.Second)
	if asg.Type != "assign" || asg.ExitAddr != exitTCP {
		t.Fatalf("distinct relay Y got %+v, want the peer-relay assign with the exit's TCP addr", asg)
	}
	sess := recvWire(t, client, time.Second)
	if sess.Relay != relayPeer {
		t.Fatalf("client relay = %q, want %q", sess.Relay, relayPeer)
	}
	// The exit node must not have been used as its own relay.
	expectSilence(t, dual)
}

// TestRelayTagWireContract pins this binary's relayTag to the same known-answer
// vectors core's relayTagFor is pinned to (core/relaychain_acceptance_test.go).
//
// The two derivations are duplicated rather than shared, as the wire literals are —
// this binary deliberately imports nothing from core. A chaining client recomputes
// the tag for every hop of its own chain and refuses the path on a match
// (verifyChainDisjoint, issue #142), so a drift between the copies would not fail
// anything: it would silently stop the check from ever matching, leaving a client
// that believes a guard is running when it is not.
func TestRelayTagWireContract(t *testing.T) {
	cases := []struct{ id, want string }{
		{"", "bbd6b36f34c5b540"},
		{"abc", "5bef601c5a2e76aa"},
		{"bacchus", "2500892b4984d747"},
	}
	for _, tc := range cases {
		if got := relayTag(tc.id); got != tc.want {
			t.Errorf("relayTag(%q) = %s, want %s — core/relaychain.go relayTagFor must agree or the chain-disjointness check silently stops matching", tc.id, got, tc.want)
		}
	}
}
