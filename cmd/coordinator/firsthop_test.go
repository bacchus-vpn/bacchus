package main

import (
	"net"
	"testing"
	"time"
)

// The coordinator half of client-assembled relay chaining (issue #142, ADR-0038;
// the connect{firstHop} field ADR-0042 §9 reserved).
//
// These exist because the client half is tested against a fake coordinator and the
// coordinator half was, for a while, tested against nothing at all — so a build in
// which the coordinator ignored firstHop entirely, or recorded the hop as the
// session's terminating exit, passed every test in the repository. Two fakes facing
// each other test the fakes; this is the real handler, driven through handle().

const (
	fhHopID    = "hop-node-1"
	fhHopTCP   = "203.0.113.11:20000"
	fhOtherID  = "exit-elsewhere"
	fhOtherTCP = "203.0.113.12:20000"
)

// connectFirstHop drives a chained relay-mode connect: it names a first hop and,
// as a real chaining client does, no country at all.
func connectFirstHop(hop string, from *net.UDPConn) {
	handle(wire{Type: "connect", FirstHop: hop, Mode: "relay"}, from.LocalAddr().(*net.UDPAddr))
}

// TestConnectFirstHopPairsTheNamedNode is the core of §9's wire: the coordinator
// wires the client to the node it NAMED, not to one the coordinator chose.
//
// The two exits sit in different countries and the request carries a country that
// matches the OTHER one. A build that fell through to chooseExit would therefore
// pair the wrong node, and the assign would land on the wrong socket.
func TestConnectFirstHopPairsTheNamedNode(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, hopP, otherP, relayP := fakePeer(t), fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(fhHopID, "DE", fhHopTCP, hopP)
	registerExit(fhOtherID, "NL", fhOtherTCP, otherP)
	registerRelay("relay-1", relayP)

	// Country names the OTHER exit's country; firstHop names the hop. firstHop wins,
	// because the coordinator is not being asked to choose.
	handle(wire{Type: "connect", FirstHop: fhHopID, Country: "NL", Mode: "relay"},
		client.LocalAddr().(*net.UDPAddr))

	asg := recvWire(t, relayP, time.Second)
	if asg.Type != "assign" || asg.ExitAddr != fhHopTCP {
		t.Fatalf("relay got %+v, want an assign splicing to the NAMED hop %q", asg, fhHopTCP)
	}
	if asg.ExitAddr == fhOtherTCP {
		t.Fatal("the coordinator chose an exit by country and ignored firstHop; the client's chain head is not what it was wired to")
	}
	expectSilence(t, otherP)
}

// TestConnectFirstHopRecordsNoTerminatingExit pins ADR-0042 §9's second
// commitment, on both the session table and the reply.
//
// The coordinator does not know where a chained path terminates — that is the
// point — so it must record nothing rather than record the hop. Recording the hop
// would charge a relay with a terminator's load, and the session count is the only
// term in §3's ranking that discriminates at all; replying with it would be the
// coordinator asserting an exit it cannot know, which a client would then have to
// decide whether to trust.
func TestConnectFirstHopRecordsNoTerminatingExit(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, hopP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(fhHopID, "DE", fhHopTCP, hopP)
	registerRelay("relay-1", relayP)
	connectFirstHop(fhHopID, client)

	_ = recvWire(t, relayP, time.Second) // the relay's assign
	sess := recvWire(t, client, time.Second)
	if sess.Type != "session" {
		t.Fatalf("client got %+v, want a session", sess)
	}
	if sess.ExitID != "" {
		t.Errorf("the reply named exit %q on a chained connect; the coordinator was told a hop and knows no exit, so asserting one invites the client to trust a value it must not", sess.ExitID)
	}

	mu.Lock()
	rec, ok := sessions[sess.Session]
	var recordedExit, recordedRelay string
	if ok {
		recordedExit, recordedRelay = rec.exitID, rec.relayID
	}
	mu.Unlock()
	if !ok {
		t.Fatalf("no session recorded for %q", sess.Session)
	}
	if recordedExit != "" {
		t.Errorf("session recorded exitID %q; a chained session must record no terminating exit, or a HOP is charged with a terminator's load in §3's ranking", recordedExit)
	}
	if recordedRelay == "" {
		t.Error("session recorded no relayID; 'who carries this session' is still known and is the slot chaining reuses (ADR-0042 §9)")
	}
}

// TestChainedSessionIsInvisibleToExitRanking is the consequence of the above,
// asserted where it actually matters rather than on the field that produces it.
//
// A chained session must not count toward any exit's load. Asserted by observing
// exitSessions — the ranking input — rather than by re-reading the empty id, so a
// build that recorded the hop somewhere else and still fed the ranking would fail.
func TestChainedSessionIsInvisibleToExitRanking(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, hopP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(fhHopID, "DE", fhHopTCP, hopP)
	registerRelay("relay-1", relayP)

	now := time.Now()
	before := exitSessions(now)[fhHopID]
	connectFirstHop(fhHopID, client)
	_ = recvWire(t, relayP, time.Second)
	_ = recvWire(t, client, time.Second)
	after := exitSessions(time.Now())[fhHopID]

	if after != before {
		t.Errorf("the hop's session count went %d -> %d; a chained session must be invisible to exit ranking, not charged to the node that merely peels its first layer", before, after)
	}
}

// TestConnectFirstHopRefusesAnUnknownNode: a client whose cached directory has
// drifted names a node this coordinator does not have. The refusal is NAMED, so the
// client can tell "refresh your directory" from a bare failure — the same reasoning
// #147 applies to the country refusals.
func TestConnectFirstHopRefusesAnUnknownNode(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, relayP := fakePeer(t), fakePeer(t)
	registerRelay("relay-1", relayP)

	connectFirstHop("a-node-that-never-registered", client)

	m := recvWire(t, client, time.Second)
	if m.Type != "error" {
		t.Fatalf("client got %+v, want an error for a hop this coordinator does not know", m)
	}
	if m.Reason != string(refuseNoHop) {
		t.Errorf("refusal reason = %q, want %q — a bare failure leaves the client unable to tell a stale directory from anything else", m.Reason, refuseNoHop)
	}
	expectSilence(t, relayP)
}

// TestConnectFirstHopRefusesAnExhaustedNode: a hop whose operator's declared
// monthly quota is spent is not assignable AS a hop either. A relay spends its
// operator's uplink peeling layers exactly as an exit does terminating them (issue
// #143, ADR-0040), so honouring firstHop past the quota would be a route around the
// one control an operator has over their own bill.
func TestConnectFirstHopRefusesAnExhaustedNode(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, hopP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExitLimits(fhHopID, "DE", fhHopTCP, 0, quotaExhausted, hopP)
	registerRelay("relay-1", relayP)

	connectFirstHop(fhHopID, client)

	m := recvWire(t, client, time.Second)
	if m.Type != "error" || m.Reason != string(refuseNoHop) {
		t.Fatalf("client got %+v, want a %q refusal — an out-of-quota node must not be assignable as a hop", m, refuseNoHop)
	}
	expectSilence(t, relayP)
}

// TestUnchainedConnectStillNamesItsExit is the zero-regression half: a connect
// carrying no firstHop behaves exactly as it did before this feature, right down to
// recording and returning the chosen exit.
//
// Without it, a mutation that treated EVERY connect as chained would pass all of
// the above while breaking every client in the fleet.
func TestUnchainedConnectStillNamesItsExit(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit(fhOtherID, "NL", fhOtherTCP, exitP)
	registerRelay("relay-1", relayP)

	handle(wire{Type: "connect", Country: "NL", Mode: "relay"}, client.LocalAddr().(*net.UDPAddr))

	_ = recvWire(t, relayP, time.Second)
	sess := recvWire(t, client, time.Second)
	if sess.ExitID != fhOtherID {
		t.Fatalf("unchained reply named exit %q, want %q — an exit's id IS its Noise static key, so a client cannot connect without it", sess.ExitID, fhOtherID)
	}
	mu.Lock()
	recorded := sessions[sess.Session].exitID
	mu.Unlock()
	if recorded != fhOtherID {
		t.Fatalf("unchained session recorded exit %q, want %q", recorded, fhOtherID)
	}
}
