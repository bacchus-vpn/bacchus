package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// Declared node limits at the matchmaking surfaces (issue #143, ADR-0040).
//
// These drive handle() directly with fake UDP peers, in the same style as
// relay_test.go, and assert the coordinator's half of the deal: it reads the
// declared limits off every register, and it stops assigning work to a node whose
// operator has spent their monthly quota.
//
// Note what the coordinator's half is NOT: the guarantee. The node enforces its own
// cap locally (core/capacity), because the operator — not this coordinator — pays
// the overage bill, and this coordinator is untrusted by standing assumption
// (ADR-0020, #60). What is tested here is the courtesy that keeps a client from
// being matched to a node that will refuse it.

// registerExitLimits / registerRelayLimits drive a register carrying declared
// limits, exactly as core/engine.go's registerLoop stamps them.
func registerExitLimits(id, country, tcpAddr string, speedCap uint64, quota string, from *net.UDPConn) {
	handle(wire{Type: "register", Role: "exit", ID: id, Country: country, Addr: tcpAddr, SpeedCap: speedCap, QuotaState: quota}, from.LocalAddr().(*net.UDPAddr))
}
func registerRelayLimits(id string, speedCap uint64, quota string, from *net.UDPConn) {
	handle(wire{Type: "register", Role: "relay", ID: id, SpeedCap: speedCap, QuotaState: quota}, from.LocalAddr().(*net.UDPAddr))
}

// TestQuotaStateWireContract pins the two duplicated copies of the quota
// dispositions together. cmd/coordinator deliberately does not import core (see
// wire's doc), so the literals exist twice and nothing but this test stops them
// drifting — the same reason TestRelayDispositionWireContract exists (issue #97).
//
// core's copy is pinned by the mirror of this test in core/capacity_wire_test.go;
// between them, a rename on either side fails a build somewhere.
func TestQuotaStateWireContract(t *testing.T) {
	if quotaOK != "ok" || quotaExhausted != "exhausted" {
		t.Fatalf("quota state literals drifted: ok=%q exhausted=%q", quotaOK, quotaExhausted)
	}
	b, err := json.Marshal(wire{Type: "register", Role: "exit", ID: "e1", SpeedCap: 20_000_000, QuotaState: quotaExhausted})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back wire
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.SpeedCap != 20_000_000 || back.QuotaState != quotaExhausted {
		t.Fatalf("declared limits did not round-trip on the wire: %s", b)
	}
}

// A register with no declared limits must produce byte-for-byte the datagram a
// node predating #143 sends. This is what makes the feature opt-in: the existing
// datacenter fleet keeps registering exactly as it does today.
func TestUndeclaredLimitsAreAbsentFromTheWire(t *testing.T) {
	b, err := json.Marshal(wire{Type: "register", Role: "exit", ID: "e1", Country: "nl", Addr: "203.0.113.10:20000"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["speedCap"]; ok {
		t.Errorf("speedCap present on a register that declared none: %s", b)
	}
	if _, ok := m["quotaState"]; ok {
		t.Errorf("quotaState present on a register that declared none: %s", b)
	}
}

func TestRegisterStoresDeclaredLimits(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, relay := fakePeer(t), fakePeer(t)

	registerExitLimits("e1", "nl", "203.0.113.10:20000", 20_000_000, quotaOK, exit)
	registerRelayLimits("r1", 5_000_000, quotaOK, relay)

	mu.Lock()
	defer mu.Unlock()
	if got := exits["e1"].speedCap; got != 20_000_000 {
		t.Errorf("exit speedCap = %d, want 20000000", got)
	}
	if exits["e1"].exhausted {
		t.Error("exit marked exhausted on a quotaOK register")
	}
	if got := relays["r1"].speedCap; got != 5_000_000 {
		t.Errorf("relay speedCap = %d, want 5000000", got)
	}
}

// TestExhaustedExitIsNotOffered: a node whose operator has spent their declared quota
// stops being offered to clients.
//
// Post-#146 the list is per-country, so "not offered" is Available == 0 rather than
// absence from an exit list. The exhausted exit's COUNTRY is deliberately still
// present, marked busy — that is #147's requirement, and the pre-#146 behaviour of
// dropping it entirely is exactly what would make "<country> is busy" unsayable.
func TestExhaustedExitIsNotOffered(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	ok, spent, client := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExitLimits("e-ok", "nl", "203.0.113.10:20000", 0, quotaOK, ok)
	registerExitLimits("e-spent", "de", "203.0.113.11:20000", 0, quotaExhausted, spent)

	requestList(client)
	reply := recvWire(t, client, time.Second)

	wantCountry(t, reply, "NL", 1, 1)
	wantCountry(t, reply, "DE", 1, 0)
}

// A node that declares no quota at all is never withheld — this is what keeps the
// change inert for the existing fleet.
func TestExitWithNoDeclaredQuotaIsAlwaysOffered(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, client := fakePeer(t), fakePeer(t)

	// No QuotaState at all: exactly what a node predating #143 sends.
	handle(wire{Type: "register", Role: "exit", ID: "e1", Country: "nl", Addr: "203.0.113.10:20000"}, exit.LocalAddr().(*net.UDPAddr))

	requestList(client)
	wantCountry(t, recvWire(t, client, time.Second), "NL", 1, 1)
}

// TestExhaustedExitRefusesConnect closes the gap the list filter alone leaves: a
// client holding a list fetched BEFORE the exit exhausted must not be matched to it.
func TestExhaustedExitRefusesConnect(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, client := fakePeer(t), fakePeer(t)

	// It registers healthy, a client learns of it, and only then does it exhaust.
	registerExitLimits("e1", "nl", "203.0.113.10:20000", 0, quotaOK, exit)
	requestList(client)
	wantCountry(t, recvWire(t, client, time.Second), "NL", 1, 1)
	registerExitLimits("e1", "nl", "203.0.113.10:20000", 0, quotaExhausted, exit)

	connectCountry("NL", "direct", client)
	reply := recvWire(t, client, time.Second)
	if reply.Type != "error" {
		t.Fatalf("connect into a country whose only exit is exhausted replied %q, want error — a stale list must not defeat the quota", reply.Type)
	}
	// The refusal names the reason (#147): the country exists, it is simply full.
	if reply.Reason != string(refuseCountryBusy) {
		t.Errorf("refusal reason = %q, want %q", reply.Reason, refuseCountryBusy)
	}
	if reply.Country != "NL" {
		t.Errorf("refusal names country %q, want NL — the client cannot say which country is busy without it", reply.Country)
	}
}

// TestExhaustedRelayIsNotPicked: pickRelay skips a relay whose operator is done
// for the cycle, and falls back to TURN when that leaves nothing — the existing
// no-relay-available path, reached for a new reason.
func TestExhaustedRelayIsNotPicked(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, relay, client := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExitLimits("e1", "nl", "203.0.113.10:20000", 0, quotaOK, exit)
	registerRelayLimits("r1", 0, quotaExhausted, relay)

	connectRelay("e1", client)
	reply := recvWire(t, client, time.Second)
	if reply.Relay != relayTURN {
		t.Fatalf("relay disposition = %q, want %q: the only relay is exhausted, so this must fall back to TURN", reply.Relay, relayTURN)
	}

	// Non-vacuity: the same setup with an unexhausted relay DOES get the peer relay,
	// so the assertion above is about the quota and not about the harness.
	resetRegistry(t)
	setPC(t)
	exit2, relay2, client2 := fakePeer(t), fakePeer(t), fakePeer(t)
	registerExitLimits("e1", "nl", "203.0.113.10:20000", 0, quotaOK, exit2)
	registerRelayLimits("r1", 0, quotaOK, relay2)
	connectRelay("e1", client2)
	if reply := recvWire(t, client2, time.Second); reply.Relay != relayPeer {
		t.Fatalf("control: relay disposition = %q, want %q for an unexhausted relay", reply.Relay, relayPeer)
	}
}

// TestQuotaStateRefreshesOnReRegister pins the interaction with this handler's
// replace-the-whole-entry behaviour, in both directions. A node that exhausts
// mid-cycle must stop being assigned within one heartbeat, and — the direction
// that actually bites — a node whose quota RESETS must come back without an
// operator touching it.
func TestQuotaStateRefreshesOnReRegister(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, client := fakePeer(t), fakePeer(t)

	registerExitLimits("e1", "nl", "203.0.113.10:20000", 0, quotaOK, exit)
	requestList(client)
	wantCountry(t, recvWire(t, client, time.Second), "NL", 1, 1)

	// Quota spent: the next register carries it, and the exit stops being offered.
	registerExitLimits("e1", "nl", "203.0.113.10:20000", 0, quotaExhausted, exit)
	requestList(client)
	wantCountry(t, recvWire(t, client, time.Second), "NL", 1, 0)

	// New billing cycle: the node says so on its next register and is offered again.
	registerExitLimits("e1", "nl", "203.0.113.10:20000", 0, quotaOK, exit)
	requestList(client)
	wantCountry(t, recvWire(t, client, time.Second), "NL", 1, 1)
}
