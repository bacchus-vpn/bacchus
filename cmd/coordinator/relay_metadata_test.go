package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// Coordinator half of the relay-metadata lane:
//   - issue #56: the peer-relay "session" reply carries a stable, opaque dedupe
//     tag derived from the relay id; direct and TURN-fallback replies carry none.
//   - issue #97: the relayPeer/relayTURN literals are pinned so this copy cannot
//     drift from core/engine.go's (the two binaries share no code).
//
// These reuse the fake-UDP-peer harness (setPC/resetRegistry/fakePeer/register*/
// recvWire) from relay_test.go and admission_test.go.

// connectDirect drives a direct-mode connect through handle() from a fake client,
// naming the COUNTRY of the given exit (see connectRelay / countryOf: a client cannot
// name an exit post-#146).
func connectDirect(exitID string, from *net.UDPConn) {
	handle(wire{Type: "connect", Country: countryOf(exitID), Mode: "direct"}, from.LocalAddr().(*net.UDPAddr))
}

// TestPeerRelaySessionCarriesStableTag: a peer-relay connect tags the client's
// reply with the relay's stable opaque tag (issue #56), so a rotating client can
// dedupe the same relay across coordinators. The tag is the hash of the relay id,
// stable and collision-distinct.
func TestPeerRelaySessionCarriesStableTag(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP, relayP := fakePeer(t), fakePeer(t), fakePeer(t)

	const exitID, exitTCP = "exit-1", "10.0.0.9:20000"
	registerExit(exitID, "RU", exitTCP, exitP)
	registerRelay("relay-1", relayP)

	connectRelay(exitID, client)

	_ = recvWire(t, relayP, time.Second) // drain the relay's assign
	sess := recvWire(t, client, time.Second)
	if sess.Type != "session" || sess.Relay != relayPeer {
		t.Fatalf("client got %+v, want a peer-relay session", sess)
	}
	if sess.RelayTag == "" {
		t.Fatal("a peer-relay session reply must carry a dedupe tag (issue #56)")
	}
	if sess.RelayTag != relayTag("relay-1") {
		t.Fatalf("tag = %q, want the stable hash of the relay id %q", sess.RelayTag, relayTag("relay-1"))
	}
	// The tag is not the relay's routable address, and it is opaque.
	if sess.RelayTag == "relay-1" {
		t.Fatal("the tag must be an opaque hash, not the raw relay id")
	}
}

// TestRelayTagStableAndDistinct pins the tag's two load-bearing properties: the
// SAME relay id always maps to the SAME tag (so two coordinators dedupe as one),
// and DIFFERENT ids map to different tags (so distinct relays are retried).
func TestRelayTagStableAndDistinct(t *testing.T) {
	if relayTag("relay-1") != relayTag("relay-1") {
		t.Fatal("relayTag must be stable for the same relay id")
	}
	if relayTag("relay-1") == relayTag("relay-2") {
		t.Fatal("relayTag must differ for different relay ids")
	}
	if relayTag("relay-1") == "" {
		t.Fatal("relayTag must never be empty for a non-empty id")
	}
}

// TestTurnFallbackCarriesNoTag: with no relay registered, the relay-mode connect
// falls back to TURN (a direct assignment). That reply must carry NO dedupe tag —
// there is no distinct relay to dedupe, and the client treats it as a direct path.
func TestTurnFallbackCarriesNoTag(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP := fakePeer(t), fakePeer(t)

	const exitID, exitTCP = "exit-1", "10.0.0.9:20000"
	registerExit(exitID, "RU", exitTCP, exitP)

	connectRelay(exitID, client)

	_ = recvWire(t, exitP, time.Second) // drain the direct assign
	sess := recvWire(t, client, time.Second)
	if sess.Relay != relayTURN {
		t.Fatalf("client got relay=%q, want the TURN fallback", sess.Relay)
	}
	if sess.RelayTag != "" {
		t.Fatalf("a TURN-fallback reply must carry no relay tag, got %q", sess.RelayTag)
	}
}

// TestDirectSessionCarriesNoTag: a mode:"direct" connect carries neither a relay
// disposition nor a dedupe tag.
func TestDirectSessionCarriesNoTag(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	client, exitP := fakePeer(t), fakePeer(t)

	const exitID, exitTCP = "exit-1", "10.0.0.9:20000"
	registerExit(exitID, "RU", exitTCP, exitP)

	connectDirect(exitID, client)

	_ = recvWire(t, exitP, time.Second) // drain the direct assign
	sess := recvWire(t, client, time.Second)
	if sess.Type != "session" {
		t.Fatalf("client got %+v, want a session", sess)
	}
	if sess.Relay != "" || sess.RelayTag != "" {
		t.Fatalf("a direct session must carry no relay disposition or tag, got relay=%q tag=%q", sess.Relay, sess.RelayTag)
	}
}

// TestRelayDispositionWireContract pins the coordinator's copy of the relay
// disposition literals. core/relay_metadata_test.go pins the identical bytes; if
// either copy drifts, one of the two tests fails (issue #97).
func TestRelayDispositionWireContract(t *testing.T) {
	if relayPeer != "peer" || relayTURN != "turn" {
		t.Fatalf("relay disposition literals drifted: peer=%q turn=%q", relayPeer, relayTURN)
	}
	// What the coordinator stamps must round-trip to the same field a client reads.
	b, err := json.Marshal(wire{Type: "session", Relay: relayPeer, RelayTag: "abc123"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back wire
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Relay != relayPeer || back.RelayTag != "abc123" {
		t.Fatalf("relay/tag did not round-trip on the wire: %s", b)
	}
}

// Directory advertisement of the relay onion-forward ingress + operator tag (issue #124,
// ADR-0038 §9 item 3). These drive register through handle() and then buildSnapshot, and
// assert what the SIGNED directory carries for a relay-capable node — the foundation the
// client-side chain assembly (§2/§4) is gated on.

// setOperators installs a coordinator-side operator/vouch-subtree map for a test,
// restoring the empty default after. Operator tags are coordinator-side truth (issue
// #124), so a test sets them here — never through a node's register wire.
func setOperators(t *testing.T, m map[string]string) {
	t.Helper()
	mu.Lock()
	operators = m
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		operators = map[string]string{}
		mu.Unlock()
	})
}

// registerRelayIngress registers a relay that advertises an onion-forward listener port
// (issue #124), the way a chain-capable relay will. The coordinator observes the source
// IP; only the port is taken from the node.
func registerRelayIngress(id string, ingressPort int, from *net.UDPConn) {
	handle(wire{Type: "register", Role: "relay", ID: id, IngressPort: ingressPort}, from.LocalAddr().(*net.UDPAddr))
}

// findEntry returns the snapshot entry with the given id, failing if absent.
func findEntry(t *testing.T, snap coldstart.Snapshot, id string) coldstart.Entry {
	t.Helper()
	for _, e := range snap.Entries {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("no entry with id %q in snapshot %+v", id, snap.Entries)
	return coldstart.Entry{}
}

// TestSnapshotAdvertisesRelayIngressAndOperator: a relay that reports an onion-forward
// port is advertised in the signed directory with (a) an ingress whose HOST is the
// coordinator-OBSERVED source IP and whose PORT is the relay's self-reported one, and
// (b) the coordinator-known operator tag. The ingress host is never the node's to assert
// — that is exactly what lets §4 trust an IP-derived AS later (issue #124).
func TestSnapshotAdvertisesRelayIngressAndOperator(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	setOperators(t, map[string]string{"relay-1": "op-acme"})
	relayP := fakePeer(t)

	const ingressPort = 8443
	registerRelayIngress("relay-1", ingressPort, relayP)

	snap := buildSnapshot("203.0.113.1:3478")
	e := findEntry(t, snap, "relay-1")

	observedIP := relayP.LocalAddr().(*net.UDPAddr).IP.String()
	wantIngress := net.JoinHostPort(observedIP, strconv.Itoa(ingressPort))
	if e.Ingress != wantIngress {
		t.Fatalf("ingress = %q, want observed-IP:self-port %q", e.Ingress, wantIngress)
	}
	// Composed from OBSERVED IP + self-reported PORT, not the signaling address: the host
	// matches the observed source, and the port is the relay's listener, not its
	// signaling port — so the ingress differs from Addr.
	if host, _, _ := net.SplitHostPort(e.Ingress); host != observedIP {
		t.Fatalf("ingress host = %q, want the observed source IP %q", host, observedIP)
	}
	if e.Ingress == e.Addr {
		t.Fatalf("ingress must differ from the signaling addr %q (self-reported listener port, not the observed one)", e.Addr)
	}
	if e.Operator != "op-acme" {
		t.Fatalf("operator = %q, want the coordinator-known tag %q", e.Operator, "op-acme")
	}
	if !e.RelayEligible() {
		t.Fatal("a relay advertising an ingress must be relay-eligible")
	}
}

// TestSnapshotRelayWithoutIngressNotEligible: a relay that reports NO onion-forward port
// (one predating #124, or not configured to forward) is still listed for rendezvous but
// advertises no ingress and is not a chain hop. Its operator tag is still stamped when
// the coordinator knows one — operator identity is independent of whether the node forwards.
func TestSnapshotRelayWithoutIngressNotEligible(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	setOperators(t, map[string]string{"relay-1": "op-acme"})
	relayP := fakePeer(t)

	registerRelay("relay-1", relayP) // the pre-#124 register path: no ingress port

	snap := buildSnapshot("203.0.113.1:3478")
	e := findEntry(t, snap, "relay-1")
	if e.Ingress != "" {
		t.Fatalf("a relay that reported no ingress port must advertise no ingress, got %q", e.Ingress)
	}
	if e.RelayEligible() {
		t.Fatal("a relay with no ingress must not be relay-eligible")
	}
	if e.Operator != "op-acme" {
		t.Fatalf("operator tag must be stamped regardless of ingress, got %q", e.Operator)
	}
}

// TestSnapshotOperatorIsCoordinatorSide: the operator tag comes from the coordinator's
// own registry, not from anything a node can put on its register wire. Two relays
// register identically; only the one the coordinator has an assignment for is labeled.
// This is the anti-Sybil property — a node cannot claim its own operator to fake diversity.
func TestSnapshotOperatorIsCoordinatorSide(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	setOperators(t, map[string]string{"relay-known": "op-acme"}) // relay-unknown deliberately absent
	knownP, unknownP := fakePeer(t), fakePeer(t)

	registerRelayIngress("relay-known", 8443, knownP)
	registerRelayIngress("relay-unknown", 8444, unknownP)

	snap := buildSnapshot("203.0.113.1:3478")
	if e := findEntry(t, snap, "relay-known"); e.Operator != "op-acme" {
		t.Fatalf("assigned relay operator = %q, want op-acme", e.Operator)
	}
	if e := findEntry(t, snap, "relay-unknown"); e.Operator != "" {
		t.Fatalf("unassigned relay must have an empty operator (coordinator-side truth), got %q", e.Operator)
	}
}

// TestLoadOperators covers the operator-map config path (issue #124): a missing file is
// NOT an error (no assignments — the -admission-revocations convention), a well-formed
// file parses, and a malformed one is a hard error so a typo cannot silently blank the
// operator-diversity signal.
func TestLoadOperators(t *testing.T) {
	// Missing file -> empty map, no error.
	got, err := loadOperators(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("missing file must yield an empty map, got %v", got)
	}

	// Well-formed file -> parsed assignments.
	dir := t.TempDir()
	good := filepath.Join(dir, "operators.json")
	if err := os.WriteFile(good, []byte(`{"relay-1":"op-acme","relay-2":"op-globex"}`), 0o600); err != nil {
		t.Fatalf("write good file: %v", err)
	}
	got, err = loadOperators(good)
	if err != nil {
		t.Fatalf("valid file: %v", err)
	}
	if got["relay-1"] != "op-acme" || got["relay-2"] != "op-globex" {
		t.Fatalf("parsed map wrong: %v", got)
	}

	// Malformed file -> error (fail hard, don't silently blank the signal).
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{not json`), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	if _, err := loadOperators(bad); err == nil {
		t.Fatal("malformed file must be an error")
	}
}

// TestSnapshotExitCarriesItsOperator pins the operator tag on EXIT entries, which
// is what makes operator-diversity hop selection work at the depth most clients run
// (issue #142, ADR-0038 §6).
//
// It was relay-only, and that quietly reduced the control to a no-op. A chain's head
// must be exit-role — it is the node the coordinator pairs the client to, via
// connect{firstHop} — so an unlabeled head was neither recorded as a used operator
// nor collided against. At depth 2 the head is the only peeling hop there is, so
// "operator diversity is enforced" described nothing at all.
//
// The operators map has never been role-scoped; it is keyed by node id. So this
// reads a value that was already loaded and was simply not being stamped.
func TestSnapshotExitCarriesItsOperator(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	setOperators(t, map[string]string{"exit-known": "op-acme"}) // exit-unknown deliberately absent
	knownP, unknownP := fakePeer(t), fakePeer(t)

	registerExit("exit-known", "NL", "203.0.113.7:20000", knownP)
	registerExit("exit-unknown", "NL", "203.0.113.8:20000", unknownP)

	snap := buildSnapshot("203.0.113.1:3478")
	if e := findEntry(t, snap, "exit-known"); e.Operator != "op-acme" {
		t.Fatalf("exit operator = %q, want op-acme — an unlabeled chain head makes ADR-0038 §6 diversity inert at depth 2", e.Operator)
	}
	// The same coordinator-side-truth rule exits inherit from relays: a node the
	// coordinator has no assignment for stays unlabeled rather than self-reporting.
	if e := findEntry(t, snap, "exit-unknown"); e.Operator != "" {
		t.Fatalf("unassigned exit must have an empty operator (coordinator-side truth), got %q", e.Operator)
	}
}
