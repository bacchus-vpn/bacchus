package coldstart

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/netip"
	"testing"
	"time"
)

// This file covers the mesh-walk courier (old #31, design §4.3): a relay/exit
// node caching a coordinator-signed snapshot and serving it, verbatim, to a
// recovering client that can no longer reach any coordinator. The security bar is
// the courier model — a courier is a dispenser, not an author — so the tests prove
// both directions of it:
//   - a genuine cached snapshot round-trips and lets the client read a FRESH
//     coordinator address it did not have (recovery works), and
//   - a courier that serves a FORGED or ALTERED snapshot is rejected by the client
//     (a courier cannot poison the directory), and
//   - the proof-of-prior-contact gate hands the snapshot only to a holder of a
//     coordinator-signed proof, so a bare prober learns nothing (anti-probe).

func mustSign(t *testing.T, priv ed25519.PrivateKey, snap Snapshot) []byte {
	t.Helper()
	signed, err := Sign(priv, snap)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signed
}

// coordSnapshot builds a valid, unexpired snapshot whose sole coordinator entry
// sits at coordAddr — so a test can tell which snapshot a walk actually adopted by
// the coordinator address that comes back.
func coordSnapshot(coordAddr string) Snapshot {
	return Snapshot{
		Version:   SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries: []Entry{
			{Role: "coordinator", ID: "coord", Addr: coordAddr},
			{Role: "relay", ID: "relay-1", Addr: "203.0.113.7:20000"},
		},
	}
}

// startCourier runs a ServeCourier on a loopback UDP socket and returns its
// address. Closing happens via t.Cleanup (cancel + close unblocks ReadFrom).
func startCourier(t *testing.T, pub ed25519.PublicKey, cache *SnapshotCache) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen courier: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = ServeCourier(ctx, pc, pub, cache); close(done) }()
	t.Cleanup(func() {
		cancel()
		_ = pc.Close()
		<-done
	})
	return pc.LocalAddr().String()
}

// TestCourierRecoversFreshSnapshot is the recovery happy path: the client holds a
// stale prior snapshot (its proof of prior contact) that points at one coordinator;
// the courier holds a FRESH one pointing at a different, live coordinator. The walk
// must return the fresh snapshot, so the client learns the new rendezvous point it
// could not have reached any coordinator to discover. This is the mechanism half of
// "a client with all coordinators down recovers via a peer's cached snapshot".
func TestCourierRecoversFreshSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	// The client's proof: an old snapshot naming a coordinator that is now dark.
	proof := mustSign(t, priv, coordSnapshot("203.0.113.1:3478"))

	// The courier's cache: a fresh snapshot naming a live coordinator elsewhere.
	cache := NewSnapshotCache()
	cache.Store(mustSign(t, priv, coordSnapshot("203.0.113.9:3478")))

	addr := startCourier(t, pub, cache)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := FetchSnapshot(ctx, addr, proof, pub)
	if err != nil {
		t.Fatalf("FetchSnapshot: %v", err)
	}
	coords := res.Snapshot.AddrsForRole("coordinator")
	if len(coords) != 1 || coords[0] != "203.0.113.9:3478" {
		t.Fatalf("walk must adopt the courier's fresh coordinator, got %v", coords)
	}
}

// TestCourierRejectsForgedSnapshot is the courier-cannot-forge invariant: a hostile
// courier serves a snapshot signed by ITS OWN key (a forged directory pointing the
// client at attacker-run coordinators). The client verifies against the real
// coordinator key and rejects it — the forged entries never reach the caller.
// It is served through serveForcedSnapshot — a courier that does not gate on the
// coordinator key (a hostile one wouldn't run our ServeCourier, which withholds
// anything it cannot itself Verify) — so the client's own signature check is what
// this pins, exactly as it must be in the field where the serving node is untrusted.
func TestCourierRejectsForgedSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)       // the real coordinator key the client trusts
	_, attackerPriv, _ := ed25519.GenerateKey(nil) // the hostile courier's own key

	// A hostile courier serves a directory signed by the ATTACKER, pointing the client
	// at attacker-run coordinators.
	addr := serveForcedSnapshot(t, mustSign(t, attackerPriv, coordSnapshot("203.0.113.66:3478")))

	proof := mustSign(t, priv, coordSnapshot("203.0.113.1:3478"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// The client verifies the RESPONSE against pub (the real coordinator), not the
	// attacker key it was signed with, so the forged directory is rejected — its
	// entries never reach the caller.
	if _, err := FetchSnapshot(ctx, addr, proof, pub); err != ErrBadSignature {
		t.Fatalf("forged snapshot must be rejected: err = %v, want ErrBadSignature", err)
	}
}

// TestCourierRejectsAlteredSnapshot is the tamper case: genuinely coordinator-signed
// bytes with one flipped in transit/storage, force-served by a non-conforming courier.
// The client's Verify catches the broken signature.
func TestCourierRejectsAlteredSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	signed := mustSign(t, priv, coordSnapshot("203.0.113.9:3478"))
	signed[10] ^= 0xFF // flip a byte in the signed body

	addr := serveForcedSnapshot(t, signed)
	proof := mustSign(t, priv, coordSnapshot("203.0.113.1:3478"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := FetchSnapshot(ctx, addr, proof, pub); err != ErrBadSignature {
		t.Fatalf("altered snapshot must be rejected: err = %v, want ErrBadSignature", err)
	}
}

// TestCourierProofGate exercises the anti-probe gate directly on the pure handler:
// the cached snapshot is attached ONLY to a request carrying a proof this
// coordinator signed, and only when the cache is warm. Everything else — a wrong-key
// proof, no proof at all — gets the bare Binding Success a plain STUN server sends.
func TestCourierProofGate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)

	cache := NewSnapshotCache()
	cache.Store(mustSign(t, priv, coordSnapshot("203.0.113.9:3478")))

	validProof := mustSign(t, priv, coordSnapshot("203.0.113.1:3478"))
	wrongProof := mustSign(t, otherPriv, coordSnapshot("203.0.113.1:3478"))

	served := func(req []byte) bool {
		t.Helper()
		resp, ok := handleCourierRequest(req, netip.AddrPort{}, pub, cache)
		if !ok {
			t.Fatal("a Binding Request must always get a response")
		}
		m, err := parse(resp)
		if err != nil {
			t.Fatalf("parse response: %v", err)
		}
		_, has := m.get(attrSnapshot)
		return has
	}

	tx := newTxID()
	if !served(buildCourierRequest(tx, validProof)) {
		t.Fatal("a valid proof against a warm cache must be served the snapshot")
	}
	if served(buildCourierRequest(tx, wrongProof)) {
		t.Fatal("a proof signed by another key must NOT be served (anti-probe)")
	}
	if served(buildRequest(tx, "", nil)) {
		t.Fatal("a bare Binding Request (no proof) must NOT be served (anti-probe)")
	}

	// Warm proof, cold cache: still nothing to serve.
	cold := NewSnapshotCache()
	resp, _ := handleCourierRequest(buildCourierRequest(tx, validProof), netip.AddrPort{}, pub, cold)
	m, _ := parse(resp)
	if _, has := m.get(attrSnapshot); has {
		t.Fatal("an empty cache must serve no snapshot even to a valid proof")
	}
}

// TestCourierAcceptsStaleProof pins the deliberate asymmetry: the proof-of-prior-
// contact may be EXPIRED (a recovering client's cached snapshot usually is — that is
// why it is recovering) and must still unlock the courier, because provenance, not
// freshness, is what the gate checks. The RESPONSE, by contrast, must be fresh
// (covered by TestFetchSnapshotRejectsExpiredResponse).
func TestCourierAcceptsStaleProof(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	stale := coordSnapshot("203.0.113.1:3478")
	stale.ExpiresAt = time.Now().Add(-24 * time.Hour) // long dead
	staleProof := mustSign(t, priv, stale)

	cache := NewSnapshotCache()
	cache.Store(mustSign(t, priv, coordSnapshot("203.0.113.9:3478")))

	resp, ok := handleCourierRequest(buildCourierRequest(newTxID(), staleProof), netip.AddrPort{}, pub, cache)
	if !ok {
		t.Fatal("expected a response")
	}
	m, _ := parse(resp)
	if _, has := m.get(attrSnapshot); !has {
		t.Fatal("an expired-but-genuinely-signed proof must still unlock the courier")
	}
}

// TestCourierWithholdsExpiredSnapshot is the serve-side of the freshness rule
// (old #115): a courier whose only cached snapshot has aged past the coordinator TTL —
// because its coordinator went unreachable for longer than one refresh could bridge —
// must serve nothing, not hand out entries that may already be gone. Even a valid
// proof of prior contact unlocks only a still-fresh snapshot; an expired cache draws
// the same plain Binding Success a bare prober gets. This enforces in code the
// courierRefresh-vs-snapshot-TTL coupling that otherwise held only by cadence.
func TestCourierWithholdsExpiredSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	expired := coordSnapshot("203.0.113.9:3478")
	expired.ExpiresAt = time.Now().Add(-time.Minute) // aged past the coordinator TTL
	cache := NewSnapshotCache()
	cache.Store(mustSign(t, priv, expired))

	validProof := mustSign(t, priv, coordSnapshot("203.0.113.1:3478"))
	resp, ok := handleCourierRequest(buildCourierRequest(newTxID(), validProof), netip.AddrPort{}, pub, cache)
	if !ok {
		t.Fatal("a Binding Request must always get a response")
	}
	m, err := parse(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if _, has := m.get(attrSnapshot); has {
		t.Fatal("a courier must withhold an expired snapshot even from a valid proof (old #115)")
	}
}

// TestFetchSnapshotRejectsExpiredResponse is the client-side backstop for the same
// rule: even if a courier does NOT honour the withhold — a node predating old #115, or a
// hostile one — and attaches an expired snapshot anyway, the client rejects it (its
// entries may be gone) and, in a real walk, moves to the next peer. serveForcedSnapshot
// stands in for that non-conforming courier so the client check is exercised in
// isolation from the now-conforming ServeCourier.
func TestFetchSnapshotRejectsExpiredResponse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	expired := coordSnapshot("203.0.113.9:3478")
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	addr := serveForcedSnapshot(t, mustSign(t, priv, expired))

	proof := mustSign(t, priv, coordSnapshot("203.0.113.1:3478"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := FetchSnapshot(ctx, addr, proof, pub); err != ErrSnapshotExpired {
		t.Fatalf("an expired reply must be rejected client-side: err = %v, want ErrSnapshotExpired", err)
	}
}

// serveForcedSnapshot stands up a raw UDP responder that answers every courier
// request by attaching signed, regardless of proof or freshness — a stand-in for a
// courier that does not honour the withhold-expired rule. It exercises the client's
// own freshness backstop in isolation from ServeCourier (which withholds correctly).
func serveForcedSnapshot(t *testing.T, signed []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen forced responder: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			m, err := parse(append([]byte(nil), buf[:n]...))
			if err != nil || m.typ != typeBindingRequest {
				continue
			}
			var reflexive netip.AddrPort
			if ua, ok := src.(*net.UDPAddr); ok {
				reflexive = ua.AddrPort()
			}
			_, _ = pc.WriteTo(buildResponse(m.tx, reflexive, signed), src)
		}
	}()
	t.Cleanup(func() { _ = pc.Close(); <-done })
	return pc.LocalAddr().String()
}

// TestFetchSnapshotUnservedIsNotAuthenticated: a reachable endpoint that attaches no
// snapshot (proof rejected, or not a courier at all) surfaces ErrNotAuthenticated,
// distinct from a network error, so a walk can tell "try the next peer" from "the
// network is down".
func TestFetchSnapshotUnservedIsNotAuthenticated(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)

	cache := NewSnapshotCache()
	cache.Store(mustSign(t, priv, coordSnapshot("203.0.113.9:3478")))
	addr := startCourier(t, pub, cache)

	// A proof the courier's key will reject: it answers as a plain STUN endpoint.
	badProof := mustSign(t, otherPriv, coordSnapshot("203.0.113.1:3478"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := FetchSnapshot(ctx, addr, badProof, pub); err != ErrNotAuthenticated {
		t.Fatalf("a rejected proof must surface ErrNotAuthenticated, got %v", err)
	}
}

// TestCourierForwardsRelayMetadataVerbatim proves the courier stays a byte-exact
// dispenser as the directory grows: a snapshot whose relay entry carries the old #124
// onion-forward ingress and operator tag is handed back unaltered, so both survive
// re-verification and the relay stays eligible. A courier caches opaque signed bytes and
// re-signs nothing (SnapshotCache holds no key), so it can neither strip nor forge the
// ingress a chain-building client depends on — the same "dispenser, not author" property
// the rest of this file pins, now covering the fields the relay-chaining epic adds.
func TestCourierForwardsRelayMetadataVerbatim(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	snap := Snapshot{
		Version:   SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries: []Entry{
			{Role: "coordinator", ID: "coord", Addr: "203.0.113.1:3478"},
			{
				Role: "relay", ID: "relay-1", Addr: "198.51.100.7:20000",
				Ingress: "203.0.113.7:8443", Operator: "op-acme",
			},
		},
	}
	cache := NewSnapshotCache()
	cache.Store(mustSign(t, priv, snap))

	// A recovering client's request carrying a valid proof of prior contact gets the
	// cached snapshot appended; drive the pure per-packet path directly (no socket).
	proof := mustSign(t, priv, coordSnapshot("203.0.113.1:3478"))
	resp, ok := handleCourierRequest(buildCourierRequest(newTxID(), proof), netip.MustParseAddrPort("192.0.2.5:1234"), pub, cache)
	if !ok {
		t.Fatal("courier dropped a well-formed proof-bearing request")
	}
	m, err := parse(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	signed, ok := m.get(attrSnapshot)
	if !ok {
		t.Fatal("courier attached no snapshot to a proof-bearing request")
	}
	got, err := Verify(pub, signed)
	if err != nil {
		t.Fatalf("forwarded snapshot fails re-verify: %v", err)
	}
	relay := got.Entries[1]
	if relay.Ingress != "203.0.113.7:8443" || relay.Operator != "op-acme" {
		t.Fatalf("courier did not forward the relay metadata intact: %+v", relay)
	}
	if !relay.RelayEligible() {
		t.Fatal("a forwarded relay carrying an ingress must remain relay-eligible")
	}
}

func TestSnapshotCacheStoreLoad(t *testing.T) {
	c := NewSnapshotCache()
	if c.Load() != nil {
		t.Fatal("a fresh cache must Load nil")
	}
	orig := []byte{1, 2, 3, 4}
	c.Store(orig)
	orig[0] = 0xFF // mutate the caller's slice after Store
	got := c.Load()
	if len(got) != 4 || got[0] != 1 {
		t.Fatalf("Store must snapshot a private copy, got %v", got)
	}
	got[1] = 0xFF // mutate the returned slice
	if again := c.Load(); again[1] != 2 {
		t.Fatalf("Load must return a private copy, got %v", again)
	}
}
