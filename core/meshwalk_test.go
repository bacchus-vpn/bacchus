package core

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// This file covers the client half of mesh-walk recovery (issue #31, design §4.3):
// when every coordinator is unreachable, the client walks known peer couriers for a
// fresh coordinator-signed directory instead of failing cold. The courier mechanism
// itself is proven in core/coldstart; here we drive the Engine.MeshWalk strategy and
// the establish -> ErrNoCoordinatorReachable trigger against real loopback couriers.

// newMeshWalkClient builds a minimal client engine — no Start, no network — for
// exercising MeshWalk directly. relayTimeout bounds each peer fetch.
func newMeshWalkClient(t *testing.T) *Engine {
	t.Helper()
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"}, // never dialed: MeshWalk does not touch links
		Roles:        []string{RoleClient},
		SocksAddr:    "127.0.0.1:0",
		Geo:          "NL", // a connect names a country, not an exit (issue #146)
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.relayTimeout = 700 * time.Millisecond
	return eng
}

// startCoreCourier runs a coldstart.ServeCourier on a loopback socket and returns
// its address; it is torn down on cleanup.
func startCoreCourier(t *testing.T, pub ed25519.PublicKey, cache *coldstart.SnapshotCache) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen courier: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = coldstart.ServeCourier(ctx, pc, pub, cache); close(done) }()
	t.Cleanup(func() {
		cancel()
		_ = pc.Close()
		<-done
	})
	return pc.LocalAddr().String()
}

// blackholeUDP binds a loopback socket that reads and discards, so a peer address
// points at something that never answers — a stand-in for an unreachable node.
func blackholeUDP(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen blackhole: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

func signedCoordSnapshot(t *testing.T, priv ed25519.PrivateKey, coordAddr string) []byte {
	t.Helper()
	snap := coldstart.Snapshot{
		Version:   coldstart.SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries: []coldstart.Entry{
			{Role: "coordinator", ID: "coord", Addr: coordAddr},
			{Role: "relay", ID: "relay-1", Addr: "203.0.113.7:20000"},
		},
	}
	signed, err := coldstart.Sign(priv, snap)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signed
}

// TestMeshWalkRecoversFreshDirectory is the recovery happy path at the client level:
// the client's coordinators are gone, it holds a stale cached snapshot as proof, and
// a known peer courier serves a fresh directory naming a live coordinator. MeshWalk
// returns that directory, so the caller can reconnect through the rediscovered
// coordinator — recovery, not a cold failure.
func TestMeshWalkRecoversFreshDirectory(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	proof := signedCoordSnapshot(t, priv, "203.0.113.1:3478") // the now-dark coordinator
	cache := coldstart.NewSnapshotCache()
	cache.Store(signedCoordSnapshot(t, priv, "203.0.113.9:3478")) // the live one
	peer := startCoreCourier(t, pub, cache)

	eng := newMeshWalkClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := eng.MeshWalk(ctx, []string{peer}, proof, pub)
	if err != nil {
		t.Fatalf("MeshWalk: %v", err)
	}
	coords := res.Snapshot.AddrsForRole("coordinator")
	if len(coords) != 1 || coords[0] != "203.0.113.9:3478" {
		t.Fatalf("recovery must adopt the peer's fresh coordinator, got %v", coords)
	}
}

// TestMeshWalkSkipsUnreachablePeer proves the walk: a dead peer first, a live courier
// second. The walk must skip the dead one and recover from the live one, not give up
// at the first miss.
func TestMeshWalkSkipsUnreachablePeer(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	proof := signedCoordSnapshot(t, priv, "203.0.113.1:3478")
	cache := coldstart.NewSnapshotCache()
	cache.Store(signedCoordSnapshot(t, priv, "203.0.113.9:3478"))

	dead := blackholeUDP(t)
	live := startCoreCourier(t, pub, cache)

	eng := newMeshWalkClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := eng.MeshWalk(ctx, []string{dead, live}, proof, pub)
	if err != nil {
		t.Fatalf("MeshWalk should recover past a dead peer: %v", err)
	}
	if got := res.Snapshot.AddrsForRole("coordinator"); len(got) != 1 || got[0] != "203.0.113.9:3478" {
		t.Fatalf("expected recovery from the live courier, got %v", got)
	}
}

// TestMeshWalkRejectsForgedDirectory is the courier-cannot-forge invariant at the
// client level: a hostile peer serves a directory signed by its own key. MeshWalk
// verifies against the real coordinator key and returns an error — the forged
// coordinators never reach the caller.
func TestMeshWalkRejectsForgedDirectory(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)       // real coordinator key
	_, attackerPriv, _ := ed25519.GenerateKey(nil) // hostile courier key

	proof := signedCoordSnapshot(t, priv, "203.0.113.1:3478")
	cache := coldstart.NewSnapshotCache()
	cache.Store(signedCoordSnapshot(t, attackerPriv, "203.0.113.66:3478")) // forged
	peer := startCoreCourier(t, pub, cache)

	eng := newMeshWalkClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := eng.MeshWalk(ctx, []string{peer}, proof, pub); err == nil {
		t.Fatal("MeshWalk must reject a forged directory, got nil error")
	}
}

// TestMeshWalkGuards covers the recovery preconditions: no proof of prior contact
// (this is recovery, not cold-start), no peers, and a missing/short public key.
func TestMeshWalkGuards(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	proof := signedCoordSnapshot(t, priv, "203.0.113.1:3478")
	eng := newMeshWalkClient(t)
	ctx := context.Background()

	if _, err := eng.MeshWalk(ctx, []string{"203.0.113.5:3478"}, nil, pub); err == nil {
		t.Fatal("MeshWalk without a proof must error (recovery needs prior contact)")
	}
	if _, err := eng.MeshWalk(ctx, nil, proof, pub); err == nil {
		t.Fatal("MeshWalk with no peers must error")
	}
	if _, err := eng.MeshWalk(ctx, []string{"203.0.113.5:3478"}, proof, ed25519.PublicKey{1, 2, 3}); err == nil {
		t.Fatal("MeshWalk with a short public key must error")
	}
}

// TestConnectAllSilentReturnsNoCoordinatorReachable proves the recovery TRIGGER: a
// client whose only coordinator is a black hole (reads, never replies) fails a
// connect with ErrNoCoordinatorReachable — the sentinel a caller keys mesh-walk
// recovery on. A coordinator that ANSWERS but can't pair returns a plain error
// instead, so this must be the all-silent case specifically.
func TestConnectAllSilentReturnsNoCoordinatorReachable(t *testing.T) {
	silent := fakeConnectCoordinator(t, func(string) (wire, bool) { return wire{}, false }) // blackhole every mode
	eng := newSmokeClient(t, silent, &fakeTransport{})
	eng.directTimeout = 150 * time.Millisecond
	eng.relayTimeout = 150 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	err := eng.Connect(ctx)
	if !errors.Is(err, ErrNoCoordinatorReachable) {
		t.Fatalf("all-silent connect must return ErrNoCoordinatorReachable, got %v", err)
	}
}
