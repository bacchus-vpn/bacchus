package core

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/selection"
)

// This file extends mesh-walk recovery past the first-connect boundary (issue #115):
// it must also engage when a LIVE session loses every coordinator mid-session, on
// both the single-transport reconnect path and the pooled failover path, and the
// pooled path must surface ErrNoCoordinatorReachable so recovery can key on it. The
// couriers are real ServeCourier endpoints on loopback UDP (via startCoreCourier),
// mirroring meshwalk_test.go; the coordinator side is driven through the establishFn
// / countriesFn seams (as reconnect_test.go and pool_test.go drive their loops) or a real
// black-hole coordinator, so the trigger is exercised without a live transport stack.

// TestReconnectMidSessionAllSilentTriggersMeshWalk is gap 1: a client connects, then
// every coordinator goes silent mid-session. The single-transport reconnect loop must
// not merely retry forever — after a run of all-silent passes it walks a known peer
// courier, rediscovers a fresh coordinator, and signals the supervisor to rebuild
// (NeedsRecovery), carrying the fresher snapshot as the next proof.
func TestReconnectMidSessionAllSilentTriggersMeshWalk(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	// The courier serves a directory naming a NEW, live coordinator — different from
	// the (now dark) one the client was built with, so recovery is a real improvement.
	cache := coldstart.NewSnapshotCache()
	cache.Store(signedCoordSnapshot(t, priv, "203.0.113.9:3478"))
	peer := startCoreCourier(t, pub, cache)

	e := newReconnectEngine(t, nil)
	e.meshPeers = []string{peer}
	e.meshProof = signedCoordSnapshot(t, priv, "203.0.113.1:3478") // stale proof of prior contact
	e.meshPubKey = pub
	e.meshRecoveryAfter = 1 // walk on the first all-silent reconnect pass — deterministic
	e.relayTimeout = 700 * time.Millisecond
	defer e.Stop()

	var n int32
	first := newFakeSession()
	e.establishFn = func(_ context.Context, _ string) (connPath, error) {
		if atomic.AddInt32(&n, 1) == 1 {
			return connPath{sess: first, mode: modeDirect}, nil // initial connect succeeds
		}
		return connPath{}, ErrNoCoordinatorReachable // every reconnect: all coordinators silent
	}

	if err := e.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	first.Close() // drop the live path -> reconnect goes all-silent -> mesh-walk must engage

	select {
	case <-e.NeedsRecovery():
	case <-time.After(5 * time.Second):
		t.Fatal("mid-session all-silent did not trigger mesh-walk recovery (issue #115)")
	}
	coords, proof := e.RecoveredDirectory()
	if len(coords) != 1 || coords[0] != "203.0.113.9:3478" {
		t.Fatalf("recovery must adopt the courier's fresh coordinator, got %v", coords)
	}
	if len(proof) == 0 {
		t.Fatal("recovery must carry the fresher snapshot as the next proof of prior contact")
	}

	// No strand, no double-connect (the #105 review lesson): once recovery is
	// signalled, the reconnect loop must STOP and hand off to the supervisor — it must
	// not keep dialing the dead pool. Record the establish count after the signal,
	// stop as the supervisor would, and prove it did not grow: nothing is racing the
	// rebuild for the SOCKS listener.
	settled := atomic.LoadInt32(&n)
	e.Stop()
	e.Wait()
	if after := atomic.LoadInt32(&n); after != settled {
		t.Fatalf("reconnect loop kept establishing after recovery (%d -> %d) — would double-connect the rebuild", settled, after)
	}
}

// TestMeshRecoverySkipsUnchangedDirectory is the ADR-0030-preserving guard: a walk
// that only re-lists the SAME coordinators the client already knows to be down is no
// improvement, so tryMeshRecovery must NOT fire — the failover loop keeps retrying in
// place rather than tearing the engine down to rebuild against the same dead address.
// This is what keeps a transient outage from churning through pointless rebuilds.
func TestMeshRecoverySkipsUnchangedDirectory(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	const coord = "203.0.113.1:3478"

	cache := coldstart.NewSnapshotCache()
	cache.Store(signedCoordSnapshot(t, priv, coord)) // names the coordinator we already hold
	peer := startCoreCourier(t, pub, cache)

	e := newMeshWalkClient(t)
	e.cfg.Coordinators = []string{coord} // current (dead) coordinator == what the courier serves
	e.meshPeers = []string{peer}
	e.meshProof = signedCoordSnapshot(t, priv, coord)
	e.meshPubKey = pub

	if e.tryMeshRecovery(context.Background()) {
		t.Fatal("tryMeshRecovery must not fire when the recovered directory names the same coordinators")
	}
	select {
	case <-e.NeedsRecovery():
		t.Fatal("NeedsRecovery must not fire when recovery found no new coordinator")
	default:
	}
}

// TestPoolConnectAllSilentReturnsSentinel is gap 2's first half: the pooled connect
// path must surface ErrNoCoordinatorReachable when every coordinator is silent —
// today it returns only a generic empty-list error, so recovery can't key on it. A
// real black-hole coordinator drives the actual ListCountries -> poolCountries -> selectPath
// -> connectPooled chain over loopback UDP.
func TestPoolConnectAllSilentReturnsSentinel(t *testing.T) {
	silent := fakeConnectCoordinator(t, func(string) (wire, bool) { return wire{}, false }) // never answers

	e, err := New(Config{
		Coordinators:  []string{silent},
		Roles:         []string{RoleClient},
		SocksAddr:     "127.0.0.1:0",
		TransportPool: []string{"webrtc"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.listTimeout = 300 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer e.Stop()

	if err := e.connectPooled(ctx); !errors.Is(err, ErrNoCoordinatorReachable) {
		t.Fatalf("pooled all-silent connect must return ErrNoCoordinatorReachable, got %v", err)
	}
}

// TestPoolMidSessionAllSilentTriggersMeshWalk is gap 2's second half: a pooled client
// connects, then every coordinator goes silent. maintainPath's reselection comes back
// all-silent, so it must escalate to a mesh-walk against a known peer courier and
// signal recovery — instead of merely giving up as the pooled failover does today.
func TestPoolMidSessionAllSilentTriggersMeshWalk(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	cache := coldstart.NewSnapshotCache()
	cache.Store(signedCoordSnapshot(t, priv, "203.0.113.9:3478")) // fresh, live coordinator
	peer := startCoreCourier(t, pub, cache)

	e := newPoolEngine(t, []CountryInfo{{Country: "RU", Exits: 1, Available: 1}})
	e.poolParallel = 1
	e.reselectBackoff = 10 * time.Millisecond // don't wait out the default 2s between reselect tries
	e.meshPeers = []string{peer}
	e.meshProof = signedCoordSnapshot(t, priv, "203.0.113.1:3478")
	e.meshPubKey = pub
	e.relayTimeout = 700 * time.Millisecond
	defer e.Stop()

	var silent atomic.Bool
	e.countriesFn = func(context.Context) ([]CountryInfo, error) {
		if silent.Load() {
			return nil, ErrNoCoordinatorReachable // coordinators gone
		}
		return []CountryInfo{{Country: "RU", Exits: 1, Available: 1}}, nil
	}
	e.dialFn = func(context.Context, selection.Candidate) (dialedPath, error) {
		return dialedPath{sess: newFakeSession(), exitID: testExitID, exitPub: testExitPub, rtt: 15 * time.Millisecond}, nil
	}

	if err := e.connectPooled(context.Background()); err != nil {
		t.Fatalf("connectPooled: %v", err)
	}
	first, _ := e.activePath()
	if first == nil {
		t.Fatal("no active pooled session after connect")
	}

	// Coordinators go dark, then the active path drops: reselection finds everything
	// silent and must escalate to mesh-walk.
	silent.Store(true)
	first.Close()

	select {
	case <-e.NeedsRecovery():
	case <-time.After(5 * time.Second):
		t.Fatal("pooled mid-session all-silent did not trigger mesh-walk recovery (issue #115)")
	}
	coords, _ := e.RecoveredDirectory()
	if len(coords) != 1 || coords[0] != "203.0.113.9:3478" {
		t.Fatalf("pooled recovery must adopt the courier's fresh coordinator, got %v", coords)
	}
}
