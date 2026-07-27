package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// fakeCoordinator stands up a real coldstart bootstrap listener on loopback that
// authenticates one secret and serves signedSnap. It returns the address to dial —
// so a courier can fetch from it exactly as it would from a live coordinator.
func fakeCoordinator(t *testing.T, secretID string, secret, signedSnap []byte) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake coordinator: %v", err)
	}
	store := coldstart.NewMemStore()
	store.Add(secretID, secret)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = coldstart.Serve(ctx, pc, store, func() []byte { return signedSnap }); close(done) }()
	t.Cleanup(func() {
		cancel()
		_ = pc.Close()
		<-done
	})
	return pc.LocalAddr().String()
}

func signedTestSnapshot(t *testing.T, priv ed25519.PrivateKey, coordAddr string) []byte {
	t.Helper()
	signed, err := coldstart.Sign(priv, coldstart.Snapshot{
		Version:   coldstart.SnapshotVersion,
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		Entries: []coldstart.Entry{
			{Role: "coordinator", ID: "coord", Addr: coordAddr},
			{Role: "relay", ID: "relay-1", Addr: "203.0.113.7:20000"},
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return signed
}

// TestStartCourierServesFetchedSnapshot drives the courier binary glue end to end:
// startCourier fetches a signed snapshot from a (fake but real) coordinator via an
// invite, caches it, and serves it; a recovering client then fetches it back from
// the courier with a proof of prior contact. This exercises the actual node-side
// wiring — DecodeInvite -> Bootstrap -> SnapshotCache -> ServeCourier — not just the
// coldstart primitives it composes.
func TestStartCourierServesFetchedSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)

	secretID, secret, err := coldstart.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	// The coordinator serves a snapshot naming a (would-be) live coordinator.
	fresh := signedTestSnapshot(t, priv, "203.0.113.9:3478")
	coordAddr := fakeCoordinator(t, secretID, secret, fresh)

	invite, err := coldstart.EncodeInvite(coldstart.Invite{
		Coordinator: coordAddr,
		SecretID:    secretID,
		Secret:      secret,
		PublicKey:   pub,
	})
	if err != nil {
		t.Fatalf("EncodeInvite: %v", err)
	}

	// Bind the courier on a free loopback port.
	lp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve courier port: %v", err)
	}
	courierAddr := lp.LocalAddr().String()
	_ = lp.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := startCourier(ctx, courierAddr, invite); err != nil {
		t.Fatalf("startCourier: %v", err)
	}

	// A recovering client presents a (stale) prior snapshot as proof and fetches the
	// courier's cached fresh one.
	proof := signedTestSnapshot(t, priv, "203.0.113.1:3478")
	var res *coldstart.Result
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) { // allow the initial async fetch to land
		fctx, fcancel := context.WithTimeout(ctx, time.Second)
		res, err = coldstart.FetchSnapshot(fctx, courierAddr, proof, pub)
		fcancel()
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("FetchSnapshot from courier: %v", err)
	}
	if got := res.Snapshot.AddrsForRole("coordinator"); len(got) != 1 || got[0] != "203.0.113.9:3478" {
		t.Fatalf("courier must serve the coordinator's fresh snapshot, got %v", got)
	}
}

func TestLoadMeshRecovery(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)

	dir := t.TempDir()
	proofPath := filepath.Join(dir, "snap.bin")
	if err := os.WriteFile(proofPath, []byte("signed-snapshot-bytes"), 0o600); err != nil {
		t.Fatalf("write proof: %v", err)
	}

	// No peers -> recovery disabled (nil, no error).
	if m, err := loadMeshRecovery("", "", ""); m != nil || err != nil {
		t.Fatalf("no peers must disable recovery, got (%v, %v)", m, err)
	}
	// Peers but missing proof/key -> error.
	if _, err := loadMeshRecovery("127.0.0.1:3479", "", pubHex); err == nil {
		t.Fatal("peers without a proof path must error")
	}
	if _, err := loadMeshRecovery("127.0.0.1:3479", proofPath, ""); err == nil {
		t.Fatal("peers without a pubkey must error")
	}
	// Bad pubkey -> error.
	if _, err := loadMeshRecovery("127.0.0.1:3479", proofPath, "not-hex"); err == nil {
		t.Fatal("a malformed pubkey must error")
	}
	// Fully configured -> populated struct.
	m, err := loadMeshRecovery("127.0.0.1:3479, 127.0.0.1:3480", proofPath, pubHex)
	if err != nil {
		t.Fatalf("valid recovery config: %v", err)
	}
	if len(m.peers) != 2 || len(m.proof) == 0 || len(m.pubkey) != ed25519.PublicKeySize {
		t.Fatalf("recovery config not populated: %+v", m)
	}
}
