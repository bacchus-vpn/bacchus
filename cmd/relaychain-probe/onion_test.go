package main

import (
	"net"
	"testing"
	"time"
)

// TestOnionPeelsOneLayerPerHop is the probe's core assertion as a test: for chains of
// 1..5 relays the telescoped onion builds, every hop peels exactly one layer (each
// relay learns only its next hop, the exit learns the destination and verifies the
// admission credential), and no build deadlocks. run() itself checks the peel
// property and returns an error if it does not hold, so a nil return is the proof.
func TestOnionPeelsOneLayerPerHop(t *testing.T) {
	for hops := 1; hops <= 5; hops++ {
		if err := run(hops); err != nil {
			t.Fatalf("%d-relay chain: %v", hops, err)
		}
	}
}

// TestWrongHopKeyFails proves a substituted or hostile hop is rejected: a client that
// authenticates a hop against the wrong static key (as a hostile coordinator naming a
// key it does not control would force) cannot complete the Noise_NK handshake, so the
// chain build aborts rather than routing through an unauthenticated relay (design
// §4.3, principle #5).
func TestWrongHopKeyFails(t *testing.T) {
	real, err := genKey()
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := genKey()
	if err != nil {
		t.Fatal(err)
	}

	c1, c2 := net.Pipe()
	// The responder holds `real`; a well-behaved responder still answers, but the
	// initiator authenticates against `wrong`, so the NK key agreement diverges.
	go func() { _, _ = acceptResponder(c2, real, []byte("cred")); _ = c2.Close() }()

	done := make(chan error, 1)
	go func() {
		_, err := dialInitiator(c1, wrong.Public, nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("handshake against the wrong hop key succeeded; a substituted hop must be rejected")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handshake against the wrong key neither completed nor failed (hang)")
	}
}

// TestCredentialSurvivesChain pins the old #60/#69 property the design leans on: the
// innermost admission credential the exit presents must reach the client unchanged
// through every relay layer. run() verifies the credential inside the client and
// fails if it did not, so this exercises the longest chain the probe supports.
func TestCredentialSurvivesChain(t *testing.T) {
	if err := run(8); err != nil {
		t.Fatalf("8-relay chain did not preserve the end-to-end credential: %v", err)
	}
}
