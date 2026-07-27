package core

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"
)

// clientEphemeral stands in for the X25519 key share uTLS puts in the ClientHello.
func clientEphemeral(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client ephemeral: %v", err)
	}
	return k
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// TestRealitySealOpenRoundTrip proves the two sides agree: a session id sealed with
// the client-side secret opens with the exit-side secret derived from the same
// ECDH, and the sealed timestamp survives.
func TestRealitySealOpenRoundTrip(t *testing.T) {
	kp, err := newRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	eph := clientEphemeral(t)
	random := randomBytes(t, 32)
	now := time.Now().Truncate(time.Second)

	clientSecret, err := realityClientSecret(eph, kp.pub)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := realitySealSessionID(clientSecret, random, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(sid) != realitySessionIDLen {
		t.Fatalf("sealed session id length = %d, want %d", len(sid), realitySessionIDLen)
	}

	serverSecret, err := kp.secretFrom(eph.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	ts, err := realityOpenSessionID(serverSecret, random, sid)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !ts.Equal(now) {
		t.Fatalf("opened timestamp = %v, want %v", ts, now)
	}
}

// TestRealityOpenRejectsStrangers proves the fork signal: neither a random 32-byte
// session id (a real browser / prober) nor a seal made against a different exit key
// opens against our key.
func TestRealityOpenRejectsStrangers(t *testing.T) {
	kp, err := newRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	eph := clientEphemeral(t)
	random := randomBytes(t, 32)
	serverSecret, err := kp.secretFrom(eph.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	// A real browser's random legacy_session_id.
	if _, err := realityOpenSessionID(serverSecret, random, randomBytes(t, 32)); err != errRealityAuthFailed {
		t.Fatalf("random session id: err = %v, want errRealityAuthFailed", err)
	}

	// A seal made for a *different* exit key must not open against ours.
	other, err := newRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherSecret, err := realityClientSecret(eph, other.pub)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := realitySealSessionID(otherSecret, random, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := realityOpenSessionID(serverSecret, random, sid); err != errRealityAuthFailed {
		t.Fatalf("cross-key seal: err = %v, want errRealityAuthFailed", err)
	}
}

// TestRealityOpenBindsToRandom proves the seal cannot be lifted onto another
// ClientHello: opening a valid session id against a different random fails.
func TestRealityOpenBindsToRandom(t *testing.T) {
	kp, err := newRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	eph := clientEphemeral(t)
	random := randomBytes(t, 32)
	clientSecret, err := realityClientSecret(eph, kp.pub)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := realitySealSessionID(clientSecret, random, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	serverSecret, err := kp.secretFrom(eph.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), random...)
	tampered[0] ^= 0x01
	if _, err := realityOpenSessionID(serverSecret, tampered, sid); err != errRealityAuthFailed {
		t.Fatalf("session id opened against a different random; want errRealityAuthFailed, got %v", err)
	}
}

func TestRealityReplayGuard(t *testing.T) {
	g := newRealityReplayGuard()
	now := time.Now()
	sid := randomBytes(t, 32)

	// Stale timestamp (older than the window) is refused even on first sight.
	if g.admit(sid, now.Add(-2*realityAuthWindow), now) {
		t.Fatal("stale timestamp admitted")
	}
	// A future timestamp beyond the window (excessive skew) is also refused.
	if g.admit(sid, now.Add(2*realityAuthWindow), now) {
		t.Fatal("future-skewed timestamp admitted")
	}
	// Fresh and unseen: admitted once.
	if !g.admit(sid, now, now) {
		t.Fatal("fresh session id not admitted")
	}
	// Verbatim replay within the window: refused.
	if g.admit(sid, now, now) {
		t.Fatal("replayed session id admitted")
	}
	// A different session id is independent.
	if !g.admit(randomBytes(t, 32), now, now) {
		t.Fatal("distinct session id not admitted")
	}
	// After a full window elapses the entry is evicted, so the same id is a fresh
	// sighting again (bounded memory, documented residual).
	later := now.Add(2 * realityAuthWindow)
	if !g.admit(sid, later, later) {
		t.Fatal("session id not re-admitted after eviction window")
	}
}
