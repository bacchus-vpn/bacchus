package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/capacity"
)

// The exit half of tier-limit enforcement (issue #58, ADR-0048): the coordinator
// resolves the connecting account's (trust, plan) pair against the signed policy and
// stamps the resulting speed cap on the assignment; this node turns that number into
// a per-session limiter and shapes its egress to it.

// TestSessionPaceIsBuiltOnlyWhenTheAssignmentCarriesACap covers the branch-free
// contract the wire field's doc promises: no cap means no limiter, and a nil
// *Limiter is inert everywhere downstream, so neither handlerFor nor exitTerminate
// needs a special case for an unpoliced coordinator.
func TestSessionPaceIsBuiltOnlyWhenTheAssignmentCarriesACap(t *testing.T) {
	if pace := sessionPace(wire{Type: "assign", Session: "s1"}); pace != nil {
		t.Error("an assignment with no cap produced a limiter — an unpoliced coordinator would shape every session")
	}
	if pace := sessionPace(wire{Type: "assign", Session: "s1", SessionCapBps: 50_000_000}); pace == nil {
		t.Fatal("an assignment carrying a 50 Mbit cap produced NO limiter — the tier's speed cap is not enforced at all")
	}
	// Nil-inert, which is what lets exitTerminate wrap unconditionally.
	var nilPace *capacity.Limiter
	r := io.Reader(bytes.NewReader([]byte("x")))
	if got := nilPace.LimitReads(context.Background(), r); got != r {
		t.Error("a nil limiter did not pass the reader through unchanged")
	}
}

// TestSessionCapShapesTheExitEgress is the tier's speed cap actually DENYING
// throughput, which is the bar issue #58 sets: a tier system whose tests have never
// been seen to deny anything is not testing enforcement.
//
// It drives the real exit egress — Noise handshake, TCP dial, both copy directions —
// and measures. The bucket starts full at burstBytes, so the assertion is on the
// bytes BEYOND the burst: at 512 kbit/s (64 KB/s) a 64 KB overshoot cannot cross in
// under a second however fast the machine is, because a token bucket's rate is not a
// property of the hardware.
//
// MUTATION: drop the pace.LimitReads wrap from exitTerminate's copies and this goes
// red — the transfer completes immediately.
func TestSessionCapShapesTheExitEgress(t *testing.T) {
	const capBps = 512_000     // 64 KB/s
	const payload = 128 * 1024 // two bursts' worth
	const wantAtLeast = 900 * time.Millisecond

	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	// The "internet" this exit egresses to: it writes payload bytes and closes, so
	// the shaped direction is the one a user experiences as download speed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write(make([]byte, payload))
	}()

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	e := &Engine{roles: map[string]bool{RoleExit: true}, exitKey: key, limiterCtx: context.Background()}
	pace := sessionPace(wire{Type: "assign", Session: "s1", SessionCapBps: capBps})
	if pace == nil {
		t.Fatal("no limiter built for a capped assignment")
	}
	go e.exitTerminate("s1", pace, sConn)

	nc, err := clientHandshake(cConn, key.Public, ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	defer nc.Close()

	start := time.Now()
	n, _ := io.ReadFull(nc, make([]byte, payload))
	elapsed := time.Since(start)

	if n < payload {
		t.Fatalf("read %d of %d bytes; the shaped copy did not deliver the payload", n, payload)
	}
	if elapsed < wantAtLeast {
		t.Errorf("%d bytes crossed a %d bps session cap in %s; want at least %s — the tier's speed cap is NOT being applied",
			payload, capBps, elapsed.Truncate(time.Millisecond), wantAtLeast)
	}
}

// TestUncappedSessionIsNotShaped is the control for the test above, and the
// regression guard for everyone this change must not touch: with no cap on the
// assignment the same transfer runs at memory speed. Without it, the timing
// assertion above could be satisfied by any accidental stall and would keep passing
// while proving nothing about the cap.
func TestUncappedSessionIsNotShaped(t *testing.T) {
	const payload = 128 * 1024

	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write(make([]byte, payload))
	}()

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	e := &Engine{roles: map[string]bool{RoleExit: true}, exitKey: key, limiterCtx: context.Background()}
	go e.exitTerminate("s1", sessionPace(wire{Type: "assign", Session: "s1"}), sConn)

	nc, err := clientHandshake(cConn, key.Public, ln.Addr().String(), nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	defer nc.Close()

	start := time.Now()
	if _, err := io.ReadFull(nc, make([]byte, payload)); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("an UNCAPPED session took %s to move %d bytes — an unpoliced coordinator's sessions are being shaped", elapsed, payload)
	}
}

// TestSessionCapWireContract is the core-side half of the pair that stops this
// binary's wire and cmd/coordinator's copy drifting apart. cmd/coordinator's mirror
// is TestSessionCapWireContract there; between them a rename on either side fails a
// build somewhere.
func TestSessionCapWireContract(t *testing.T) {
	b, err := json.Marshal(wire{Type: "assign", Session: "s1", SessionCapBps: 200_000_000})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back wire
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.SessionCapBps != 200_000_000 {
		t.Fatalf("the assignment's cap did not round-trip on the wire: %s", b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["sessionCapBps"]; !ok {
		t.Fatalf("the cap is not on the wire under the agreed key: %s", b)
	}
}
