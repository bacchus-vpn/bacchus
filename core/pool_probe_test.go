package core

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/capacity"
)

// TestProbeEchoIsMetered is the regression test for the second silent exception in
// exitTerminate's early returns. The first was the UDP relay
// (TestUDPRelayIsMetered); this is the same defect in the branch beside it, and it
// survived the audit that fixed the first one.
//
// The echo dials nothing and terminates here, which is exactly why it read as
// harmless — but the operator's ISP does not care that these bytes are a probe.
// They arrive and they leave, and the bill is identical. maxProbeEcho bounds ONE
// stream at 1 MB; nothing bounds streams per session (see exitTerminate's
// AcceptStream loop), so unmetered it is an unbounded, uncounted, unpaced draw on a
// volunteer's uplink available to anyone who can complete a handshake — and
// admission is opt-in and fail-open without an anchor, so that is anyone.
//
// Metering and pacing arrive together in e.meter, so counting proves both.
func TestProbeEchoIsMetered(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	// A quota far smaller than one probe (probeBytes = 32 KB), so an unmetered echo
	// sails through it and a metered one cannot.
	const quota = 4000
	q, err := capacity.NewQuota(capacity.Limits{MonthlyQuota: quota, CycleDay: 17}, "", time.Now())
	if err != nil {
		t.Fatalf("NewQuota: %v", err)
	}
	e := &Engine{exitKey: key, quota: q, limiterCtx: context.Background()}
	go e.exitTerminate("", sConn)

	nc, err := clientHandshake(cConn, key.Public, probeSentinel, nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	defer nc.Close()

	// Expected to fail: the quota cuts the echo off mid-flow. That is the point.
	_, _ = runProbe(nc)

	if used := q.Used(time.Now()); used == 0 {
		t.Fatal("the probe echo round-tripped bytes and the quota counted NONE: the echo path spends the operator's uplink uncounted and unpaced, for anyone who can handshake")
	}
	if !q.Exhausted(time.Now()) {
		t.Errorf("a %d-byte probe against a %d-byte quota left it unexhausted (used %d): the echo is counted but not enforced", probeBytes, quota, q.Used(time.Now()))
	}
}

// TestProbeRoundTrip exercises the real sustained-flow validation path end to
// end: the client pushes probeBytes over the Noise channel to the exit's echo
// responder and reads every byte back — exactly what validateSession does to
// prove a path clears the freeze threshold before the pool commits to it. It
// runs over a byte pipe with no transport underneath, isolating the probe, the
// echo, and the e2e framing (which must re-delimit ~32 KB across many frames).
func TestProbeRoundTrip(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	// Exit side: run the identical handshake, confirm the reserved sentinel, echo.
	errc := make(chan error, 1)
	go func() {
		nc, target, err := exitHandshake(sConn, key, nil)
		if err != nil {
			errc <- err
			return
		}
		if target != probeSentinel {
			errc <- fmt.Errorf("exit saw target %q, want the probe sentinel", target)
			return
		}
		(&Engine{}).handleProbeStream(nc) // echoes until the client closes
		errc <- nil
	}()

	nc, err := clientHandshake(cConn, key.Public, probeSentinel, nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	rtt, err := runProbe(nc)
	if err != nil {
		t.Fatalf("runProbe (a working path must round-trip the full payload): %v", err)
	}
	// rtt can legitimately measure 0 on a fast in-process pipe (below the clock's
	// resolution) — the meaningful signal is that the whole payload round-tripped
	// without error; just sanity-check the measurement is not negative.
	if rtt < 0 {
		t.Fatalf("probe rtt = %v, want a non-negative measurement", rtt)
	}
	_ = nc.Close() // ends the exit's echo loop
	if err := <-errc; err != nil {
		t.Fatalf("exit side: %v", err)
	}
}

// TestProbeFailsOnTruncatedFlow shows the other half of trap #1: a path that
// stops carrying bytes partway (the freeze) never completes the probe, so it is
// never mistaken for working. Closing the exit's side after the handshake models
// a flow that dies before the payload returns.
func TestProbeFailsOnTruncatedFlow(t *testing.T) {
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	go func() {
		if _, _, err := exitHandshake(sConn, key, nil); err != nil {
			return
		}
		_ = sConn.Close() // freeze: complete the handshake, then carry nothing
	}()

	nc, err := clientHandshake(cConn, key.Public, probeSentinel, nil)
	if err != nil {
		// A handshake failure here is also an acceptable "not working" signal.
		return
	}
	if _, err := runProbe(nc); err == nil {
		t.Fatal("a frozen path must fail the probe, not validate")
	}
}
