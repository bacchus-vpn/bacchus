package core

import (
	"crypto/rand"
	"io"
	"time"
)

// Sustained-flow validation (issue #15, trap #1): "connected" is not "working".
// A Russian soft-block lets a transport complete its handshake and then wedges
// the flow at roughly 16 KB / ~25 packets (the "destination-freeze"), so a path
// that merely dialed is not yet a path the user's traffic should ride. The pool
// commits to a candidate only after it round-trips real bytes past that
// threshold — and the round-trip it measures doubles as the exit's ping, which
// ranks exits within a geo (core/selection).
//
// The probe reuses the accounting-sentinel trick (core/accounting.go): the
// client opens an ordinary end-to-end stream whose target is a reserved
// never-real host, and the exit branches on it *after* the identical Noise_NK
// handshake to echo instead of dial. So it needs no change to core/e2e.go, rides
// inside the same encryption as real traffic (indistinguishable on the wire),
// and is reachable only by a peer that already completed transport setup and
// authenticated the exit — the same admission/anti-probe gates (#42/#60/#62) as
// any real connection, adding no new external surface.
const (
	// probeSentinel is the reserved .invalid target (RFC 2606) that turns a
	// stream into an echo probe. Like acctSentinel it passes validTarget's
	// host:port shape check unchanged.
	probeSentinel = "bacchus-probe.invalid:0"

	// probeBytes is how much the client round-trips to prove sustained flow —
	// deliberately past the ~16 KB freeze threshold, so echoing all of it back
	// proves the path survives the freeze, not merely the handshake.
	probeBytes = 32 * 1024

	// maxProbeEcho caps how much an exit will echo for one probe, so the echo
	// path can never be driven to unbounded work. Echoing is 1:1 (no
	// amplification) and gated behind a full Noise_NK, but a ceiling is cheap.
	maxProbeEcho = 1 << 20
)

// handleProbeStream is the exit side of a validation probe: echo whatever the
// client sends, bounded by maxProbeEcho, then stop. It dials nothing and learns
// no destination — the sentinel target never leaves the exit. It ends when the
// client closes its side (the normal case, once the client has its bytes back)
// or the cap is reached.
//
// Metered and paced like any other forwarded stream (issue #143), because the
// operator's ISP does not care that these bytes are a probe: they arrive and they
// leave, and the bill is the same. maxProbeEcho bounds one stream, but nothing
// bounds streams per session (see exitTerminate's AcceptStream loop), so an
// unmetered echo is an unbounded, uncounted, unpaced draw on a volunteer's uplink
// for anyone who can complete a handshake — and admission is opt-in and fail-open
// without an anchor, so that is anyone at all. This is the same defect the UDP
// relay had: an early return in exitTerminate that skipped the meter the branch
// below it applies.
func (e *Engine) handleProbeStream(nc *noiseConn) {
	defer nc.Close()
	_, _ = io.Copy(nc, e.meter(io.LimitReader(nc, maxProbeEcho)))
}

// runProbe pushes probeBytes through an already-handshaked end-to-end channel
// and reads them back, returning the round-trip time once the full echo returns.
// A path that returns every byte has sustained flow past the freeze threshold;
// one that wedges mid-stream never completes the read. It has no internal
// deadline: the caller bounds it by closing the underlying stream on timeout,
// which unblocks the read with an error (the pool always races under a context).
//
// Write runs concurrently with the read so the ~32 KB in flight can't deadlock
// on transport flow control — the read drains the exit's echo while the write is
// still pushing.
func runProbe(nc *noiseConn) (time.Duration, error) {
	payload := make([]byte, probeBytes)
	if _, err := rand.Read(payload); err != nil {
		return 0, err
	}
	start := time.Now()
	werr := make(chan error, 1)
	go func() {
		_, err := nc.Write(payload)
		werr <- err
	}()
	if _, err := io.ReadFull(nc, make([]byte, probeBytes)); err != nil {
		return 0, err
	}
	if err := <-werr; err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
