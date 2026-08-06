package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
	"github.com/flynn/noise"
)

// acctSentinel is the reserved, never-real-DNS target (RFC 2606's .invalid)
// the client sends instead of a host:port to open an accounting round trip
// instead of a proxied connection. It passes validTarget's syntax check
// unchanged (SplitHostPort only needs a host:port shape), so it needs no
// changes to core/e2e.go: the exit runs the exact same exitHandshake as every
// other stream and only branches on the target string afterwards, in
// exitTerminate.
const acctSentinel = "bacchus-accounting.invalid:0"

// acctLabel tags the transport-level stream the accounting round trip runs
// over. The label is inert today (relayPipe and the exit's stream dispatch
// don't branch on it -- see forwarder.go), but it keeps the intent visible in
// logs and traces rather than looking like just another e2e stream.
const acctLabel = "acct"

// defaultAcctIntervalSec is used when accounting is enabled (Config.AcctDir
// set) but Config.AcctIntervalSec is left at its zero value.
const defaultAcctIntervalSec = 60

// satBlockThreshold is how long a single tunnel write must block before the client
// counts the interval demand-saturated (accounting.Counter.WatchSaturation, issue #158).
// A write to a healthy tunnel returns promptly; one that stalls this long means the
// tunnel's send window is full while the application still has bytes to send — the
// client wanted to move more than the link carried (design §5.3). 250ms is generous
// enough that ordinary scheduling jitter does not trip it and small enough that
// sustained backpressure does. A starting value — the saturation bit is a heuristic
// (design §8.2) — tunable once there is real data.
const satBlockThreshold = 250 * time.Millisecond

// acctEnabled reports whether this engine should count bytes and run the
// accounting exchange at all. Empty AcctDir is the off switch: existing
// callers/tests that never set it get exactly today's behavior, no extra
// goroutines, streams, or files.
func (e *Engine) acctEnabled() bool { return e.cfg.AcctDir != "" }

// setupAccounting prepares the exit's stable accounting identity and the
// on-disk receipt stores, if configured. It is called once from New, at
// construction time, so a bad AcctDir (e.g. unwritable) is a construction
// error like any other bad Config field, not a surprise deep into Start.
//
// Only the exit role derives a signing key: it is the metered/paid party a
// receipt is attributed to across sessions, so its accounting identity needs
// to be stable (see accounting.AcctKeyFromSeed). The client role opens its own
// store for its copy of each receipt but has no persistent accounting
// identity -- see runClientAccounting, which mints a fresh keypair per
// session.
func setupAccounting(cfg Config, roles map[string]bool, exitKey noise.DHKey) (acctKey ed25519.PrivateKey, exitStore, clientStore *accounting.Store, err error) {
	if cfg.AcctDir == "" {
		return nil, nil, nil, nil
	}
	if roles[RoleExit] {
		k, err := accounting.AcctKeyFromSeed(exitKey.Private)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("core: accounting key: %w", err)
		}
		s, err := accounting.OpenStore(filepath.Join(cfg.AcctDir, "receipts-exit.jsonl"))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("core: accounting store: %w", err)
		}
		acctKey, exitStore = k, s
	}
	if roles[RoleClient] {
		s, err := accounting.OpenStore(filepath.Join(cfg.AcctDir, "receipts-client.jsonl"))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("core: accounting store: %w", err)
		}
		clientStore = s
	}
	return acctKey, exitStore, clientStore, nil
}

// acctCounter returns the byte counter for sid, creating it on first use.
// Shared by both roles: an exit's exitTerminate feeds it from the streams it
// terminates for sid, a client's handleSocks feeds it from the streams it
// opens for its own sid -- the two never collide because a given running
// Engine only ever originates or terminates any one given sid, never both.
func (e *Engine) acctCounter(sid string) *accounting.Counter {
	e.acctMu.Lock()
	defer e.acctMu.Unlock()
	c, ok := e.acctCounters[sid]
	if !ok {
		c = &accounting.Counter{}
		e.acctCounters[sid] = c
	}
	return c
}

// dropAcctState removes sid's counter and sequence number. Called from the
// same per-session cleanup goroutine that already drops e.sessions[sid].
func (e *Engine) dropAcctState(sid string) {
	e.acctMu.Lock()
	defer e.acctMu.Unlock()
	delete(e.acctCounters, sid)
	delete(e.acctSeq, sid)
}

// startAccounting begins the client-side accounting loop for sid over sess,
// if accounting is configured. It returns the counter the SOCKS server's stream
// copies should feed -- nil when accounting is disabled, which is safe to
// pass straight through (Counter's methods are nil-safe).
//
// Direct-mode sessions only for this stub: a relay-forwarded connection
// reaches the exit as a bare spliced TCP stream with no session id attached
// (see forwarder.go's relayPipe/serveExit), so the exit has nothing to key a
// counter by. Extending relay-mode accounting needs a correlation id on the
// relay<->exit wire, which is a real follow-up, not a same-PR fix -- see
// ADR-0021.
// l is the coordinator link that paired this session; the client sends its
// capacity-reports (issue #158) back over it. It may be nil (e.g. a reconnect that
// re-establishes without a fresh pairing) — reports are then simply not sent, which is a
// missed measurement, not a fault.
func (e *Engine) startAccounting(sid string, sess Session, l *coordLink, exitPub []byte) *accounting.Counter {
	if e.acctClientStore == nil {
		return nil
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		e.emit(EventError, sid, "accounting: generate client key: %v", err)
		return nil
	}
	ctr := e.acctCounter(sid)
	interval := e.cfg.AcctIntervalSec
	if interval <= 0 {
		interval = defaultAcctIntervalSec
	}
	e.wg.Add(1)
	go e.runClientAccounting(sid, sess, key, ctr, time.Duration(interval)*time.Second, l, exitPub)
	return ctr
}

// runClientAccounting periodically opens a fresh accounting stream to the
// exit and cosigns a receipt for the bytes ctr counted since the last tick.
// One goroutine per Connect() call; it exits when the session closes or the
// engine stops.
func (e *Engine) runClientAccounting(sid string, sess Session, key ed25519.PrivateKey, ctr *accounting.Counter, interval time.Duration, l *coordLink, exitPub []byte) {
	defer e.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-sess.Closed():
			return
		case <-t.C:
		}

		delta := ctr.Delta()
		if delta == 0 {
			continue // nothing served this interval -- no point in a round trip
		}
		st, err := sess.OpenStream(context.Background(), acctLabel)
		if err != nil {
			e.emit(EventError, sid, "accounting: open stream: %v", err)
			continue
		}
		// The accounting stream is a fresh Noise_NK handshake to the same exit, so
		// it verifies the exit's admission credential (issue #60) exactly as a
		// data stream does — a rejected exit yields no receipt round trip.
		nc, err := clientHandshake(st, exitPub, acctSentinel, e.exitVerifyFunc(exitPub))
		if err != nil {
			_ = st.Close()
			e.emit(EventError, sid, "accounting: handshake: %v", err)
			continue
		}
		r, err := accounting.ClientCosign(nc, key, delta)
		_ = nc.Close()
		if err != nil {
			e.emit(EventError, sid, "accounting: %v", err)
			continue
		}
		if err := e.acctClientStore.Append(r); err != nil {
			e.emit(EventError, sid, "accounting: persist receipt: %v", err)
		}
		e.sendCapacityReport(r, key, ctr, l)
	}
}

// sendCapacityReport turns one co-signed receipt into a capacity-report to the
// coordinator (issue #158). It stamps the receipt with this interval's client-asserted
// saturation bit — read-and-cleared from ctr, so it partitions into the same interval as
// the byte count — signs the receipt+bit with the client accounting key (accounting.
// SignReport, so a node cannot forge or flip the bit), and sends it back over the
// coordinator link that paired the session.
//
// Best-effort, and deliberately so: it rides the same best-effort UDP the rest of
// coordinator signaling does, a lost report is just a missed sample, and a nil link (a
// session with no live pairing) simply sends nothing. Saturated is NOT part of the
// co-signed receipt canonical (core/accounting), so stamping it here does not disturb
// the co-signature already verified above.
func (e *Engine) sendCapacityReport(r accounting.Receipt, key ed25519.PrivateKey, ctr *accounting.Counter, l *coordLink) {
	if l == nil {
		return
	}
	r.Saturated = ctr.TakeSaturated()
	l.send(e, wire{
		Type:      "capacity-report",
		Receipt:   &r,
		ReportSig: accounting.SignReport(key, r),
		Cred:      e.admissionCred(),
	})
}

// handleAcctStream runs the exit side of one accounting interval once a
// client has opened a stream carrying acctSentinel (recognized by
// exitTerminate). It reports the delta ctr has counted for sid since the last
// interval, cosigns with the client, and persists the result.
//
// sid is empty for relay-forwarded connections (see startAccounting's doc) --
// those are silently skipped, matching how the exit already does not track
// them as sessions at all today.
func (e *Engine) handleAcctStream(sid string, nc *noiseConn) {
	defer nc.Close()
	if sid == "" || e.acctKey == nil {
		return
	}
	ctr := e.acctCounter(sid)
	delta := ctr.Delta()

	e.acctMu.Lock()
	seq := e.acctSeq[sid]
	e.acctSeq[sid] = seq + 1
	e.acctMu.Unlock()

	intervalSec := e.cfg.AcctIntervalSec
	if intervalSec <= 0 {
		intervalSec = defaultAcctIntervalSec
	}
	r, err := accounting.ExitPropose(nc, e.acctKey, e.cfg.ID, sid, seq, uint32(intervalSec), delta)
	if err != nil {
		e.emit(EventError, sid, "accounting: interval %d: %v", seq, err)
		return
	}
	if err := e.acctStore.Append(r); err != nil {
		e.emit(EventError, sid, "accounting: persist receipt: %v", err)
	}
}
