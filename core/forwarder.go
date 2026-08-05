package core

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
	"github.com/bacchus-vpn/bacchus/core/capacity"
)

// startFwdSession accepts a forwarder-side (exit/relay) transport session for an
// assigned session id and forwards each inbound stream to its egress. The node
// is the responder; the client dials. l is the pool member that sent the
// assignment: the session's signaling is bound to it, so answers and candidates
// go back to the coordinator that paired us, not some other member.
func (e *Engine) startFwdSession(m wire, l *coordLink) {
	sid := m.Session
	e.sessMu.Lock()
	_, exists := e.sessions[sid]
	e.sessMu.Unlock()
	if exists {
		return
	}

	sig := e.newSignaler(sid, l)
	sess, err := e.transport.Accept(context.Background(), sig)
	if err != nil {
		e.dropSignaler(sid)
		e.emit(EventError, sid, "accept: %v", err)
		return
	}
	e.emit(EventSession, sid, "session %s assigned", sid)
	ts := e.trackSession(sid, sess, true)

	handle := e.handlerFor(m)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			st, err := sess.AcceptStream(context.Background())
			if err != nil {
				return
			}
			ts.touch() // a new stream is activity; its I/O keeps the session live (reapStream)
			go handle(e.reapStream(ts, st))
		}
	}()
}

// handlerFor picks the egress for an assigned session: peer relay when the
// assignment carries an exitAddr (issue #17 — this node splices client<->exit),
// direct exit egress otherwise. The "otherwise" covers both a mode:"direct"
// connect and a relay-mode TURN fallback (issue #97): the coordinator wires both
// as an assign with no exitAddr, so the exit cannot tell them apart — correctly,
// since both are genuinely direct exit<->client data planes. sid is threaded
// through for that direct case: a peer-relay-forwarded connection instead reaches
// the exit via serveExit's bare TCP listener with no session id (relayPipe never
// looks inside the stream), so there is nothing for exitTerminate to key
// accounting state by there — the relay-side accounting gap #17/ADR-0033 defers
// to a follow-up. See core/accounting.go.
//
// The tier's per-session speed cap (issue #58/#74, ADR-0048) is built here, once
// per assignment, for BOTH egresses: whichever party moves the bytes is the party
// that paces them. The exit shapes a direct session; the relay shapes a
// peer-relayed one, terminating nothing but forwarding every byte (issue #74's
// ruling — see relayPipe). sessionPace returns nil when the assignment carries no
// cap, and a nil *Limiter is inert, so "no cap" needs no branch anywhere
// downstream — which is what keeps the relay branch shapeless for a chained
// connect, where the coordinator deliberately sends none (ADR-0042 §9).
func (e *Engine) handlerFor(m wire) func(Stream) {
	if m.ExitAddr != "" {
		ea, pace := m.ExitAddr, sessionPace(m)
		return func(st Stream) { e.relayPipe(st, pace, ea) }
	}
	sid, pace := m.Session, sessionPace(m)
	return func(st Stream) { e.exitDirect(sid, pace, st) }
}

// sessionPace builds the per-session rate limiter for an assignment (issue #58,
// ADR-0048): the coordinator resolved the connecting account's (trust, plan) pair
// against the signed policy it verified and stamped the resulting speed_cap_bps
// on the assign, and this is where the exit turns that number into enforcement.
//
// The exit does NOT resolve the tier itself, and does not see the client's
// admission credential at all. That is a privacy decision, not a layering
// convenience: a credential's Serial is a stable per-device identifier that
// outlives any one session, and the exit is the single party that sees the user's
// actual traffic, so handing it a credential would hand it a join key for linking
// one user's sessions to each other — exactly the correlation ADR-0042 and
// ADR-0035 exist to deny. It receives a number instead, which links nothing.
//
// The cost is stated rather than hidden: a hostile coordinator can send a large
// cap, or none, and this node will honour it. That is a revenue-integrity
// failure, not a linkability one — and it is bounded from above by this node's
// OWN declared aggregate cap (ADR-0040), which e.limiter enforces locally and no
// coordinator can raise. See ADR-0048 §4.
//
// Returns nil — inert — for an assignment carrying no cap, which is every
// assignment from an unpoliced coordinator and every one predating #58.
func sessionPace(m wire) *capacity.Limiter {
	return capacity.NewLimiter(capacity.Rate(m.SessionCapBps))
}

// exitDirect is the exit-side egress for a direct (client<->exit) session: it
// terminates the end-to-end channel over the transport stream, shaped to the
// tier's per-session cap (nil pace = uncapped).
func (e *Engine) exitDirect(sid string, pace *capacity.Limiter, st Stream) {
	e.exitTerminate(sid, pace, st)
}

// exitTerminate runs the Noise responder over raw, reads the client's requested
// destination from the encrypted channel, dials it, and splices. It is the sole
// point where the exit learns the destination, and it is identical whether the
// client arrived directly or through a relay.
//
// A client requesting the reserved accounting sentinel (see acctSentinel)
// instead of a real target hands control to handleAcctStream instead of
// dialing anything — the same Noise_NK handshake, branching only on the
// preamble result, so core/e2e.go needs no changes for this. sid is empty for
// relay-forwarded connections (see handlerFor); handleAcctStream and the
// counting wrap below both no-op on an empty sid / disabled accounting.
//
// A target carrying udpTargetPrefix (issue #41) is a UDP relay request, not a
// TCP CONNECT — same overloaded-target-field trick as acctSentinel/
// probeSentinel, branching to exitTerminateUDP (core/udprelay.go) instead of
// dialing TCP.
//
// A target carrying hopTargetPrefix (issue #142, ADR-0038) is an onion forward:
// this node is an INTERMEDIATE hop in a client-assembled chain, so it splices to
// the next Bacchus node rather than egressing. That branch is what makes this
// function serve two roles — the exit's egress and a relay's onion ingress (see
// Start's RelayIngress listener) — and it is why the internet-egress paths below
// are now gated on actually holding the exit role. The distinction is carried by
// the client's encrypted target, so a hop is the same Noise_NK exchange as every
// other and needs no new message type and no coordinator involvement.
//
// pace is the tier's per-session speed cap (issue #58, ADR-0048), nil for
// uncapped. It travels with sid and is nil in exactly the same places sid is
// empty, because both name the coordinator-assigned session: a relay-forwarded
// connection arrives through serveExit's bare TCP listener, which the coordinator
// never assigned a session, so there is no tier to shape it to HERE. Such a
// session is shaped at the relay instead, which does hold the assign (relayPipe,
// issue #74) — deliberately leaving this exit knowing nothing about it. See
// ADR-0048 §5.
func (e *Engine) exitTerminate(sid string, pace *capacity.Limiter, raw io.ReadWriteCloser) {
	defer raw.Close()
	// The exit presents its admission credential (issue #60) in the handshake so
	// the client can verify end-to-end that this exit is admission-authorized.
	// Holding none presents none — unchanged behavior for an exit that has no
	// credential, against a client that doesn't require one. Read per handshake
	// (admissionCred), so a volunteering client that renewed mid-run presents the
	// credential it holds NOW rather than the one it started with (bacchus#166).
	nc, target, err := exitHandshake(raw, e.exitKey, []byte(e.admissionCred()))
	if err != nil {
		return
	}
	if target == acctSentinel {
		e.handleAcctStream(sid, nc)
		return
	}
	if target == probeSentinel {
		// Sustained-flow validation (issue #15): echo the client's bytes back so
		// it can confirm the path survives the freeze threshold before committing.
		// Like accounting, this branches after the identical handshake and dials
		// nothing. Reached both directly and via a relay splice (sid may be empty).
		e.handleProbeStream(nc)
		return
	}
	prefix, addr := splitTargetPrefix(target)
	if prefix == hopTargetPrefix {
		// An onion forward (issue #142, ADR-0038): splice to the next Bacchus node
		// instead of egressing. relayForward enforces that the next hop is a node in
		// the signed directory and that this node opted into forwarding at all — see
		// its doc for why neither check is optional.
		e.relayForward(nc, addr)
		return
	}
	// Everything below this line EGRESSES to the internet under this operator's
	// address, and only an exit may do that. The gate matters because this function
	// now also serves a relay-only node's onion ingress (see Start): without it, a
	// relay would dial any host:port a client named and the mesh's relay/exit safety
	// line — a relay forwards ciphertext and never egresses (ADR-0038 principle #4,
	// rendezvous-cold-start §5.3) — would hold only by the accident of relays not
	// having had a listener before. The sentinel branches above are deliberately
	// outside it: they dial nothing.
	if !e.roles[RoleExit] {
		e.emit(EventError, "", "onion: refusing to egress — this node is a relay, not an exit")
		return
	}
	if prefix == udpTargetPrefix {
		// Shaped to the same tier cap as the TCP path below (issue #74, ADR-0048 §5).
		// The UDP relay hand-rolls its own datagram loop rather than copying a stream,
		// so it applies pace per datagram through WaitN instead of wrapping an
		// io.Reader — same limiter, same composition inside the operator's own cap.
		e.exitTerminateUDP(sid, pace, nc, addr)
		return
	}
	// dialServed, not net.DialTimeout: this is the egress that the exit opt-in
	// promises leaves under this operator's own address, and on a machine that
	// routes itself through Bacchus it only does so if the socket says which
	// address it is (issue #109, ADR-0053). Unchanged on every node that is not
	// routing itself, which is all of cmd/node.
	remote, err := e.dialServed("tcp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()

	// Meter this session only when there is a session id to attribute bytes to and
	// the exit opted into accounting (ADR-0021, direct-mode-only). A sid-bearing
	// session is a direct-shaped assign — a mode:"direct" connect OR a relay-mode
	// TURN fallback (issue #97); the client treats a TURN fallback as the direct
	// disposition and cosigns exactly like a direct connect (core/client.go), so
	// this counter is used, not orphaned. A peer-relay splice arrives with sid==""
	// (see handlerFor) and stays unmetered — the one relayed case ADR-0021 still
	// cannot attribute. nil ctr is a no-op (Counter's methods are nil-safe).
	var ctr *accounting.Counter
	if sid != "" && e.acctEnabled() {
		ctr = e.acctCounter(sid)
	}
	// Three wrappers, three different questions, innermost first: the accounting
	// counter says what the session MOVED (a receipt's claim, ADR-0021), the
	// per-session limiter says what this user's TIER is entitled to (#58), and
	// e.meter says what this OPERATOR is willing to carry (#143, ADR-0040). The
	// tier cap sits inside the operator's, which is the composition ADR-0048 §4
	// depends on: a coordinator stamping a large SessionCapBps widens only the
	// inner bound, and the node's own aggregate limiter still paces the result.
	//
	// Order does not change any count — every limiter delays bytes rather than
	// dropping them — so this reads as three independent facts about the same
	// bytes, which is what it is.
	go func() {
		_, _ = io.Copy(remote, e.meter(pace.LimitReads(e.limiterCtx, ctr.CountReads(nc))))
		_ = remote.Close()
	}()
	_, _ = io.Copy(nc, e.meter(pace.LimitReads(e.limiterCtx, ctr.CountReads(remote))))
}

// meter applies this node's DECLARED limits (issue #143, ADR-0040) to one
// direction of one session's copy: the aggregate speed cap paces it, and the
// monthly quota counts it and cuts it off once the operator's cap is spent.
//
// Returns r unchanged when nothing is declared (both are nil-inert), which is
// every node in today's fleet.
//
// Wrapped AROUND the accounting counter at each call site — meter(ctr.CountReads(x))
// — so the two measure different things on purpose: accounting counts the bytes a
// session actually moved (what a receipt claims, ADR-0021), while this counts them
// against the operator's ISP bill and stops them. The nesting order does not change
// either count, since the limiter delays bytes rather than dropping them. The two
// will not agree, and should not: the quota charges both of a forwarded byte's link
// crossings (capacity.LinkCrossings), so it reads about twice the receipt.
//
// Both forwarder roles are metered, not just the exit. A relay spends its
// operator's uplink exactly as an exit does and their ISP meters it identically,
// so a residential relay volunteer needs this every bit as much — issue #143 is
// about the household, not about the role.
//
// What must be metered, stated as a rule with its exceptions ENUMERATED rather than
// as a universal that is quietly false. The rule: every byte this node moves in
// UNBOUNDED VOLUME on a user's behalf goes through here or meterN — exitTerminate's
// TCP forward, exitTerminateUDP (meterN), relayPipe, and handleProbeStream's echo,
// which is user-driven and unbounded per session even though it terminates here
// rather than being forwarded on.
//
// The exceptions we have found, because a rule whose carve-outs are written down can
// be checked and one that merely sounds true cannot. The list started at one and is now
// at four; each round of review found another, so read it as "the ones we know", not as
// a closed set:
//
//   - handleAcctStream — ADR-0021's receipt exchange: a few hundred bytes, bounded
//     by the accounting interval, attributable to no user. Same class as the
//     coordinator heartbeat, also unmetered.
//   - exitHandshake — the Noise_NK handshake itself, a fixed number of bytes per
//     stream, before there is a session to attribute them to.
//   - coldstart.ServeCourier (cmd/node's -courier-listen) — answers a Binding Request
//     with a signed snapshot. Small per request (~KB) but unbounded in aggregate: no
//     rate limit, every request answered. Opt-in and off by default, so low harm;
//     listed because "all of them" has been wrong three times.
//   - the reality transport's camouflage splice (core/transport_reality.go's
//     rawSplice/bridge/holdAndDrain). It is unbounded and not small, and it is NOT
//     reachable from here — a probe never completes the handshake that would reach
//     exitTerminate. It USED to be the one that mattered: unmetered, on by default,
//     able to exceed a declared quota on its own (design §8.7). Issue #163 closed
//     that — it is now counted and paced by realitySpliceLimits (a separate handle
//     sharing this node's quota and limiter), enforced at splice ADMISSION rather
//     than per-read, because cutting a probe response mid-copy is the tell ADR-0027
//     exists to avoid. So it is metered, just not THROUGH here; it stays on this list
//     because the rule is "through here or meterN", and this is the third path.
//
// The first three are why the honest scope is "unbounded volume on a user's behalf",
// not "every byte". The reality splice is now metered too (#163), so §4.2's *never*
// holds for it up to a bounded in-flight overshoot — the price of not truncating a
// probe response — argued in ADR-0027/ADR-0041 rather than left as a silent hole.
//
// This rule has been broken twice inside this file, both times identically: a
// sentinel branch in exitTerminate returns EARLY, above the wrap, so it has to carry
// its own. The UDP relay shipped that way (now meterN) and so did the probe echo
// (now metered at handleProbeStream) — and the audit that caught the first one
// stopped at finding *an* exception instead of enumerating *the* exceptions, which
// is how the second survived it. A new early return here needs its own meter before
// it needs anything else.
func (e *Engine) meter(r io.Reader) io.Reader {
	return e.limiter.LimitReads(e.limiterCtx, e.quota.MeterForwarded(r, time.Now))
}

// meterN is meter's datagram counterpart: it applies the same declared limits to n
// bytes that moved outside an io.Reader, and reports ErrQuotaExhausted once the
// operator's cap is spent so the caller tears the flow down.
//
// The UDP relay (ADR-0034, core/udprelay.go) hand-rolls its own read/write loop
// over whole datagrams rather than copying a stream, so meter() has nothing to
// wrap there. It still spends the operator's uplink, and their ISP still meters it
// — a client pulling QUIC/HTTP3 or DNS moves real bytes through a real exit. An
// unmetered UDP path would let exactly the traffic most people generate sail past
// a declared quota, which is the overage bill issue #143 exists to prevent.
func (e *Engine) meterN(n int) error {
	if n <= 0 {
		return nil
	}
	now := time.Now()
	if e.quota.Exhausted(now) {
		return capacity.ErrQuotaExhausted
	}
	e.quota.AddForwarded(uint64(n), now)
	return e.limiter.WaitN(e.limiterCtx, n)
}

// relayPipe is the peer-relay splice (issue #17, ADR-0033): dial the exit's
// advertised address and forward ciphertext both ways. The relay adds no
// preamble and reads nothing from the stream — it forwards to the next hop only
// and never sees the destination or content.
//
// This is what makes a peer relay transparent to the end-to-end layer: the
// client's Noise_NK channel (and the exit's admission credential riding inside
// it, #60/#69) is spliced through untouched, so the client still authenticates
// and admission-verifies the *exit*, not this relay — proven end-to-end by
// TestPeerRelaySplicePreservesE2E. The only engine state it touches is emit, to
// surface a dial-to-exit failure (issue #97).
//
// pace is the tier's per-session speed cap (issue #74, ADR-0048 §5), nil for
// uncapped. This is where a peer-relayed session is shaped, and the relay is the
// right party for it precisely BECAUSE it terminates nothing: it moves every byte,
// so it can pace them, while the exit on the far side is told nothing at all — no
// session identity, no token, no credential — which is what leaves ADR-0048 §4's
// linkability property untouched rather than trading it away.
//
// Pacing does not cost the transparency above. The limiter wraps the copies, so
// the relay learns only how fast to move bytes it still cannot read: no
// destination, no plaintext, no preamble. What it does learn — a coarse cap — it
// could already derive by measuring the throughput it forwards, which is why the
// disclosure is materially smaller than the credential-to-exit design §4 rejected.
func (e *Engine) relayPipe(st Stream, pace *capacity.Limiter, exitAddr string) {
	defer st.Close()
	// Served, like the exit's own egress above: this leg carries a client's
	// traffic onward, so it must leave this relay under this relay's address
	// rather than through a Bacchus connection this machine is also using.
	up, err := e.dialServed("tcp", exitAddr, 10*time.Second)
	if err != nil {
		// A relay that cannot reach its assigned exit is a real operational fault
		// (exit down, stale advertised address, or a partitioned relay->exit leg),
		// not something to swallow — a relay operator needs the signal (issue #97).
		// The splice carries no session id or destination (see handlerFor), so this
		// names only the exit address the relay already dials; the client is
		// unaffected end-to-end — its transport to this relay simply carries nothing,
		// so it times out and reconnects (issue #2) or is nudged onto another relay
		// (issue #96).
		e.emit(EventError, "", "relay: dial exit %s: %v", exitAddr, err)
		return
	}
	defer up.Close()
	// Two limiters, two questions, innermost first — the same composition the exit's
	// TCP path uses (ADR-0048 §4): pace says what this session's TIER is entitled to,
	// e.meter says what this OPERATOR is willing to carry (#143, ADR-0040). The tier
	// cap sits inside the operator's, so a coordinator stamping a large SessionCapBps
	// widens only the inner bound and this relay's own aggregate limiter still paces
	// the result. There is no accounting counter here: a relayed session has no
	// session id to attribute bytes to (ADR-0021, and see handlerFor).
	go func() {
		_, _ = io.Copy(up, e.meter(pace.LimitReads(e.limiterCtx, st)))
		_ = up.Close()
	}()
	_, _ = io.Copy(st, e.meter(pace.LimitReads(e.limiterCtx, up)))
}

// serveExit is the exit's TCP ingress that relays connect to. The listener is
// bound by Start; this loop runs until the listener is closed by Stop. Each
// relayed connection carries a client's end-to-end channel, terminated exactly
// as a direct one.
func (e *Engine) serveExit(ln net.Listener) {
	defer e.wg.Done()
	e.emit(EventInfo, "", "exit TCP server on %s", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-e.stop:
				return
			default:
				continue
			}
		}
		// Relay-forwarded: no session id and, for the same reason, no tier cap HERE.
		// The coordinator assigned this exit nothing — a peer-relay assign goes to the
		// RELAY — so there is no (trust, plan) resolution attached to this connection
		// to shape it by.
		//
		// That is no longer a gap: issue #74 shapes a peer-relayed session at the
		// relay, which holds the assign and moves every byte (see relayPipe). This exit
		// is deliberately left knowing nothing about it — giving it an identity for a
		// relayed session is the option ADR-0048 §5 rejected, because it is what would
		// reopen §4's linkability question. The splice stays transparent by design
		// (TestPeerRelaySplicePreservesE2E, ADR-0033).
		go e.exitTerminate("", nil, c) // see exitTerminate's doc
	}
}
