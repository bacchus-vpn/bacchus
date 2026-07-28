package main

import (
	"net"
	"time"
)

// Per-connect idempotency (issue #1, ADR-0042 §2).
//
// # What was wrong
//
// A client sends each connect several times against UDP loss (core's sendN, three
// copies 60ms apart), and this coordinator's handler processed every copy
// independently: each minted its own session through a fresh randomized chooseExit.
// One pairing request was therefore several assignments, and two things followed that
// ADR-0042 §2 recorded as an open residual rather than a closed one.
//
// **Pinning by resampling.** Country-only assignment (#146) removed the client's
// ability to NAME an exit, on the reasoning that the pick is randomized and a client
// gets one draw. It got three, saw all three answers, and could simply drive whichever
// named the exit it wanted — a pin with no exclusion at all, and with three exits in a
// country it lands about nine times in ten in a single round trip. The retransmission
// long predates #146 and was harmless then, because every copy named the same
// client-chosen exit; making the coordinator choose is what turned each retransmit into
// an independent draw.
//
// **Load inflation by a client.** exitSessions counts sessions to rank exits, and it is
// the one ranking term no NODE can forge. A client minting several sessions per connect
// and using one of them inflates the count for the rest, which under
// rankShare = usable/(sessions+1) is enough to push a competitor exit out of the octave
// tier one datagram at a time.
//
// # What this does
//
// The client stamps one fresh nonce per pairing request and repeats it on every copy
// (wire.Nonce). The first copy to arrive is assigned normally; its two sends — the
// assign to the paired node and the session reply to the client — are remembered here
// under (observed source address, nonce), and every later copy REPLAYS those exact
// bytes. One request is one assignment, and the client still gets its loss protection:
// a replayed answer is what a retransmit is for.
//
// # Why the source address is part of the key
//
// For the same reason it is part of the session binding in excludedExits. Keyed on the
// nonce alone, a client that observed or guessed another client's nonce could claim its
// session — learning which exit that client was given, and steering its own retries
// around it. Keyed on (src, nonce) a client can only ever collapse its own
// retransmissions, which is the whole of what the mechanism is for.
//
// # Why replaying the node's assign too, and not just the client's reply
//
// The datagram that went missing may have been either one. Replaying both makes a
// retransmit recover the whole pairing rather than half of it, which is a strict
// improvement on the pre-#1 behaviour: there, a lost assign was "recovered" by minting a
// second session against a possibly different exit, so the client and the node it had
// been paired with could be left holding different session ids.

const (
	// connectDedupeTTL is how long a minted connect's answer stays replayable.
	//
	// It only has to outlast one request's retransmission window — three copies 60ms
	// apart, plus whatever reordering and jitter the path adds — so this sits two
	// orders of magnitude above it and needs no tuning. It is deliberately SHORTER than
	// sessionTTL: an entry that outlived the session it names would replay a session id
	// the registry has already reaped.
	//
	// It is not a retry budget. A client that genuinely retries after a failure sends a
	// FRESH nonce and is assigned again immediately, exactly as before; only copies of
	// one request collapse.
	connectDedupeTTL = 30 * time.Second

	// maxNonceLen bounds the nonce this coordinator will key a map on. A resource
	// bound, not a security property — the security is the (src, nonce) binding, which
	// holds at any length — so an over-long value is REFUSED rather than ignored.
	// Ignoring it would hand a client a way to opt out of idempotency by sending
	// something too long to store, which is the guard defeating itself.
	//
	// core mints 16 hex bytes (32 characters); this leaves ample headroom for a longer
	// key without letting one datagram place an arbitrary string in this map.
	maxNonceLen = 64
)

// mintedConnect is one answered connect, held so its retransmitted copies replay it.
// It records both sends rather than just the client's, so a lost assign is recovered
// too — see the file doc.
type mintedConnect struct {
	peer   *net.UDPAddr // the node that was told to expect this session (exit or relay)
	assign wire         // what that node was sent
	reply  wire         // what the client was sent
	at     time.Time    // when the connect was minted; pruneMintedConnects expires it
}

// mintedConnects maps (observed source address, client nonce) to the answer that was
// minted for it. Guarded by mu like every other registry map — every reader and writer
// is reached from handle or from reselectLoop, both of which hold it.
//
// Its size is bounded by connectDedupeTTL against the connect rate, and a connect that
// creates an entry here has already created a session, so this adds a bounded constant
// factor to a surface that exists either way rather than a new unbounded one.
var mintedConnects = map[string]*mintedConnect{}

// connectKey is the dedupe key: the observed source address joined to the client's
// nonce. NUL-separated so a source address and a nonce cannot be split differently by
// two clients to collide on one key (an address never contains a NUL, and a nonce that
// did would produce its own distinct key rather than aliasing someone else's).
func connectKey(src *net.UDPAddr, nonce string) string {
	if src == nil {
		return ""
	}
	return src.String() + "\x00" + nonce
}

// replayMintedConnect re-sends the answer already minted for this (source, nonce), and
// reports whether there was one. A false return means this is the first copy of the
// request to arrive and the caller should assign normally.
//
// The replay is byte-identical to the original by construction — the stored wire values
// are re-marshalled, not rebuilt — so a client cannot tell a replayed answer from the
// first one, which is the point: to a client, all it ever sees is that its connect was
// answered.
func replayMintedConnect(src *net.UDPAddr, nonce string, now time.Time) bool {
	if src == nil || nonce == "" {
		return false
	}
	mc := mintedConnects[connectKey(src, nonce)]
	if mc == nil || now.Sub(mc.at) > connectDedupeTTL {
		// An expired entry is left for pruneMintedConnects rather than deleted here, so
		// this stays a pure lookup; treating it as absent is what matters.
		return false
	}
	if mc.peer != nil {
		send(mc.peer, mc.assign)
	}
	send(src, mc.reply)
	return true
}

// pairAndReply performs the two sends that answer a connect — the assign to the node
// being paired and the session reply to the client — and remembers both so a
// retransmitted copy of this same request replays them instead of drawing a fresh exit.
//
// The sends and the record are together in one function deliberately: an answer that is
// sent without being recorded is one that a retransmit will re-assign, which is the bug
// this file exists to close, and three call sites (direct, peer-relay, TURN fallback)
// each doing it by hand is three chances to forget.
func pairAndReply(src *net.UDPAddr, nonce string, peer *net.UDPAddr, assign, reply wire, now time.Time) {
	send(peer, assign)
	send(src, reply)
	if src == nil || nonce == "" {
		return
	}
	mintedConnects[connectKey(src, nonce)] = &mintedConnect{peer: peer, assign: assign, reply: reply, at: now}
}

// pruneMintedConnects drops dedupe entries past connectDedupeTTL. Called from prune, so
// it runs on the same packet-driven and timer-driven sweeps every other registry map is
// expired on.
func pruneMintedConnects(now time.Time) {
	for k, mc := range mintedConnects {
		if now.Sub(mc.at) > connectDedupeTTL {
			delete(mintedConnects, k)
		}
	}
}
