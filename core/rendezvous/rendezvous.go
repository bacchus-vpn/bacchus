// Package rendezvous is the PEER half of the shaped rendezvous hop: what
// something standing in for a coordinator needs in order to be reachable by a
// current Bacchus client.
//
// # Why it exists
//
// The client's path to a coordinator stopped being cleartext (issue #175 slice 2,
// ADR-0062). It sends an ICE connectivity check and then a DTLS ClientHello on the
// same 5-tuple, and — deliberately, ruling B3 — it has no fallback to plaintext: a
// censor dropping the handshake and a coordinator that never learned it are the
// same silence, and answering that silence with plaintext would send exactly what
// the shape exists to hide.
//
// The consequence is that "bind a UDP socket and speak JSON" no longer stands in
// for a coordinator anywhere — not in core's tests, not in the desktop clients'.
// This package is the one place that plumbing lives, so a stand-in adopts the shape
// by changing which object it reads and writes rather than by growing its own DTLS
// server.
//
// # What it is not
//
// It is NOT cmd/coordinator's mux. That one carries what a public port needs and
// this one deliberately does not: a bounded association table with an idle sweep, a
// latched at-capacity refusal, and the raw-JSON compatibility path ADR-0059 §4
// argues for at length. A [Peer] is unbounded and speaks both shapes without
// distinction, which is right for a stand-in and wrong for an internet-facing
// coordinator. The two are pinned against each other by
// cmd/coordinator's real-client-against-real-coordinator integration test, which
// runs the production mux rather than this.
package rendezvous

// The classifier below is shared with the client half in package core (which
// imports it) rather than written twice. cmd/coordinator keeps its own copy,
// because that binary deliberately does not link core; TestTheTwoDTLSClassifiersAgree
// over there pins the two against each other over a corpus.

const (
	// dtlsRecordVersionMajor is the first byte of every DTLS protocol version.
	// DTLS versions are the 1's complement of their TLS counterparts, so 1.0 is
	// 0xfeff and 1.2 is 0xfefd — both begin 0xfe, and no JSON document does.
	dtlsRecordVersionMajor = 0xfe

	// dtlsRecordHeaderSize is the fixed part of a DTLS record header: type(1) +
	// version(2) + epoch(2) + sequence(6) + length(2). A datagram shorter than this
	// cannot be a DTLS record whatever its first byte says.
	dtlsRecordHeaderSize = 13

	// handshakeRecord is the ContentType of a DTLS handshake record. Only one from
	// an unknown source may create state — see Peer.route.
	handshakeRecord = 22
)

// LooksLikeDTLS reports whether raw is conclusively the start of a DTLS record.
//
// Three facts, none of them heuristic: a DTLS record begins with a one-byte
// ContentType (20 change_cipher_spec, 21 alert, 22 handshake, 23 application_data,
// 25 connection_id), followed by a two-byte version that for DTLS is 0xfeff (1.0)
// or 0xfefd (1.2), and it cannot be shorter than its own header. A JSON value
// begins with '{', '[', '"', a digit, '-', 't', 'f', 'n' or ASCII whitespace, so
// the two sets are disjoint on the FIRST byte alone; the version check is what
// turns "unlikely to misclassify" into "cannot".
func LooksLikeDTLS(raw []byte) bool {
	if len(raw) < dtlsRecordHeaderSize {
		return false
	}
	switch raw[0] {
	case 20, 21, 22, 23, 25:
	default:
		return false
	}
	return raw[1] == dtlsRecordVersionMajor && (raw[2] == 0xff || raw[2] == 0xfd)
}
