package coldstart

import (
	"encoding/binary"
	"net/netip"
)

// BindingResponse answers a bare STUN Binding Request the way an ordinary STUN
// server does: a Binding Success Response carrying XOR-MAPPED-ADDRESS for from,
// plus FINGERPRINT, and nothing else. ok is false for anything that is not a
// well-formed Binding Request, and the caller must then treat raw exactly as it
// would have without this call.
//
// # Why this is exported rather than reimplemented at the caller
//
// It exists so the rendezvous signaling port can answer ICE connectivity checks
// with bytes shaped exactly like the ones this coordinator's TURN port already
// sends (issue #202, ADR-0060). pion/turn's handleBindingRequest builds
// XOR-MAPPED-ADDRESS then Fingerprint, which is attribute-for-attribute what
// [buildResponse] produces with a nil snapshot. Two UDP ports on one host that
// answer the same question with differently-shaped bytes are a distinguisher, so
// sharing one codec is the point rather than a convenience.
//
// # What it deliberately does not do
//
// It does not verify MESSAGE-INTEGRITY, and does not put one in the response.
// Real ICE keys that attribute on the peer's pwd, agreed in SDP; the rendezvous
// hop has no channel over which a pwd could have been agreed, and the only key
// both ends already share is fleet-wide. Verifying against a fleet-wide secret
// would look like authentication while providing none. ADR-0060 records that
// trade and what it costs.
//
// It also answers only Binding Requests. Any other STUN method — an Allocate, a
// Refresh, a ChannelBind — returns ok false and is left to the caller, which on
// the signaling port means it is dropped exactly as it was before. This port is
// not a TURN server and does not pretend to be one.
func BindingResponse(raw []byte, from netip.AddrPort) (resp []byte, ok bool) {
	m, err := parse(raw)
	if err != nil || m.typ != typeBindingRequest {
		return nil, false
	}
	return buildResponse(m.tx, from, nil), true
}

// BindingRequest encodes an ICE connectivity check: a Binding Request carrying
// USERNAME, MESSAGE-INTEGRITY keyed by key, and FINGERPRINT — the same three
// attributes, in the same order, a real ICE agent puts on a check.
//
// # Why this is exported rather than reimplemented at the caller
//
// [BindingResponse]'s reason, from the other end. The client now emits a
// connectivity check on the signaling 5-tuple before its DTLS ClientHello (issue
// #175 slice 2, ADR-0062), because a ClientHello arriving from nowhere is
// DTLS-shaped rather than WebRTC-shaped and the difference is free for a
// classifier to read. This package already owned the repository's STUN codec and
// already emits checks of exactly this shape to the bootstrap listener, so two
// differently-shaped Binding Requests leaving one client would be the kind of
// distinguisher the feature exists to remove.
//
// # What the MESSAGE-INTEGRITY is and is not
//
// It is CAMOUFLAGE, and the caller must not read it as anything else. Real ICE
// keys this attribute on the peer's `pwd`, agreed in SDP; the rendezvous hop has
// no channel over which a pwd could have been agreed, so the caller passes a
// freshly drawn one of its own and nothing at the far end verifies it — ADR-0060
// records why a fleet-wide key would be a false claim of authentication rather
// than a weak one. What it buys is that the bytes on the wire look like a check
// instead of looking like a probe.
func BindingRequest(username string, key []byte) []byte {
	return buildRequest(newTxID(), username, key)
}

// LooksLikeBindingSuccess reports whether raw is a STUN Binding Success Response.
//
// It is the narrow classifier a client needs on a 5-tuple that carries both ICE
// checks and DTLS: the answer to the check it just sent has to be told apart from
// a DTLS record and consumed rather than handed to the DTLS layer, which is what a
// real ICE agent's demultiplexer does (RFC 7983).
//
// The three tests are the ones cmd/coordinator applies to a request, with the
// method swapped: the exact type, the magic cookie at bytes 4..8, and a declared
// attribute length that accounts for every remaining byte — over UDP a STUN
// message IS the datagram, so "fits" is not enough.
//
// It deliberately does NOT check the transaction id. The response is discarded, it
// gates nothing, and the only thing matching would change is how long a caller
// waits before starting its handshake.
func LooksLikeBindingSuccess(raw []byte) bool {
	if len(raw) < headerLen {
		return false
	}
	if binary.BigEndian.Uint16(raw[0:2]) != typeBindingSuccess {
		return false
	}
	if binary.BigEndian.Uint32(raw[4:8]) != magicCookie {
		return false
	}
	return headerLen+int(binary.BigEndian.Uint16(raw[2:4])) == len(raw)
}
