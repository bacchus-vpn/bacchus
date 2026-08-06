package coldstart

import "net/netip"

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
