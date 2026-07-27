// Package handshake defines the version + capability negotiation two Bacchus
// peers run as the very first exchange on the coordinator channel, before any
// role logic (registration, client actions, forwarder assignment). A
// coordinator and a node may ship from different releases — a volunteer relay
// can lag, a client can be mid-update — and without an explicit check, a wire
// shape neither side actually agrees on fails silently deep inside role logic
// instead of being caught at the door (issue #8, ADR-0016). Catching drift
// here also matters for detection: an unexpected wire shape from stale nodes
// is itself a fingerprint (see ADR-0015).
//
// This is unrelated to the Noise_NK handshake in core/e2e.go, which
// authenticates and encrypts the client<->exit data channel; this package
// only negotiates whether two peers speak the same app-layer protocol at all.
//
// The package has no dependency on the rest of core (or WebRTC), so the
// coordinator — a small, dependency-light binary — can use it exactly like
// core/coldstart without pulling in the transport stack.
package handshake

import "fmt"

// ProtocolVersion is this build's app-layer wire protocol version: the shape
// of the messages peers exchange over the coordinator channel (register,
// list, connect, signaling, and this handshake itself). Bump it on any
// breaking change to that shape. It is deliberately not the product's
// semver release (ADR-0015 covers that, separately, for client/node update
// policy) — this is the one number a peer checks before it trusts anything
// else on the wire.
const ProtocolVersion = 1

// Magic identifies a Hello as a genuine Bacchus handshake, so a peer can
// reject unrelated or malformed traffic on the coordinator port with the same
// "bad magic" path used for a real version mismatch, before it ever tries to
// interpret the rest of the message.
const Magic = "bacchus-hello-1"

// Capability names an optional protocol feature a peer supports. None are
// defined yet — the type and the wire field exist now so a future feature can
// be negotiated without another protocol-breaking version bump.
type Capability string

// Hello is the versioned greeting two peers exchange first, before any role
// logic. It carries no identity (no node id, role, or address) — those belong
// to the role-specific messages that follow once the handshake succeeds.
type Hello struct {
	Magic        string       `json:"magic"`
	Version      int          `json:"version"`
	Capabilities []Capability `json:"capabilities,omitempty"`
}

// Local returns this build's Hello: the value every peer sends first.
func Local() Hello {
	return Hello{Magic: Magic, Version: ProtocolVersion}
}

// Check validates a peer's Hello against this build's version and reports
// whether the channel may proceed to role logic. On rejection, reason says
// which side is behind so the failure is actionable ("clear reject/upgrade
// path", issue #8) — it contains only protocol/version data, never anything
// that identifies the peer, so it is always safe to log.
func Check(peer Hello) (ok bool, reason string) {
	if peer.Magic != Magic {
		return false, "not a bacchus peer (bad magic)"
	}
	switch {
	case peer.Version < ProtocolVersion:
		return false, fmt.Sprintf("peer protocol version %d is older than %d — peer must update", peer.Version, ProtocolVersion)
	case peer.Version > ProtocolVersion:
		return false, fmt.Sprintf("peer protocol version %d is newer than %d — this side must update", peer.Version, ProtocolVersion)
	}
	return true, ""
}
