package coldstart

import (
	"net"
	"net/netip"
)

// Demux wraps pc so that bootstrap-shaped requests and ordinary STUN/TURN
// traffic can share one UDP socket and port (issue #30): a STUN Binding
// Request carrying the bootstrap USERNAME attribute is answered directly,
// using the same authenticate-then-maybe-attach-SNAPSHOT logic [Serve] uses;
// every other packet — a bare Binding Request (ordinary reflexive-address
// gathering) or any TURN message (Allocate, Refresh, CreatePermission,
// ChannelBind, Send/ChannelData) — passes through [net.PacketConn.ReadFrom]
// unmodified for the caller (typically a pion/turn server) to handle.
//
// The demux key is simply whether the Binding Request carries a USERNAME
// attribute at all. An ordinary reflexive-gathering Binding Request never
// carries one (RFC 5389 Binding requests are unauthenticated), so this can't
// misroute real ICE traffic; it also means ordinary Binding Requests keep
// getting pion/turn's native response unchanged (including its FINGERPRINT
// attribute) rather than [Serve]'s minimal one, which only ever appears on
// wire shapes no legitimate STUN client produces. See
// docs/design/bootstrap-protocol.md and ADR-0017 for the design.
func Demux(pc net.PacketConn, secrets SecretStore, snapshotFn func() []byte) net.PacketConn {
	return &demuxConn{PacketConn: pc, secrets: secrets, snapshotFn: snapshotFn}
}

// demuxConn embeds net.PacketConn so every method other than ReadFrom
// (WriteTo, Close, LocalAddr, the deadline setters) passes through
// untouched via Go's normal method promotion.
type demuxConn struct {
	net.PacketConn
	secrets    SecretStore
	snapshotFn func() []byte
}

// ReadFrom answers and swallows bootstrap-shaped packets internally,
// looping until it has a packet to hand back to the caller — or the
// underlying conn errors or closes, which it reports immediately. It never
// takes over the read loop itself; the caller keeps pulling one packet at a
// time, exactly as it would from the wrapped conn directly.
func (d *demuxConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	for {
		n, src, err := d.PacketConn.ReadFrom(buf)
		if err != nil {
			return n, src, err
		}
		if !d.intercept(buf[:n], src) {
			return n, src, nil
		}
	}
}

// intercept reports whether raw was a bootstrap-shaped Binding Request —
// meaning it has already been answered on d.PacketConn and must not reach
// the caller. Anything else (wrong message type, or a Binding Request with
// no USERNAME at all) is left for the caller to handle.
func (d *demuxConn) intercept(raw []byte, src net.Addr) bool {
	m, err := parse(raw)
	if err != nil || m.typ != typeBindingRequest {
		return false
	}
	if _, ok := m.get(attrUsername); !ok {
		return false
	}

	var reflexive netip.AddrPort
	if ua, ok := src.(*net.UDPAddr); ok {
		reflexive = ua.AddrPort()
	}
	resp, ok := handleRequest(raw, reflexive, d.secrets, d.snapshotFn)
	if !ok {
		return false
	}
	_, _ = d.PacketConn.WriteTo(resp, src)
	return true
}
