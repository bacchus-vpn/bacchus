package coldstart

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// Mesh-walk recovery (old #31, design §4.3) — the "warm re-bootstrap".
//
// Once a client has ever connected it has met peers. If every coordinator it
// knows goes unreachable, it must not fail cold: it asks any node it knows — even
// a plain relay — for a current, coordinator-signed snapshot and walks the mesh
// until it finds a live rendezvous point. This is the courier half of that.
//
// A relay/exit node is a COURIER, not an author. It caches the last signed
// snapshot it received from a coordinator (SnapshotCache) and hands those exact
// bytes back on request (ServeCourier). It cannot forge or edit an entry: the
// snapshot is ed25519-signed by the coordinator, and the recovering client
// re-verifies that signature with Verify before trusting a byte of it. So the
// worst a hostile courier can do is serve a stale (but genuine) snapshot or serve
// nothing — never a poisoned directory. This is the same signed-snapshot mechanism
// the coordinator pool (old #6) hands out; a courier is just another dispenser of
// it, reached when the coordinators themselves cannot be.
//
// Anti-probe (design principle #4). The courier serves the snapshot only to a
// request that proves prior contact: a PROOF attribute carrying a snapshot this
// coordinator once signed. A prober with no prior snapshot — a censor port-scanning
// datacenter IPs for couriers — gets exactly the plain Binding Success Response a
// public STUN server sends, learning nothing. The proof is checked with VerifySigned
// (signature only, expiry ignored): a recovering client's proof is legitimately
// stale, and staleness is not the property that matters here — provenance is.

// SnapshotCache holds the latest signed snapshot a courier node has received from
// a coordinator, safe for concurrent Store/Load. It stores the opaque signed bytes
// verbatim — a courier forwards what the coordinator signed and never re-signs, so
// it needs no private key.
type SnapshotCache struct {
	cur atomic.Pointer[[]byte]
}

// NewSnapshotCache returns an empty cache whose Load reports nil until the first
// Store.
func NewSnapshotCache() *SnapshotCache { return &SnapshotCache{} }

// Store replaces the cached snapshot with a private copy of signed, so a later
// mutation of the caller's slice can't change what the courier serves.
func (c *SnapshotCache) Store(signed []byte) {
	cp := append([]byte(nil), signed...)
	c.cur.Store(&cp)
}

// Load returns a private copy of the cached signed snapshot, or nil if none has
// been stored yet.
func (c *SnapshotCache) Load() []byte {
	p := c.cur.Load()
	if p == nil {
		return nil
	}
	return append([]byte(nil), (*p)...)
}

// ServeCourier answers mesh-walk courier requests on pc until ctx is done or
// pc.ReadFrom errors. pub is the coordinator's snapshot-signing public key, used
// to check each request's proof-of-prior-contact; cache supplies the snapshot to
// hand out.
//
// Every well-formed Binding Request gets a plain Binding Success Response with the
// reflexive address, exactly as a public STUN server would — so a courier port is
// indistinguishable from an ordinary STUN endpoint to a prober. Only a request
// whose PROOF attribute is a snapshot signed by pub gets the cached snapshot
// appended to that same response, and only when the cache is non-empty.
func ServeCourier(ctx context.Context, pc net.PacketConn, pub ed25519.PublicKey, cache *SnapshotCache) error {
	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return err
		}
		raw := append([]byte(nil), buf[:n]...)
		var reflexive netip.AddrPort
		if ua, ok := src.(*net.UDPAddr); ok {
			reflexive = ua.AddrPort()
		}
		resp, ok := handleCourierRequest(raw, reflexive, pub, cache)
		if !ok {
			continue
		}
		_, _ = pc.WriteTo(resp, src)
	}
}

// handleCourierRequest is the pure per-packet logic behind ServeCourier, split out
// so it can be unit-tested without a live socket. It returns the response bytes and
// true for any Binding Request, false (drop) for anything else. The snapshot is
// attached only when the request carries a PROOF attribute that VerifySigned
// accepts against pub AND the cache holds a still-unexpired snapshot; otherwise the
// response is the bare reflexive-address Binding Success a plain STUN server sends.
func handleCourierRequest(raw []byte, reflexive netip.AddrPort, pub ed25519.PublicKey, cache *SnapshotCache) ([]byte, bool) {
	m, err := parse(raw)
	if err != nil || m.typ != typeBindingRequest {
		return nil, false
	}

	var snapshot []byte
	if proof, ok := m.get(attrProof); ok {
		if _, err := VerifySigned(pub, proof); err == nil {
			snapshot = servableSnapshot(pub, cache)
		}
	}

	return buildResponse(m.tx, reflexive, snapshot), true
}

// servableSnapshot returns the cached snapshot only while it is still fresh, or nil
// once it has expired. This enforces the courierRefresh (30s) vs coordinator
// snapshot-TTL (old #31, ~5 min) coupling in the serve path rather than leaving it
// to hold merely by cadence (old #115): while a courier's coordinator is up, its
// 30s refresh keeps the cache well inside the TTL; but if that coordinator goes
// unreachable for longer than the TTL, the last cached snapshot ages out, and a
// courier must then serve nothing — its entries may already be gone. The client
// re-checks freshness on receipt anyway (FetchSnapshot uses Verify, expiry enforced),
// so this makes the two ends symmetric: a courier never hands out what a client would
// only reject, and a probe times the same plain-STUN answer whether the cache is cold
// or merely stale. Freshness is checked with Verify (signature + ExpiresAt) against
// the same key the client verifies with; the cache itself stays keyless (it holds
// opaque signed bytes and re-signs nothing).
func servableSnapshot(pub ed25519.PublicKey, cache *SnapshotCache) []byte {
	cached := cache.Load()
	if cached == nil {
		return nil
	}
	if _, err := Verify(pub, cached); err != nil {
		return nil // expired (or, defensively, unverifiable) — withhold, answer as plain STUN
	}
	return cached
}

// FetchSnapshot performs one mesh-walk fetch against a peer courier at addr: it
// sends proof (a previously-received signed snapshot, the caller's proof of prior
// contact) and, on a signature-verified, unexpired response, returns the fresh
// snapshot ready to adopt and re-cache. pub is the coordinator's snapshot-signing
// public key — the same key that verifies a cold bootstrap — and both the proof it
// sends and the snapshot it receives are checked against it. ctx bounds the whole
// exchange, including the wait for a reply.
//
// It returns ErrNotAuthenticated when the peer answered as a plain STUN endpoint
// but attached no snapshot: the proof was rejected (stale beyond signing-key
// rotation, or from a different coordinator), or this endpoint is not a courier —
// the two are indistinguishable by design, exactly as in Bootstrap. A caller
// walking several peers treats that like a miss and tries the next one.
func FetchSnapshot(ctx context.Context, addr string, proof []byte, pub ed25519.PublicKey) (*Result, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("coldstart: resolve %s: %w", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("coldstart: dial %s: %w", addr, err)
	}
	defer conn.Close()

	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(defaultTimeout)
	}
	if err := conn.SetDeadline(dl); err != nil {
		return nil, fmt.Errorf("coldstart: set deadline: %w", err)
	}

	tx := newTxID()
	if _, err := conn.Write(buildCourierRequest(tx, proof)); err != nil {
		return nil, fmt.Errorf("coldstart: send courier request: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("coldstart: read courier response: %w", err)
	}

	m, err := parse(buf[:n])
	if err != nil {
		return nil, err
	}
	if m.typ != typeBindingSuccess {
		return nil, errNotBindingOK
	}
	if m.tx != tx {
		return nil, errTxMismatch
	}

	signed, ok := m.get(attrSnapshot)
	if !ok {
		return nil, ErrNotAuthenticated
	}
	// Verify (not VerifySigned): a client adopting a directory to reconnect through
	// wants a LIVE one. A courier serving an expired snapshot is no better than no
	// snapshot — the entries in it may already be gone — so an expired reply is
	// rejected here and the caller walks on to the next peer.
	snap, err := Verify(pub, signed)
	if err != nil {
		return nil, err
	}
	return &Result{Snapshot: snap, Signed: append([]byte(nil), signed...)}, nil
}
