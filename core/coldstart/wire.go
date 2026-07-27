package coldstart

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/netip"
)

// STUN (RFC 5389) framing constants. We reuse the standard message layout and
// attribute type codes so a bootstrap exchange is byte-shape-identical to a
// real ICE connectivity check — see docs/design/bootstrap-protocol.md. We do
// not implement RFC 5389 in full (no SASLprep, no long-term credentials, no
// error responses): only the subset needed for shape-compatibility on the
// wire, since we control both endpoints and need no interop with third-party
// STUN clients.
const (
	magicCookie = 0x2112A442

	typeBindingRequest = 0x0001
	typeBindingSuccess = 0x0101

	attrUsername         = 0x0006
	attrMessageIntegrity = 0x0008
	attrXORMappedAddress = 0x0020
	attrFingerprint      = 0x8028
	// attrSnapshot carries the signed directory snapshot in the response.
	// Comprehension-optional range (top bit set); never present unless the
	// request authenticated.
	attrSnapshot = 0xC001
	// attrProof carries the requester's proof-of-prior-contact in a mesh-walk
	// courier request (issue #31): a previously-received coordinator-signed
	// snapshot. Comprehension-optional, like attrSnapshot; its presence is what
	// distinguishes a mesh-walk request from an ordinary reflexive-gathering
	// Binding Request, the same way USERNAME distinguishes a bootstrap request.
	attrProof = 0xC002

	fingerprintXOR = 0x5354554e

	headerLen               = 20
	messageIntegrityAttrLen = 4 + 20 // header + HMAC-SHA1 output
	fingerprintAttrLen      = 4 + 4  // header + CRC32
)

var magicCookieBytes = [4]byte{0x21, 0x12, 0xA4, 0x42}

var (
	errShortMessage  = errors.New("coldstart: short STUN message")
	errBadCookie     = errors.New("coldstart: bad magic cookie")
	errBadLength     = errors.New("coldstart: attribute length exceeds message")
	errNotBindingReq = errors.New("coldstart: not a binding request")
	errNotBindingOK  = errors.New("coldstart: not a binding success response")
	errTxMismatch    = errors.New("coldstart: transaction id mismatch")
)

// txID is a STUN 96-bit transaction ID.
type txID [12]byte

func newTxID() txID {
	var id txID
	_, _ = rand.Read(id[:])
	return id
}

type attribute struct {
	typ uint16
	val []byte
}

type message struct {
	typ   uint16
	tx    txID
	attrs []attribute
}

func (m *message) get(typ uint16) ([]byte, bool) {
	for _, a := range m.attrs {
		if a.typ == typ {
			return a.val, true
		}
	}
	return nil, false
}

// encodeAttrs serializes attrs (TLV, each padded to a 4-byte boundary, per
// RFC 5389 §15).
func encodeAttrs(attrs []attribute) []byte {
	var out []byte
	for _, a := range attrs {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint16(hdr[0:2], a.typ)
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(a.val)))
		out = append(out, hdr...)
		out = append(out, a.val...)
		if pad := len(a.val) % 4; pad != 0 {
			out = append(out, make([]byte, 4-pad)...)
		}
	}
	return out
}

// encodeHeader builds the 20-byte STUN header for typ/tx with the attribute
// section length attrLen (already padded).
func encodeHeader(typ uint16, tx txID, attrLen int) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], typ)
	binary.BigEndian.PutUint16(b[2:4], uint16(attrLen))
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	return b
}

// buildRequest encodes a Binding Request. When key is non-nil the request
// carries USERNAME (username) + MESSAGE-INTEGRITY (HMAC-SHA1 keyed by key,
// per RFC 5389 §15.4) + FINGERPRINT — the same three attributes, in the same
// order, that a real ICE connectivity check carries. When key is nil the
// request is a bare Binding Request (ordinary STUN reachability check, no
// credential).
func buildRequest(tx txID, username string, key []byte) []byte {
	var attrs []attribute
	if key != nil {
		attrs = append(attrs, attribute{attrUsername, []byte(username)})
		body := encodeAttrs(attrs)
		reserved := len(body) + messageIntegrityAttrLen
		hdr := encodeHeader(typeBindingRequest, tx, reserved)
		mi := hmacSHA1(key, append(append([]byte{}, hdr...), body...))
		attrs = append(attrs, attribute{attrMessageIntegrity, mi})
	}
	body := encodeAttrs(attrs)
	withFP := len(body) + fingerprintAttrLen
	hdr := encodeHeader(typeBindingRequest, tx, withFP)
	fp := fingerprint(append(append([]byte{}, hdr...), body...))
	attrs = append(attrs, attribute{attrFingerprint, fp})

	body = encodeAttrs(attrs)
	hdr = encodeHeader(typeBindingRequest, tx, len(body))
	return append(hdr, body...)
}

// buildCourierRequest encodes a Binding Request carrying the mesh-walk PROOF
// attribute (a prior coordinator-signed snapshot) followed by a trailing
// FINGERPRINT. It carries no USERNAME/MESSAGE-INTEGRITY — a mesh-walk courier
// authorizes by verifying the proof's signature, not a per-user secret — so a
// coordinator's bootstrap demux (which keys on USERNAME) never mistakes it for a
// bootstrap request. Shape-wise it is still a FINGERPRINT-bearing Binding Request,
// indistinguishable to a shape-based observer from an ICE check that carries one
// comprehension-optional attribute.
func buildCourierRequest(tx txID, proof []byte) []byte {
	attrs := []attribute{{attrProof, proof}}
	body := encodeAttrs(attrs)
	withFP := len(body) + fingerprintAttrLen
	hdr := encodeHeader(typeBindingRequest, tx, withFP)
	fp := fingerprint(append(append([]byte{}, hdr...), body...))
	attrs = append(attrs, attribute{attrFingerprint, fp})

	body = encodeAttrs(attrs)
	hdr = encodeHeader(typeBindingRequest, tx, len(body))
	return append(hdr, body...)
}

// buildResponse encodes a Binding Success Response carrying the reflexive
// address, when snapshot is non-nil the signed-snapshot attribute, and always
// a trailing FINGERPRINT — the same shape pion/turn's own Binding Success
// response carries, since #30 put both on the same UDP port/process. A
// response never depends on whether the peer's request authenticated except
// through the caller's choice of snapshot — the header/attribute shape is
// identical either way, so an unauthenticated prober's response is
// byte-for-byte what a plain public STUN server would send.
func buildResponse(tx txID, addr netip.AddrPort, snapshot []byte) []byte {
	var attrs []attribute
	attrs = append(attrs, attribute{attrXORMappedAddress, encodeXORMapped(addr, tx)})
	if snapshot != nil {
		attrs = append(attrs, attribute{attrSnapshot, snapshot})
	}
	body := encodeAttrs(attrs)
	withFP := len(body) + fingerprintAttrLen
	hdr := encodeHeader(typeBindingSuccess, tx, withFP)
	fp := fingerprint(append(append([]byte{}, hdr...), body...))
	attrs = append(attrs, attribute{attrFingerprint, fp})

	body = encodeAttrs(attrs)
	hdr = encodeHeader(typeBindingSuccess, tx, len(body))
	return append(hdr, body...)
}

func hmacSHA1(key, msg []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

func fingerprint(msg []byte) []byte {
	v := crc32.ChecksumIEEE(msg) ^ fingerprintXOR
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// parse decodes the STUN header and attribute list without interpreting
// them. It validates the magic cookie and that the declared attribute
// section fits in the buffer.
func parse(b []byte) (message, error) {
	if len(b) < headerLen {
		return message{}, errShortMessage
	}
	if binary.BigEndian.Uint32(b[4:8]) != magicCookie {
		return message{}, errBadCookie
	}
	var m message
	m.typ = binary.BigEndian.Uint16(b[0:2])
	copy(m.tx[:], b[8:20])

	attrLen := int(binary.BigEndian.Uint16(b[2:4]))
	if headerLen+attrLen > len(b) {
		return message{}, errBadLength
	}
	p := b[headerLen : headerLen+attrLen]
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p[0:2])
		l := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+l > len(p) {
			break
		}
		val := p[4 : 4+l]
		m.attrs = append(m.attrs, attribute{typ, val})
		adv := 4 + l
		if pad := l % 4; pad != 0 {
			adv += 4 - pad
		}
		if adv > len(p) {
			break
		}
		p = p[adv:]
	}
	return m, nil
}

// verifyMessageIntegrity re-derives MESSAGE-INTEGRITY over raw up to (not
// including) the attribute at byte offset miOffset, with the header length
// field rewritten as RFC 5389 §15.4 requires (as if the message ended at the
// end of the MESSAGE-INTEGRITY attribute), and compares it to the value at
// that offset.
func verifyMessageIntegrity(raw []byte, miOffset int, key []byte) bool {
	if miOffset < headerLen || miOffset+4+20 > len(raw) {
		return false
	}
	body := make([]byte, miOffset)
	copy(body, raw[:miOffset])
	binary.BigEndian.PutUint16(body[2:4], uint16(miOffset-headerLen+messageIntegrityAttrLen))
	expected := hmacSHA1(key, body)
	got := raw[miOffset+4 : miOffset+4+20]
	return hmac.Equal(expected, got)
}

// messageIntegrityOffset returns the byte offset of the MESSAGE-INTEGRITY
// attribute's header within raw, or -1 if absent.
func messageIntegrityOffset(raw []byte) int {
	if len(raw) < headerLen {
		return -1
	}
	attrLen := int(binary.BigEndian.Uint16(raw[2:4]))
	end := headerLen + attrLen
	if end > len(raw) {
		end = len(raw)
	}
	p := raw[headerLen:end]
	off := headerLen
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p[0:2])
		l := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+l > len(p) {
			return -1
		}
		if typ == attrMessageIntegrity {
			return off
		}
		adv := 4 + l
		if pad := l % 4; pad != 0 {
			adv += 4 - pad
		}
		if adv > len(p) {
			return -1
		}
		p = p[adv:]
		off += adv
	}
	return -1
}

func encodeXORMapped(addr netip.AddrPort, tx txID) []byte {
	a := addr.Addr()
	if !a.IsValid() {
		a = netip.IPv4Unspecified()
	}
	if a.Is4() {
		v := make([]byte, 8)
		v[1] = 0x01
		binary.BigEndian.PutUint16(v[2:4], addr.Port()^0x2112)
		ip := a.As4()
		for i := range ip {
			ip[i] ^= magicCookieBytes[i]
		}
		copy(v[4:8], ip[:])
		return v
	}
	v := make([]byte, 20)
	v[1] = 0x02
	binary.BigEndian.PutUint16(v[2:4], addr.Port()^0x2112)
	var key [16]byte
	copy(key[0:4], magicCookieBytes[:])
	copy(key[4:16], tx[:])
	ip := a.As16()
	for i := range ip {
		ip[i] ^= key[i]
	}
	copy(v[4:20], ip[:])
	return v
}

func decodeXORMapped(val []byte, tx txID) (netip.AddrPort, bool) {
	if len(val) < 4 {
		return netip.AddrPort{}, false
	}
	family := val[1]
	port := binary.BigEndian.Uint16(val[2:4]) ^ 0x2112
	switch family {
	case 0x01:
		if len(val) < 8 {
			return netip.AddrPort{}, false
		}
		var a [4]byte
		copy(a[:], val[4:8])
		for i := range a {
			a[i] ^= magicCookieBytes[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case 0x02:
		if len(val) < 20 {
			return netip.AddrPort{}, false
		}
		var key [16]byte
		copy(key[0:4], magicCookieBytes[:])
		copy(key[4:16], tx[:])
		var a [16]byte
		copy(a[:], val[4:20])
		for i := range a {
			a[i] ^= key[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
	}
	return netip.AddrPort{}, false
}
