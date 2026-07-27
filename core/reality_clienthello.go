package core

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/cryptobyte"
)

// The exit forks on the ClientHello before it terminates TLS (ADR-0032), so it must
// read the raw first flight off the wire and parse out three things: the random and
// the X25519 key share (to recompute the ECDH secret) and the legacy_session_id
// (the client's authenticator). Everything read is buffered so it can be replayed —
// into a local tls.Server on the terminate path, or to the real origin on the splice
// path — without the client noticing the peek.

const (
	tlsRecordHandshake = 22     // TLS record content type: handshake
	tlsMsgClientHello  = 1      // handshake message type: ClientHello
	tlsExtKeyShare     = 0x0033 // extension: key_share (RFC 8446)
	tlsGroupX25519     = 29     // named group: x25519
	tlsMaxRecordLen    = 16384  // RFC 8446 plaintext record cap
)

// errNotClientHello marks bytes that are not a parseable TLS ClientHello — a
// non-handshake record, a truncated flight, or junk. The caller treats it exactly
// like a failed authentication: an unauthenticated peer to be forked to the origin.
var errNotClientHello = errors.New("core: not a tls clienthello")

// realityClientHello is the subset of a ClientHello the exit authentication needs.
type realityClientHello struct {
	random    []byte // 32-byte ClientHello random (HKDF salt / AEAD additional data)
	sessionID []byte // legacy_session_id — where the client's authenticator rides
	x25519    []byte // group-29 key_exchange (32 bytes); nil if the peer sent none
}

// peekClientHello reads exactly one TLS handshake record from r and parses it. It
// returns everything it read (record header + payload) as raw for replay, plus the
// parsed fields. On any anomaly it still returns the bytes consumed so the caller
// can splice them onward, alongside a non-nil error.
func peekClientHello(r io.Reader) (raw []byte, hello *realityClientHello, err error) {
	hdr := make([]byte, 5)
	n, e := io.ReadFull(r, hdr)
	raw = hdr[:n]
	if e != nil {
		return raw, nil, e
	}
	if hdr[0] != tlsRecordHandshake {
		return raw, nil, errNotClientHello
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 4 || recLen > tlsMaxRecordLen {
		return raw, nil, errNotClientHello
	}
	body := make([]byte, recLen)
	n, e = io.ReadFull(r, body)
	raw = append(raw, body[:n]...)
	if e != nil {
		return raw, nil, e
	}
	hello, err = parseClientHello(body)
	return raw, hello, err
}

// parseClientHello walks a single handshake-record payload with cryptobyte, the
// same bounds-checked reader crypto/tls uses, so a malformed field can never read
// out of bounds — it just fails the parse and the peer is treated as unauthenticated.
func parseClientHello(body []byte) (*realityClientHello, error) {
	h := &realityClientHello{}
	s := cryptobyte.String(body)

	var msgType uint8
	var hs cryptobyte.String
	if !s.ReadUint8(&msgType) || msgType != tlsMsgClientHello || !s.ReadUint24LengthPrefixed(&hs) {
		return nil, errNotClientHello
	}

	var legacyVersion uint16
	if !hs.ReadUint16(&legacyVersion) || !hs.ReadBytes(&h.random, 32) {
		return nil, errNotClientHello
	}
	var session cryptobyte.String
	if !hs.ReadUint8LengthPrefixed(&session) {
		return nil, errNotClientHello
	}
	h.sessionID = []byte(session)

	var cipherSuites, compression cryptobyte.String
	if !hs.ReadUint16LengthPrefixed(&cipherSuites) || !hs.ReadUint8LengthPrefixed(&compression) {
		return nil, errNotClientHello
	}
	if hs.Empty() {
		return h, nil // TLS 1.2-style hello with no extensions: no key share, unauth
	}

	var exts cryptobyte.String
	if !hs.ReadUint16LengthPrefixed(&exts) {
		return nil, errNotClientHello
	}
	for !exts.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&extType) || !exts.ReadUint16LengthPrefixed(&extData) {
			return nil, errNotClientHello
		}
		if extType != tlsExtKeyShare {
			continue
		}
		var shares cryptobyte.String
		if !extData.ReadUint16LengthPrefixed(&shares) {
			return nil, errNotClientHello
		}
		for !shares.Empty() {
			var group uint16
			var ke cryptobyte.String
			if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&ke) {
				return nil, errNotClientHello
			}
			if group == tlsGroupX25519 && len(ke) == 32 {
				h.x25519 = []byte(ke)
			}
		}
	}
	return h, nil
}

// prefixConn re-emits a buffered prefix before reading from the wrapped conn, so a
// peeked ClientHello can be replayed into a local tls.Server as if it were never
// read off the wire. Writes and the rest of net.Conn pass straight through.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
