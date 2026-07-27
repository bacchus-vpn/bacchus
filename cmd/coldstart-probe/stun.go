// Minimal, dependency-free STUN (RFC 5389) Binding Request/Response codec for the
// cold-start reachability probe. We hand-roll just the Binding exchange rather
// than pull a STUN library, because the spike only needs to prove that a
// STUN-shaped UDP packet reaches a server and a matching reply returns.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	magicCookie       = 0x2112A442
	bindingRequest    = 0x0001
	bindingResponse   = 0x0101
	attrMappedAddr    = 0x0001
	attrXORMappedAddr = 0x0020
)

var magicCookieBytes = [4]byte{0x21, 0x12, 0xA4, 0x42}

// newTxID returns a random 96-bit STUN transaction ID.
func newTxID() [12]byte {
	var id [12]byte
	_, _ = rand.Read(id[:])
	return id
}

// buildBindingRequest encodes a STUN Binding Request with no attributes.
func buildBindingRequest(tx [12]byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], bindingRequest)
	binary.BigEndian.PutUint16(b[2:4], 0) // attribute section is empty
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	return b
}

var (
	errShort      = errors.New("stun: short message")
	errNotResp    = errors.New("stun: not a binding success response")
	errBadCookie  = errors.New("stun: bad magic cookie")
	errTxMismatch = errors.New("stun: transaction id mismatch")
	errNoAddr     = errors.New("stun: no mapped-address attribute")
)

// parseBindingResponse validates a STUN Binding Success Response against the
// transaction ID we sent and returns the reflexive (server-observed) address.
// The transaction-ID check is what lets the probe trust that a reply is really
// an answer to its own request and not stray UDP.
func parseBindingResponse(b []byte, tx [12]byte) (netip.AddrPort, error) {
	if len(b) < 20 {
		return netip.AddrPort{}, errShort
	}
	if binary.BigEndian.Uint16(b[0:2]) != bindingResponse {
		return netip.AddrPort{}, errNotResp
	}
	if binary.BigEndian.Uint32(b[4:8]) != magicCookie {
		return netip.AddrPort{}, errBadCookie
	}
	if [12]byte(b[8:20]) != tx {
		return netip.AddrPort{}, errTxMismatch
	}
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	if 20+msgLen > len(b) {
		return netip.AddrPort{}, errShort
	}
	p := b[20 : 20+msgLen]

	var fallback netip.AddrPort
	var haveFallback bool
	for len(p) >= 4 {
		atyp := binary.BigEndian.Uint16(p[0:2])
		alen := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+alen > len(p) {
			break
		}
		val := p[4 : 4+alen]
		switch atyp {
		case attrXORMappedAddr:
			if ap, ok := parseXORMapped(val, tx); ok {
				return ap, nil
			}
		case attrMappedAddr:
			if ap, ok := parseMapped(val); ok {
				fallback, haveFallback = ap, true
			}
		}
		adv := 4 + alen
		if pad := adv % 4; pad != 0 { // attributes are padded to 4 bytes
			adv += 4 - pad
		}
		if adv > len(p) {
			break
		}
		p = p[adv:]
	}
	if haveFallback {
		return fallback, nil
	}
	return netip.AddrPort{}, errNoAddr
}

func parseXORMapped(val []byte, tx [12]byte) (netip.AddrPort, bool) {
	if len(val) < 4 {
		return netip.AddrPort{}, false
	}
	family := val[1]
	port := binary.BigEndian.Uint16(val[2:4]) ^ 0x2112 // high 16 bits of the cookie
	switch family {
	case 0x01: // IPv4
		if len(val) < 8 {
			return netip.AddrPort{}, false
		}
		var a [4]byte
		copy(a[:], val[4:8])
		for i := range a {
			a[i] ^= magicCookieBytes[i]
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case 0x02: // IPv6
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

func parseMapped(val []byte) (netip.AddrPort, bool) {
	if len(val) < 4 {
		return netip.AddrPort{}, false
	}
	family := val[1]
	port := binary.BigEndian.Uint16(val[2:4])
	switch family {
	case 0x01:
		if len(val) < 8 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(val[4:8])), port), true
	case 0x02:
		if len(val) < 20 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(val[4:20])), port), true
	}
	return netip.AddrPort{}, false
}
