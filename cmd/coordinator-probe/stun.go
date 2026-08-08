// A minimal, dependency-free STUN (RFC 5389) Binding codec for the deployed-build
// probe: build a bare Binding Request, and decide whether what came back is a
// well-formed Binding Success Response to THAT request.
//
// # Why this is hand-rolled next to core/coldstart, which already has a codec
//
// Because this file is the VERIFIER and core/coldstart is the thing verified. The
// coordinator's answer is produced by coldstart.BindingResponse (cmd/coordinator's
// answerSTUN calls it); if the check that reads the answer were built from the same
// encoder, a bug in that encoder would cancel itself out and the probe would report
// success on bytes no real STUN client accepts. An independent reader is the only
// kind whose agreement means anything. cmd/coldstart-probe hand-rolls its own for the
// same reason, and coordinator_probe_test.go closes the loop from the other side by
// running THIS parser against the PRODUCTION encoder.
//
// It implements only what the probe needs: no error responses, no MESSAGE-INTEGRITY,
// no attribute the coordinator does not send.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net/netip"
)

const (
	magicCookie     = 0x2112A442
	bindingRequest  = 0x0001
	bindingResponse = 0x0101

	attrXORMappedAddr = 0x0020
	attrFingerprint   = 0x8028

	// fingerprintXOR is RFC 5389 §15.5's constant: FINGERPRINT carries the CRC-32
	// of the message up to (not including) the attribute, XORed with this, which is
	// what stops a plain CRC from being mistaken for one.
	fingerprintXOR = 0x5354554e

	headerLen = 20

	// wantLenV4/wantLenV6 are the exact sizes coldstart.BindingResponse produces:
	// header + XOR-MAPPED-ADDRESS + FINGERPRINT, and nothing else. They are checked
	// rather than merely parsed because "and nothing else" is part of what the
	// coordinator promises (ADR-0060: no SOFTWARE attribute, no MESSAGE-INTEGRITY),
	// and a reply carrying more is a different server answering.
	wantLenV4 = headerLen + 12 + 8
	wantLenV6 = headerLen + 24 + 8
)

var magicCookieBytes = [4]byte{0x21, 0x12, 0xA4, 0x42}

// newTxID returns a random 96-bit STUN transaction ID. It is what lets a reply be
// attributed to the request this probe sent rather than to stray UDP arriving on the
// same socket — which matters here more than in an ordinary STUN client, because a
// reply misattributed to our request is precisely a false PASS.
func newTxID() [12]byte {
	var id [12]byte
	_, _ = rand.Read(id[:])
	return id
}

// buildBindingRequest encodes the exact 20 bytes the card's instrument names: type
// 0x0001, a zero attribute-section length, the magic cookie, and 12 random
// transaction-ID bytes.
//
// Bare, with no FINGERPRINT and no USERNAME, deliberately. coldstart.BindingRequest
// builds the ICE-check shape a client emits (USERNAME + MESSAGE-INTEGRITY +
// FINGERPRINT); this is the ordinary-STUN shape, and it is the one confirmed against
// real hardware in both directions. cmd/coordinator's looksLikeSTUN accepts either —
// it tests the method, the cookie, and that the declared attribute length accounts
// for every remaining byte — so the bare form exercises the same responder without
// depending on any attribute the responder does not read.
func buildBindingRequest(tx [12]byte) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], bindingRequest)
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	return b
}

var (
	errShort      = errors.New("short message")
	errNotResp    = errors.New("not a binding success response")
	errBadCookie  = errors.New("bad magic cookie")
	errTxMismatch = errors.New("transaction id mismatch")
	errBadLength  = errors.New("declared attribute length does not account for the datagram")
	errNoAddr     = errors.New("no XOR-MAPPED-ADDRESS attribute")
	errNoFP       = errors.New("no FINGERPRINT attribute")
	errBadFP      = errors.New("FINGERPRINT does not match the message")
)

// bindingReply is what the probe learned from one answered Binding Request.
type bindingReply struct {
	// Reflexive is the address the far end says it saw us from. Reported to the
	// operator and compared against nothing: this probe is not a NAT test.
	Reflexive netip.AddrPort
	// Len is the datagram size, kept because the expected size is itself part of
	// the fingerprint of the answer (see wantLenV4/wantLenV6).
	Len int
	// ExactShape is true when the reply is exactly header + XOR-MAPPED-ADDRESS +
	// FINGERPRINT for its address family — what this coordinator sends. A reply
	// that parses but carries more is reported rather than refused, because the
	// probe's job is to describe what answered, and "something else is on this
	// port" is a more useful sentence than "failed".
	ExactShape bool
}

// parseBindingResponse validates a reply against the transaction ID we sent and
// returns what it says.
//
// Every check here can only ever turn a PASS into a FAIL, which is the polarity this
// tool needs: its output is used to decide that a deployment is current, and the
// expensive mistake is believing that when it is not. In particular the FINGERPRINT
// is verified rather than skipped — it is the one field that ties the whole datagram
// together, and verifying it costs a CRC32.
func parseBindingResponse(b []byte, tx [12]byte) (bindingReply, error) {
	if len(b) < headerLen {
		return bindingReply{}, errShort
	}
	if binary.BigEndian.Uint16(b[0:2]) != bindingResponse {
		return bindingReply{}, errNotResp
	}
	if binary.BigEndian.Uint32(b[4:8]) != magicCookie {
		return bindingReply{}, errBadCookie
	}
	if [12]byte(b[8:20]) != tx {
		return bindingReply{}, errTxMismatch
	}
	// Over UDP a STUN message IS the datagram, so the declared length must account
	// for every remaining byte rather than merely fit — the same test
	// cmd/coordinator's looksLikeSTUN applies to a request, from the other side.
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	if headerLen+msgLen != len(b) {
		return bindingReply{}, errBadLength
	}

	var (
		out      bindingReply
		haveAddr bool
		haveFP   bool
		nAttr    int
	)
	p := b[headerLen:]
	off := headerLen
	for len(p) >= 4 {
		atyp := binary.BigEndian.Uint16(p[0:2])
		alen := int(binary.BigEndian.Uint16(p[2:4]))
		if 4+alen > len(p) {
			return bindingReply{}, errBadLength
		}
		val := p[4 : 4+alen]
		nAttr++
		switch atyp {
		case attrXORMappedAddr:
			ap, ok := parseXORMapped(val, tx)
			if !ok {
				return bindingReply{}, fmt.Errorf("malformed XOR-MAPPED-ADDRESS (%d bytes)", alen)
			}
			out.Reflexive, haveAddr = ap, true
		case attrFingerprint:
			if alen != 4 {
				return bindingReply{}, fmt.Errorf("FINGERPRINT is %d bytes, want 4", alen)
			}
			// RFC 5389 §15.5: the CRC covers the message up to this attribute, with
			// the header's length field set as if the message ended just after it.
			// Recomputing that means rebuilding the prefix rather than hashing the
			// buffer as received.
			prefix := make([]byte, off)
			copy(prefix, b[:off])
			binary.BigEndian.PutUint16(prefix[2:4], uint16(off-headerLen+4+4))
			if binary.BigEndian.Uint32(val) != crc32.ChecksumIEEE(prefix)^fingerprintXOR {
				return bindingReply{}, errBadFP
			}
			haveFP = true
		}
		adv := 4 + alen
		if pad := adv % 4; pad != 0 { // attributes are padded to a 4-byte boundary
			adv += 4 - pad
		}
		if adv > len(p) {
			return bindingReply{}, errBadLength
		}
		p = p[adv:]
		off += adv
	}
	if !haveAddr {
		return bindingReply{}, errNoAddr
	}
	if !haveFP {
		return bindingReply{}, errNoFP
	}
	out.Len = len(b)
	want := wantLenV4
	if out.Reflexive.Addr().Is6() {
		want = wantLenV6
	}
	out.ExactShape = nAttr == 2 && len(b) == want
	return out, nil
}

// parseXORMapped decodes XOR-MAPPED-ADDRESS (RFC 5389 §15.2).
func parseXORMapped(val []byte, tx [12]byte) (netip.AddrPort, bool) {
	if len(val) < 4 {
		return netip.AddrPort{}, false
	}
	family := val[1]
	port := binary.BigEndian.Uint16(val[2:4]) ^ 0x2112 // the cookie's high 16 bits
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
