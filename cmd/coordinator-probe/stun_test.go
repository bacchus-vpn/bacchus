package main

import (
	"encoding/binary"
	"hash/crc32"
	"net/netip"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// Documentation addresses throughout (RFC 5737 / RFC 3849), the rule the rest of this
// repository's fixtures already follow: the codec does not care what the numbers mean,
// so there is no reason for a real one to appear in a test.

func TestBuildBindingRequest_IsTheTwentyByteInstrument(t *testing.T) {
	tx := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	b := buildBindingRequest(tx)
	if len(b) != 20 {
		t.Fatalf("len=%d, want exactly 20 — the card's instrument is a BARE Binding Request", len(b))
	}
	if got := binary.BigEndian.Uint16(b[0:2]); got != bindingRequest {
		t.Errorf("type=%#04x, want %#04x", got, bindingRequest)
	}
	if got := binary.BigEndian.Uint16(b[2:4]); got != 0 {
		t.Errorf("attribute length=%d, want 0 (no attributes)", got)
	}
	if got := binary.BigEndian.Uint32(b[4:8]); got != magicCookie {
		t.Errorf("cookie=%#08x, want %#08x", got, magicCookie)
	}
	if [12]byte(b[8:20]) != tx {
		t.Error("transaction id not copied into the header")
	}
}

// The request must survive cmd/coordinator's own gate. looksLikeSTUN is unexported in
// package main of another command, so its three tests are restated here against the
// bytes this probe actually sends: the exact method, the cookie, and a declared
// attribute length that accounts for every remaining byte. If any of the three ever
// stops holding for a bare request, the probe is sending something the coordinator
// drops and every result it prints is "stale".
func TestBuildBindingRequest_PassesTheCoordinatorsGate(t *testing.T) {
	raw := buildBindingRequest(newTxID())
	if len(raw) < headerLen {
		t.Fatalf("len=%d < header", len(raw))
	}
	if binary.BigEndian.Uint16(raw[0:2]) != 0x0001 {
		t.Error("not a Binding Request method")
	}
	if binary.BigEndian.Uint32(raw[4:8]) != 0x2112A442 {
		t.Error("cookie is not at bytes 4..8")
	}
	if headerLen+int(binary.BigEndian.Uint16(raw[2:4])) != len(raw) {
		t.Error("declared attribute length does not account for the whole datagram")
	}
}

// attr is a test-side STUN attribute, so a response can be built with something the
// coordinator would never send.
type attr struct {
	typ uint16
	val []byte
}

// encodeResponse builds a Binding Success Response carrying XOR-MAPPED-ADDRESS for ap,
// then extra, then a correct FINGERPRINT. Independent of the production encoder on
// purpose: these tests need to produce shapes coldstart.BindingResponse cannot.
func encodeResponse(tx [12]byte, ap netip.AddrPort, extra ...attr) []byte {
	addr := ap.Addr()
	var val []byte
	port := ap.Port() ^ 0x2112
	if addr.Is4() {
		a := addr.As4()
		for i := range a {
			a[i] ^= magicCookieBytes[i]
		}
		val = append([]byte{0, 0x01, 0, 0}, a[:]...)
	} else {
		a := addr.As16()
		var key [16]byte
		copy(key[0:4], magicCookieBytes[:])
		copy(key[4:16], tx[:])
		for i := range a {
			a[i] ^= key[i]
		}
		val = append([]byte{0, 0x02, 0, 0}, a[:]...)
	}
	binary.BigEndian.PutUint16(val[2:4], port)

	attrs := append([]attr{{attrXORMappedAddr, val}}, extra...)
	body := encodeAttrsTest(attrs)

	// FINGERPRINT covers the message with the header length set as if the message
	// ended just after the FINGERPRINT attribute (RFC 5389 §15.5).
	hdr := make([]byte, headerLen)
	binary.BigEndian.PutUint16(hdr[0:2], bindingResponse)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)+8))
	binary.BigEndian.PutUint32(hdr[4:8], magicCookie)
	copy(hdr[8:20], tx[:])
	fp := make([]byte, 4)
	binary.BigEndian.PutUint32(fp, crc32.ChecksumIEEE(append(append([]byte{}, hdr...), body...))^fingerprintXOR)

	body = encodeAttrsTest(append(attrs, attr{attrFingerprint, fp}))
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)))
	return append(hdr, body...)
}

func encodeAttrsTest(attrs []attr) []byte {
	var out []byte
	for _, a := range attrs {
		h := make([]byte, 4)
		binary.BigEndian.PutUint16(h[0:2], a.typ)
		binary.BigEndian.PutUint16(h[2:4], uint16(len(a.val)))
		out = append(out, h...)
		out = append(out, a.val...)
		if pad := len(a.val) % 4; pad != 0 {
			out = append(out, make([]byte, 4-pad)...)
		}
	}
	return out
}

func TestParseBindingResponse_v4(t *testing.T) {
	tx := newTxID()
	want := netip.MustParseAddrPort("203.0.113.5:51820")
	got, err := parseBindingResponse(encodeResponse(tx, want), tx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reflexive != want {
		t.Fatalf("reflexive %s, want %s", got.Reflexive, want)
	}
	if got.Len != wantLenV4 {
		t.Errorf("len=%d, want %d (20 header + 12 XOR-MAPPED-ADDRESS + 8 FINGERPRINT)", got.Len, wantLenV4)
	}
	if !got.ExactShape {
		t.Error("ExactShape=false for exactly the two attributes ADR-0060 sends")
	}
}

func TestParseBindingResponse_v6(t *testing.T) {
	tx := newTxID()
	want := netip.MustParseAddrPort("[2001:db8::1]:3478")
	got, err := parseBindingResponse(encodeResponse(tx, want), tx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Reflexive != want {
		t.Fatalf("reflexive %s, want %s", got.Reflexive, want)
	}
	if got.Len != wantLenV6 || !got.ExactShape {
		t.Errorf("len=%d exact=%v, want %d/true", got.Len, got.ExactShape, wantLenV6)
	}
}

// An extra attribute is not an error — it is a DIFFERENT SERVER, and the probe's job
// is to say so rather than to fail. This is the reading that separates "the
// coordinator answered" from "something on this port answered".
func TestParseBindingResponse_ExtraAttributeIsNotThisCoordinatorsShape(t *testing.T) {
	tx := newTxID()
	raw := encodeResponse(tx, netip.MustParseAddrPort("203.0.113.5:1234"), attr{0x8022, []byte("other-stun\x00\x00")})
	got, err := parseBindingResponse(raw, tx)
	if err != nil {
		t.Fatalf("a SOFTWARE-bearing response is still valid STUN and must parse: %v", err)
	}
	if got.ExactShape {
		t.Error("ExactShape=true for a response carrying a third attribute")
	}
}

func TestParseBindingResponse_Rejections(t *testing.T) {
	tx := newTxID()
	ap := netip.MustParseAddrPort("203.0.113.5:1234")
	good := encodeResponse(tx, ap)

	t.Run("transaction id mismatch", func(t *testing.T) {
		if _, err := parseBindingResponse(good, newTxID()); err != errTxMismatch {
			t.Fatalf("got %v, want errTxMismatch — a reply to somebody else's request is a false PASS", err)
		}
	})
	t.Run("not a response", func(t *testing.T) {
		if _, err := parseBindingResponse(buildBindingRequest(tx), tx); err != errNotResp {
			t.Fatalf("got %v, want errNotResp", err)
		}
	})
	t.Run("bad cookie", func(t *testing.T) {
		bad := append([]byte{}, good...)
		bad[5] ^= 0xff
		if _, err := parseBindingResponse(bad, tx); err != errBadCookie {
			t.Fatalf("got %v, want errBadCookie", err)
		}
	})
	t.Run("length does not account for the datagram", func(t *testing.T) {
		bad := append(append([]byte{}, good...), 0, 0, 0, 0)
		if _, err := parseBindingResponse(bad, tx); err != errBadLength {
			t.Fatalf("got %v, want errBadLength — over UDP the message IS the datagram", err)
		}
	})
	t.Run("corrupted fingerprint", func(t *testing.T) {
		bad := append([]byte{}, good...)
		bad[len(bad)-1] ^= 0x01
		if _, err := parseBindingResponse(bad, tx); err != errBadFP {
			t.Fatalf("got %v, want errBadFP", err)
		}
	})
	t.Run("no fingerprint", func(t *testing.T) {
		// A response with only XOR-MAPPED-ADDRESS: what a STUN server that omits
		// FINGERPRINT sends. Valid RFC 5389; not what this coordinator sends.
		raw := encodeResponse(tx, ap)
		body := raw[headerLen : headerLen+12]
		hdr := append([]byte{}, raw[:headerLen]...)
		binary.BigEndian.PutUint16(hdr[2:4], 12)
		if _, err := parseBindingResponse(append(hdr, body...), tx); err != errNoFP {
			t.Fatalf("got %v, want errNoFP", err)
		}
	})
	t.Run("short", func(t *testing.T) {
		if _, err := parseBindingResponse(good[:8], tx); err != errShort {
			t.Fatalf("got %v, want errShort", err)
		}
	})
}

// The one that matters: this probe's INDEPENDENT parser must accept the bytes the
// PRODUCTION encoder emits — coldstart.BindingResponse, which is what
// cmd/coordinator's answerSTUN calls. Everything else in this file tests the parser
// against a fixture written beside it, and a fixture written beside a parser can be
// wrong in the same direction as the parser. This is the only test in which the two
// halves were written by different code paths for different purposes.
func TestParser_AcceptsTheProductionEncoder(t *testing.T) {
	for _, want := range []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.5:51820"),
		netip.MustParseAddrPort("[2001:db8::1]:3478"),
	} {
		tx := newTxID()
		raw, ok := coldstart.BindingResponse(buildBindingRequest(tx), want)
		if !ok {
			t.Fatalf("coldstart.BindingResponse refused this probe's own Binding Request for %s — "+
				"the probe is sending something the coordinator will not answer", want)
		}
		got, err := parseBindingResponse(raw, tx)
		if err != nil {
			t.Fatalf("production encoder -> this parser (%s): %v", want, err)
		}
		if got.Reflexive != want {
			t.Errorf("reflexive %s, want %s", got.Reflexive, want)
		}
		if !got.ExactShape {
			t.Errorf("%s: ExactShape=false against the production encoder — wantLenV4/wantLenV6 no longer "+
				"describe what cmd/coordinator sends, so every real probe will print the caveat", want)
		}
	}
}
