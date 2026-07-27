package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestBuildBindingRequest(t *testing.T) {
	tx := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	b := buildBindingRequest(tx)
	if len(b) != 20 {
		t.Fatalf("len=%d, want 20", len(b))
	}
	if got := binary.BigEndian.Uint16(b[0:2]); got != bindingRequest {
		t.Errorf("type=%#x", got)
	}
	if got := binary.BigEndian.Uint16(b[2:4]); got != 0 {
		t.Errorf("attr len=%d, want 0", got)
	}
	if got := binary.BigEndian.Uint32(b[4:8]); got != magicCookie {
		t.Errorf("cookie=%#x", got)
	}
	if [12]byte(b[8:20]) != tx {
		t.Error("transaction id not echoed into header")
	}
}

// encodeXORMappedResp builds a Binding Success Response carrying a single
// XOR-MAPPED-ADDRESS, so the parse path can be round-tripped without a network.
func encodeXORMappedResp(tx [12]byte, ap netip.AddrPort) []byte {
	addr := ap.Addr()
	var fam byte
	var xaddr []byte
	port := ap.Port() ^ 0x2112
	if addr.Is4() {
		fam = 0x01
		a := addr.As4()
		for i := range a {
			a[i] ^= magicCookieBytes[i]
		}
		xaddr = a[:]
	} else {
		fam = 0x02
		a := addr.As16()
		var key [16]byte
		copy(key[0:4], magicCookieBytes[:])
		copy(key[4:16], tx[:])
		for i := range a {
			a[i] ^= key[i]
		}
		xaddr = a[:]
	}
	val := make([]byte, 4+len(xaddr))
	val[1] = fam
	binary.BigEndian.PutUint16(val[2:4], port)
	copy(val[4:], xaddr)

	attr := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(attr[0:2], attrXORMappedAddr)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(val)))
	copy(attr[4:], val)

	msg := make([]byte, 20+len(attr))
	binary.BigEndian.PutUint16(msg[0:2], bindingResponse)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[8:20], tx[:])
	copy(msg[20:], attr)
	return msg
}

func TestParseBindingResponse_XORv4(t *testing.T) {
	tx := newTxID()
	want := netip.MustParseAddrPort("203.0.113.5:51820")
	got, err := parseBindingResponse(encodeXORMappedResp(tx, want), tx)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestParseBindingResponse_XORv6(t *testing.T) {
	tx := newTxID()
	want := netip.MustParseAddrPort("[2001:db8::1]:3478")
	got, err := parseBindingResponse(encodeXORMappedResp(tx, want), tx)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestParseBindingResponse_TxMismatch(t *testing.T) {
	tx := newTxID()
	resp := encodeXORMappedResp(tx, netip.MustParseAddrPort("203.0.113.5:1234"))
	if _, err := parseBindingResponse(resp, newTxID()); err != errTxMismatch {
		t.Fatalf("got %v, want errTxMismatch", err)
	}
}

func TestParseBindingResponse_NotAResponse(t *testing.T) {
	tx := newTxID()
	if _, err := parseBindingResponse(buildBindingRequest(tx), tx); err != errNotResp {
		t.Fatalf("got %v, want errNotResp", err)
	}
}
