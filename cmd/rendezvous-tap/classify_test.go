package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/rendezvous"
)

// classify.go is written independently of the code it measures, and these are
// what stop "independent" from becoming "wrong": the reader is run against the
// PRODUCTION encoders and the PRODUCTION classifier, from the outside.
//
// cmd/coordinator-probe closes the same loop the same way, and its stun.go gives
// the reason in the same words: an instrument built from the thing it measures
// cancels out that thing's bugs, so the independence is the point — but an
// independent reader that disagrees with reality is worse than no reader, so the
// agreement is asserted rather than assumed.
//
// These imports are TEST-ONLY. The tap binary itself links neither package, and
// keeping it that way is what lets it be trusted about them.

func TestTheRealBindingRequestAClientSendsReadsAsOne(t *testing.T) {
	// The shape ADR-0060 has the client emit before its ClientHello: USERNAME,
	// MESSAGE-INTEGRITY and FINGERPRINT, not a bare request.
	raw := coldstart.BindingRequest("bacchus:tap", []byte("not-a-real-key"))
	got := classify(raw)
	if got.family != familySTUN {
		t.Fatalf("the client's own connectivity check classified as %s: %s", got.family, got.detail)
	}
	if !got.bindingRequest {
		t.Fatalf("the client's own connectivity check is not read as a Binding Request: %s", got.detail)
	}
	if got.detail != "Binding Request" {
		t.Errorf("detail = %q", got.detail)
	}
	if got.size != len(raw) {
		t.Errorf("size = %d, datagram was %d bytes", got.size, len(raw))
	}
}

func TestTheRealBindingResponseACoordinatorSendsReadsAsOne(t *testing.T) {
	req := coldstart.BindingRequest("bacchus:tap", []byte("not-a-real-key"))
	// RFC 5737 documentation address; nothing here reaches a network.
	resp, ok := coldstart.BindingResponse(req, netip.MustParseAddrPort("192.0.2.10:41000"))
	if !ok {
		t.Fatal("the production encoder refused to answer its own Binding Request")
	}
	got := classify(resp)
	if got.family != familySTUN || got.detail != "Binding Success Response" {
		t.Fatalf("the coordinator's answer classified as %s: %s", got.family, got.detail)
	}
	if got.bindingRequest {
		t.Error("a Binding Success Response was read as a Binding Request, which would satisfy the " +
			"first assertion with the wrong datagram")
	}
}

// The tap's DTLS reader and the one the client and coordinator route on must
// agree about every datagram, or the tap is describing a different wire than the
// one being spoken. core/rendezvous.LooksLikeDTLS is the production classifier
// (cmd/coordinator keeps a second copy, pinned against it over there).
func TestTheTwoDTLSReadersAgree(t *testing.T) {
	corpus := [][]byte{
		{},
		{0x16},
		{0x16, 0xfe, 0xfd},
		dtlsRecord(dtlsHandshake, 0),
		dtlsRecord(dtlsHandshake, 700),
		dtlsRecord(dtlsChangeCipherSpec, 1),
		dtlsRecord(dtlsAlert, 2),
		dtlsRecord(dtlsApplicationData, 900),
		dtlsRecord(dtlsConnectionID, 40),
		stunBindingRequest(),
		coldstart.BindingRequest("bacchus:tap", []byte("k")),
		[]byte(`{"type":"connect","geo":"NL"}`),
		bytes.Repeat([]byte{0x00}, 64),
		bytes.Repeat([]byte{0xff}, 64),
		// A record header whose version is TLS rather than DTLS: both readers
		// must refuse it, and this is the case a first-byte-only check passes.
		{0x16, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00},
	}
	for i, raw := range corpus {
		mine := looksLikeDTLSRecord(raw)
		theirs := rendezvous.LooksLikeDTLS(raw)
		if mine != theirs {
			t.Errorf("corpus[%d] (%d bytes, leading 0x%02x): the tap says DTLS=%v and "+
				"core/rendezvous says %v", i, len(raw), leadingByte(raw), mine, theirs)
		}
	}
}

func leadingByte(raw []byte) byte {
	if len(raw) == 0 {
		return 0
	}
	return raw[0]
}

// The STUN type field interleaves 12 method bits and 2 class bits, so comparing
// whole 16-bit values gets the four Binding messages right and mislabels
// everything else. An instrument that called an Allocate a Binding Request would
// satisfy the first assertion with a datagram that is not the one it names.
func TestTheSTUNTypeIsDecodedRatherThanCompared(t *testing.T) {
	for _, tc := range []struct {
		typ  uint16
		want string
	}{
		{0x0001, "Binding Request"},
		{0x0011, "Binding Indication"},
		{0x0101, "Binding Success Response"},
		{0x0111, "Binding Error Response"},
		{0x0003, "method 0x003 Request"}, // Allocate
		{0x0113, "method 0x003 Error Response"},
	} {
		raw := make([]byte, stunHeaderLen)
		binary.BigEndian.PutUint16(raw[0:2], tc.typ)
		binary.BigEndian.PutUint32(raw[4:8], magicCookie)
		got := classify(raw)
		if got.detail != tc.want {
			t.Errorf("type 0x%04x read as %q, want %q", tc.typ, got.detail, tc.want)
		}
		if want := tc.typ == 0x0001; got.bindingRequest != want {
			t.Errorf("type 0x%04x: bindingRequest = %v, want %v", tc.typ, got.bindingRequest, want)
		}
	}
}

// Over UDP a STUN message IS the datagram, so a declared length that does not
// account for every remaining byte means this is not one — whatever the first
// four bytes say. Without this, arbitrary UDP that happens to start with two zero
// bits and carry the cookie would be reported as a Binding Request.
func TestSTUNWhoseLengthDoesNotAccountForTheDatagramIsNotSTUN(t *testing.T) {
	for _, tc := range []struct {
		name    string
		declare uint16
		extra   int
	}{
		{"trailing bytes the header does not declare", 0, 8},
		{"a declared length longer than the datagram", 16, 0},
		{"a length that is not a multiple of four", 3, 3},
	} {
		raw := make([]byte, stunHeaderLen+tc.extra)
		binary.BigEndian.PutUint16(raw[0:2], 0x0001)
		binary.BigEndian.PutUint16(raw[2:4], tc.declare)
		binary.BigEndian.PutUint32(raw[4:8], magicCookie)
		if got := classify(raw); got.family == familySTUN {
			t.Errorf("%s: classified as STUN (%s)", tc.name, got.detail)
		}
	}
}

// A handshake flight is normally several records in one datagram, and the budget
// is spent on the datagram. A reader that stopped at the first header would
// describe a 756-byte flight as one record and hide what the rest of it was.
func TestACoalescedFlightIsCountedRecordByRecord(t *testing.T) {
	raw := append(dtlsRecord(dtlsHandshake, 100), dtlsRecord(dtlsHandshake, 200)...)
	raw = append(raw, dtlsRecord(dtlsChangeCipherSpec, 1)...)
	got := classify(raw)
	if got.family != familyDTLS {
		t.Fatalf("family = %s: %s", got.family, got.detail)
	}
	if !strings.Contains(got.detail, "3 records") {
		t.Errorf("detail = %q, want it to name 3 records", got.detail)
	}
	if !got.dtlsHandshake {
		t.Error("a flight whose FIRST record is a handshake must satisfy the 0x16 assertion")
	}
	if got.size != len(raw) {
		t.Errorf("size = %d, datagram was %d bytes", got.size, len(raw))
	}
}

// Record lengths that do not add up are reported rather than swallowed. That is
// the sort of thing worth seeing on a testbed, and a reader that quietly rounded
// it off to "one record" would be hiding its own best find.
func TestAFlightWhoseRecordLengthsDoNotAddUpSaysSo(t *testing.T) {
	raw := append(dtlsRecord(dtlsHandshake, 10), 0x99, 0x99)
	got := classify(raw)
	if got.family != familyDTLS {
		t.Fatalf("family = %s: %s", got.family, got.detail)
	}
	if !strings.Contains(got.detail, "do not account") {
		t.Errorf("detail = %q, want it to say the lengths do not account for the datagram", got.detail)
	}
}

func TestTheJSONTellIsFoundAtAnyOffset(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		want bool
		at   int
	}{
		{"at the front", []byte(`{"type":"connect"}`), true, 0},
		{"buried", append(bytes.Repeat([]byte{0x00}, 37), []byte(`{"type":"hello"}`)...), true, 37},
		{"inside a DTLS record", append(dtlsRecord(dtlsHandshake, 0), []byte(`{"type":"x"}`)...), true, dtlsHeaderLen},
		{"absent", []byte(`{"kind":"connect"}`), false, 0},
		{"absent, binary", bytes.Repeat([]byte{0x16}, 40), false, 0},
	} {
		got := classify(tc.raw)
		if got.carriesJSONTell != tc.want {
			t.Errorf("%s: carriesJSONTell = %v, want %v", tc.name, got.carriesJSONTell, tc.want)
		}
		if tc.want && got.jsonTellOffset != tc.at {
			t.Errorf("%s: offset = %d, want %d", tc.name, got.jsonTellOffset, tc.at)
		}
	}
}

// A zero-length UDP datagram is legal, arrives as n=0, and is the easiest thing
// in a proxy to mistake for end-of-stream. The classifier must have an answer for
// it rather than an index out of range.
func TestAnEmptyDatagramIsClassifiedRatherThanPanicking(t *testing.T) {
	got := classify(nil)
	if got.size != 0 || !got.empty {
		t.Fatalf("size = %d, empty = %v", got.size, got.empty)
	}
	if got.family != familyOther || got.detail == "" {
		t.Fatalf("family = %s, detail = %q", got.family, got.detail)
	}
	if got.bindingRequest || got.dtlsHandshake || got.carriesJSONTell {
		t.Error("an empty datagram satisfied one of the assertions")
	}
}
