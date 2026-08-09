// A dependency-free reader for the three shapes that can appear on the
// rendezvous 5-tuple: a STUN message, a DTLS record, and cleartext JSON.
//
// # Why this is hand-rolled next to core/coldstart and core/rendezvous, which
// already classify these bytes
//
// Because this file is the INSTRUMENT and those are the things being measured.
// core/rendezvous.LooksLikeDTLS is what the client and the coordinator use to
// decide what they just received; coldstart.BindingRequest is what builds the
// check the client sends. A tap built out of either would agree with a bug in
// it and report a clean wire, which is the one failure an instrument must not
// have. cmd/coordinator-probe hand-rolls its own STUN reader for exactly this
// reason and says so in the same words.
//
// The loop is closed from the other side rather than left as an assertion:
// classify_test.go runs this reader against the PRODUCTION encoders — the real
// coldstart.BindingRequest a client emits, and the real
// core/rendezvous.LooksLikeDTLS — so "independent" does not become "wrong".
//
// It implements only what the tap reports. No attribute parsing, no
// MESSAGE-INTEGRITY, no decryption of anything: the whole point of the shaped
// hop is that the payload is opaque on the wire, and a tap that could read it
// would be reporting on a hop that had not been shaped.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// The families a datagram on this 5-tuple can belong to. Reported as text
// because everything this tool produces is read by a person watching a testbed
// run, not parsed by another program.
const (
	familySTUN  = "STUN"
	familyDTLS  = "DTLS"
	familyJSON  = "JSON"
	familyOther = "other"
)

const (
	stunHeaderLen = 20
	// magicCookie is RFC 5389 §6's constant at bytes 4..8. It is what separates
	// STUN from RFC 3489's classic header and from everything else.
	magicCookie = 0x2112A442

	// STUN method and class, decoded from the 14 scattered type bits rather than
	// compared against whole 16-bit values. Comparing whole values works for the
	// four Binding messages and quietly mislabels every other method, and an
	// instrument that says "Binding Request" about an Allocate is worse than one
	// that says "unknown".
	methodBinding = 0x001

	classRequest    = 0x0
	classIndication = 0x1
	classSuccess    = 0x2
	classError      = 0x3
)

const (
	// A DTLS record header: type(1) version(2) epoch(2) sequence(6) length(2).
	dtlsHeaderLen = 13

	// The ContentTypes RFC 6347 defines, plus 25 (connection_id, RFC 9146).
	dtlsChangeCipherSpec = 20
	dtlsAlert            = 21
	dtlsHandshake        = 22
	dtlsApplicationData  = 23
	dtlsConnectionID     = 25
)

// jsonTell is the byte string ADR-0059 exists to remove from this hop and the
// literal #212 step 2 names. It is checked as a SUBSTRING, not as a prefix: a
// datagram that carries it anywhere at all is a datagram a DPI box can read.
var jsonTell = []byte(`{"type"`)

// observation is everything the tap keeps about one datagram. It deliberately
// does NOT include the bytes.
//
// The datagrams on this hop carry admission credentials, device credentials and
// issuer certs. An instrument that retained them would be a file full of
// credentials sitting on a testbed machine, so the payload is classified as it
// is forwarded and then dropped: what survives is a size and a sentence.
type observation struct {
	size int

	family string
	// detail is the human-readable half: "Binding Request", "handshake record,
	// DTLS 1.2", and so on. Never empty.
	detail string

	// leading is the datagram's first byte, kept because two of the four
	// assertions are stated in terms of it and because it is the one byte worth
	// naming when a datagram is none of the three shapes.
	leading byte
	empty   bool

	// bindingRequest and dtlsHandshake are the two assertions this reader can
	// settle on its own, precomputed so the summary reads them rather than
	// re-deriving them from prose.
	bindingRequest bool
	dtlsHandshake  bool

	// carriesJSONTell is the third. offset is where, for a datagram that does.
	carriesJSONTell bool
	jsonTellOffset  int
}

// classify reads one datagram and says what it is. It never fails: an
// unrecognised datagram is a result, not an error, and one that the tap must
// still report a size for.
func classify(raw []byte) observation {
	o := observation{
		size:   len(raw),
		family: familyOther,
		empty:  len(raw) == 0,
	}
	if len(raw) > 0 {
		o.leading = raw[0]
	}
	if i := bytes.Index(raw, jsonTell); i >= 0 {
		o.carriesJSONTell = true
		o.jsonTellOffset = i
	}

	switch {
	case len(raw) == 0:
		o.detail = "empty datagram"
	case describeSTUN(raw) != "":
		o.family = familySTUN
		o.detail = describeSTUN(raw)
		o.bindingRequest = stunIsBindingRequest(raw)
	case describeDTLS(raw) != "":
		o.family = familyDTLS
		o.detail = describeDTLS(raw)
		o.dtlsHandshake = raw[0] == dtlsHandshake
	case o.carriesJSONTell || raw[0] == '{':
		o.family = familyJSON
		o.detail = "cleartext JSON"
	default:
		o.detail = fmt.Sprintf("unrecognised, leading byte 0x%02x", raw[0])
	}
	return o
}

// stunHeaderOK applies the four tests that make a datagram conclusively a STUN
// message, in RFC 5389 §7.3's own terms.
//
// The last of them — that the declared attribute length accounts for every
// remaining byte — is what makes this safe to run against arbitrary UDP: over
// UDP a STUN message IS the datagram, so "the length fits" is not enough, and
// core/coldstart.LooksLikeBindingSuccess and cmd/coordinator's looksLikeSTUN
// both make the same distinction.
func stunHeaderOK(raw []byte) bool {
	if len(raw) < stunHeaderLen {
		return false
	}
	if raw[0]&0xC0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(raw[4:8]) != magicCookie {
		return false
	}
	n := int(binary.BigEndian.Uint16(raw[2:4]))
	if n%4 != 0 {
		return false
	}
	return stunHeaderLen+n == len(raw)
}

// stunMethodClass decodes RFC 5389 §6's interleaved type field: the 12 method
// bits and the 2 class bits are scattered through the 16-bit value so that the
// two leading zeros stay where RFC 3489 put a message type.
func stunMethodClass(t uint16) (method, class uint16) {
	method = (t & 0x000F) | ((t & 0x00E0) >> 1) | ((t & 0x3E00) >> 2)
	class = ((t & 0x0100) >> 7) | ((t & 0x0010) >> 4)
	return method, class
}

func stunIsBindingRequest(raw []byte) bool {
	if !stunHeaderOK(raw) {
		return false
	}
	method, class := stunMethodClass(binary.BigEndian.Uint16(raw[0:2]))
	return method == methodBinding && class == classRequest
}

// describeSTUN returns a sentence for a STUN message, or "" for a datagram that
// is not one.
func describeSTUN(raw []byte) string {
	if !stunHeaderOK(raw) {
		return ""
	}
	method, class := stunMethodClass(binary.BigEndian.Uint16(raw[0:2]))
	name := "Binding"
	if method != methodBinding {
		name = fmt.Sprintf("method 0x%03x", method)
	}
	switch class {
	case classRequest:
		return name + " Request"
	case classIndication:
		return name + " Indication"
	case classSuccess:
		return name + " Success Response"
	case classError:
		return name + " Error Response"
	}
	return name
}

// describeDTLS returns a sentence for a datagram that begins with a DTLS record,
// or "" for one that does not.
//
// It walks the whole datagram rather than reading the first header and stopping,
// because DTLS permits several records in one datagram and a handshake flight
// normally is several. The count is the number this hop's budget is being spent
// on, so an instrument that reported "1 record" for a coalesced flight would be
// describing the wrong thing.
func describeDTLS(raw []byte) string {
	if !looksLikeDTLSRecord(raw) {
		return ""
	}
	var kinds []string
	off, records := 0, 0
	for off+dtlsHeaderLen <= len(raw) && looksLikeDTLSRecord(raw[off:]) {
		n := int(binary.BigEndian.Uint16(raw[off+11 : off+13]))
		kinds = append(kinds, dtlsContentType(raw[off]))
		records++
		off += dtlsHeaderLen + n
		if off > len(raw) {
			break
		}
	}
	version := dtlsVersion(raw[1], raw[2])
	switch {
	case off != len(raw):
		// Not refused, reported. A flight whose record lengths do not add up to
		// the datagram is exactly the kind of thing worth seeing on a testbed,
		// and an instrument that swallowed it would be hiding its own best find.
		return fmt.Sprintf("%s record (%s), record lengths do not account for the datagram (%d of %d bytes)",
			kinds[0], version, off, len(raw))
	case records == 1:
		return fmt.Sprintf("%s record (%s)", kinds[0], version)
	default:
		return fmt.Sprintf("%d records (%s): %s", records, version, strings.Join(kinds, ", "))
	}
}

// looksLikeDTLSRecord applies the three facts that make a record conclusive: a
// known ContentType, a version whose major byte is 0xfe (DTLS versions are the
// 1's complement of their TLS counterparts), and enough bytes for its own
// header. No JSON value can begin with any of those ContentTypes, so the sets
// are disjoint on the first byte and the version check is what turns "unlikely
// to be confused" into "cannot be".
func looksLikeDTLSRecord(raw []byte) bool {
	if len(raw) < dtlsHeaderLen {
		return false
	}
	switch raw[0] {
	case dtlsChangeCipherSpec, dtlsAlert, dtlsHandshake, dtlsApplicationData, dtlsConnectionID:
	default:
		return false
	}
	return raw[1] == 0xfe && (raw[2] == 0xff || raw[2] == 0xfd)
}

func dtlsContentType(b byte) string {
	switch b {
	case dtlsChangeCipherSpec:
		return "change_cipher_spec"
	case dtlsAlert:
		return "alert"
	case dtlsHandshake:
		return "handshake"
	case dtlsApplicationData:
		return "application_data"
	case dtlsConnectionID:
		return "connection_id"
	}
	return fmt.Sprintf("content type %d", b)
}

func dtlsVersion(major, minor byte) string {
	switch {
	case major == 0xfe && minor == 0xff:
		return "DTLS 1.0"
	case major == 0xfe && minor == 0xfd:
		return "DTLS 1.2"
	}
	return fmt.Sprintf("version 0x%02x%02x", major, minor)
}
