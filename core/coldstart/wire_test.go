package coldstart

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/pion/stun/v3"
)

func TestBuildRequestUnauthenticatedParses(t *testing.T) {
	tx := newTxID()
	raw := buildRequest(tx, "", nil)
	m, err := parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.typ != typeBindingRequest {
		t.Fatalf("typ = %#x, want binding request", m.typ)
	}
	if m.tx != tx {
		t.Fatalf("tx mismatch")
	}
	if _, ok := m.get(attrUsername); ok {
		t.Fatalf("unauthenticated request should carry no USERNAME")
	}
	if _, ok := m.get(attrFingerprint); !ok {
		t.Fatalf("expected FINGERPRINT attribute")
	}
}

func TestAuthenticatedRequestMessageIntegrityVerifies(t *testing.T) {
	tx := newTxID()
	secret := []byte("super-secret-key-material------")
	raw := buildRequest(tx, "deadbeefcafef00d", secret)

	off := messageIntegrityOffset(raw)
	if off < 0 {
		t.Fatalf("MESSAGE-INTEGRITY attribute not found")
	}
	if !verifyMessageIntegrity(raw, off, secret) {
		t.Fatalf("MESSAGE-INTEGRITY should verify with the correct secret")
	}
	if verifyMessageIntegrity(raw, off, []byte("wrong-key-wrong-key-wrong-key!!")) {
		t.Fatalf("MESSAGE-INTEGRITY verified with the wrong secret")
	}

	tampered := append([]byte(nil), raw...)
	tampered[headerLen] ^= 0xFF // flip a byte inside the USERNAME attribute
	if verifyMessageIntegrity(tampered, off, secret) {
		t.Fatalf("MESSAGE-INTEGRITY verified after tampering with a covered byte")
	}
}

func TestBuildResponseRoundTripsXORMappedAddress(t *testing.T) {
	tx := newTxID()
	addr := netip.MustParseAddrPort("203.0.113.7:51820")
	raw := buildResponse(tx, addr, nil)

	m, err := parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.typ != typeBindingSuccess {
		t.Fatalf("typ = %#x, want binding success", m.typ)
	}
	val, ok := m.get(attrXORMappedAddress)
	if !ok {
		t.Fatalf("missing XOR-MAPPED-ADDRESS")
	}
	got, ok := decodeXORMapped(val, tx)
	if !ok || got != addr {
		t.Fatalf("decodeXORMapped = %v, %v; want %v, true", got, ok, addr)
	}
	if _, ok := m.get(attrSnapshot); ok {
		t.Fatalf("unauthenticated response should carry no SNAPSHOT attribute")
	}
}

func TestBuildResponseCarriesSnapshotWhenGiven(t *testing.T) {
	tx := newTxID()
	addr := netip.MustParseAddrPort("198.51.100.9:3478")
	payload := []byte(`{"fake":"signed snapshot bytes"}`)
	raw := buildResponse(tx, addr, payload)

	m, err := parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	val, ok := m.get(attrSnapshot)
	if !ok {
		t.Fatalf("missing SNAPSHOT attribute")
	}
	if string(val) != string(payload) {
		t.Fatalf("snapshot payload = %q, want %q", val, payload)
	}
}

// TestBuildResponseCarriesFingerprint pins issue #46: a Binding Success
// Response must carry FINGERPRINT, as the last attribute (RFC 5389 §15.5),
// regardless of whether SNAPSHOT is present — matching the shape pion/turn's
// own Binding Success response carries on the same shared port (issue #30).
func TestBuildResponseCarriesFingerprint(t *testing.T) {
	tx := newTxID()
	addr := netip.MustParseAddrPort("198.51.100.9:3478")

	for name, raw := range map[string][]byte{
		"unauthenticated": buildResponse(tx, addr, nil),
		"authenticated":   buildResponse(tx, addr, []byte("snapshot bytes")),
	} {
		m, err := parse(raw)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if _, ok := m.get(attrFingerprint); !ok {
			t.Fatalf("%s: expected FINGERPRINT attribute", name)
		}
		if last := m.attrs[len(m.attrs)-1]; last.typ != attrFingerprint {
			t.Fatalf("%s: FINGERPRINT must be the last attribute, last was %#x", name, last.typ)
		}
	}
}

// TestBuildResponseMatchesPionTurnShape pins byte-for-byte parity against
// pion/turn's actual Binding Success response (built with the real pion/stun
// library, not a hand-rolled reimplementation of what we think it does) —
// XOR-MAPPED-ADDRESS + FINGERPRINT, nothing else. This is what issue #46
// flagged as missing: without it, the two response shapes sharing the port
// since issue #30 were trivially separable by a censor doing shape analysis.
func TestBuildResponseMatchesPionTurnShape(t *testing.T) {
	tx := newTxID()
	addr := netip.MustParseAddrPort("203.0.113.7:51820")

	ours := buildResponse(tx, addr, nil)

	theirs := stun.MustBuild(
		&stun.Message{TransactionID: tx},
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: addr.Addr().AsSlice(), Port: int(addr.Port())},
		stun.Fingerprint,
	).Raw

	if !bytes.Equal(ours, theirs) {
		t.Fatalf("buildResponse = % x\nwant byte-identical to pion/turn's own shape = % x", ours, theirs)
	}
}

func TestUnauthenticatedAndAuthenticatedResponsesAreShapeIdentical(t *testing.T) {
	// The whole point of the design (docs/design/bootstrap-protocol.md): a
	// prober without the secret must not be able to tell "wrong secret" apart
	// from "right secret, endpoint just doesn't like me" by response shape —
	// only by the (absent) SNAPSHOT attribute, which requires already having
	// solved the credential.
	tx := newTxID()
	addr := netip.MustParseAddrPort("192.0.2.55:3478")
	plain := buildResponse(tx, addr, nil)
	withSnap := buildResponse(tx, addr, []byte("x"))

	mp, err := parse(plain)
	if err != nil {
		t.Fatalf("parse plain: %v", err)
	}
	ms, err := parse(withSnap)
	if err != nil {
		t.Fatalf("parse withSnap: %v", err)
	}
	if mp.typ != ms.typ {
		t.Fatalf("type differs between authenticated/unauthenticated response")
	}
	pv, _ := mp.get(attrXORMappedAddress)
	sv, _ := ms.get(attrXORMappedAddress)
	if string(pv) != string(sv) {
		t.Fatalf("XOR-MAPPED-ADDRESS differs between authenticated/unauthenticated response")
	}
}

func TestParseRejectsBadCookie(t *testing.T) {
	raw := buildRequest(newTxID(), "", nil)
	raw[4] ^= 0xFF
	if _, err := parse(raw); err != errBadCookie {
		t.Fatalf("parse with bad cookie: err = %v, want errBadCookie", err)
	}
}

func TestParseRejectsShortMessage(t *testing.T) {
	if _, err := parse([]byte{1, 2, 3}); err != errShortMessage {
		t.Fatalf("parse short message: err = %v, want errShortMessage", err)
	}
}
