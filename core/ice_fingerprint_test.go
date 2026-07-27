package core

import (
	"strings"
	"testing"

	dtlsElliptic "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// --- ICE credential fingerprint (issue #49, lever 1) -------------------------

// onlyICEChars reports whether every character of s is in the RFC 5245 ice-char
// set we draw from. Notably this set includes digits and '+' / '/', which pion's
// letters-only default does not.
func onlyICEChars(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune(iceCharset, c) {
			return false
		}
	}
	return true
}

// TestBrowserICECredentials checks the generator's contract: the uniform
// libwebrtc shape (4/24) for every profile, drawn from the ICE-char set, above
// pion's insufficient-bits floor, and fresh on each call.
func TestBrowserICECredentials(t *testing.T) {
	for _, p := range []dtlsProfile{chromeProfile(), firefoxProfile()} {
		ufrag, pwd, err := browserICECredentials(p)
		if err != nil {
			t.Fatalf("%s: browserICECredentials: %v", p.name, err)
		}
		if len(ufrag) != chromeICEShape.ufragLen || len(pwd) != chromeICEShape.pwdLen {
			t.Errorf("%s: shape = %d/%d, want %d/%d (uniform libwebrtc)",
				p.name, len(ufrag), len(pwd), chromeICEShape.ufragLen, chromeICEShape.pwdLen)
		}
		if !onlyICEChars(ufrag) || !onlyICEChars(pwd) {
			t.Errorf("%s: creds use non-ICE chars: ufrag=%q pwd=%q", p.name, ufrag, pwd)
		}
		// pion rejects len(ufrag)*8 < 24 and len(pwd)*8 < 128 as "insufficient bits".
		if len(ufrag)*8 < 24 || len(pwd)*8 < 128 {
			t.Errorf("%s: below pion's floor: ufrag=%d bits, pwd=%d bits", p.name, len(ufrag)*8, len(pwd)*8)
		}
	}

	// Fresh per call (crypto/rand): two draws must not collide.
	u1, p1, _ := browserICECredentials(chromeProfile())
	u2, p2, _ := browserICECredentials(chromeProfile())
	if u1 == u2 || p1 == p2 {
		t.Errorf("credentials not fresh per call: ufrag %q/%q pwd %q/%q", u1, u2, p1, p2)
	}
}

// TestICECharsetWiderThanPion proves the alphabet is the full ICE-char set, not
// pion's letters-only one: a long draw is statistically certain to include a
// non-letter, and every character must stay inside iceCharset.
func TestICECharsetWiderThanPion(t *testing.T) {
	s, err := randomICEString(2000)
	if err != nil {
		t.Fatalf("randomICEString: %v", err)
	}
	if !onlyICEChars(s) {
		t.Fatal("randomICEString produced a character outside iceCharset")
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return // saw a digit or '+'/'/': wider than pion's letters-only alphabet
		}
	}
	t.Error("2000-char draw contained only letters; charset no wider than pion's")
}

// sdpAttr returns the value of the first "a=<attr>:VALUE" line in an SDP, or "".
func sdpAttr(sdp, attr string) string {
	prefix := "a=" + attr + ":"
	for _, line := range strings.Split(sdp, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	return ""
}

// offerICECreds builds one PeerConnection through the transport (a data channel
// gives the offer an m=application section carrying the ICE credentials) and
// returns the ufrag/pwd its offer advertises. CreateOffer does not gather, so
// this stays hermetic — no sockets, no STUN.
func offerICECreds(t *testing.T, tr *webrtcTransport) (ufrag, pwd string) {
	t.Helper()
	pc, err := tr.newPC()
	if err != nil {
		t.Fatalf("newPC: %v", err)
	}
	defer func() { _ = pc.Close() }()
	if _, err := pc.CreateDataChannel("probe", nil); err != nil {
		t.Fatalf("CreateDataChannel: %v", err)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatalf("CreateOffer: %v", err)
	}
	return sdpAttr(offer.SDP, "ice-ufrag"), sdpAttr(offer.SDP, "ice-pwd")
}

// TestPerConnectionICECredentials is lever 1's core proof: two PeerConnections
// from the *same* transport advertise browser-shaped ICE credentials that are
// different from each other — i.e. the reshape is per-connection, not one static
// pair reused fleet-wide (which would be a stronger fingerprint than pion's
// default, the trap issue #49 calls out).
func TestPerConnectionICECredentials(t *testing.T) {
	tr := newWebRTCTransport(Config{DTLSFingerprint: FingerprintChrome}, nil)
	uf1, pw1 := offerICECreds(t, tr)
	uf2, pw2 := offerICECreds(t, tr)

	for _, c := range []struct{ name, ufrag, pwd string }{{"conn1", uf1, pw1}, {"conn2", uf2, pw2}} {
		if len(c.ufrag) != chromeICEShape.ufragLen {
			t.Errorf("%s: ufrag len = %d (%q), want %d", c.name, len(c.ufrag), c.ufrag, chromeICEShape.ufragLen)
		}
		if len(c.pwd) != chromeICEShape.pwdLen {
			t.Errorf("%s: pwd len = %d, want %d", c.name, len(c.pwd), chromeICEShape.pwdLen)
		}
		if !onlyICEChars(c.ufrag) || !onlyICEChars(c.pwd) {
			t.Errorf("%s: non-ICE chars: ufrag=%q pwd=%q", c.name, c.ufrag, c.pwd)
		}
	}
	if uf1 == uf2 || pw1 == pw2 {
		t.Errorf("ICE creds reused across connections: ufrag %q/%q pwd %q/%q", uf1, uf2, pw1, pw2)
	}
}

// TestICECredentialsOffKeepsPionDefault confirms the reshape is gated on the
// DTLS fingerprint being active: with "off", the offer keeps pion's default
// 16/32 credentials (pinned pion behavior — see pion/ice rand.go), so we don't
// silently alter a debugging/interop baseline.
func TestICECredentialsOffKeepsPionDefault(t *testing.T) {
	tr := newWebRTCTransport(Config{DTLSFingerprint: FingerprintOff}, nil)
	ufrag, pwd := offerICECreds(t, tr)
	if len(ufrag) != 16 || len(pwd) != 32 {
		t.Errorf("off mode should keep pion's default 16/32, got ufrag=%d pwd=%d", len(ufrag), len(pwd))
	}
}

// --- mDNS wiring (issue #49, lever 2) ----------------------------------------

// TestMDNSTransportBuildsPeerConnection is a smoke test: with ICEmDNS on, the
// transport still builds a PeerConnection (the mDNS mode is a valid enum and the
// wiring holds). It stops short of gathering — .local candidate resolution over
// loopback is exactly the connectivity trade-off that keeps mDNS off by default.
func TestMDNSTransportBuildsPeerConnection(t *testing.T) {
	tr := newWebRTCTransport(Config{DTLSFingerprint: FingerprintChrome, ICEmDNS: true}, nil)
	if !tr.mdns {
		t.Fatal("ICEmDNS not propagated to the transport")
	}
	pc, err := tr.newPC()
	if err != nil {
		t.Fatalf("newPC with mDNS enabled failed: %v", err)
	}
	_ = pc.Close()
}

// --- DTLS ServerHello reshape (issue #49, lever 3) ---------------------------

func extTypeList(list []extension.Extension) []extension.TypeValue {
	out := make([]extension.TypeValue, len(list))
	for i, e := range list {
		out[i] = e.TypeValue()
	}
	return out
}

func typeSeqEqual(a, b []extension.TypeValue) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameTypeSet(a, b []extension.TypeValue) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[extension.TypeValue]int{}
	for _, x := range a {
		count[x]++
	}
	for _, x := range b {
		count[x]--
	}
	for _, v := range count {
		if v != 0 {
			return false
		}
	}
	return true
}

// TestRewriteServerHelloReordersAndPreserves checks the ServerHello reshape: it
// reorders the answerer's extensions to serverExtOrder while preserving the
// whole set (nothing dropped or added), and lands on an order distinct from
// pion's. Transcript validity of the reorder is covered end to end by
// TestWebRTCHandshakeAcrossFingerprints, whose accepter is the DTLS server.
func TestRewriteServerHelloReordersAndPreserves(t *testing.T) {
	// A ServerHello shaped like pion's, extensions in pion's fixed emit order:
	// extended_master_secret, renegotiation_info, ec_point_formats, alpn.
	in := handshake.MessageServerHello{
		Extensions: []extension.Extension{
			&extension.UseExtendedMasterSecret{Supported: true},
			&extension.RenegotiationInfo{RenegotiatedConnection: 0},
			&extension.SupportedPointFormats{PointFormats: []dtlsElliptic.CurvePointFormat{dtlsElliptic.CurvePointFormatUncompressed}},
			&extension.ALPN{ProtocolNameList: []string{"h2"}},
		},
	}
	inOrder := extTypeList(in.Extensions)

	out, ok := rewriteServerHello(in).(*handshake.MessageServerHello)
	if !ok {
		t.Fatalf("rewriteServerHello returned %T, want *handshake.MessageServerHello", rewriteServerHello(in))
	}
	gotOrder := extTypeList(out.Extensions)

	// Set preserved — nothing dropped or added, so every negotiated parameter
	// still travels.
	if !sameTypeSet(gotOrder, inOrder) {
		t.Errorf("extension set changed: %v -> %v", inOrder, gotOrder)
	}
	// Order now follows serverExtOrder (renegotiation_info leads, ems next, ...).
	wantOrder := []extension.TypeValue{
		extension.RenegotiationInfoTypeValue,
		extension.UseExtendedMasterSecretTypeValue,
		extension.SupportedPointFormatsTypeValue,
		extension.ALPNTypeValue,
	}
	if !typeSeqEqual(gotOrder, wantOrder) {
		t.Errorf("server ext order = %v, want %v", gotOrder, wantOrder)
	}
	// And it is no longer pion's input order (the whole point of the reshape).
	if typeSeqEqual(gotOrder, inOrder) {
		t.Error("rewriteServerHello left pion's extension order unchanged")
	}
}
