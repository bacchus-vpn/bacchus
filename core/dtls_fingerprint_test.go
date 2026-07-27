package core

import (
	"context"
	"encoding/binary"
	"io"
	mrand "math/rand"
	"testing"
	"time"

	dtls "github.com/pion/dtls/v3"
	dtlsElliptic "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

// pionDefaultCiphers is the fixed cipher-suite list pion advertises by default —
// the static signature this change breaks (pion/dtls defaultCipherSuites()).
var pionDefaultCiphers = []uint16{0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc00a, 0xc014, 0xc02c, 0xc030}

// pionDefaultHello builds a ClientHello shaped like pion's default: the default
// cipher list and a representative set of the extensions pion always sends. It
// stands in for "what pion emits" so the tests can assert the rewrite changes
// it. isKnownExt below tracks which of these survive a peer's parse.
func pionDefaultHello() handshake.MessageClientHello {
	return handshake.MessageClientHello{
		Random:         handshake.Random{GMTUnixTime: time.Unix(0, 0)},
		CipherSuiteIDs: append([]uint16(nil), pionDefaultCiphers...),
		Extensions: []extension.Extension{
			&extension.SupportedEllipticCurves{EllipticCurves: []dtlsElliptic.Curve{dtlsElliptic.X25519, dtlsElliptic.P256, dtlsElliptic.P384}},
			&extension.SupportedPointFormats{PointFormats: []dtlsElliptic.CurvePointFormat{dtlsElliptic.CurvePointFormatUncompressed}},
			&extension.RenegotiationInfo{RenegotiatedConnection: 0},
			&extension.UseExtendedMasterSecret{Supported: true},
			&extension.ALPN{ProtocolNameList: []string{"h2"}},
		},
	}
}

func asHello(t *testing.T, m handshake.Message) *handshake.MessageClientHello {
	t.Helper()
	h, ok := m.(*handshake.MessageClientHello)
	if !ok {
		t.Fatalf("rewrite returned %T, want *handshake.MessageClientHello", m)
	}
	return h
}

func isGrease(v uint16) bool {
	for _, g := range greaseValues {
		if v == g {
			return true
		}
	}
	return false
}

func contains(list []uint16, v uint16) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// TestRewriteBreaksStaticPionSignature is the core acceptance check: the Chrome
// profile turns pion's default ClientHello into something that no longer matches
// the "pion default" cipher/extension signature, while staying a valid handshake
// a pion peer can complete.
func TestRewriteBreaksStaticPionSignature(t *testing.T) {
	r := mrand.New(mrand.NewSource(1))
	out := asHello(t, rewriteClientHello(pionDefaultHello(), chromeProfile(), r))

	// Cipher list must differ from pion's default and carry GREASE up front,
	// yet still advertise the suite pion actually negotiates.
	if sameU16(out.CipherSuiteIDs, pionDefaultCiphers) {
		t.Fatal("cipher list still matches the pion default signature")
	}
	if !isGrease(out.CipherSuiteIDs[0]) {
		t.Errorf("Chrome profile: first cipher %#x is not GREASE", out.CipherSuiteIDs[0])
	}
	if !contains(out.CipherSuiteIDs, uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)) {
		t.Error("negotiable suite ECDHE_ECDSA_AES128_GCM dropped from the advertised list")
	}

	// Extensions must be bracketed by two distinct GREASE extensions.
	first, ok1 := out.Extensions[0].(*rawExtension)
	last, ok2 := out.Extensions[len(out.Extensions)-1].(*rawExtension)
	if !ok1 || !ok2 {
		t.Fatalf("GREASE extensions not bracketing the list: first=%T last=%T", out.Extensions[0], out.Extensions[len(out.Extensions)-1])
	}
	if !isGrease(uint16(first.typ)) || !isGrease(uint16(last.typ)) {
		t.Errorf("bracket extension types not GREASE: %#x %#x", first.typ, last.typ)
	}
	if first.typ == last.typ {
		t.Error("the two GREASE extensions should use distinct values (RFC 8701)")
	}

	// A GREASE group must lead supported-groups, with the real curves retained.
	sg := findGroups(t, out.Extensions)
	if !isGrease(uint16(sg.EllipticCurves[0])) {
		t.Errorf("supported-groups does not lead with GREASE: %#x", sg.EllipticCurves[0])
	}
	if !hasCurve(sg.EllipticCurves, dtlsElliptic.X25519) {
		t.Error("X25519 dropped from supported-groups")
	}

	// The whole message must still marshal to valid wire bytes.
	if raw, err := out.Marshal(); err != nil || len(raw) == 0 {
		t.Fatalf("rewritten ClientHello does not marshal: %v (len %d)", err, len(raw))
	}
}

// TestPeerToleratesRewrittenExtensions proves a pion peer parses our reshaped
// extension list: known extensions survive, and the injected GREASE/raw
// extensions are skipped rather than rejected (pion's extension.Unmarshal
// ignores unknown types). The transcript stays consistent because pion hashes
// the raw received bytes, not the reparsed struct.
func TestPeerToleratesRewrittenExtensions(t *testing.T) {
	r := mrand.New(mrand.NewSource(7))
	out := asHello(t, rewriteClientHello(pionDefaultHello(), chromeProfile(), r))

	raw, err := extension.Marshal(out.Extensions)
	if err != nil {
		t.Fatalf("marshal rewritten extensions: %v", err)
	}
	parsed, err := extension.Unmarshal(raw)
	if err != nil {
		t.Fatalf("a pion peer failed to parse the rewritten extensions: %v", err)
	}

	// Every known extension type from the input must survive the peer's parse.
	for _, want := range []extension.TypeValue{
		extension.SupportedEllipticCurvesTypeValue,
		extension.SupportedPointFormatsTypeValue,
		extension.RenegotiationInfoTypeValue,
		extension.UseExtendedMasterSecretTypeValue,
		extension.ALPNTypeValue,
	} {
		if !hasExt(parsed, want) {
			t.Errorf("known extension %#x lost after peer parse", uint16(want))
		}
	}
	// The GREASE bracket extensions must be dropped by the peer (unknown types),
	// so the parsed count equals the known-extension count.
	if len(parsed) != 5 {
		t.Errorf("peer kept %d extensions, want 5 known (GREASE should be skipped)", len(parsed))
	}
}

// TestFirefoxProfileIsStableAndUngreased checks the Firefox profile reshapes the
// cipher list but adds no GREASE and injects no extra extensions — a distinct,
// stable browser shape rather than Chrome's per-connection variation.
func TestFirefoxProfileIsStableAndUngreased(t *testing.T) {
	base := pionDefaultHello()
	nExt := len(base.Extensions)
	out := asHello(t, rewriteClientHello(base, firefoxProfile(), mrand.New(mrand.NewSource(3))))

	if isGrease(out.CipherSuiteIDs[0]) {
		t.Error("Firefox profile should not prepend a GREASE cipher")
	}
	if sameU16(out.CipherSuiteIDs, pionDefaultCiphers) {
		t.Error("Firefox profile did not change the cipher list")
	}
	if len(out.Extensions) != nExt {
		t.Errorf("Firefox profile changed extension count %d -> %d; expected no injection", nExt, len(out.Extensions))
	}
	for _, e := range out.Extensions {
		if _, ok := e.(*rawExtension); ok {
			t.Error("Firefox profile injected a raw/GREASE extension")
		}
	}
}

// TestChromePermutesPerConnection verifies Chrome's per-connection variation:
// two connections differ in GREASE and (very likely) extension order, while the
// set of real extensions is unchanged.
func TestChromePermutesPerConnection(t *testing.T) {
	a := asHello(t, rewriteClientHello(pionDefaultHello(), chromeProfile(), mrand.New(mrand.NewSource(1))))
	b := asHello(t, rewriteClientHello(pionDefaultHello(), chromeProfile(), mrand.New(mrand.NewSource(2))))

	if a.CipherSuiteIDs[0] == b.CipherSuiteIDs[0] && orderEqual(a.Extensions, b.Extensions) {
		t.Error("two Chrome connections produced identical GREASE and extension order; not varying")
	}
	// Same real extensions present in both, regardless of order.
	for _, want := range []extension.TypeValue{
		extension.SupportedEllipticCurvesTypeValue,
		extension.RenegotiationInfoTypeValue,
		extension.UseExtendedMasterSecretTypeValue,
		extension.ALPNTypeValue,
	} {
		if hasExtTyped(a.Extensions, want) != hasExtTyped(b.Extensions, want) {
			t.Errorf("real extension %#x inconsistent across connections", uint16(want))
		}
	}
}

func TestGreaseValuesAreReserved(t *testing.T) {
	r := mrand.New(mrand.NewSource(42))
	for i := 0; i < 200; i++ {
		if !isGrease(greaseValue(r)) {
			t.Fatal("greaseValue produced a non-reserved code point")
		}
		x, y := twoGreaseValues(r)
		if !isGrease(x) || !isGrease(y) || x == y {
			t.Fatalf("twoGreaseValues invalid or equal: %#x %#x", x, y)
		}
	}
}

func TestProfileForModes(t *testing.T) {
	r := mrand.New(mrand.NewSource(1))
	cases := []struct {
		mode   string
		wantOK bool
	}{
		{"", true}, {FingerprintAuto, true}, {FingerprintChrome, true},
		{FingerprintFirefox, true}, {FingerprintOff, false}, {"nonsense", false},
	}
	for _, c := range cases {
		p, ok := profileFor(c.mode, r)
		if ok != c.wantOK {
			t.Errorf("profileFor(%q) ok=%v, want %v", c.mode, ok, c.wantOK)
		}
		if ok && p.name != FingerprintChrome && p.name != FingerprintFirefox {
			t.Errorf("profileFor(%q) picked unknown profile %q", c.mode, p.name)
		}
	}
	if p, _ := profileFor(FingerprintChrome, r); p.name != FingerprintChrome {
		t.Errorf("explicit chrome resolved to %q", p.name)
	}
}

func TestRawExtensionRoundTrip(t *testing.T) {
	e := &rawExtension{typ: 0x0a0a, data: []byte{0x01, 0x02, 0x03}}
	raw, err := e.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got rawExtension
	if err := got.Unmarshal(raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.typ != e.typ || string(got.data) != string(e.data) {
		t.Errorf("round-trip mismatch: %#x %v -> %#x %v", e.typ, e.data, got.typ, got.data)
	}
	if err := (&rawExtension{}).Unmarshal([]byte{0x00}); err == nil {
		t.Error("Unmarshal of a short buffer should error")
	}
}

// --- real pion handshake, end to end -----------------------------------------

// TestWebRTCHandshakeAcrossFingerprints stands up two real pion WebRTC endpoints
// over an in-memory signaler and loopback ICE, and round-trips a stream through
// the reshaped DTLS handshake. It is the functional proof that the fingerprint
// rewrite doesn't break the handshake — including a mixed pairing (a Chrome-
// profile node talking to a Firefox-profile node) and the plain "off" baseline.
func TestWebRTCHandshakeAcrossFingerprints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real WebRTC handshake in -short")
	}
	cases := []struct{ dialer, accepter string }{
		{FingerprintChrome, FingerprintChrome},
		{FingerprintFirefox, FingerprintFirefox},
		{FingerprintChrome, FingerprintFirefox},
		{FingerprintOff, FingerprintOff},
	}
	for _, c := range cases {
		t.Run(c.dialer+"_to_"+c.accepter, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			handshakeRoundTrip(ctx, t, c.dialer, c.accepter)
		})
	}
}

func handshakeRoundTrip(ctx context.Context, t *testing.T, dialerMode, accepterMode string) {
	t.Helper()
	dialTr := newWebRTCTransport(Config{DTLSFingerprint: dialerMode}, nil)
	acceptTr := newWebRTCTransport(Config{DTLSFingerprint: accepterMode}, nil)
	if dialTr.fingerprint != wantName(dialerMode) || acceptTr.fingerprint != wantName(accepterMode) {
		t.Fatalf("fingerprint not applied: dialer=%q accepter=%q", dialTr.fingerprint, acceptTr.fingerprint)
	}

	dialerSig, accepterSig := newMemSignalerPair()
	accepted := make(chan error, 1)
	go func() {
		sess, err := acceptTr.Accept(ctx, accepterSig)
		if err != nil {
			accepted <- err
			return
		}
		accepted <- nil
		echoSession(sess)
	}()

	sess, err := dialTr.Dial(ctx, dialerSig)
	if err != nil {
		t.Fatalf("Dial (%s->%s): %v", dialerMode, accepterMode, err)
	}
	defer sess.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("Accept (%s->%s): %v", dialerMode, accepterMode, err)
	}

	st, err := sess.OpenStream(ctx, "probe:1")
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	msg := []byte("fingerprinted-datachannel")
	go func() { _, _ = st.Write(msg) }()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(msg))
		_, err := io.ReadFull(st, buf)
		if err == nil && string(buf) != string(msg) {
			err = io.ErrUnexpectedEOF
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("echo round-trip failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("handshake/echo timed out: %v", ctx.Err())
	}
}

// TestWebRTCConcurrentHandshakes runs several handshakes at once through a single
// shared transport pair. The ClientHello hook keeps no shared mutable state (it
// draws a fresh PRNG per connection), so concurrent sessions must each complete
// with their own GREASE/permutation. This is the concurrency contract the design
// relies on in place of a lock; it also stands in for the -race check where cgo
// is unavailable.
func TestWebRTCConcurrentHandshakes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real WebRTC handshake in -short")
	}
	const n = 6
	dialTr := newWebRTCTransport(Config{DTLSFingerprint: FingerprintChrome}, nil)
	acceptTr := newWebRTCTransport(Config{DTLSFingerprint: FingerprintChrome}, nil)

	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { errs <- oneHandshake(dialTr, acceptTr) }()
	}
	deadline := time.After(60 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Fatalf("concurrent handshake %d/%d failed: %v", i+1, n, err)
			}
		case <-deadline:
			t.Fatalf("concurrent handshakes timed out after %d/%d", i, n)
		}
	}
}

// oneHandshake dials one session through the given transports, echoes a probe
// byte string, and returns any failure. It shares transports safely with peers.
func oneHandshake(dialTr, acceptTr *webrtcTransport) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	dialerSig, accepterSig := newMemSignalerPair()

	acceptErr := make(chan error, 1)
	go func() {
		sess, err := acceptTr.Accept(ctx, accepterSig)
		if err != nil {
			acceptErr <- err
			return
		}
		acceptErr <- nil
		echoSession(sess)
	}()

	sess, err := dialTr.Dial(ctx, dialerSig)
	if err != nil {
		return err
	}
	defer sess.Close()
	if err := <-acceptErr; err != nil {
		return err
	}

	st, err := sess.OpenStream(ctx, "probe:1")
	if err != nil {
		return err
	}
	msg := []byte("concurrent-probe")
	go func() { _, _ = st.Write(msg) }()
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(st, buf); err != nil {
		return err
	}
	if string(buf) != string(msg) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// --- issue #57: handshake Random has no timestamp ----------------------------

// randomFirst4 populates a fresh handshake.Random exactly the way pion itself
// does — both flight0handler.go (ServerHello) and flight1handler.go
// (ClientHello) call this same state.localRandom.Populate() — and returns the
// first 4 bytes of its wire form, the bytes upstream used to fill with a real
// gmt_unix_time.
func randomFirst4(t *testing.T) uint32 {
	t.Helper()
	var r handshake.Random
	if err := r.Populate(); err != nil {
		t.Fatalf("Random.Populate: %v", err)
	}
	wire := r.MarshalFixed()
	return binary.BigEndian.Uint32(wire[0:4])
}

// TestHandshakeRandomHasNoTimestamp is issue #57's core proof: the vendored
// pion patch (third_party/pion-dtls) makes Random.Populate fill all 32 bytes
// randomly, so the first 4 bytes no longer carry a wall-clock-correlated
// gmt_unix_time. It calls Populate directly rather than driving a real
// handshake because that one method is the shared source for both the
// ClientHello's and the ServerHello's Random (see randomFirst4) — testing it
// once covers both sides, and is exactly why reshaping the wire bytes in a
// SetDTLS*HelloMessageHook instead (as ADR-0018 does for ciphers/extensions)
// could never have fixed this: the hook never sees state.localRandom itself.
func TestHandshakeRandomHasNoTimestamp(t *testing.T) {
	now := uint32(time.Now().Unix())
	a := randomFirst4(t)
	time.Sleep(1100 * time.Millisecond)
	b := randomFirst4(t)

	// A real gmt_unix_time would land within seconds of wall-clock time; a
	// uniform 32-bit draw has only a ~1-in-600,000 chance of doing so, so this
	// isn't a source of flakiness.
	const window = 3600 // seconds either side of "now"
	for _, v := range []uint32{a, b} {
		if diff := int64(v) - int64(now); diff > -window && diff < window {
			t.Errorf("Random first 4 bytes %d fall within an hour of wall-clock time %d; looks like a timestamp", v, now)
		}
	}
	// A real timestamp would advance by ~the elapsed real time (~1.1s)
	// between the two draws; true randomness will not, with the same
	// vanishing false-positive probability as above.
	if elapsed := int64(b) - int64(a); elapsed > 0 && elapsed < window {
		t.Errorf("second draw is %d greater than the first, drawn ~1.1s later — looks like elapsed wall-clock time, not randomness", elapsed)
	}
}

// TestHandshakeCompletesAfterRandomPatch is the non-negotiable trap detector
// for issue #57. The wrong fix — overwriting the timestamp only inside
// SetDTLSClientHelloMessageHook/SetDTLSServerHelloMessageHook — would leave
// state.localRandom (which pion hashes directly into the master-secret PRF,
// state.go) disagreeing with the wire bytes the peer actually parsed as its
// remoteRandom, desyncing the two sides' derived master secret. That fails
// the handshake outright (a bad Finished MAC), so a passing real handshake
// here is proof the fix lives in the right place: pion's Random.Populate
// itself, not a post-hoc rewrite. Run twice with a real time gap to rule out
// any accidental dependence on a fixed startup timestamp.
func TestHandshakeCompletesAfterRandomPatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real WebRTC handshake in -short")
	}
	for i := 0; i < 2; i++ {
		if i > 0 {
			time.Sleep(1100 * time.Millisecond)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		handshakeRoundTrip(ctx, t, FingerprintChrome, FingerprintChrome)
		cancel()
	}
}

func wantName(mode string) string {
	if mode == FingerprintOff {
		return FingerprintOff
	}
	return mode // chrome/firefox resolve to themselves; this test never uses "auto"
}

// --- small helpers -----------------------------------------------------------

func sameU16(a, b []uint16) bool {
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

func orderEqual(a, b []extension.Extension) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].TypeValue() != b[i].TypeValue() {
			return false
		}
	}
	return true
}

func hasExt(list []extension.Extension, typ extension.TypeValue) bool {
	return hasExtTyped(list, typ)
}

func hasExtTyped(list []extension.Extension, typ extension.TypeValue) bool {
	for _, e := range list {
		if e.TypeValue() == typ {
			return true
		}
	}
	return false
}

func hasCurve(list []dtlsElliptic.Curve, c dtlsElliptic.Curve) bool {
	for _, x := range list {
		if x == c {
			return true
		}
	}
	return false
}

func findGroups(t *testing.T, list []extension.Extension) *extension.SupportedEllipticCurves {
	t.Helper()
	for _, e := range list {
		if sg, ok := e.(*extension.SupportedEllipticCurves); ok {
			return sg
		}
	}
	t.Fatal("supported-groups extension missing")
	return nil
}
