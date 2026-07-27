package core

// DTLS fingerprint randomization.
//
// WebRTC (pion) buys NAT traversal, not camouflage. pion emits a *stable,
// published* DTLS ClientHello — a fixed cipher-suite list, a fixed extension
// order, no GREASE. That shape says "this is pion-webrtc, not a browser making a
// real call," and it is a single-rule distinguisher: Russia fingerprinted and
// blocked Snowflake by exactly this kind of static DTLS signature, and the
// mid-2026 censor auto-blocks nodes case-by-case on protocol signature. One
// signature push and a static fingerprint is fleet-wide detectable (issue #14,
// ADR-0018).
//
// This file rewrites the ClientHello to look like a mainstream browser's WebRTC
// handshake instead. The rewrite runs inside pion via
// SettingEngine.SetDTLSClientHelloMessageHook, which pion invokes with the fully
// built ClientHello immediately before it is marshalled and — critically — the
// *rewritten* bytes are what pion hashes into the handshake transcript, so both
// peers stay in agreement (pion/dtls conn.writePackets pushes the marshalled
// hooked message to the handshake cache). The peer parses our extra cipher IDs
// as opaque uint16s and skips unknown/GREASE extensions and groups, so injecting
// browser/GREASE values never breaks the handshake between two of our own nodes.
//
// Scope (issue #14): break the static pion signature and blend toward common
// browser shapes. It is deliberately not a full obfuscated transport — a
// DataChannel bulk tunnel still doesn't match a real video call's traffic shape
// over time. That residual is documented in docs/design/dtls-fingerprint.md and
// is the job of the second transport (#16), not this change.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	mrand "math/rand"
	"sort"

	dtls "github.com/pion/dtls/v3"
	dtlsElliptic "github.com/pion/dtls/v3/pkg/crypto/elliptic"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/pion/webrtc/v4"
)

var errShortRawExtension = errors.New("core: raw extension too short")

// Fingerprint modes accepted by Config.DTLSFingerprint. Empty is treated as
// FingerprintAuto.
const (
	FingerprintAuto    = "auto"    // pick a profile per node at startup
	FingerprintChrome  = "chrome"  // imitate Chrome's WebRTC DTLS ClientHello
	FingerprintFirefox = "firefox" // imitate Firefox's WebRTC DTLS ClientHello
	FingerprintOff     = "off"     // leave pion's default ClientHello untouched
)

// greaseValues are the 16 reserved GREASE code points (RFC 8701): both bytes
// equal, low nibble 0xA. They are valid in cipher lists, extension types, and
// supported-group lists, and a compliant peer must ignore them — so they shape
// the fingerprint without touching what actually gets negotiated. Chrome sends
// fresh ones per connection; so do we.
var greaseValues = [16]uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

// negotiableSuites are the cipher suites pion actually implements and can
// complete a handshake with. They are all ECDHE_ECDSA because a pion WebRTC
// endpoint authenticates with a self-signed ECDSA P-256 certificate, so an RSA
// suite could never be selected between two of our nodes. This set is installed
// on the SettingEngine (the accept side negotiates from it); the browser-shaped
// wire list advertised in the ClientHello is a superset of it, so a peer always
// finds a mutually supported suite here.
var negotiableSuites = []dtls.CipherSuiteID{
	dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
}

// browserCurves is the supported-groups list common to Chrome and Firefox
// WebRTC, in their order. pion negotiates the first it supports (X25519).
var browserCurves = []dtlsElliptic.Curve{dtlsElliptic.X25519, dtlsElliptic.P256, dtlsElliptic.P384}

// Browser cipher-suite orders (the on-wire list). Each is a real browser's
// DTLS 1.2 WebRTC offering: a handful of suites pion negotiates (the ECDHE_ECDSA
// ones) interleaved with suites pion doesn't — RSA and plain-RSA-kx suites that
// exist only to make the list the right length and order. The peer skips the
// ones it can't do and lands on an ECDHE_ECDSA suite.
var (
	chromeCipherOrder = []uint16{
		0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
		0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	}
	firefoxCipherOrder = []uint16{
		0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
		0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
	}
)

// browserExtOrder is a stable, browser-plausible extension ordering used by the
// Firefox profile. It is deliberately different from pion's default order (whose
// order is itself a tell); extensions not listed keep their original relative
// order at the end. It is a priority list, not an exact capture of any one
// browser build — see docs/design/dtls-fingerprint.md on the limits of this.
var browserExtOrder = []extension.TypeValue{
	extension.UseExtendedMasterSecretTypeValue,
	extension.RenegotiationInfoTypeValue,
	extension.SupportedEllipticCurvesTypeValue,
	extension.SupportedPointFormatsTypeValue,
	extension.SupportedSignatureAlgorithmsTypeValue,
	extension.UseSRTPTypeValue,
	extension.ALPNTypeValue,
	extension.ServerNameTypeValue,
	extension.ConnectionIDTypeValue,
}

// serverExtOrder is a browser-plausible ordering for the DTLS ServerHello
// extensions the answerer selects, deliberately distinct from pion's fixed
// server order (which is itself the tell). Unlike the ClientHello there is no
// GREASE or permutation here — GREASE is a client-side tolerance trick browsers
// do not place in a ServerHello, and a server does not permute — so reshaping
// the answer side is a pure reorder. Extensions not listed keep their original
// relative order at the end (see reorderByPriority).
var serverExtOrder = []extension.TypeValue{
	extension.RenegotiationInfoTypeValue,
	extension.UseExtendedMasterSecretTypeValue,
	extension.SupportedPointFormatsTypeValue,
	extension.UseSRTPTypeValue,
	extension.ALPNTypeValue,
	extension.ConnectionIDTypeValue,
}

// dtlsProfile describes how to reshape the ClientHello for one browser identity.
type dtlsProfile struct {
	name        string
	cipherOrder []uint16 // exact on-wire cipher list, minus any leading GREASE

	// grease adds RFC 8701 GREASE to the cipher list, the supported-groups list,
	// and the extension list (a leading empty GREASE extension and a trailing
	// one-byte GREASE extension) — Chrome does this, Firefox does not.
	grease bool

	// permuteExtensions shuffles the extension order per connection. Chrome
	// permutes its ClientHello extensions (since v110), so a per-connection order
	// is itself authentic and defeats a static order signature.
	permuteExtensions bool

	// extOrder, when set, reorders extensions to this fixed browser-like priority
	// (used by Firefox, which does not permute). It is mutually exclusive with
	// permuteExtensions. When neither is set, pion's order is kept.
	extOrder []extension.TypeValue
}

// profileFor resolves a fingerprint mode to a concrete profile. ok is false for
// FingerprintOff (no rewrite) and for unknown modes. rnd is consumed only by
// FingerprintAuto, to pick a browser identity for this node.
func profileFor(mode string, rnd *mrand.Rand) (dtlsProfile, bool) {
	switch mode {
	case "", FingerprintAuto:
		if rnd.Intn(2) == 0 {
			return chromeProfile(), true
		}
		return firefoxProfile(), true
	case FingerprintChrome:
		return chromeProfile(), true
	case FingerprintFirefox:
		return firefoxProfile(), true
	default: // FingerprintOff and anything unrecognized
		return dtlsProfile{}, false
	}
}

func chromeProfile() dtlsProfile {
	return dtlsProfile{name: FingerprintChrome, cipherOrder: chromeCipherOrder, grease: true, permuteExtensions: true}
}

func firefoxProfile() dtlsProfile {
	return dtlsProfile{name: FingerprintFirefox, cipherOrder: firefoxCipherOrder, grease: false, extOrder: browserExtOrder}
}

// apply installs the profile on a SettingEngine: the negotiable suites and
// browser curves (which change what pion will actually agree to), and the
// ClientHello + ServerHello hooks (which change the bytes on the wire). The
// ClientHello hook draws fresh randomness per connection so GREASE values and
// Chrome's extension order vary call to call, the way a real browser's do; the
// ServerHello hook is a deterministic reorder (issue #49). A node installs both
// because it may end up either the DTLS client or the server for a given peer.
func (p dtlsProfile) apply(se *webrtc.SettingEngine) {
	se.SetDTLSCipherSuites(negotiableSuites...)
	se.SetDTLSEllipticCurves(browserCurves...)
	se.SetDTLSClientHelloMessageHook(func(m handshake.MessageClientHello) handshake.Message {
		return rewriteClientHello(m, p, newConnRand())
	})
	se.SetDTLSServerHelloMessageHook(func(m handshake.MessageServerHello) handshake.Message {
		return rewriteServerHello(m)
	})
}

// newConnRand returns a per-connection PRNG seeded from crypto/rand. A fresh
// instance per call keeps the hook race-free under concurrent handshakes without
// a lock; the values are camouflage, not secrets, so a PRNG is fine.
func newConnRand() *mrand.Rand {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return mrand.New(mrand.NewSource(int64(binary.LittleEndian.Uint64(b[:])))) //nolint:gosec // camouflage, not crypto
}

// rewriteClientHello reshapes pion's ClientHello into the profile's browser form
// and returns it as a handshake.Message for pion to marshal and send. It only
// adds and reorders: every extension pion needs to negotiate is preserved, so
// the handshake still completes. r supplies GREASE values and, for Chrome, the
// per-connection extension permutation.
func rewriteClientHello(m handshake.MessageClientHello, p dtlsProfile, r *mrand.Rand) handshake.Message {
	// Cipher list: the browser order, optionally behind a leading GREASE suite.
	ciphers := make([]uint16, 0, len(p.cipherOrder)+1)
	if p.grease {
		ciphers = append(ciphers, greaseValue(r))
	}
	m.CipherSuiteIDs = append(ciphers, p.cipherOrder...)

	// Copy the extension list so we never mutate pion's per-connection slice in
	// place, transforming supported-groups as we go.
	exts := make([]extension.Extension, 0, len(m.Extensions)+2)
	for _, ext := range m.Extensions {
		if sg, ok := ext.(*extension.SupportedEllipticCurves); ok && p.grease {
			// Prepend a GREASE group. The peer drops it on parse (its
			// supported-groups unmarshal filters to known curves) yet still
			// hashes the raw bytes, so the transcript stays consistent.
			curves := append([]dtlsElliptic.Curve{dtlsElliptic.Curve(greaseValue(r))}, sg.EllipticCurves...)
			exts = append(exts, &extension.SupportedEllipticCurves{EllipticCurves: curves})
			continue
		}
		exts = append(exts, ext)
	}

	// Extension order is itself a fingerprint. Chrome permutes per connection
	// (authentic since v110); Firefox uses a fixed browser-like priority. Either
	// way the result differs from pion's default order.
	switch {
	case p.permuteExtensions:
		r.Shuffle(len(exts), func(i, j int) { exts[i], exts[j] = exts[j], exts[i] })
	case len(p.extOrder) > 0:
		exts = reorderByPriority(exts, p.extOrder)
	}

	// GREASE extensions bracket the list: an empty one first, a one-byte one
	// last (RFC 8701 recommends two distinct GREASE values).
	if p.grease {
		lead, trail := twoGreaseValues(r)
		exts = append([]extension.Extension{&rawExtension{typ: extension.TypeValue(lead)}}, exts...)
		exts = append(exts, &rawExtension{typ: extension.TypeValue(trail), data: []byte{0x00}})
	}

	m.Extensions = exts
	return &m
}

// rewriteServerHello reshapes pion's DTLS ServerHello into a browser-plausible
// extension order (issue #49). It is a pure reorder — no GREASE, no permutation
// (see serverExtOrder) — and transcript-safe for the same reason the ClientHello
// rewrite is: pion marshals the hooked message and both peers hash those exact
// bytes, while reorderByPriority preserves the whole extension set, so every
// negotiated parameter still travels. The ServerHello carries far less signal
// than the ClientHello (one chosen cipher, a few answerer-selected extensions),
// so this is the lightest of #49's levers, but it clears the last "pion emits
// its extensions in this fixed order" tell on the answer side.
func rewriteServerHello(m handshake.MessageServerHello) handshake.Message {
	m.Extensions = reorderByPriority(m.Extensions, serverExtOrder)
	return &m
}

// reorderByPriority returns exts ordered by the given type priority. Extensions
// whose type is not in priority keep their original relative order, appended
// after the prioritized ones. It preserves the set — nothing is dropped — so all
// negotiation-relevant extensions still travel.
func reorderByPriority(exts []extension.Extension, priority []extension.TypeValue) []extension.Extension {
	rank := make(map[extension.TypeValue]int, len(priority))
	for i, tv := range priority {
		rank[tv] = i
	}
	ranked := make([]extension.Extension, 0, len(exts))
	var rest []extension.Extension
	for _, e := range exts {
		if _, ok := rank[e.TypeValue()]; ok {
			ranked = append(ranked, e)
		} else {
			rest = append(rest, e)
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool { return rank[ranked[i].TypeValue()] < rank[ranked[j].TypeValue()] })
	return append(ranked, rest...)
}

func greaseValue(r *mrand.Rand) uint16 { return greaseValues[r.Intn(len(greaseValues))] }

// twoGreaseValues returns two distinct GREASE code points.
func twoGreaseValues(r *mrand.Rand) (uint16, uint16) {
	a := r.Intn(len(greaseValues))
	b := (a + 1 + r.Intn(len(greaseValues)-1)) % len(greaseValues)
	return greaseValues[a], greaseValues[b]
}

// rawExtension is a TLS extension of arbitrary type and body, used to inject
// GREASE extensions pion has no typed representation for. On the wire a TLS
// extension is type(2) || length(2) || body, which is exactly what Marshal
// emits; a peer that doesn't recognize the type skips it by that length.
type rawExtension struct {
	typ  extension.TypeValue
	data []byte
}

func (e *rawExtension) Marshal() ([]byte, error) {
	out := make([]byte, 4+len(e.data))
	binary.BigEndian.PutUint16(out[0:2], uint16(e.typ))
	binary.BigEndian.PutUint16(out[2:4], uint16(len(e.data))) //nolint:gosec // bounded by construction
	copy(out[4:], e.data)
	return out, nil
}

func (e *rawExtension) Unmarshal(data []byte) error {
	if len(data) < 4 {
		return errShortRawExtension
	}
	e.typ = extension.TypeValue(binary.BigEndian.Uint16(data[0:2]))
	n := int(binary.BigEndian.Uint16(data[2:4]))
	if len(data) < 4+n {
		return errShortRawExtension
	}
	e.data = append([]byte(nil), data[4:4+n]...)
	return nil
}

func (e *rawExtension) TypeValue() extension.TypeValue { return e.typ }
