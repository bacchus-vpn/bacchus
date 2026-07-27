package core

// ICE credential fingerprint.
//
// pion draws its ICE ufrag/pwd as a fixed ufrag=16 / pwd=32 from a letters-only
// alphabet ([a-zA-Z]). A mainstream browser draws a *short* ufrag and a pwd from
// the full RFC 5245 "ice-char" set (letters, digits, '+', '/'). pion's longer,
// letters-only credentials are therefore a weak-but-real distinguisher in the
// STUN connectivity checks — the "pion-ish" residual left over from #14, which
// only reshaped the DTLS ClientHello (issue #49).
//
// The fix must be *per connection*. pion's SetICECredentials writes a single
// static pair onto the SettingEngine, and because a transport shares one API
// across every connection, that pair would be reused fleet-wide — a *stronger*,
// stable fingerprint than pion's default, the opposite of what we want. So the
// transport builds a fresh SettingEngine + API per PeerConnection (see newPC in
// transport_webrtc.go) and installs freshly generated credentials on each.

import "crypto/rand"

// iceCharset is the full RFC 5245 "ice-char" set: ALPHA / DIGIT / "+" / "/".
// Browsers draw ICE credentials from this whole set; pion uses letters only, so
// the presence of digits and '+' / '/' — together with browser-length creds — is
// what moves the shape off pion's default. It is exactly 64 = 2^6 characters, so
// masking a random byte to its low 6 bits selects one character with no modulo
// bias (see randomICEString).
const iceCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// iceCredShape is the ufrag/pwd length one browser profile advertises. Like the
// DTLS profiles, these are browser-*informed*, not byte-exact captures: the
// load-bearing change is "short ufrag + full ICE-char set" versus pion's "long
// ufrag, letters only", not matching a specific browser build to the character.
type iceCredShape struct {
	ufragLen int
	pwdLen   int
}

// chromeICEShape is the Chrome/libwebrtc shape: ufrag=4, pwd=24 — the RFC 5245
// minimum lengths — over the base64 ICE-char set. libwebrtc is the dominant
// WebRTC engine in the wild (Chrome, Edge, Electron, most native/mobile apps),
// so this is the most common real ICE credential shape to blend with.
var chromeICEShape = iceCredShape{ufragLen: 4, pwdLen: 24}

// randomICEString returns a cryptographically random string of n characters
// drawn uniformly from iceCharset. iceCharset is 64 characters, so each byte
// masked to 6 bits (b & 0x3f) maps to exactly one character with no bias — no
// rejection sampling needed. crypto/rand because the pwd this feeds keys the
// STUN MESSAGE-INTEGRITY on every connectivity check; it must be unpredictable.
func randomICEString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = iceCharset[b&0x3f]
	}
	return string(out), nil
}

// browserICECredentials generates a fresh browser-shaped ICE ufrag/pwd pair for
// one connection. newPC installs the result on a per-connection SettingEngine
// via SetICECredentials; on a non-nil error newPC keeps pion's defaults, so a
// failed randomness draw never takes a session down.
//
// Every node uses the Chrome/libwebrtc shape (chromeICEShape, 4/24) regardless
// of its DTLS profile. libwebrtc is the dominant WebRTC engine in the wild
// (Chrome, Edge, Electron, most native/mobile apps), so 4/24 over the base64
// ICE-char set is the single most common real ICE credential shape to blend
// with. A firefox-profile node therefore pairs a Firefox DTLS handshake with a
// libwebrtc-shaped ICE credential — a weak joint-fingerprint inconsistency we
// accept, since Electron-class apps genuinely mix stacks and a *guessed* Firefox
// ICE shape (nICEr, which we can't capture precisely here) could be a stronger
// tell than the mismatch it would fix. p is kept in the signature so a future
// profile-consistent shape can branch on it without touching the caller.
//
// Both values come from randomICEString (crypto/rand): the pwd keys the STUN
// MESSAGE-INTEGRITY on every connectivity check, so it must be unpredictable,
// not a math/rand draw. chromeICEShape clears pion's floor (ufrag >= 3 chars,
// pwd >= 16 chars).
func browserICECredentials(p dtlsProfile) (ufrag, pwd string, err error) {
	ufrag, err = randomICEString(chromeICEShape.ufragLen)
	if err != nil {
		return "", "", err
	}
	pwd, err = randomICEString(chromeICEShape.pwdLen)
	if err != nil {
		return "", "", err
	}
	return ufrag, pwd, nil
}
