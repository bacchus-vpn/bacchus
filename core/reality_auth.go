package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

// Reality authenticates a client to the exit *inside the ClientHello* (ADR-0032),
// so the exit can decide — before it terminates TLS — whether a peer is one of our
// clients or an unauthenticated stranger (a prober or a real browser). The signal
// rides in the 32-byte TLS 1.3 legacy_session_id, where a real client would put 32
// random bytes: an AEAD seal keyed by an X25519 ECDH between the client's
// ClientHello key share and the exit's static key, bound to the ClientHello random.
//
// Only the exit's static private key can open the seal, so a stranger cannot forge
// it; binding the seal to the per-connection random and ephemeral key share means a
// session id sniffed on the wire cannot be lifted onto a different ClientHello.

const (
	// realitySessionIDLen is the fixed legacy_session_id length we emit. A TLS 1.3
	// client in middlebox-compatibility mode sends exactly 32 random bytes here, so
	// our sealed id must be the same length to blend.
	realitySessionIDLen = 32

	// realityAuthPlainLen is the sealed plaintext length. AES-GCM adds a 16-byte
	// tag, so 16 + 16 == realitySessionIDLen. Only the first 8 bytes carry a coarse
	// timestamp; the rest is zero padding to reach a full 32-byte sealed id.
	realityAuthPlainLen = 16

	// realityAuthWindow bounds clock skew and how long a captured ClientHello stays
	// replayable: a sealed timestamp further than this from the exit's clock (either
	// direction) is refused, and the replay set need only remember one window.
	realityAuthWindow = 90 * time.Second

	realityAuthInfoKey   = "bacchus-reality-v1 sid-key"
	realityAuthInfoNonce = "bacchus-reality-v1 sid-nonce"
)

// errRealityAuthFailed marks a ClientHello whose legacy_session_id is not one of
// ours — a prober or a real browser. It is the fork signal, not an error to log
// loudly: unauthenticated peers are the common case on :443.
var errRealityAuthFailed = errors.New("core: reality clienthello not authenticated")

// realityKeyPair is an exit's static X25519 identity for the ClientHello handshake.
// It is generated per listener at startup; the public half rides in every answer
// (over the coordinator-authenticated channel), so it needs no out-of-band config
// and may rotate freely on restart.
type realityKeyPair struct {
	priv *ecdh.PrivateKey
	pub  []byte // 32-byte raw X25519 public key, as advertised in the answer
}

func newRealityKeyPair() (*realityKeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &realityKeyPair{priv: priv, pub: priv.PublicKey().Bytes()}, nil
}

// secretFrom computes the shared secret on the exit side from a client's X25519
// ClientHello key share. It errors on a malformed share (wrong length / not on the
// curve), which the caller treats as unauthenticated.
func (kp *realityKeyPair) secretFrom(clientKeyShare []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(clientKeyShare)
	if err != nil {
		return nil, err
	}
	return kp.priv.ECDH(pub)
}

// realityClientSecret computes the same shared secret on the client side, from its
// ClientHello ephemeral key share and the exit's advertised static public key.
func realityClientSecret(ephemeral *ecdh.PrivateKey, exitStaticPub []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(exitStaticPub)
	if err != nil {
		return nil, err
	}
	return ephemeral.ECDH(pub)
}

// realityAuthGCM derives the per-connection AES-GCM from the shared secret and the
// ClientHello random. Because the random is unique per connection, both the key and
// the nonce are fresh every time, so the fixed derived nonce is never reused under a
// repeated key.
func realityAuthGCM(secret, random []byte) (cipher.AEAD, []byte, error) {
	key, err := hkdf.Key(sha256.New, secret, random, realityAuthInfoKey, 32)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := hkdf.Key(sha256.New, secret, random, realityAuthInfoNonce, 12)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return gcm, nonce, nil
}

// realitySealSessionID produces the 32-byte legacy_session_id the client puts in
// its ClientHello. secret is ECDH(clientEphemeral, exitStatic); random is the
// ClientHello random. The random is also the AEAD additional data, binding the seal
// to this exact ClientHello.
func realitySealSessionID(secret, random []byte, now time.Time) ([]byte, error) {
	gcm, nonce, err := realityAuthGCM(secret, random)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, realityAuthPlainLen)
	binary.BigEndian.PutUint64(pt[:8], uint64(now.Unix()))
	sid := gcm.Seal(nil, nonce, pt, random)
	return sid, nil // len(pt)+tag == 16 + 16 == realitySessionIDLen
}

// realityOpenSessionID verifies an inbound legacy_session_id on the exit. secret is
// ECDH(exitStatic, clientKeyShare); random and sessionID come straight from the
// ClientHello. It returns the sealed timestamp on success, or errRealityAuthFailed
// for anything that is not one of our clients.
func realityOpenSessionID(secret, random, sessionID []byte) (time.Time, error) {
	if len(sessionID) != realitySessionIDLen {
		return time.Time{}, errRealityAuthFailed
	}
	gcm, nonce, err := realityAuthGCM(secret, random)
	if err != nil {
		return time.Time{}, err
	}
	pt, err := gcm.Open(nil, nonce, sessionID, random)
	if err != nil {
		return time.Time{}, errRealityAuthFailed
	}
	return time.Unix(int64(binary.BigEndian.Uint64(pt[:8])), 0), nil
}

// realityReplayGuard rejects verbatim ClientHello replays within the freshness
// window. An authenticated client mints a fresh ephemeral key share and random each
// connection, so a repeated sealed session id can only be a captured replay; a
// replay that slips the terminate path would only reach the inner handshake and
// fall through to the ADR-0027 response, but denying it up front keeps a replay from
// being a distinguisher between the terminate and splice paths.
type realityReplayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // sealed session id -> first-seen
}

func newRealityReplayGuard() *realityReplayGuard {
	return &realityReplayGuard{seen: map[string]time.Time{}}
}

// admit reports whether a freshly-opened session id may take the terminate path. It
// rejects stale timestamps (outside the window) and verbatim replays. now is a
// parameter so tests can drive the clock; production passes time.Now().
func (g *realityReplayGuard) admit(sessionID []byte, ts, now time.Time) bool {
	if d := now.Sub(ts); d > realityAuthWindow || d < -realityAuthWindow {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	// Evict entries older than one window so the set is bounded by the window's
	// worth of connections, not by total traffic.
	for k, t := range g.seen {
		if now.Sub(t) > realityAuthWindow {
			delete(g.seen, k)
		}
	}
	key := string(sessionID)
	if _, dup := g.seen[key]; dup {
		return false
	}
	g.seen[key] = now
	return true
}
