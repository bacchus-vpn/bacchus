package core

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/flynn/noise"
)

// End-to-end encryption client<->exit. A relay in the path forwards ciphertext
// and the next hop only; it cannot recover the destination or the content
// (ADR-0009, issue #12). The handshake is Noise_NK: the exit's static public key
// is its node id, so the client authenticates the exit it selected and a
// malicious relay cannot impersonate it. NK leaves the client anonymous.
//
// Both connection modes run this layer, so the exit terminates E2E identically
// whether it was reached directly or through a relay, and the destination never
// travels as a cleartext stream label.

// e2eLabel is the non-revealing transport-stream label the client uses; the
// destination lives inside the encrypted channel, not in the label.
const e2eLabel = "e2e"

// udpTargetPrefix marks an E2E target as a UDP relay request (issue #41)
// rather than a TCP CONNECT: the client sends "udp:"+host:port instead of a
// bare host:port, overloading the same target field the way acctSentinel and
// probeSentinel already do (core/accounting.go, core/pool.go) — no change to
// the Noise handshake or its framing, just which string it carries. See
// core/udprelay.go for both sides of the branch this enables.
const udpTargetPrefix = "udp:"

// hopTargetPrefix marks an E2E target as an onion FORWARD to another Bacchus
// node (issue #142, ADR-0038) rather than an egress to the internet: the client
// sends "hop:"+host:port, naming the next hop's forwarding ingress
// (coldstart.Entry.Ingress, issue #124). It overloads the same target field as
// udpTargetPrefix/acctSentinel/probeSentinel — so a chain needs no new message
// type, no handshake change, and no coordinator change; a hop is the existing
// Noise_NK exchange with a different target string.
//
// The prefix is what separates the two egresses a node can offer, and that
// separation is load-bearing rather than cosmetic: a bare target means "dial the
// internet" (exit role only) while this means "splice to the next mesh node"
// (relay role only, and only to a node in the signed directory). See
// core/relaychain.go's relayForward for the constraint, and ADR-0038 principle
// #4 — a relay must never become an open internet proxy.
const hopTargetPrefix = "hop:"

const (
	maxPlain = 16384 // plaintext chunk per Noise message
	maxFrame = 65535 // ciphertext/handshake frame cap (uint16 length prefix)
)

var (
	noiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

	errFrameTooLarge       = errors.New("core: e2e frame too large")
	errHandshakeIncomplete = errors.New("core: noise handshake did not complete")
	errBadTarget           = errors.New("core: invalid e2e target")
)

// generateExitKey returns a fresh X25519 static keypair for an exit.
func generateExitKey() (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(rand.Reader)
}

// exitKeyFromSeed derives an exit keypair from a fixed 32-byte private key, so
// an exit can keep a stable identity across restarts.
func exitKeyFromSeed(priv []byte) (noise.DHKey, error) {
	if len(priv) != 32 {
		return noise.DHKey{}, errors.New("core: exit key must be a 32-byte X25519 private key")
	}
	// GenerateKeypair reads the private scalar from its reader, then derives the
	// matching public key with the same DH the handshake uses.
	return noise.DH25519.GenerateKeypair(newFixedReader(priv))
}

// clientHandshake runs the Noise_NK initiator over raw, authenticating the exit
// by exitPub, then sends target as the first encrypted message. The returned
// conn carries the tunnelled bytes.
//
// verifyExit, when non-nil, is the end-to-end admission check (issue #60): it is
// handed the admission credential the exit presented in msg2's Noise payload and
// returns a non-nil error to reject the exit, on which the handshake aborts and
// no target is ever sent. A nil verifyExit means the client has no admission
// anchor and does not verify (fail-open, matching the coordinator when
// -admission-pubkey is unset, #42).
func clientHandshake(raw io.ReadWriteCloser, exitPub []byte, target string, verifyExit func(cred []byte) error) (*noiseConn, error) {
	nc := newNoiseConn(raw)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noiseSuite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  exitPub,
	})
	if err != nil {
		return nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := nc.writeFrame(msg1); err != nil {
		return nil, err
	}
	msg2, err := nc.readFrame()
	if err != nil {
		return nil, err
	}
	// NK completes at msg2: cs0 encrypts initiator->responder, cs1 the reverse.
	// msg2's payload carries the exit's admission credential (issue #60). It is
	// AEAD-sealed under a key that already mixes the exit's static key, so a relay
	// in the path can neither read nor forge it, and it is cryptographically bound
	// to the very key this handshake authenticates.
	cred, cs0, cs1, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, err
	}
	if cs0 == nil || cs1 == nil {
		return nil, errHandshakeIncomplete
	}
	// Verify the exit is admission-authorized before routing a single byte
	// through it. A hostile coordinator can name a hostile exit id that completes
	// Noise_NK (it holds that key), but it cannot present a credential signed by
	// the admission root that binds that key to the exit role — so we abort here,
	// before target is sent.
	if verifyExit != nil {
		if err := verifyExit(cred); err != nil {
			return nil, err
		}
	}
	nc.enc, nc.dec = cs0, cs1
	if _, err := nc.Write([]byte(target)); err != nil {
		return nil, err
	}
	return nc, nil
}

// exitHandshake runs the Noise_NK responder over raw with the exit's static key
// and returns the tunnel plus the client's requested target. It does not dial;
// callers splice.
//
// cred is the exit's admission credential (issue #60), carried verbatim in
// msg2's Noise payload so the client can verify end-to-end that this exit is
// admission-authorized — not merely the id the coordinator named. An empty cred
// presents none: an old client simply ignores the payload, and a client with no
// admission anchor does not require one.
func exitHandshake(raw io.ReadWriteCloser, key noise.DHKey, cred []byte) (*noiseConn, string, error) {
	nc := newNoiseConn(raw)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noiseSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: key,
	})
	if err != nil {
		return nil, "", err
	}
	msg1, err := nc.readFrame()
	if err != nil {
		return nil, "", err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, "", err
	}
	msg2, cs0, cs1, err := hs.WriteMessage(nil, cred)
	if err != nil {
		return nil, "", err
	}
	if err := nc.writeFrame(msg2); err != nil {
		return nil, "", err
	}
	if cs0 == nil || cs1 == nil {
		return nil, "", errHandshakeIncomplete
	}
	// Responder: encrypt responder->initiator with cs1, decrypt the reverse with cs0.
	nc.enc, nc.dec = cs1, cs0
	targetB, err := nc.readMessage()
	if err != nil {
		return nil, "", err
	}
	target := string(targetB)
	if !validTarget(target) {
		return nil, "", errBadTarget
	}
	return nc, target, nil
}

// validTarget rejects obviously malformed destinations before the exit dials.
// A routing prefix is stripped first, so a UDP relay request (issue #41) and an
// onion forward (issue #142) both validate the same host:port shape underneath
// theirs. Exactly one prefix is stripped: the prefixes are distinct 4-byte
// literals, so "udp:hop:…" is not a valid nesting and does not validate — the
// only shapes that pass are a bare host:port and one prefix in front of one.
func validTarget(target string) bool {
	if len(target) == 0 || len(target) > 255+maxTargetPrefixLen {
		return false
	}
	_, target = splitTargetPrefix(target)
	_, _, err := net.SplitHostPort(target)
	return err == nil
}

// maxTargetPrefixLen is the longest routing prefix validTarget allows in front
// of a host:port, so the length bound stays correct as prefixes are added.
const maxTargetPrefixLen = len(udpTargetPrefix) // == len(hopTargetPrefix)

// splitTargetPrefix separates a routing prefix from the address behind it,
// returning the prefix ("" when the target is a bare address) and the remainder.
// It is the single place the target vocabulary is parsed, so the exit-side
// dispatch (exitTerminate) and the validator agree by construction rather than
// by two copies of the same TrimPrefix chain.
func splitTargetPrefix(target string) (prefix, addr string) {
	for _, p := range []string{udpTargetPrefix, hopTargetPrefix} {
		if strings.HasPrefix(target, p) {
			return p, target[len(p):]
		}
	}
	return "", target
}

// noiseConn is a length-prefixed, Noise-encrypted byte stream over raw. The same
// framing (a 2-byte big-endian length + body) carries the plaintext handshake
// messages and, once enc/dec are set, the encrypted transport frames. An
// internal accumulation buffer re-delimits frames, so it is correct whether raw
// is message-oriented (a WebRTC data channel) or a byte stream (the relay's TCP
// hop, which flattens message boundaries).
type noiseConn struct {
	raw io.ReadWriteCloser

	wmu sync.Mutex // serializes raw writes (and enc nonce order)
	rmu sync.Mutex // serializes raw reads (and dec nonce order)

	rbuf []byte // buffered raw bytes not yet parsed into a frame
	rtmp []byte // scratch read buffer
	pt   []byte // decrypted plaintext not yet handed to the caller

	enc *noise.CipherState // nil until the handshake completes
	dec *noise.CipherState
}

func newNoiseConn(raw io.ReadWriteCloser) *noiseConn {
	return &noiseConn{raw: raw, rtmp: make([]byte, maxFrame+2)}
}

func (c *noiseConn) writeFrame(b []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.writeRawFrame(b)
}

func (c *noiseConn) writeRawFrame(b []byte) error {
	if len(b) > maxFrame {
		return errFrameTooLarge
	}
	frame := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(b)))
	copy(frame[2:], b)
	_, err := c.raw.Write(frame)
	return err
}

func (c *noiseConn) readFrame() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	return c.readFrameLocked()
}

func (c *noiseConn) readFrameLocked() ([]byte, error) {
	for {
		if f, ok := c.takeFrame(); ok {
			return f, nil
		}
		n, err := c.raw.Read(c.rtmp)
		if n > 0 {
			c.rbuf = append(c.rbuf, c.rtmp[:n]...)
		}
		if err != nil {
			if f, ok := c.takeFrame(); ok {
				return f, nil
			}
			return nil, err
		}
	}
}

// takeFrame pops one complete frame from rbuf, if present.
func (c *noiseConn) takeFrame() ([]byte, bool) {
	if len(c.rbuf) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(c.rbuf[:2]))
	if len(c.rbuf) < 2+n {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, c.rbuf[2:2+n])
	c.rbuf = c.rbuf[2+n:]
	if len(c.rbuf) == 0 {
		c.rbuf = c.rbuf[:0]
	}
	return out, true
}

// readMessage returns the plaintext of exactly one encrypted frame. It is used
// for the target preamble and must be called before the first Read.
func (c *noiseConn) readMessage() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	frame, err := c.readFrameLocked()
	if err != nil {
		return nil, err
	}
	return c.dec.Decrypt(nil, nil, frame)
}

func (c *noiseConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.pt) == 0 {
		frame, err := c.readFrameLocked()
		if err != nil {
			return 0, err
		}
		pt, err := c.dec.Decrypt(nil, nil, frame)
		if err != nil {
			return 0, err
		}
		c.pt = pt
	}
	n := copy(p, c.pt)
	c.pt = c.pt[n:]
	return n, nil
}

func (c *noiseConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxPlain {
			n = maxPlain
		}
		ct, err := c.enc.Encrypt(nil, nil, p[:n])
		if err != nil {
			return total, err
		}
		if err := c.writeRawFrame(ct); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (c *noiseConn) Close() error { return c.raw.Close() }

// fixedReader yields a fixed byte slice once, then EOF — a deterministic source
// for deriving a keypair from a stored private key.
type fixedReader struct {
	b []byte
}

func newFixedReader(b []byte) *fixedReader { return &fixedReader{b: b} }

func (r *fixedReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
