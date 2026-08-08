// Minimal, self-contained Noise_NK layer codec for the relay-chaining feasibility
// probe. It is a trimmed port of core/e2e.go's noiseConn + handshake, kept local so
// the probe imports no core package and wires nothing into production — exactly as
// cmd/coldstart-probe hand-rolls its own STUN codec rather than import core/coldstart.
//
// It uses the real flynn/noise handshake (already a module dependency), because the
// whole point of the probe is to show that the *actual* primitive nests: a chain is
// this same Noise_NK exchange run once per hop, each layer riding inside the previous
// one's encrypted byte stream. Nothing here is new cryptography — it mirrors the
// shipped client<->exit channel.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/flynn/noise"
)

const (
	maxPlain = 16384 // plaintext chunk per Noise message (matches core/e2e.go)
	maxFrame = 65535 // ciphertext/handshake frame cap (uint16 length prefix)
)

var (
	suite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

	errFrameTooLarge       = errors.New("onion: frame too large")
	errHandshakeIncomplete = errors.New("onion: handshake did not complete")
)

// genKey returns a fresh X25519 static keypair. A node's public key is its id —
// the client authenticates each hop by it, so a coordinator that does not hold the
// private key cannot substitute the hop (design §4.3).
func genKey() (noise.DHKey, error) { return noise.DH25519.GenerateKeypair(rand.Reader) }

// layer is one Noise_NK-encrypted, length-prefixed byte stream over an arbitrary
// io.ReadWriteCloser. Because it re-delimits frames from an opaque byte stream, a
// layer can run *over another layer* — which is exactly onion nesting: the client
// stacks layers, each hop peels one. This mirrors core/e2e.go's noiseConn, whose
// doc notes the same "works over a byte stream that flattens message boundaries".
type layer struct {
	raw      io.ReadWriteCloser
	rbuf     []byte
	rtmp     []byte
	pt       []byte
	enc, dec *noise.CipherState // nil until the handshake completes
}

func newLayer(raw io.ReadWriteCloser) *layer {
	return &layer{raw: raw, rtmp: make([]byte, maxFrame+2)}
}

// dialInitiator runs the Noise_NK initiator against peerPub. verifyCred, when
// non-nil, is handed the credential the responder presents in msg2 and may reject
// the peer (the old #60/#69 end-to-end exit-admission check, modelled here) — on
// rejection the handshake aborts before any target is sent. This is core/e2e.go's
// clientHandshake, minus sending the target (the caller sends it per layer).
func dialInitiator(raw io.ReadWriteCloser, peerPub []byte, verifyCred func([]byte) error) (*layer, error) {
	l := newLayer(raw)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  peerPub,
	})
	if err != nil {
		return nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := l.writeFrame(msg1); err != nil {
		return nil, err
	}
	msg2, err := l.readFrame()
	if err != nil {
		return nil, err
	}
	cred, cs0, cs1, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, err // a substituted/wrong-key hop fails here (design §4.3)
	}
	if cs0 == nil || cs1 == nil {
		return nil, errHandshakeIncomplete
	}
	if verifyCred != nil {
		if err := verifyCred(cred); err != nil {
			return nil, err
		}
	}
	l.enc, l.dec = cs0, cs1
	return l, nil
}

// acceptResponder runs the Noise_NK responder with key, presenting cred in msg2
// (the exit's admission credential in the real system; a stand-in token here). This
// is core/e2e.go's exitHandshake, minus reading the target (the caller reads it).
func acceptResponder(raw io.ReadWriteCloser, key noise.DHKey, cred []byte) (*layer, error) {
	l := newLayer(raw)
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   suite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: key,
	})
	if err != nil {
		return nil, err
	}
	msg1, err := l.readFrame()
	if err != nil {
		return nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, err // wrong key => cannot decrypt the initiator's msg1
	}
	msg2, cs0, cs1, err := hs.WriteMessage(nil, cred)
	if err != nil {
		return nil, err
	}
	if err := l.writeFrame(msg2); err != nil {
		return nil, err
	}
	if cs0 == nil || cs1 == nil {
		return nil, errHandshakeIncomplete
	}
	l.enc, l.dec = cs1, cs0 // responder: encrypt resp->init with cs1, decrypt with cs0
	return l, nil
}

// sendTarget writes one framed message — the next-hop address for a relay layer, or
// the real destination for the innermost (exit) layer.
func (l *layer) sendTarget(target string) error {
	_, err := l.Write([]byte(target))
	return err
}

// readTarget reads exactly one framed message (the target). Bytes after it stay in
// the buffer for the splice, so a relay reads its next-hop address and then forwards
// the untouched inner stream — the one-layer peel.
func (l *layer) readTarget() (string, error) {
	frame, err := l.readFrame()
	if err != nil {
		return "", err
	}
	pt, err := l.dec.Decrypt(nil, nil, frame)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (l *layer) writeFrame(b []byte) error {
	if len(b) > maxFrame {
		return errFrameTooLarge
	}
	frame := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(b)))
	copy(frame[2:], b)
	_, err := l.raw.Write(frame)
	return err
}

func (l *layer) readFrame() ([]byte, error) {
	for {
		if f, ok := l.takeFrame(); ok {
			return f, nil
		}
		n, err := l.raw.Read(l.rtmp)
		if n > 0 {
			l.rbuf = append(l.rbuf, l.rtmp[:n]...)
		}
		if err != nil {
			if f, ok := l.takeFrame(); ok {
				return f, nil
			}
			return nil, err
		}
	}
}

func (l *layer) takeFrame() ([]byte, bool) {
	if len(l.rbuf) < 2 {
		return nil, false
	}
	n := int(binary.BigEndian.Uint16(l.rbuf[:2]))
	if len(l.rbuf) < 2+n {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, l.rbuf[2:2+n])
	l.rbuf = l.rbuf[2+n:]
	return out, true
}

// Read/Write make a layer an io.ReadWriteCloser, so a deeper layer can run over it
// (the nesting) and a relay can io.Copy-splice the decrypted inner stream onward.
func (l *layer) Read(p []byte) (int, error) {
	for len(l.pt) == 0 {
		frame, err := l.readFrame()
		if err != nil {
			return 0, err
		}
		pt, err := l.dec.Decrypt(nil, nil, frame)
		if err != nil {
			return 0, err
		}
		l.pt = pt
	}
	n := copy(p, l.pt)
	l.pt = l.pt[n:]
	return n, nil
}

func (l *layer) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > maxPlain {
			n = maxPlain
		}
		ct, err := l.enc.Encrypt(nil, nil, p[:n])
		if err != nil {
			return total, err
		}
		if err := l.writeFrame(ct); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func (l *layer) Close() error { return l.raw.Close() }
