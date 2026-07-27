package coldstart

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"time"
)

// defaultTimeout bounds a Bootstrap call when ctx carries no deadline of its
// own — a cold-start fetch must not block indefinitely on a silent peer.
const defaultTimeout = 5 * time.Second

// ErrNotAuthenticated means the request reached the server and got a normal
// STUN Binding Success Response — so the endpoint is reachable — but no
// SNAPSHOT attribute came back, meaning the secret was rejected (or this
// endpoint doesn't run the bootstrap protocol at all; the two are
// indistinguishable by design, see docs/design/bootstrap-protocol.md).
// Distinct from a network-level timeout so a caller trying several entry
// points from a seed (design doc §4.2) can tell "wrong credential/not a
// bootstrap endpoint" apart from "unreachable, try the next one anyway
// later."
var ErrNotAuthenticated = errors.New("coldstart: reachable but not authenticated")

// Result is a successful [Bootstrap] outcome: the verified snapshot plus its
// signed wire form, ready to hand to [SaveCache].
type Result struct {
	Snapshot Snapshot
	Signed   []byte
}

// Bootstrap performs one cold-start fetch against addr: it sends a
// STUN-shaped Binding Request authenticated with secretID/secret, and on a
// successful, signature-verified response returns the decoded snapshot. ctx
// bounds the whole exchange, including the wait for a reply.
func Bootstrap(ctx context.Context, addr, secretID string, secret []byte, pub ed25519.PublicKey) (*Result, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("coldstart: resolve %s: %w", addr, err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("coldstart: dial %s: %w", addr, err)
	}
	defer conn.Close()

	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(defaultTimeout)
	}
	if err := conn.SetDeadline(dl); err != nil {
		return nil, fmt.Errorf("coldstart: set deadline: %w", err)
	}

	tx := newTxID()
	req := buildRequest(tx, secretID, secret)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("coldstart: send request: %w", err)
	}

	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("coldstart: read response: %w", err)
	}
	raw := buf[:n]

	m, err := parse(raw)
	if err != nil {
		return nil, err
	}
	if m.typ != typeBindingSuccess {
		return nil, errNotBindingOK
	}
	if m.tx != tx {
		return nil, errTxMismatch
	}

	signed, ok := m.get(attrSnapshot)
	if !ok {
		return nil, ErrNotAuthenticated
	}
	snap, err := Verify(pub, signed)
	if err != nil {
		return nil, err
	}
	return &Result{Snapshot: snap, Signed: append([]byte(nil), signed...)}, nil
}
