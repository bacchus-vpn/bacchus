package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Transport establishes authenticated, peer-to-peer, bidirectional byte-stream
// sessions between two nodes the coordinator has already paired. Everything
// above this line — role logic, SOCKS, forwarding — is transport-agnostic.
//
// WebRTC (pion) is the first implementation (transport_webrtc.go), valued for
// its built-in ICE/STUN/TURN NAT traversal, not trusted as camouflage. Other
// transports (obfuscated UDP, Reality-XHTTP) implement the same interface and
// run behind a client-side pool with per-user failover — coverage is the union
// of many partial transports, not any single one's properties (see ADR-0008).
//
// A single Transport value serves many concurrent sessions. Dial and Accept each
// build one Session, driving the handshake through the supplied Signaler.
type Transport interface {
	// Name identifies the transport for logging and the pool.
	Name() string

	// Dial establishes a session as the initiator (client side). It drives
	// signaling through sig and returns once the session is usable, or an error
	// if the handshake fails or ctx is done.
	Dial(ctx context.Context, sig Signaler) (Session, error)

	// Accept establishes a session as the responder (exit/relay side). It drives
	// signaling through sig and returns once the local end is set up; inbound
	// streams then arrive via Session.AcceptStream.
	Accept(ctx context.Context, sig Signaler) (Session, error)
}

// Session is an established transport session: a multiplexed set of labeled,
// bidirectional byte-streams between the two paired peers. It is safe for
// concurrent use.
type Session interface {
	// OpenStream opens an outbound stream carrying label; the remote peer
	// receives it via AcceptStream. It blocks until the stream is usable, the
	// session closes, or ctx is done.
	OpenStream(ctx context.Context, label string) (Stream, error)

	// AcceptStream returns the next stream the remote peer opened. It blocks
	// until one arrives, the session closes, or ctx is done.
	AcceptStream(ctx context.Context) (Stream, error)

	// Closed is closed when the session ends (peer gone, transport failure, or
	// Close). It never carries a value.
	Closed() <-chan struct{}

	// Close tears the session and its streams down. It is idempotent.
	Close() error
}

// Stream is one bidirectional byte-stream within a Session, tagged with the
// label its opener supplied. The label is meaningful to the application layer
// (e.g. a target host:port) and opaque to the transport.
type Stream interface {
	io.ReadWriteCloser
	Label() string
}

// Signaler relays a transport's opaque handshake frames to and from the remote
// peer of a pending session, through the coordinator. The engine owns the
// concrete implementation (it holds the coordinator connection and the session
// id); a Transport only sends and receives frames and never learns how they are
// carried.
type Signaler interface {
	// Send delivers one frame to the remote peer.
	Send(ctx context.Context, f SignalFrame) error
	// Recv returns the next inbound frame, blocking until one arrives, the
	// session tears down, or ctx is done.
	Recv(ctx context.Context) (SignalFrame, error)
}

// SignalFrame is one handshake message. Kind is a transport-defined tag; it is
// routed verbatim as the coordinator wire type, so it must be one the
// coordinator relays ("offer", "answer", "candidate"). Data is the
// transport-defined payload, opaque to both the engine and the coordinator.
type SignalFrame struct {
	Kind string
	Data json.RawMessage
}

var (
	errSessionClosed = errors.New("core: session closed")
	errEngineStopped = errors.New("core: engine stopped")
)

// Built-in transports, usable by name in [Config.Transport] (one) or
// [Config.TransportPool] (several). WebRTC (UDP/DTLS) brings NAT traversal;
// Reality (TCP :443, camouflage TLS) covers networks that throttle UDP or
// DataChannels and fails on a different axis (ADR-0008, issue #16). The
// client-side pool races them per user when TransportPool is set (issue #15,
// ADR-0028); otherwise [Config.Transport] selects exactly one.
const (
	TransportWebRTC  = "webrtc"
	TransportReality = "reality"
)

// newTransport builds the session transport named by cfg.Transport. An empty
// value defaults to WebRTC, preserving every caller that predates the field.
func newTransport(cfg Config, onEvent func(kind, msg string)) (Transport, error) {
	switch cfg.Transport {
	case "", TransportWebRTC:
		return newWebRTCTransport(cfg, onEvent), nil
	case TransportReality:
		return newRealityTransport(cfg, onEvent)
	default:
		return nil, fmt.Errorf("core: unknown transport %q (want %q or %q)",
			cfg.Transport, TransportWebRTC, TransportReality)
	}
}
