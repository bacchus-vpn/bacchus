package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
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

// ---------- transport protocol versions (issue #176, decision B3) ----------

// transportVersionSep separates a transport's base name from the protocol
// version of that transport in a configured name: "reality/2".
const transportVersionSep = "/"

// transportVersions is the protocol version THIS BUILD implements for each
// transport — the number that changes when a camouflage protocol is patched into
// a shape an older peer cannot complete a handshake with.
//
// It is a third version axis and deliberately none of the other two:
//
//   - Release (ADR-0015/0029) versions the whole binary and fences stale NODES
//     through -min-serving-version.
//   - handshake.ProtocolVersion (ADR-0016) versions the signaling wire shape
//     between a peer and a coordinator.
//   - This versions ONE transport's own handshake, which the coordinator never
//     sees: it rides SignalFrame.Data, opaque to the engine and the coordinator
//     alike (see Signaler). Before #176 a transport was identified by a bare
//     name, so a patched "reality" and an unpatched "reality" agreed that they
//     agreed — the #114 failure one layer further down, and with less protection
//     than the node level had.
//
// Bump the entry for a transport when its handshake or framing changes in a way
// a peer on the previous number cannot complete or cannot decode.
var transportVersions = map[string]int{
	TransportWebRTC:  1,
	TransportReality: 1,
}

// defaultTransportVersion is what a bare name means. A name with no version is
// version 1 and not "unversioned", so every configuration that predates #176
// keeps naming exactly the transport it always named.
const defaultTransportVersion = 1

// splitTransportName splits a configured transport name into its base name and
// the protocol version it asks for: "reality/2" is ("reality", 2), and a bare
// "reality" is ("reality", 1). The empty name is ("", 1) so newTransport's
// default-to-WebRTC case is reached unchanged.
//
// A version that is not a positive integer is an error rather than a fallback.
// Silently reading "reality/two" as version 1 would give an operator who typed a
// version the transport they were trying to move OFF, under the name of the one
// they asked for — which is the failure #176 exists to close, produced by its own
// parser.
func splitTransportName(name string) (base string, version int, err error) {
	i := strings.Index(name, transportVersionSep)
	if i < 0 {
		return name, defaultTransportVersion, nil
	}
	base, raw := name[:i], name[i+len(transportVersionSep):]
	v, convErr := strconv.Atoi(raw)
	if convErr != nil || v < 1 {
		return "", 0, fmt.Errorf("core: transport %q has a malformed version %q — want a positive integer, as in %q",
			name, raw, TransportReality+transportVersionSep+"2")
	}
	return base, v, nil
}

// transportName renders a base name and version back into a configured name. A
// version-1 transport renders bare, so nothing this build writes back out gains
// a suffix that did not arrive with it.
func transportName(base string, version int) string {
	if version == defaultTransportVersion {
		return base
	}
	return base + transportVersionSep + strconv.Itoa(version)
}

// newTransport builds the session transport named by cfg.Transport. An empty
// value defaults to WebRTC, preserving every caller that predates the field.
//
// The name may carry a protocol version (issue #176): "reality/2" builds the
// reality transport and records that this configuration asked for version 2.
//
// # A version this build does not implement is REPORTED, not refused
//
// That is decision B3 and it is the whole of what #176 ships. Refusing to build
// the transport would be a fence, and a fence is only a repair tool where an
// update can be delivered: #34 (the signed release channel) is unstarted, and its
// own words are that "a fence without a channel is a kill switch". A peer left on
// the wrong transport version today has no path to the build that would bring it
// back, so it keeps its ladder and the mismatch announces itself in the log
// instead. B1 — actually declining to match — becomes a flag flip once #34 lands.
//
// The version is not thrown away by being unenforced. It is part of the pool's
// KEY (Engine.transports and selection.Candidate.Transport are both the configured
// string), so bumping it invalidates the learned winner for that path rather than
// letting a route validated against the old shape be tried first next time.
//
// What this does NOT do, and it is the larger half: nothing carries this number
// to the PEER. A transport's own handshake rides SignalFrame.Data, which the
// coordinator relays opaquely, so today only the local side can log the number it
// asked for. Making two peers compare theirs needs a field on a wire message —
// see docs/design/transport-pool.md.
func newTransport(cfg Config, onEvent func(kind, msg string)) (Transport, error) {
	base, version, err := splitTransportName(cfg.Transport)
	if err != nil {
		return nil, err
	}
	if impl, known := transportVersions[base]; known && version != impl && onEvent != nil {
		onEvent(EventInfo, fmt.Sprintf(
			"transport %q asks for protocol version %d and this build implements version %d for %q — "+
				"it is being built and tried anyway, because nothing is fenced on this number until there is a way to deliver an update (issue #34). "+
				"A peer on a different version of this transport may fail to complete a handshake, or complete one and then wedge",
			cfg.Transport, version, impl, base))
	}
	switch base {
	case "", TransportWebRTC:
		return newWebRTCTransport(cfg, onEvent), nil
	case TransportReality:
		return newRealityTransport(cfg, onEvent)
	default:
		return nil, fmt.Errorf("core: unknown transport %q (want %q or %q, each optionally versioned as in %q)",
			cfg.Transport, TransportWebRTC, TransportReality, TransportReality+transportVersionSep+"2")
	}
}
