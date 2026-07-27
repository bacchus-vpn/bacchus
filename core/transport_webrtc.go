package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	ice "github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
)

// Signaling frame kinds. These double as coordinator wire types, so they must
// stay within the set the coordinator relays.
const (
	sigOffer     = "offer"
	sigAnswer    = "answer"
	sigCandidate = "candidate"
)

// ctrlLabel is an internal data channel the initiator opens purely to detect
// that the session is usable: its OnOpen marks the path established. It carries
// no application data.
const ctrlLabel = "control"

// webrtcTransport is the pion/WebRTC implementation of Transport. It holds the
// ICE configuration and the resolved DTLS fingerprint profile; each Dial/Accept
// builds its own SettingEngine + PeerConnection (see newPC) so ICE credentials
// can be freshly browser-shaped per connection.
type webrtcTransport struct {
	iceServers    []webrtc.ICEServer
	icePolicy     webrtc.ICETransportPolicy
	profile       dtlsProfile            // DTLS fingerprint profile; valid iff profileActive
	profileActive bool                   // false when DTLSFingerprint is "off"/unrecognized
	fingerprint   string                 // active profile name, or "off"
	mdns          bool                   // emit .local mDNS host candidates instead of raw IPs
	onEvent       func(kind, msg string) // optional; ICE-state + error notices
}

// newWebRTCTransport builds the transport from a node Config. onEvent, when
// non-nil, receives transport-level notices (ICE state changes, errors).
//
// The DTLS fingerprint profile is resolved once, here, and reused for every
// connection this node makes: an "auto" node commits to one browser identity for
// its lifetime — a node that flipped Chrome<->Firefox per call would itself be
// an anomaly. Per-connection variation (GREASE, extension permutation, ICE
// credentials) is drawn inside newPC, the way one real browser still varies from
// call to call.
func newWebRTCTransport(cfg Config, onEvent func(kind, msg string)) *webrtcTransport {
	var iceServers []webrtc.ICEServer
	if cfg.STUNURL != "" {
		iceServers = append(iceServers, webrtc.ICEServer{URLs: []string{cfg.STUNURL}})
	}
	if cfg.TURNURL != "" {
		iceServers = append(iceServers, webrtc.ICEServer{
			URLs:       []string{cfg.TURNURL},
			Username:   cfg.TURNUser,
			Credential: cfg.TURNPass,
		})
	}
	policy := webrtc.ICETransportPolicyAll
	if cfg.ForceRelay {
		policy = webrtc.ICETransportPolicyRelay
	}

	t := &webrtcTransport{
		iceServers:  iceServers,
		icePolicy:   policy,
		fingerprint: FingerprintOff,
		mdns:        cfg.ICEmDNS,
		onEvent:     onEvent,
	}
	// Resolve the DTLS fingerprint profile once (issue #14, ADR-0018). It is
	// re-installed on each per-connection SettingEngine in newPC.
	if prof, ok := profileFor(cfg.DTLSFingerprint, newConnRand()); ok {
		t.profile = prof
		t.profileActive = true
		t.fingerprint = prof.name
	}
	return t
}

func (t *webrtcTransport) Name() string { return "webrtc" }

// newPC builds a PeerConnection on its own SettingEngine + API. A fresh
// SettingEngine per connection is what makes ICE credentials per-connection:
// pion bakes the ufrag/pwd into the API at construction time (the ICE gatherer
// reads SettingEngine.candidates), so a shared API could only ever carry one
// credential pair — and reusing one pair fleet-wide is a *stronger* fingerprint
// than pion's default, not a weaker one (issue #49). Building the API here costs
// a little per dial/accept, but a DataChannel-only API is cheap to assemble.
func (t *webrtcTransport) newPC() (*webrtc.PeerConnection, error) {
	se := webrtc.SettingEngine{}
	se.DetachDataChannels()

	if t.profileActive {
		// DTLS ClientHello + ServerHello reshaping (issues #14 and #49).
		t.profile.apply(&se)
		// Browser-shaped, per-connection ICE ufrag/pwd (issue #49). On error we
		// leave pion's defaults rather than fail the connection: the pwd is a real
		// MESSAGE-INTEGRITY key, so a bad randomness draw must never take a session
		// down — camouflage is best-effort, connectivity is not.
		if ufrag, pwd, err := browserICECredentials(t.profile); err == nil && ufrag != "" {
			se.SetICECredentials(ufrag, pwd)
		}
	}

	// mDNS host candidates (.local) instead of raw private IPs. Off by default —
	// a connectivity trade-off for the full-device client (issue #49, ADR-0022).
	if t.mdns {
		se.SetICEMulticastDNSMode(ice.MulticastDNSModeQueryAndGather)
	}

	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))
	return api.NewPeerConnection(webrtc.Configuration{
		ICEServers:         t.iceServers,
		ICETransportPolicy: t.icePolicy,
	})
}

// Dial is the initiator: open a control channel, send an offer, apply the
// answer + trickled candidates, and return once the control channel opens.
func (t *webrtcTransport) Dial(ctx context.Context, sig Signaler) (Session, error) {
	pc, err := t.newPC()
	if err != nil {
		return nil, err
	}
	s := newWebRTCSession(pc, t.Name(), t.onEvent)
	t.trickleOut(s, sig)

	ready := make(chan struct{})
	var once sync.Once
	ctrl, err := pc.CreateDataChannel(ctrlLabel, nil)
	if err != nil {
		s.Close()
		return nil, err
	}
	ctrl.OnOpen(func() { _, _ = ctrl.Detach(); once.Do(func() { close(ready) }) })

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		s.Close()
		return nil, err
	}

	go t.signalingLoop(s, sig, false)
	t.sendSDP(s.ctx, sig, sigOffer, offer.SDP)

	select {
	case <-ready:
		return s, nil
	case <-ctx.Done():
		s.Close()
		return nil, ctx.Err()
	case <-s.closed:
		return nil, errors.New("core: webrtc session closed during dial")
	}
}

// Accept is the responder: answer inbound offers and surface data channels as
// streams. It returns immediately; streams arrive via AcceptStream.
func (t *webrtcTransport) Accept(ctx context.Context, sig Signaler) (Session, error) {
	pc, err := t.newPC()
	if err != nil {
		return nil, err
	}
	s := newWebRTCSession(pc, t.Name(), t.onEvent)
	t.trickleOut(s, sig)
	go t.signalingLoop(s, sig, true)
	return s, nil
}

// trickleOut ships our local ICE candidates to the peer as they are gathered.
func (t *webrtcTransport) trickleOut(s *webrtcSession, sig Signaler) {
	s.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		raw, _ := json.Marshal(c.ToJSON())
		_ = sig.Send(s.ctx, SignalFrame{Kind: sigCandidate, Data: raw})
	})
}

// signalingLoop applies inbound frames to the peer connection for the session's
// lifetime. answerer distinguishes the responder (consumes offers, produces
// answers) from the initiator (consumes answers).
func (t *webrtcTransport) signalingLoop(s *webrtcSession, sig Signaler, answerer bool) {
	for {
		f, err := sig.Recv(s.ctx)
		if err != nil {
			return
		}
		switch f.Kind {
		case sigOffer:
			if !answerer {
				continue
			}
			sdp, ok := decodeSDP(f.Data)
			if !ok || !s.setRemote(webrtc.SDPTypeOffer, sdp) {
				continue
			}
			ans, err := s.pc.CreateAnswer(nil)
			if err != nil {
				continue
			}
			if err := s.pc.SetLocalDescription(ans); err != nil {
				continue
			}
			t.sendSDP(s.ctx, sig, sigAnswer, ans.SDP)
		case sigAnswer:
			if answerer {
				continue
			}
			if sdp, ok := decodeSDP(f.Data); ok {
				s.setRemote(webrtc.SDPTypeAnswer, sdp)
			}
		case sigCandidate:
			var ci webrtc.ICECandidateInit
			if json.Unmarshal(f.Data, &ci) == nil {
				s.addCandidate(ci)
			}
		}
	}
}

// sendSDP encodes an SDP as a frame and retransmits it a couple of times, since
// coordinator signaling rides best-effort UDP.
func (t *webrtcTransport) sendSDP(ctx context.Context, sig Signaler, kind, sdp string) {
	data, _ := json.Marshal(sdp)
	for i := 0; i < 2; i++ {
		if err := sig.Send(ctx, SignalFrame{Kind: kind, Data: data}); err != nil {
			return
		}
		time.Sleep(60 * time.Millisecond)
	}
}

func decodeSDP(data json.RawMessage) (string, bool) {
	var sdp string
	if json.Unmarshal(data, &sdp) != nil {
		return "", false
	}
	return sdp, true
}

// webrtcSession is one established (or establishing) PeerConnection behind the
// Session interface. Application streams are non-control data channels; the
// control channel is consumed internally.
type webrtcSession struct {
	name    string
	pc      *webrtc.PeerConnection
	ctx     context.Context
	cancel  context.CancelFunc
	onEvent func(kind, msg string)

	accept chan Stream
	closed chan struct{}
	once   sync.Once

	remoteMu  sync.Mutex
	remoteSet bool
	pending   []webrtc.ICECandidateInit
}

func newWebRTCSession(pc *webrtc.PeerConnection, name string, onEvent func(kind, msg string)) *webrtcSession {
	ctx, cancel := context.WithCancel(context.Background())
	s := &webrtcSession{
		name:    name,
		pc:      pc,
		ctx:     ctx,
		cancel:  cancel,
		onEvent: onEvent,
		accept:  make(chan Stream, 8),
		closed:  make(chan struct{}),
	}
	pc.OnICEConnectionStateChange(func(st webrtc.ICEConnectionState) {
		if s.onEvent != nil {
			s.onEvent(EventICE, fmt.Sprintf("%s ICE: %s", name, st))
		}
		if st == webrtc.ICEConnectionStateFailed || st == webrtc.ICEConnectionStateClosed {
			_ = s.Close()
		}
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		if dc.Label() == ctrlLabel {
			dc.OnOpen(func() { _, _ = dc.Detach() })
			return
		}
		label := dc.Label()
		dc.OnOpen(func() {
			raw, err := dc.Detach()
			if err != nil {
				return
			}
			st := &webrtcStream{label: label, rwc: raw}
			select {
			case s.accept <- st:
			case <-s.closed:
				_ = raw.Close()
			}
		})
	})
	return s
}

// setRemote sets the remote description once and flushes any candidates that
// arrived before it. It reports whether the description was applied.
func (s *webrtcSession) setRemote(typ webrtc.SDPType, sdp string) bool {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	if s.remoteSet {
		return false
	}
	if err := s.pc.SetRemoteDescription(webrtc.SessionDescription{Type: typ, SDP: sdp}); err != nil {
		return false
	}
	s.remoteSet = true
	for _, ci := range s.pending {
		_ = s.pc.AddICECandidate(ci)
	}
	s.pending = nil
	return true
}

// addCandidate applies a remote ICE candidate, buffering it until the remote
// description is set.
func (s *webrtcSession) addCandidate(ci webrtc.ICECandidateInit) {
	s.remoteMu.Lock()
	defer s.remoteMu.Unlock()
	if s.remoteSet {
		_ = s.pc.AddICECandidate(ci)
	} else {
		s.pending = append(s.pending, ci)
	}
}

func (s *webrtcSession) OpenStream(ctx context.Context, label string) (Stream, error) {
	dc, err := s.pc.CreateDataChannel(label, nil)
	if err != nil {
		return nil, err
	}
	rwCh := make(chan io.ReadWriteCloser, 1)
	dc.OnOpen(func() {
		raw, err := dc.Detach()
		if err != nil {
			close(rwCh)
			return
		}
		rwCh <- raw
	})
	select {
	case raw := <-rwCh:
		if raw == nil {
			return nil, errors.New("core: data channel detach failed")
		}
		return &webrtcStream{label: label, rwc: raw}, nil
	case <-ctx.Done():
		_ = dc.Close()
		return nil, ctx.Err()
	case <-s.closed:
		_ = dc.Close()
		return nil, errSessionClosed
	}
}

func (s *webrtcSession) AcceptStream(ctx context.Context) (Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.closed:
		return nil, errSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *webrtcSession) Closed() <-chan struct{} { return s.closed }

func (s *webrtcSession) Close() error {
	s.once.Do(func() {
		s.cancel()
		close(s.closed)
		_ = s.pc.Close()
	})
	return nil
}

// webrtcStream adapts a detached data channel (an io.ReadWriteCloser) to Stream
// by attaching its label.
type webrtcStream struct {
	label string
	rwc   io.ReadWriteCloser
}

func (s *webrtcStream) Read(p []byte) (int, error)  { return s.rwc.Read(p) }
func (s *webrtcStream) Write(p []byte) (int, error) { return s.rwc.Write(p) }
func (s *webrtcStream) Close() error                { return s.rwc.Close() }
func (s *webrtcStream) Label() string               { return s.label }
