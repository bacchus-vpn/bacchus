package core

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Compile-time checks that every transport satisfies the interface set.
var (
	_ Transport = (*webrtcTransport)(nil)
	_ Transport = (*realityTransport)(nil)
	_ Transport = loopbackTransport{}
	_ Session   = (*webrtcSession)(nil)
	_ Session   = (*realitySession)(nil)
	_ Session   = (*lbSession)(nil)
	_ Stream    = (*webrtcStream)(nil)
	_ Stream    = (*realityStream)(nil)
	_ Stream    = (*lbStream)(nil)
	_ Signaler  = (*coordSignaler)(nil)
	_ Signaler  = (*memSignaler)(nil)
)

// memSignaler is an in-memory Signaler for tests; a pair is cross-wired so one
// end's Send is the other end's Recv.
type memSignaler struct {
	out chan SignalFrame
	in  chan SignalFrame
}

func newMemSignalerPair() (*memSignaler, *memSignaler) {
	a2b := make(chan SignalFrame, 32)
	b2a := make(chan SignalFrame, 32)
	return &memSignaler{out: a2b, in: b2a}, &memSignaler{out: b2a, in: a2b}
}

func (s *memSignaler) Send(ctx context.Context, f SignalFrame) error {
	select {
	case s.out <- f:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *memSignaler) Recv(ctx context.Context) (SignalFrame, error) {
	select {
	case f := <-s.in:
		return f, nil
	case <-ctx.Done():
		return SignalFrame{}, ctx.Err()
	}
}

// loopbackTransport is a trivial in-process Transport used to exercise the
// interface without WebRTC. Dial and Accept rendezvous through lbHub using an id
// carried in a single signaling frame.
type loopbackTransport struct{}

func (loopbackTransport) Name() string { return "loopback" }

type lbPair struct {
	toResp chan Stream
	toInit chan Stream
	closed chan struct{}
	once   sync.Once
}

func (p *lbPair) close() { p.once.Do(func() { close(p.closed) }) }

var lbHub = struct {
	sync.Mutex
	m map[string]*lbPair
}{m: map[string]*lbPair{}}

func (loopbackTransport) Dial(ctx context.Context, sig Signaler) (Session, error) {
	id := randID()
	p := &lbPair{toResp: make(chan Stream, 16), toInit: make(chan Stream, 16), closed: make(chan struct{})}
	lbHub.Lock()
	lbHub.m[id] = p
	lbHub.Unlock()
	data, _ := json.Marshal(id)
	if err := sig.Send(ctx, SignalFrame{Kind: sigOffer, Data: data}); err != nil {
		return nil, err
	}
	return &lbSession{pair: p, out: p.toResp, in: p.toInit}, nil
}

func (loopbackTransport) Accept(ctx context.Context, sig Signaler) (Session, error) {
	f, err := sig.Recv(ctx)
	if err != nil {
		return nil, err
	}
	var id string
	if json.Unmarshal(f.Data, &id) != nil {
		return nil, errors.New("loopback: bad frame")
	}
	lbHub.Lock()
	p := lbHub.m[id]
	delete(lbHub.m, id)
	lbHub.Unlock()
	if p == nil {
		return nil, errors.New("loopback: unknown pair")
	}
	return &lbSession{pair: p, out: p.toInit, in: p.toResp}, nil
}

type lbSession struct {
	pair *lbPair
	out  chan Stream // peer ends of streams we open
	in   chan Stream // streams the peer opens
}

func (s *lbSession) OpenStream(ctx context.Context, label string) (Stream, error) {
	select {
	case <-s.pair.closed:
		return nil, errSessionClosed
	default:
	}
	a, b := net.Pipe()
	local := &lbStream{Conn: a, label: label}
	peer := &lbStream{Conn: b, label: label}
	select {
	case s.out <- peer:
		return local, nil
	case <-s.pair.closed:
		a.Close()
		b.Close()
		return nil, errSessionClosed
	case <-ctx.Done():
		a.Close()
		b.Close()
		return nil, ctx.Err()
	}
}

func (s *lbSession) AcceptStream(ctx context.Context) (Stream, error) {
	select {
	case st := <-s.in:
		return st, nil
	case <-s.pair.closed:
		return nil, errSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *lbSession) Closed() <-chan struct{} { return s.pair.closed }
func (s *lbSession) Close() error            { s.pair.close(); return nil }

type lbStream struct {
	net.Conn
	label string
}

func (s *lbStream) Label() string { return s.label }

// echoSession accepts every stream on sess and echoes it back until closed.
func echoSession(sess Session) {
	for {
		st, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func(st Stream) {
			_, _ = io.Copy(st, st)
			_ = st.Close()
		}(st)
	}
}

func TestLoopbackTransportRoundTrip(t *testing.T) {
	dialerSig, accepterSig := newMemSignalerPair()
	var tr loopbackTransport

	accepted := make(chan Session, 1)
	go func() {
		sess, err := tr.Accept(context.Background(), accepterSig)
		if err != nil {
			t.Errorf("Accept: %v", err)
			accepted <- nil
			return
		}
		accepted <- sess
		echoSession(sess)
	}()

	sess, err := tr.Dial(context.Background(), dialerSig)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer sess.Close()
	if s := <-accepted; s == nil {
		t.Fatal("accept side failed")
	}

	const label = "example.com:443"
	st, err := sess.OpenStream(context.Background(), label)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if st.Label() != label {
		t.Fatalf("label = %q, want %q", st.Label(), label)
	}

	msg := []byte("hello transport")
	go func() { _, _ = st.Write(msg) }()
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(st, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf, msg)
	}
	_ = st.Close()
}

func TestLoopbackSessionClose(t *testing.T) {
	dialerSig, accepterSig := newMemSignalerPair()
	var tr loopbackTransport

	go func() {
		if _, err := tr.Accept(context.Background(), accepterSig); err != nil {
			t.Errorf("Accept: %v", err)
		}
	}()

	sess, err := tr.Dial(context.Background(), dialerSig)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	sess.Close()

	select {
	case <-sess.Closed():
	case <-time.After(time.Second):
		t.Fatal("Closed() not signalled after Close()")
	}
	if _, err := sess.OpenStream(context.Background(), "x:1"); err == nil {
		t.Fatal("OpenStream on a closed session should fail")
	}
}
