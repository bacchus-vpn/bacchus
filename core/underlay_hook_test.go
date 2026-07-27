package core

import (
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

// TestRealityUnderlayDialWiredFromConfig proves Config.OnUnderlayDial reaches the
// reality transport — a nil hook stays nil, a set hook is stored — so a
// full-device client that sets it actually gets the pre-dial callback (issue
// #109).
func TestRealityUnderlayDialWiredFromConfig(t *testing.T) {
	bare, err := newRealityTransport(Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bare.onUnderlayDial != nil {
		t.Fatal("onUnderlayDial should be nil when Config.OnUnderlayDial is unset")
	}
	called := false
	wired, err := newRealityTransport(Config{OnUnderlayDial: func(string) { called = true }}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if wired.onUnderlayDial == nil {
		t.Fatal("onUnderlayDial should be set from Config.OnUnderlayDial")
	}
	wired.onUnderlayDial("x")
	if !called {
		t.Fatal("stored hook is not the one from Config")
	}
}

// TestRealityUnderlayDialFiresBeforeUnderlayConnect is the leak-focused ordering
// proof for issue #109: OnUnderlayDial must run — and, for a full-device client,
// finish making the address tunnel-safe — BEFORE reality opens the underlay TCP
// connection to it. If it fired after the dial (a "route flip races the real
// address" leak), the connection would already be established here.
//
// The hook blocks inside dialInner; while it is held, the test asserts the
// listener has accepted nothing. In correct (pre-dial) code the connection has
// not been dialed yet, so nothing is accepted. Move the hook to AFTER
// d.DialContext and this fails: the connection is accepted before the hook is
// even entered. NON-VACUOUS — verified by doing exactly that revert and watching
// it fail.
func TestRealityUnderlayDialFiresBeforeUnderlayConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = c.Close() // so the client's TLS handshake fails fast, not on the deadline
	}()

	hookEntered := make(chan struct{})
	release := make(chan struct{})
	var gotAddr string
	tr, err := newRealityTransport(Config{
		OnUnderlayDial: func(addr string) {
			gotAddr = addr
			close(hookEntered)
			<-release // hold the dial path inside the hook
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// A well-formed answer: 16-byte token, 32-byte exit key, the listener's
	// address. dialInner validates these before it reaches the hook + dial.
	ans := realityAnswer{
		Addr:  ln.Addr().String(),
		Token: hex.EncodeToString(newToken()),
		Pub:   hex.EncodeToString(make([]byte, 32)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dialDone := make(chan error, 1)
	go func() {
		_, err := tr.dialInner(ctx, ans, ctrlLabel)
		dialDone <- err
	}()

	select {
	case <-hookEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("OnUnderlayDial was never called on the dial path")
	}
	// The hook is now blocked inside dialInner. Prove no underlay connection
	// exists yet — this is the whole leak-safety invariant.
	select {
	case <-accepted:
		t.Fatal("underlay connection was accepted before OnUnderlayDial returned — pre-dial ordering violated (leak window)")
	case <-time.After(200 * time.Millisecond):
		// good: nothing dialed while the hook is held
	}
	if gotAddr != ans.Addr {
		t.Fatalf("OnUnderlayDial got %q, want the exit's dial address %q", gotAddr, ans.Addr)
	}
	close(release) // let the dial proceed; the handshake then fails harmlessly

	select {
	case <-accepted:
		// expected: once released, the underlay is dialed and accepted
	case <-time.After(3 * time.Second):
		t.Fatal("underlay was never dialed after the hook released")
	}
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("dialInner did not return")
	}
}
