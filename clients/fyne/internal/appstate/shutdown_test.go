package appstate

import (
	"sync/atomic"
	"testing"
	"time"
)

// slowSession is an enforcement.Session whose teardown takes long enough to
// tell "waited for it" apart from "started it".
//
// The real one is not instant either: Close lifts the kill-switch, restores the
// firewall profiles' DefaultOutboundAction and removes the split-default routes,
// which on Windows is a sequence of PowerShell invocations.
type slowSession struct {
	took   time.Duration
	closed atomic.Bool
}

func (s *slowSession) ReserveUnderlay(string) {}

func (s *slowSession) Close() {
	time.Sleep(s.took)
	s.closed.Store(true)
}

// TestDisconnectAndWaitWaits is the ordering guarantee bacchus#186's quit path
// rests on.
//
// The close button used to be `ctrl.Disconnect(); w.Close()`, which reads as an
// ordering and is not one: Disconnect spawns a goroutine and returns, w.Close()
// takes the last window down, and the driver exits the process. Whether the
// kill-switch was lifted before the process died was a race — and losing it is
// bacchus#115's stranded machine, firewall profiles left at Block with no client
// left to lift them and nothing said anywhere.
//
// Mutation check: make DisconnectAndWait call Disconnect and this goes red.
func TestDisconnectAndWaitWaits(t *testing.T) {
	sess := &slowSession{took: 150 * time.Millisecond}

	c := NewController(Config{})
	c.OnState = func(ConnState) {}
	c.OnDetail = func(Detail) {}
	c.mu.Lock()
	c.sess, c.state = sess, Protected
	c.mu.Unlock()

	c.DisconnectAndWait()

	if !sess.closed.Load() {
		t.Fatal("DisconnectAndWait returned with the enforcement session still coming down — the process can exit with the kill-switch armed")
	}
	c.mu.Lock()
	got := c.state
	c.mu.Unlock()
	if got != Disconnected {
		t.Errorf("state is %v after DisconnectAndWait, want Disconnected", got)
	}
}

// TestDisconnectStillDoesNotWait pins the other side of the split, so that
// TestDisconnectAndWaitWaits cannot pass by both functions having quietly
// become synchronous.
//
// Disconnect's asynchrony is deliberate and stays: it is called from the UI
// goroutine by the window's button, and the state is published the instant the
// user asks rather than when the last goroutine winds up — which is also simply
// the truth, since the session is unreachable from the moment it is detached.
func TestDisconnectStillDoesNotWait(t *testing.T) {
	sess := &slowSession{took: 2 * time.Second}

	c := NewController(Config{})
	c.OnState = func(ConnState) {}
	c.OnDetail = func(Detail) {}
	c.mu.Lock()
	c.sess, c.state = sess, Protected
	c.mu.Unlock()

	start := time.Now()
	c.Disconnect()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Disconnect blocked for %s — it is called from the UI goroutine and must not", elapsed)
	}
	if sess.closed.Load() {
		t.Fatal("the teardown finished inside Disconnect, so this test is asserting nothing")
	}

	// Left running; the goroutine finishes on its own. Waited for here only so
	// the test does not leave one behind for -race to trip over.
	deadline := time.Now().Add(10 * time.Second)
	for !sess.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("Disconnect never completed its teardown")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
