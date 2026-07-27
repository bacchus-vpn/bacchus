package core

import "testing"

// onRelayReselect is the client half of issue #96: a coordinator "reselect" push —
// the peer relay carrying this client's single-transport session has died — closes
// the active session so reconnectLoop re-establishes onto a fresh relay or the TURN
// fallback. It is scoped to the live session id so a stale nudge (for a path the
// client already left after its own transport recovered) can never tear down the
// healthy session. These drive onRelayReselect directly with a fakeSession and no
// coordinator I/O, mirroring reaper_test's style; assertClosed/assertOpen and
// newFakeSession come from reaper_test.go / pool_test.go.

func TestOnRelayReselectClosesMatchingSession(t *testing.T) {
	e := newReconnectEngine(t, nil)
	sess := newFakeSession()
	e.setReconnectSession(connPath{sess: sess, ctr: nil, sid: "sid-live", exitPub: testExitPub})

	e.onRelayReselect(wire{Type: "reselect", Session: "sid-live"})

	// Closing the active session is what fires reconnectLoop's Closed() watch.
	assertClosed(t, sess, "active session on a matching reselect")
}

func TestOnRelayReselectIgnoresStaleSession(t *testing.T) {
	e := newReconnectEngine(t, nil)
	sess := newFakeSession()
	e.setReconnectSession(connPath{sess: sess, ctr: nil, sid: "sid-current", exitPub: testExitPub})

	// A nudge for a session the client already moved off must not touch the live one.
	e.onRelayReselect(wire{Type: "reselect", Session: "sid-old"})

	assertOpen(t, sess, "active session on a stale reselect")
}

func TestOnRelayReselectIgnoresEmptySessionID(t *testing.T) {
	e := newReconnectEngine(t, nil)
	sess := newFakeSession()
	e.setReconnectSession(connPath{sess: sess, ctr: nil, sid: "sid-current", exitPub: testExitPub})

	// A malformed nudge carrying no session id must not match (and so must not
	// close) the live session, even though rcSid is likewise never empty here.
	e.onRelayReselect(wire{Type: "reselect", Session: ""})

	assertOpen(t, sess, "active session on an empty-id reselect")
}

func TestOnRelayReselectNoActiveSessionIsNoop(t *testing.T) {
	e := newReconnectEngine(t, nil)
	// rcSess is nil (never connected, or a pooled client with its own failover):
	// the nudge must be a safe no-op, not a nil-session panic.
	e.onRelayReselect(wire{Type: "reselect", Session: "whatever"})
}
