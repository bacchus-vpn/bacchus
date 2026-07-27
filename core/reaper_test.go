package core

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// newReaperEngine builds an exit-role engine without starting it, so a test can
// drive trackSession/reapIdle directly with fakeSessions and no coordinator or
// transport I/O. Stop is registered as cleanup to drain the per-session watcher
// goroutines trackSession spawns.
func newReaperEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleExit},
		Advertise:    "127.0.0.1:9",
		ListenAddr:   "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { e.Stop(); e.Wait() })
	return e
}

// memStream is an in-memory Stream: reads drain rd, writes collect into wr. It
// lets a test exercise the activityStream wrapper without a real transport.
type memStream struct {
	label string
	rd    *bytes.Reader
	wr    bytes.Buffer
}

func (m *memStream) Read(p []byte) (int, error)  { return m.rd.Read(p) }
func (m *memStream) Write(p []byte) (int, error) { return m.wr.Write(p) }
func (m *memStream) Close() error                { return nil }
func (m *memStream) Label() string               { return m.label }

// backdate makes ts look idle since well before any test's idleTTL, so the
// reaper's decision turns on the predicate rather than on wall-clock timing.
func backdate(ts *trackedSession) {
	ts.lastNano.Store(time.Now().Add(-time.Hour).UnixNano())
}

func assertClosed(t *testing.T, s *fakeSession, what string) {
	t.Helper()
	select {
	case <-s.Closed():
	default:
		t.Fatalf("%s was not closed", what)
	}
}

func assertOpen(t *testing.T, s *fakeSession, what string) {
	t.Helper()
	select {
	case <-s.Closed():
		t.Fatalf("%s was closed but should have been spared", what)
	default:
	}
}

// TestReapIdleClosesOnlyIdleForwarderSessions exercises the reaper predicate on
// both axes: it closes a forwarder session idle past idleTTL, spares a forwarder
// session with recent activity, and never touches a client session however idle.
// Activity times are set rather than slept, so the outcome cannot flake on
// scheduling.
func TestReapIdleClosesOnlyIdleForwarderSessions(t *testing.T) {
	e := newReaperEngine(t)
	e.idleTTL = time.Minute

	idle := newFakeSession()   // forwarder gone quiet -> reaped
	busy := newFakeSession()   // forwarder just active -> spared
	client := newFakeSession() // client, equally quiet -> spared (never reaped)

	tsIdle := e.trackSession("idle", idle, true)
	e.trackSession("busy", busy, true) // freshly touched by trackSession
	tsClient := e.trackSession("client", client, false)

	if got := e.SessionCount(); got != 3 {
		t.Fatalf("SessionCount = %d, want 3", got)
	}

	backdate(tsIdle)
	backdate(tsClient) // just as idle as 'idle', but reap=false must still protect it

	if n := e.reapIdle(time.Now()); n != 1 {
		t.Fatalf("reapIdle closed %d sessions, want exactly 1 (the idle forwarder)", n)
	}

	assertClosed(t, idle, "idle forwarder session")
	assertOpen(t, busy, "busy forwarder session")
	assertOpen(t, client, "client session")

	// The reaped session's watcher frees it from the map asynchronously.
	if !waitFor(time.Second, func() bool { return e.SessionCount() == 2 }) {
		t.Fatalf("map still holds %d sessions, want 2 after the reap", e.SessionCount())
	}
}

// TestReapStreamRefreshesActivityOnIO proves the reaper's notion of "idle" is
// "no bytes": movement in either direction through the wrapped stream refreshes
// the owning session's last-activity time, so a busy-but-no-new-streams session
// (a long download) is never mistaken for idle. The stream label must pass
// through untouched — the transport keys on it.
func TestReapStreamRefreshesActivityOnIO(t *testing.T) {
	e := newReaperEngine(t)
	ts := e.trackSession("s", newFakeSession(), true)

	ts.lastNano.Store(0)
	st := e.reapStream(ts, &memStream{label: "example.com:443", rd: bytes.NewReader([]byte("hello"))})
	if _, err := st.Read(make([]byte, 8)); err != nil {
		t.Fatalf("read: %v", err)
	}
	if ts.lastNano.Load() == 0 {
		t.Fatal("reapStream.Read did not refresh the session's last-activity time")
	}

	ts.lastNano.Store(0)
	if _, err := st.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if ts.lastNano.Load() == 0 {
		t.Fatal("reapStream.Write did not refresh the session's last-activity time")
	}

	if got := st.Label(); got != "example.com:443" {
		t.Fatalf("Label() = %q, want it passed through unchanged", got)
	}
}

// TestSessionCountIsLiveCardinality checks the exported metric tracks live
// sessions and drops one when it closes.
func TestSessionCountIsLiveCardinality(t *testing.T) {
	e := newReaperEngine(t)
	if got := e.SessionCount(); got != 0 {
		t.Fatalf("fresh engine SessionCount = %d, want 0", got)
	}

	s1, s2 := newFakeSession(), newFakeSession()
	e.trackSession("a", s1, true)
	e.trackSession("b", s2, false)
	if got := e.SessionCount(); got != 2 {
		t.Fatalf("SessionCount = %d, want 2", got)
	}

	s1.Close()
	if !waitFor(time.Second, func() bool { return e.SessionCount() == 1 }) {
		t.Fatalf("after closing one session SessionCount = %d, want 1", e.SessionCount())
	}
}

// TestConnectDisconnectSoakNoLeak is the leak soak the acceptance asks for: many
// connect/disconnect cycles must return both the session map and the goroutine
// count to baseline. Each trackSession spawns one watcher goroutine; closing the
// session must let it exit, or the counts would climb with N.
func TestConnectDisconnectSoakNoLeak(t *testing.T) {
	e := newReaperEngine(t)

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()

	const N = 300
	for i := 0; i < N; i++ {
		s := newFakeSession()
		e.trackSession(fmt.Sprintf("s%d", i), s, true)
		s.Close() // clean disconnect
	}

	if !waitFor(2*time.Second, func() bool { return e.SessionCount() == 0 }) {
		t.Fatalf("session map did not return to baseline: %d still tracked", e.SessionCount())
	}
	// No goroutine leak: the count must not grow with N. The small slack absorbs
	// runtime bookkeeping goroutines but stays far below the N watchers a leak
	// would add.
	if !waitFor(2*time.Second, func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= baseGoroutines+5
	}) {
		t.Fatalf("goroutines did not return to baseline: have %d, base %d (leaked ~%d)",
			runtime.NumGoroutine(), baseGoroutines, runtime.NumGoroutine()-baseGoroutines)
	}
}

// TestReaperDrainsHalfOpenSessions proves the new behavior end to end: N
// forwarder sessions whose peer vanished (never closed, no activity) are all
// reclaimed by the running reaper, returning the map and goroutine count to
// baseline. This is the "12s disconnect" bug class made a tested guarantee.
func TestReaperDrainsHalfOpenSessions(t *testing.T) {
	e := newReaperEngine(t)
	e.idleTTL = 20 * time.Millisecond
	e.reapInterval = 5 * time.Millisecond
	e.wg.Add(1)
	go e.reapLoop()

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()

	const N = 300
	for i := 0; i < N; i++ {
		ts := e.trackSession(fmt.Sprintf("s%d", i), newFakeSession(), true)
		backdate(ts) // half-open: no FIN, no bytes -> only the reaper frees it
	}

	if !waitFor(3*time.Second, func() bool { return e.SessionCount() == 0 }) {
		t.Fatalf("reaper did not drain half-open sessions: %d still tracked", e.SessionCount())
	}
	if !waitFor(3*time.Second, func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= baseGoroutines+5
	}) {
		t.Fatalf("goroutines did not return to baseline: have %d, base %d",
			runtime.NumGoroutine(), baseGoroutines)
	}
}
