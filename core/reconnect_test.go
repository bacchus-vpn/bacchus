package core

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// newReconnectEngine builds a client engine on the default single-transport path
// (pool off) with a well-formed exit id and an ephemeral SOCKS address, plus fast
// reconnect timings so backoff/failover run in milliseconds. Start is never
// called and establishFn is overridden, so there is no coordinator or transport
// I/O — the reconnect driver is exercised entirely through the seam, mirroring how
// pool_test drives the pool through dialFn. onEvent may be nil (events swallowed).
func newReconnectEngine(t *testing.T, onEvent func(Event)) *Engine {
	t.Helper()
	e, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		SocksAddr:    "127.0.0.1:0",
		Geo:          "NL", // a connect names a country, not an exit (issue #146)
	})
	if err != nil {
		t.Fatal(err)
	}
	if onEvent == nil {
		onEvent = func(Event) {}
	}
	e.cfg.OnEvent = onEvent
	e.reconnectBase = 25 * time.Millisecond
	e.reconnectMax = 10 * time.Second
	e.reconnectHealthy = 0 // a drop counts as a genuine one-off (skip the flap wait) unless a test sets it
	return e
}

// collectEvents returns an OnEvent sink and a snapshot function so a test can
// assert on the state transitions the driver surfaces.
func collectEvents() (func(Event), func() []Event) {
	var mu sync.Mutex
	var evs []Event
	sink := func(ev Event) {
		mu.Lock()
		evs = append(evs, ev)
		mu.Unlock()
	}
	snap := func() []Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]Event(nil), evs...)
	}
	return sink, snap
}

func hasEventContaining(evs []Event, kind, substr string) bool {
	for _, ev := range evs {
		if ev.Kind == kind && strings.Contains(ev.Message, substr) {
			return true
		}
	}
	return false
}

func sameModes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestReconnectModesOrdering pins the candidate ordering that realizes "retry the
// current path first, then fail over": a dropped relay retries relay before
// direct, the initial pass is direct-then-relay, and direct is offered only on the
// first member of a pass (allowDirect).
func TestReconnectModesOrdering(t *testing.T) {
	cases := []struct {
		prefer      string
		allowDirect bool
		want        []string
	}{
		{"", true, []string{modeDirect, modeRelay}},         // initial pass, first member
		{"", false, []string{modeRelay}},                    // initial pass, later member (direct already tried)
		{modeDirect, true, []string{modeDirect, modeRelay}}, // dropped direct: retry direct, then relay
		{modeRelay, true, []string{modeRelay, modeDirect}},  // dropped relay: retry relay first
		{modeRelay, false, []string{modeRelay}},             // dropped relay, later member: relay only
	}
	for _, tc := range cases {
		if got := reconnectModes(tc.prefer, tc.allowDirect); !sameModes(got, tc.want) {
			t.Errorf("reconnectModes(%q, %v) = %v, want %v", tc.prefer, tc.allowDirect, got, tc.want)
		}
	}
}

// TestCapDelay checks the backoff ceiling clamp.
func TestCapDelay(t *testing.T) {
	if got := capDelay(2*time.Second, 5*time.Second); got != 2*time.Second {
		t.Fatalf("below ceiling should pass through: got %s", got)
	}
	if got := capDelay(9*time.Second, 5*time.Second); got != 5*time.Second {
		t.Fatalf("above ceiling should clamp: got %s", got)
	}
}

// TestReconnectBackoffIsBoundedNoBusyLoop is the first half of the #2 acceptance:
// when the path stays down, reconnection retries with growing (exponential),
// bounded backoff — never a busy-loop. It bounds the otherwise-unbounded driver
// with reconnectMaxAttempts so the test terminates, then asserts the retries were
// actually spaced and the spacing grew.
func TestReconnectBackoffIsBoundedNoBusyLoop(t *testing.T) {
	type call struct {
		prefer string
		at     time.Time
	}
	var mu sync.Mutex
	var calls []call

	e := newReconnectEngine(t, nil)
	e.reconnectMaxAttempts = 5 // give up after 5 failed passes so the test ends
	defer e.Stop()

	first := newFakeSession()
	e.establishFn = func(_ context.Context, prefer string) (connPath, error) {
		mu.Lock()
		calls = append(calls, call{prefer, time.Now()})
		n := len(calls)
		mu.Unlock()
		if n == 1 {
			return connPath{sess: first, mode: modeDirect}, nil // initial connect
		}
		return connPath{}, errors.New("still down") // every reconnect attempt fails
	}

	if err := e.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	first.Close() // drop the live path

	// 1 initial + 5 reconnect attempts, then the driver gives up.
	if !waitFor(5*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(calls) >= 6
	}) {
		mu.Lock()
		n := len(calls)
		mu.Unlock()
		t.Fatalf("expected 6 establish calls (1 initial + 5 reconnect), got %d", n)
	}
	// Let it settle; it must not keep calling past the budget.
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	got := append([]call(nil), calls...)
	mu.Unlock()
	if len(got) != 6 {
		t.Fatalf("bounded driver should stop after the attempt budget: got %d calls", len(got))
	}

	// Every reconnect pass must retry the just-dropped mode (direct).
	for i := 1; i < len(got); i++ {
		if got[i].prefer != modeDirect {
			t.Fatalf("reconnect attempt %d used prefer %q, want dropped mode %q", i, got[i].prefer, modeDirect)
		}
	}
	// Gaps between reconnect attempts (nominal 25, 50, 100, 200ms) must each wait
	// (no busy-loop) and grow (exponential).
	gaps := make([]time.Duration, 0, 4)
	for i := 2; i < len(got); i++ {
		gaps = append(gaps, got[i].at.Sub(got[i-1].at))
	}
	for i, g := range gaps {
		if g < 18*time.Millisecond {
			t.Fatalf("gap %d = %s too short — backoff not applied (busy-loop)", i, g)
		}
	}
	if gaps[len(gaps)-1] <= gaps[0] {
		t.Fatalf("backoff did not grow (not exponential): gaps = %v", gaps)
	}
}

// TestReconnectFailsOverToOtherCandidate is the second half of the #2 acceptance:
// when the dropped path's mode can no longer be re-established, the driver fails
// over to the next candidate (direct -> relay) and surfaces it.
func TestReconnectFailsOverToOtherCandidate(t *testing.T) {
	sink, snap := collectEvents()
	e := newReconnectEngine(t, sink)
	defer e.Stop()

	var mu sync.Mutex
	callN := 0
	initial := newFakeSession()
	e.establishFn = func(_ context.Context, prefer string) (connPath, error) {
		mu.Lock()
		callN++
		n := callN
		mu.Unlock()
		if n == 1 {
			return connPath{sess: initial, mode: modeDirect}, nil // initial: direct is up
		}
		// After the drop direct is blocked; walk the real ladder and take the first
		// mode that still works (relay).
		for _, m := range reconnectModes(prefer, true) {
			if m == modeDirect {
				continue // blocked
			}
			return connPath{sess: newFakeSession(), mode: m}, nil
		}
		return connPath{}, errors.New("all candidates blocked")
	}

	if err := e.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if s, _, _ := e.activeReconnectSession(); s != Session(initial) {
		t.Fatal("initial active session should be the direct path")
	}
	initial.Close() // the exit/relay for the direct path is gone

	if !waitFor(3*time.Second, func() bool {
		s, _, _ := e.activeReconnectSession()
		return s != nil && s != Session(initial)
	}) {
		t.Fatal("driver did not fail over after the direct path dropped")
	}
	evs := snap()
	if !hasEventContaining(evs, EventError, "connection lost (DIRECT)") {
		t.Fatalf("expected a 'connection lost (DIRECT)' event; got %+v", evs)
	}
	if !hasEventContaining(evs, EventConnected, "reconnected via RELAY") {
		t.Fatalf("expected a 'reconnected via RELAY' failover event; got %+v", evs)
	}
}

// TestReconnectSwapsSessionBindingOnce proves the SOCKS listener is bound once and
// the live session is swapped underneath it across repeated drops — no rebind.
func TestReconnectSwapsSessionBindingOnce(t *testing.T) {
	e := newReconnectEngine(t, nil)
	defer e.Stop()

	e.establishFn = func(_ context.Context, _ string) (connPath, error) {
		return connPath{sess: newFakeSession(), mode: modeDirect}, nil
	}
	if err := e.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	for round := 0; round < 2; round++ {
		cur, _, _ := e.activeReconnectSession()
		_ = cur.Close()
		if !waitFor(3*time.Second, func() bool {
			s, _, _ := e.activeReconnectSession()
			return s != nil && s != cur
		}) {
			t.Fatalf("round %d: no session swap after drop", round)
		}
	}
	e.mu.Lock()
	nLn := len(e.listeners)
	e.mu.Unlock()
	if nLn != 1 {
		t.Fatalf("expected exactly one SOCKS listener across reconnects, got %d", nLn)
	}
	e.rcMu.Lock()
	bound := e.rcBound
	e.rcMu.Unlock()
	if !bound {
		t.Fatal("rcBound should be set after Connect")
	}
}

// TestReconnectFlapDoesNotBusyLoop covers the flap case the pool's validation
// probe damps for free but this path does not: a candidate that connects then
// drops almost immediately must not spin. The flap guard spaces the cycles.
func TestReconnectFlapDoesNotBusyLoop(t *testing.T) {
	e := newReconnectEngine(t, nil)
	e.reconnectHealthy = time.Hour // every drop looks immediate => always the flap path
	e.reconnectBase = 20 * time.Millisecond
	e.reconnectMax = 80 * time.Millisecond
	defer e.Stop()

	var mu sync.Mutex
	var times []time.Time
	e.establishFn = func(_ context.Context, _ string) (connPath, error) {
		s := newFakeSession()
		mu.Lock()
		times = append(times, time.Now())
		mu.Unlock()
		go s.Close() // connects, then dies at once
		return connPath{sess: s, mode: modeDirect}, nil
	}
	if err := e.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	time.Sleep(400 * time.Millisecond) // let several flap cycles run
	e.Stop()
	waitStopped(t, e, 5*time.Second)

	mu.Lock()
	ts := append([]time.Time(nil), times...)
	mu.Unlock()
	if len(ts) < 3 {
		t.Fatalf("expected several flap reconnects, got %d", len(ts))
	}
	// A busy-loop would produce hundreds of cycles in 400ms; the flap guard keeps
	// it to a handful. The exact count varies with scheduling, so assert a generous
	// ceiling well below a spin.
	if len(ts) > 40 {
		t.Fatalf("too many reconnects in 400ms (%d) — flap guard not limiting the rate", len(ts))
	}
	for i := 1; i < len(ts); i++ {
		if gap := ts[i].Sub(ts[i-1]); gap < 15*time.Millisecond {
			t.Fatalf("flap cycle %d gap = %s — too tight (busy-loop)", i, gap)
		}
	}
}

// TestReconnectStopsPromptlyDuringBackoff proves the unbounded (retry-forever)
// driver still tears down at once: a Stop during a long backoff wait interrupts it
// rather than blocking on the full delay, so there is no shutdown-time leak.
func TestReconnectStopsPromptlyDuringBackoff(t *testing.T) {
	e := newReconnectEngine(t, nil)
	e.reconnectBase = 5 * time.Second // a long backoff Stop must not wait out
	e.reconnectMax = 30 * time.Second
	e.reconnectMaxAttempts = 0 // unbounded, the production default

	var mu sync.Mutex
	n := 0
	first := newFakeSession()
	e.establishFn = func(_ context.Context, _ string) (connPath, error) {
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		if k == 1 {
			return connPath{sess: first, mode: modeDirect}, nil
		}
		return connPath{}, errors.New("down") // reconnect fails -> parks in the 5s backoff
	}
	if err := e.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	first.Close()
	time.Sleep(150 * time.Millisecond) // ensure the driver is parked in sleepBackoff

	done := make(chan struct{})
	go func() { e.Stop(); e.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second): // must be far under the 5s backoff
		t.Fatal("Stop did not interrupt the reconnect backoff promptly")
	}
}

// TestConnectClosesSessionWhenSocksBindFails is the non-pooled counterpart to
// TestPoolConnectClosesSessionWhenSocksBindFails: on the single-transport Connect
// path, if the SOCKS listener cannot bind, the just-established session must be
// closed rather than leaked (issue #85). The establishFn seam stands a fake
// session in for a real dialed path, with no coordinator or transport I/O.
func TestConnectClosesSessionWhenSocksBindFails(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	defer occupied.Close()

	e, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		SocksAddr:    occupied.Addr().String(), // already bound -> serveReconnectSocks fails
		Geo:          "NL",                     // a connect names a country, not an exit (issue #146)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	sess := newFakeSession()
	e.establishFn = func(context.Context, string) (connPath, error) {
		return connPath{sess: sess, mode: modeDirect}, nil
	}

	if err := e.Connect(context.Background()); err == nil {
		t.Fatal("Connect must fail when the SOCKS listener cannot bind")
	}
	select {
	case <-sess.Closed():
	default:
		t.Fatal("Connect must close the established session when serveReconnectSocks fails (issue #85)")
	}
}
