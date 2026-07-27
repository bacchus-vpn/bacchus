package core

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/selection"
	"github.com/bacchus-vpn/bacchus/core/version"
)

// fakeSession is a Session with no streams whose lifetime the test controls via
// Close (which fires Closed). connectPooled only needs Closed/Close; OpenStream
// is never reached unless a SOCKS client connects, which these tests don't do.
type fakeSession struct {
	closed chan struct{}
	once   sync.Once
}

func newFakeSession() *fakeSession { return &fakeSession{closed: make(chan struct{})} }

// testExitID / testExitPub stand in for the exit a coordinator ASSIGNS (issue #146). A
// candidate names a country, so a stubbed dialer has to report an exit back the way
// dialAndValidate does — the pool reads its static key out of the dialed path to key
// every stream's end-to-end handshake, and a stub that returned none would exercise a
// path production never takes.
var (
	testExitID  = strings.Repeat("ab", 32)
	testExitPub = func() []byte {
		b, err := hex.DecodeString(testExitID)
		if err != nil {
			panic(err)
		}
		return b
	}()
)

func (s *fakeSession) OpenStream(context.Context, string) (Stream, error) {
	return nil, errors.New("fake: no streams")
}
func (s *fakeSession) AcceptStream(ctx context.Context) (Stream, error) {
	<-s.closed
	return nil, errors.New("fake: closed")
}
func (s *fakeSession) Closed() <-chan struct{} { return s.closed }
func (s *fakeSession) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}

// newPoolEngine builds a client engine with the pool on, a fast stagger, and no
// coordinator I/O (Start is never called). Tests override countriesFn/dialFn.
func newPoolEngine(t *testing.T, countries []CountryInfo) *Engine {
	t.Helper()
	e, err := New(Config{
		Coordinators:  []string{"127.0.0.1:1"},
		Roles:         []string{RoleClient},
		SocksAddr:     "127.0.0.1:0",
		TransportPool: []string{"reality", "webrtc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.poolStagger = 30 * time.Millisecond
	e.countriesFn = func(context.Context) ([]CountryInfo, error) { return countries, nil }
	return e
}

func cand(tr, country string) selection.Candidate {
	return selection.Candidate{Transport: tr, Country: country, Mode: selection.ModeDirect}
}

// eventRecorder captures emitted events so a test can assert on them, guarded
// by a mutex since emit is not necessarily called from the test goroutine.
type eventRecorder struct {
	mu     sync.Mutex
	events []Event
}

func (r *eventRecorder) record(ev Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *eventRecorder) hasSubstring(kind, sub string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range r.events {
		if ev.Kind == kind && strings.Contains(ev.Message, sub) {
			return true
		}
	}
	return false
}

// newPoolEngineForVersionGate builds a pool engine like newPoolEngine, but
// leaves countriesFn wired to the real poolCountries (rather than stubbing it) and
// captures emitted events, so the force-major tests (issue #79) exercise the
// actual withhold-the-pin logic and can assert the "update required" event
// fires. No coordinator is
// reachable (Start is never called), so ListCountries always fails fast with the
// ordinary "no coordinator answered" error; observeNetworkVersion is called
// directly to simulate the coordinator's advertised release, exactly as
// version_policy_test.go does.
func newPoolEngineForVersionGate(t *testing.T, exitID string) (*Engine, *eventRecorder) {
	t.Helper()
	rec := &eventRecorder{}
	e, err := New(Config{
		Coordinators:  []string{"127.0.0.1:1"},
		Roles:         []string{RoleClient},
		SocksAddr:     "127.0.0.1:0",
		TransportPool: []string{"reality", "webrtc"},
		ExitID:        exitID,
		OnEvent:       rec.record,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.poolStagger = 30 * time.Millisecond
	return e, rec
}

// aheadMajor is a release one MAJOR ahead of this build — observing it always
// latches the force-major requirement (version.ClientMustUpdate).
func aheadMajor() string {
	self := version.Current()
	return version.Version{Major: self.Major + 1}.String()
}

// TestPoolFindsWorkingWhenPrimaryBlocked is the first half of the #15 acceptance:
// with the primary transport blocked on every exit, the pool automatically walks
// the ladder to a working alternate-transport candidate — and remembers it.
func TestPoolFindsWorkingWhenPrimaryBlocked(t *testing.T) {
	e := newPoolEngine(t, []CountryInfo{{Country: "RU", Exits: 2, Available: 2}, {Country: "BY", Exits: 1, Available: 1}})
	e.poolParallel = 1 // deterministic: one candidate at a time, next on failure
	defer e.Stop()

	work := cand("webrtc", "RU") // reality (primary) is blocked everywhere
	e.dialFn = func(_ context.Context, c selection.Candidate) (dialedPath, error) {
		if c == work {
			return dialedPath{sess: newFakeSession(), exitID: testExitID, exitPub: testExitPub, rtt: 30 * time.Millisecond}, nil
		}
		return dialedPath{}, errors.New("blocked")
	}

	if err := e.connectPooled(context.Background()); err != nil {
		t.Fatalf("connectPooled: %v", err)
	}
	sess, _ := e.activePath()
	if sess == nil {
		t.Fatal("no active session after a working candidate existed")
	}
	// The winner was learned so it is tried first next time.
	got, ok := e.store.Best(selection.NetworkKey(), "", time.Now())
	if !ok || got != work {
		t.Fatalf("learned winner = %+v ok=%v, want %+v", got, ok, work)
	}
}

// TestPoolStaggerFallsBackOnStall shows the happy-eyeballs behaviour: a top
// candidate that stalls (handshakes but never validates) does not block the
// pool — the next candidate is started after the stagger and wins.
func TestPoolStaggerFallsBackOnStall(t *testing.T) {
	e := newPoolEngine(t, []CountryInfo{{Country: "RU", Exits: 2, Available: 2}, {Country: "BY", Exits: 1, Available: 1}})
	e.poolParallel = 2
	defer e.Stop()

	stall := cand("reality", "RU") // ladder[0]: first country, primary transport
	work := cand("reality", "BY")  // ladder[1]: next country
	e.dialFn = func(ctx context.Context, c selection.Candidate) (dialedPath, error) {
		switch c {
		case stall:
			<-ctx.Done() // never returns until the race is won and cancels
			return dialedPath{}, ctx.Err()
		case work:
			return dialedPath{sess: newFakeSession(), exitID: testExitID, exitPub: testExitPub, rtt: 20 * time.Millisecond}, nil
		default:
			return dialedPath{}, errors.New("other")
		}
	}

	path, winner, err := e.selectPath(context.Background())
	if err != nil {
		t.Fatalf("selectPath: %v", err)
	}
	if winner != work {
		t.Fatalf("winner = %+v, want the fallback %+v", winner, work)
	}
	path.sess.Close()
}

// TestPoolFailoverReconnects is the second half of the #15 acceptance: when the
// committed path drops, the pool reselects a *different* candidate under the same
// SOCKS listener — no rebind, no manual reconnect.
func TestPoolFailoverReconnects(t *testing.T) {
	e := newPoolEngine(t, []CountryInfo{{Country: "RU", Exits: 2, Available: 2}, {Country: "BY", Exits: 1, Available: 1}})
	e.poolParallel = 1
	defer e.Stop()

	// Every candidate connects; whichever is top of the ladder wins. After the
	// first winner is cooled (its path dropped), the ladder sinks it and a
	// different candidate is chosen.
	var mu sync.Mutex
	var dialed []selection.Candidate
	e.dialFn = func(_ context.Context, c selection.Candidate) (dialedPath, error) {
		mu.Lock()
		dialed = append(dialed, c)
		mu.Unlock()
		return dialedPath{sess: newFakeSession(), exitID: testExitID, exitPub: testExitPub, rtt: 15 * time.Millisecond}, nil
	}

	if err := e.connectPooled(context.Background()); err != nil {
		t.Fatalf("connectPooled: %v", err)
	}
	first, _ := e.activePath()
	firstWinner := lastDialed(&mu, &dialed)

	// Simulate the active path being blocked/dropped.
	first.Close()

	// maintainPath should swap in a new session on a different candidate.
	if !waitFor(2*time.Second, func() bool {
		s, _ := e.activePath()
		return s != nil && s != first
	}) {
		t.Fatal("pool did not reconnect after the active path dropped")
	}
	secondWinner := lastDialed(&mu, &dialed)
	if secondWinner == firstWinner {
		t.Fatalf("reconnected to the same candidate %+v; expected a different one", firstWinner)
	}
}

// TestPoolFailoverSurvivesTransientBlip proves failover is not killed by a
// momentary total outage: if the first reselection round finds nothing (the same
// blip that dropped the path), the backoff retry recovers once a candidate works.
func TestPoolFailoverSurvivesTransientBlip(t *testing.T) {
	e := newPoolEngine(t, []CountryInfo{{Country: "RU", Exits: 1, Available: 1}})
	e.poolParallel = 1
	e.reselectBackoff = 10 * time.Millisecond
	defer e.Stop()

	var mu sync.Mutex
	blocked := false // flips true right after the first commit, then back to false
	e.dialFn = func(_ context.Context, c selection.Candidate) (dialedPath, error) {
		mu.Lock()
		defer mu.Unlock()
		if blocked {
			return dialedPath{}, errors.New("transient outage")
		}
		return dialedPath{sess: newFakeSession(), exitID: testExitID, exitPub: testExitPub, rtt: 15 * time.Millisecond}, nil
	}

	if err := e.connectPooled(context.Background()); err != nil {
		t.Fatalf("connectPooled: %v", err)
	}
	first, _ := e.activePath()

	// Everything goes dark, then the active path drops.
	mu.Lock()
	blocked = true
	mu.Unlock()
	first.Close()

	// Let a reselection round run and fail, then restore connectivity.
	time.Sleep(15 * time.Millisecond)
	mu.Lock()
	blocked = false
	mu.Unlock()

	if !waitFor(2*time.Second, func() bool {
		s, _ := e.activePath()
		return s != nil && s != first
	}) {
		t.Fatal("failover did not recover after a transient total outage")
	}
}

// TestResetSelectionForgetsWinner proves the user-facing reset clears learning.
func TestResetSelectionForgetsWinner(t *testing.T) {
	e := newPoolEngine(t, []CountryInfo{{Country: "RU", Exits: 1, Available: 1}})
	e.poolParallel = 1
	defer e.Stop()
	e.dialFn = func(_ context.Context, c selection.Candidate) (dialedPath, error) {
		return dialedPath{sess: newFakeSession(), exitID: testExitID, exitPub: testExitPub, rtt: 10 * time.Millisecond}, nil
	}
	if err := e.connectPooled(context.Background()); err != nil {
		t.Fatalf("connectPooled: %v", err)
	}
	if _, ok := e.store.Best(selection.NetworkKey(), "", time.Now()); !ok {
		t.Fatal("expected a learned winner before reset")
	}
	if err := e.ResetSelection(); err != nil {
		t.Fatalf("ResetSelection: %v", err)
	}
	if _, ok := e.store.Best(selection.NetworkKey(), "", time.Now()); ok {
		t.Fatal("ResetSelection should have forgotten the winner")
	}
}

// TestPoolCountriesAllSilentThenForceMajor unit-tests poolCountries directly. With no
// coordinator reachable (Start is never called), every member is silent, so before
// any version mismatch poolCountries surfaces ErrNoCoordinatorReachable rather than the
// pinned exit — a pin cannot be paired without a coordinator, so the sentinel that
// triggers mesh-walk recovery is the right answer (issue #115). Once a force-major
// mismatch is latched it must take precedence and withhold everything with the
// update error, so a pinned client can never bypass the cutover (issue #79).
func TestPoolCountriesAllSilentThenForceMajor(t *testing.T) {
	e, _ := newPoolEngineForVersionGate(t, "A")
	defer e.Stop()

	got, err := e.poolCountries(context.Background())
	if got != nil || !errors.Is(err, ErrNoCoordinatorReachable) {
		t.Fatalf("all-silent poolCountries = (%+v, %v), want (nil, ErrNoCoordinatorReachable)", got, err)
	}

	e.observeNetworkVersion(aheadMajor())

	got, err = e.poolCountries(context.Background())
	if got != nil || err == nil || !strings.Contains(err.Error(), "major update") {
		t.Fatalf("force-major poolCountries = (%+v, %v), want (nil, <update-required error>) — precedence over the all-silent sentinel", got, err)
	}
}

// TestPoolConnectAbortsOnForceMajorPinned is the pinned-exit half of the #79
// acceptance: a pooled client configured with a pinned exit must not bypass
// the force-major cutover by falling back to it.
func TestPoolConnectAbortsOnForceMajorPinned(t *testing.T) {
	e, rec := newPoolEngineForVersionGate(t, "A")
	defer e.Stop()
	e.observeNetworkVersion(aheadMajor())

	dialed := false
	e.dialFn = func(context.Context, selection.Candidate) (dialedPath, error) {
		dialed = true
		return dialedPath{sess: newFakeSession(), exitID: testExitID, exitPub: testExitPub, rtt: time.Millisecond}, nil
	}

	err := e.connectPooled(context.Background())
	if err == nil {
		t.Fatal("connectPooled must abort once the network requires a major update, even with a pinned exit")
	}
	if !strings.Contains(err.Error(), "major update") {
		t.Fatalf("error = %q, want it to say a major update is required", err)
	}
	if dialed {
		t.Fatal("connectPooled must not dial the pinned exit once force-major is latched")
	}
	if !rec.hasSubstring(EventError, "update required") {
		t.Fatal(`expected an EventError containing "update required"`)
	}
}

// TestPoolConnectAbortsOnForceMajorNoPin is the no-pin half of the #79
// acceptance: without a pinned exit the client must still get the actionable
// "update required" error, not a generic empty-list failure.
func TestPoolConnectAbortsOnForceMajorNoPin(t *testing.T) {
	e, rec := newPoolEngineForVersionGate(t, "")
	defer e.Stop()
	e.observeNetworkVersion(aheadMajor())

	dialed := false
	e.dialFn = func(context.Context, selection.Candidate) (dialedPath, error) {
		dialed = true
		return dialedPath{sess: newFakeSession(), exitID: testExitID, exitPub: testExitPub, rtt: time.Millisecond}, nil
	}

	err := e.connectPooled(context.Background())
	if err == nil {
		t.Fatal("connectPooled must abort once the network requires a major update")
	}
	if !strings.Contains(err.Error(), "major update") {
		t.Fatalf("error = %q, want the clear force-major message, not a generic empty-list error", err)
	}
	if dialed {
		t.Fatal("connectPooled must not attempt to dial once force-major is latched")
	}
	if !rec.hasSubstring(EventError, "update required") {
		t.Fatal(`expected an EventError containing "update required"`)
	}
}

// TestPoolConnectEmptyExitListFailsNormally guards against over-broadening the
// #79 fix: an ordinary empty exit list (no force-major involved) must still
// fail with the original generic error, not be mistaken for a version gate.
func TestPoolConnectEmptyExitListFailsNormally(t *testing.T) {
	e := newPoolEngine(t, nil) // countriesFn stub returns an empty list
	defer e.Stop()

	err := e.connectPooled(context.Background())
	if err == nil {
		t.Fatal("connectPooled must fail when there are no exits to select from")
	}
	if strings.Contains(err.Error(), "major update") {
		t.Fatalf("error = %q, an ordinary empty list must not look like a force-major abort", err)
	}
}

// TestPoolConnectClosesSessionWhenSocksBindFails covers the minor tidy noted
// in issue #79: if bindPoolSocks fails after selectPath already committed a
// session, connectPooled must close that session and clear the active path
// rather than leaking it and leaving stale active-path state.
func TestPoolConnectClosesSessionWhenSocksBindFails(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	defer occupied.Close()

	e, err := New(Config{
		Coordinators:  []string{"127.0.0.1:1"},
		Roles:         []string{RoleClient},
		SocksAddr:     occupied.Addr().String(), // already bound -> bindPoolSocks fails
		TransportPool: []string{"reality", "webrtc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.poolStagger = 30 * time.Millisecond
	e.countriesFn = func(context.Context) ([]CountryInfo, error) {
		return []CountryInfo{{Country: "RU", Exits: 1, Available: 1}}, nil
	}
	defer e.Stop()

	sess := newFakeSession()
	e.dialFn = func(context.Context, selection.Candidate) (dialedPath, error) {
		return dialedPath{sess: sess, exitID: testExitID, exitPub: testExitPub, rtt: time.Millisecond}, nil
	}

	if err := e.connectPooled(context.Background()); err == nil {
		t.Fatal("connectPooled must fail when the SOCKS listener cannot bind")
	}
	select {
	case <-sess.Closed():
	default:
		t.Fatal("connectPooled must close the committed session when bindPoolSocks fails")
	}
	if s, _ := e.activePath(); s != nil {
		t.Fatal("connectPooled must clear the active path when bindPoolSocks fails")
	}
}

func lastDialed(mu *sync.Mutex, dialed *[]selection.Candidate) selection.Candidate {
	mu.Lock()
	defer mu.Unlock()
	return (*dialed)[len(*dialed)-1]
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}

// TestPoolConnectRetriesSocksBindAfterFailure guards against a latch-ordering
// bug in bindPoolSocks: if the first bind fails (e.g. the address is already
// in use), socksBound must not be left permanently true, or every later retry
// silently no-ops without ever calling Listen again.
func TestPoolConnectRetriesSocksBindAfterFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy a port: %v", err)
	}
	addr := occupied.Addr().String()

	e, err := New(Config{
		Coordinators:  []string{"127.0.0.1:1"},
		Roles:         []string{RoleClient},
		SocksAddr:     addr, // already bound -> the first bindPoolSocks fails
		TransportPool: []string{"reality", "webrtc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.poolStagger = 30 * time.Millisecond
	e.countriesFn = func(context.Context) ([]CountryInfo, error) {
		return []CountryInfo{{Country: "RU", Exits: 1, Available: 1}}, nil
	}
	e.dialFn = func(context.Context, selection.Candidate) (dialedPath, error) {
		return dialedPath{sess: newFakeSession(), exitID: testExitID, exitPub: testExitPub, rtt: time.Millisecond}, nil
	}
	defer e.Stop()

	if err := e.connectPooled(context.Background()); err == nil {
		t.Fatal("connectPooled must fail while the SOCKS address is occupied")
	}

	// Free the port, then retry: bindPoolSocks must actually attempt Listen
	// again rather than treating the first failed attempt as permanently bound.
	if err := occupied.Close(); err != nil {
		t.Fatalf("free the occupied port: %v", err)
	}
	if err := e.connectPooled(context.Background()); err != nil {
		t.Fatalf("connectPooled retry after the port freed up: %v", err)
	}

	// Prove a real listener is up, not just that connectPooled claimed success:
	// the bug this guards against makes bindPoolSocks a permanent no-op after
	// one failure, so connectPooled would report nil here even with nothing
	// actually listening.
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("SOCKS listener did not actually bind on retry: %v", err)
	}
	conn.Close()
}
