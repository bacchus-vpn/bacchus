//go:build windows

package main

// Supervisor-level coverage for live country switching (issue #137). Shares the
// harness in midsession_recovery_test.go — the wire-compatible fake
// coordinator, the real exit engines, the real SOCKS5 echo round trip, and
// the connection-state helpers — for the same reason that file gives: this
// is orchestration over core.Engine and the package's own connection
// globals, so it can be driven exactly as the tray drives it without a
// wintun adapter or Administrator elevation.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/pion/turn/v4"
)

// startTestTURN runs a real pion TURN server on loopback, built the same way
// cmd/coordinator builds the production one.
//
// It is not optional scaffolding. switchCountry sets ForceRelay, exactly as
// connect() does, which puts the new engine's ICE agent on a relay-only
// policy: with no TURN server configured it gathers no candidates at all and
// the handshake fails after ICE's own 30s timeout. A test that quietly
// dropped ForceRelay to avoid needing this would be testing a configuration
// the client never actually runs — and ForceRelay is load-bearing for
// full-device routing (it pins every candidate to one already-excluded
// address, so a post-ICE address can never race the route setup), so it is
// the last thing to fake.
func startTestTURN(t *testing.T) (url, user, pass string) {
	t.Helper()
	const realm, u, p = "bacchus.test", "test-user", "test-pass"
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test TURN: %v", err)
	}
	key := turn.GenerateAuthKey(u, realm, p)
	srv, err := turn.NewServer(turn.ServerConfig{
		Realm: realm,
		AuthHandler: func(username, _ string, _ net.Addr) ([]byte, bool) {
			return key, username == u
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: conn,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				// Advertise loopback but bind the relay sockets on all
				// interfaces, exactly as cmd/coordinator does with its own
				// public IP. Binding them on 127.0.0.1 instead looks tidier
				// and does not work: pion does not gather loopback host
				// candidates, so the peer's candidates are LAN addresses, and
				// a relay socket bound to loopback has no route to them —
				// ICE then spends its full 30s timeout failing.
				RelayAddress: net.IPv4(127, 0, 0, 1),
				Address:      "0.0.0.0",
			},
		}},
	})
	if err != nil {
		_ = conn.Close()
		t.Fatalf("start test TURN: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return "turn:" + conn.LocalAddr().String(), u, p
}

// pickCountryInTray sets the picker selection the way selectExit does, which is
// what switchCountry reads. Under mu, because that is the lock every read of it
// takes.
func pickCountryInTray(code string) {
	mu.Lock()
	selectedID, selectedLbl = code, code
	mu.Unlock()
}

// TestSwitchCountry_ConcurrentDisconnectDoesNotResurrectTheSession covers the
// orchestration issue #137 added and the #183 review found unguarded:
// switchCountry checked "is this session still mine?" in one critical section
// and published the replacement engine in another, with core.New and Start
// in between.
//
// The failure it pins is not a lost update, it is a resurrection. A
// disconnect() landing in that window closes the full-device tunnel, lifts
// the kill-switch and clears every connection global; switchCountry then
// publishes its new engine over the top. What the user is left with is a
// live engine serving SOCKS with no tunnel above it — the device's traffic
// out on the physical interface in the clear — a tray reading
// "Protected — <country>", and no way back, because connect() returns
// immediately while engine is non-nil. That is the ADR-0039 belief-safety
// failure ("the tunnel came up… 100% of traffic went out in the clear")
// reached through a new door, so the assertions below are on exactly that
// state rather than on eventual convergence: a test that only checked
// "everything ends up torn down" would pass whether or not the guard exists,
// which is what let this through the first time.
//
// -race would not have caught it either. Every access to engine/
// engineCancel/activeTunnel/liveCountry is correctly mutex-guarded; what was
// missing is atomicity *across* two of them, which no data-race detector
// models.
//
// Structure — three real switches, the last one raced:
//
//  1. Connect in country AA through coordA, proven by a real SOCKS5 CONNECT
//     and echo, with the globals seeded as connect() leaves them.
//  2. Switch to country ZZ through coordB with no interference. This is the
//     positive control: it establishes that a live switch genuinely
//     completes in this environment, so step 3 failing to produce a live
//     engine can only be the guard doing its job, never a switch that would
//     have failed anyway.
//  3. Switch back to AA (a third fake coordinator, a fresh exit instance
//     sharing A's identity) with disconnect() pinned inside the rebuild
//     window by gateEngineRebuild.
//
// Slow and gated behind -short for the same reason as the two recovery tests
// it sits beside: real WebRTC handshakes on core's own fixed timeouts.
func TestSwitchCountry_ConcurrentDisconnectDoesNotResurrectTheSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real live-country-switch race in -short")
	}
	// Order matters: t.Cleanup runs LIFO, and resetConnectionState's teardown
	// stops engines and closes a tunnel, which reaches logEvent/logLine. Redirect
	// the log FIRST so that teardown still writes into the temp file rather than
	// the developer's real %APPDATA%\Bacchus\bacchus.log — a clean run happens to
	// be contained either way, but a failing one is exactly when the teardown has
	// something to say.
	redirectEventLogForTest(t)
	resetConnectionState(t)
	requireFreeSocksAddr(t)

	keyA, keyB := randomExitKeyHex(t), randomExitKeyHex(t)
	coordA := newFakeRendezvous(t, "coordA")
	coordB := newFakeRendezvous(t, "coordB")
	coordC := newFakeRendezvous(t, "coordC")
	echoAddr := startEchoServer(t)
	turnURL, turnUser, turnPass := startTestTURN(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// Each fake coordinator serves exactly one client/exit pairing for its
	// lifetime (see fakeRendezvous), so every switch needs its own. coordC's
	// exit shares A's key, and therefore A's id: the same node reachable
	// again through a different coordinator, which is what switching "back
	// to AA" means to a client.
	exitA := startTestExit(t, ctx, keyA, []string{coordA.addr()}, testCountry)
	exitAID := exitA.ID()
	exitB := startTestExit(t, ctx, keyB, []string{coordB.addr()}, testCountryAlt)
	exitBID := exitB.ID()
	startTestExit(t, ctx, keyA, []string{coordC.addr()}, testCountry) // cleanup-registered; not otherwise referenced
	for _, c := range []struct {
		name string
		rv   *fakeRendezvous
	}{{"coordA", coordA}, {"coordB", coordB}, {"coordC", coordC}} {
		if !waitUntil(20*time.Second, c.rv.hasExit) {
			t.Fatalf("no exit ever registered with %s", c.name)
		}
	}
	if exitAID == exitBID {
		t.Fatal("exit A and exit B must be distinct for a switch to be a switch")
	}

	// Step 1: a real session in country AA, with the globals seeded as connect()
	// leaves them once its tunnel is up.
	engCfg := core.Config{
		Roles:     []string{core.RoleClient},
		SocksAddr: socksAddr,
		// The client names a country and nothing else; the exit id comes back on
		// the session reply (issue #146, ADR-0042).
		Geo:          testCountry,
		Coordinators: []string{coordA.addr()},
		OnEvent:      testEventSink(t, "switch"),
	}
	eng, err := core.New(engCfg)
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	if err := eng.Start(sessionCtx); err != nil {
		sessionCancel()
		t.Fatalf("Start: %v", err)
	}
	seedLiveSession(eng, sessionCancel, testCountry)
	if err := eng.Connect(sessionCtx); err != nil {
		t.Fatalf("initial Connect: %v", err)
	}
	setStatus("Protected — " + testCountry)
	if err := waitUntilNoErr(90*time.Second, func() error {
		return echoThrough(socksAddr, echoAddr, "hello-country-aa")
	}); err != nil {
		t.Fatalf("initial connect never came up over a real SOCKS5 round trip: %v", err)
	}
	// The client never named this exit; the only thing that could have keyed the
	// end-to-end channel is the id on the session reply.
	if got := coordA.registeredExit(); got != exitAID {
		t.Fatalf("coordA handed back exit %q; the exit running in %s is %q", got, testCountry, exitAID)
	}

	// Step 2 (positive control): an unraced live switch to country ZZ.
	// switchCountry builds its engine from the cfg global and reads the target
	// country from the picker, so point both at coordB / ZZ first, exactly as the
	// tray would.
	setTestConfig(Config{Coordinators: []string{coordB.addr()}, TURN: turnURL, TURNUser: turnUser, TURNPass: turnPass})
	pickCountryInTray(testCountryAlt)
	switchCountry()

	mu.Lock()
	afterSwitch, liveAfterSwitch := engine, liveCountry
	mu.Unlock()
	if afterSwitch == nil || afterSwitch == eng {
		t.Fatalf("unraced switch did not swap the engine (nil: %v, unchanged: %v)", afterSwitch == nil, afterSwitch == eng)
	}
	if liveAfterSwitch != testCountryAlt {
		t.Fatalf("unraced switch left liveCountry = %q, want %q", liveAfterSwitch, testCountryAlt)
	}
	if got := currentStatus(); got != "Protected — "+testCountryAlt {
		t.Fatalf("unraced switch left the status %q, want %q", got, "Protected — "+testCountryAlt)
	}
	if err := waitUntilNoErr(90*time.Second, func() error {
		return echoThrough(socksAddr, echoAddr, "hello-country-zz")
	}); err != nil {
		t.Fatalf("unraced switch never carried real traffic to country %s: %v", testCountryAlt, err)
	}
	// The switch really moved the session, not just the label: coordB minted its
	// session against exit B, which is a different node from exit A.
	if got := coordB.registeredExit(); got != exitBID {
		t.Fatalf("coordB handed back exit %q, want exit B %q — the session did not actually move", got, exitBID)
	}

	// Step 3: the race. disconnect() runs to completion inside the window
	// between switchCountry's staleness check and its publication of the new
	// engine.
	setTestConfig(Config{Coordinators: []string{coordC.addr()}, TURN: turnURL, TURNUser: turnUser, TURNPass: turnPass})
	pickCountryInTray(testCountry)
	entered, release := gateEngineRebuild(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		switchCountry()
	}()

	select {
	case <-entered:
	case <-time.After(60 * time.Second):
		t.Fatal("switchCountry never reached its engine-rebuild window")
	}
	disconnect()
	close(release)

	select {
	case <-done:
	case <-time.After(180 * time.Second):
		t.Fatal("switchCountry never returned after the concurrent disconnect")
	}

	mu.Lock()
	engAfter, tunnelAfter, cancelAfter, countryAfter := engine, activeTunnel, engineCancel, liveCountry
	mu.Unlock()

	// The assertion the blocker is about: an engine alive with no tunnel
	// under it. Checked first and reported in full, because every other
	// symptom below is downstream of it.
	if engAfter != nil {
		t.Errorf("switchCountry resurrected the session after a concurrent disconnect: engine live with activeTunnel-set=%v, liveCountry=%q, status=%q — "+
			"the tray claims protection over a torn-down tunnel, and connect() cannot start a replacement while engine is non-nil",
			tunnelAfter != nil, countryAfter, currentStatus())
	}
	if tunnelAfter != nil || cancelAfter != nil || countryAfter != "" {
		t.Errorf("disconnect() during a live country switch left stale state: tunnel-set=%v cancel-set=%v country=%q",
			tunnelAfter != nil, cancelAfter != nil, countryAfter)
	}
	// What the client tells the user has to match what is true.
	// "Protected — A" here is the whole harm; "Disconnected" is what
	// disconnect() published and nothing after it had the right to overwrite.
	if got := currentStatus(); got != "Disconnected" {
		t.Errorf("status after the raced switch is %q, want %q — the client is claiming a session it does not have", got, "Disconnected")
	}
	// Nothing may still be serving SOCKS. A listener left on the fixed local
	// address is a live egress path with no tunnel and no kill-switch above
	// it — the leak itself, not a symptom of it.
	if !waitUntil(20*time.Second, func() bool {
		ln, err := net.Listen("tcp", socksAddr)
		if err != nil {
			return false
		}
		_ = ln.Close()
		return true
	}) {
		t.Errorf("something is still serving %s after the raced switch — an engine outlived the disconnect", socksAddr)
	}
	// The engine that was live going into the race must have been stopped,
	// not merely dropped: an unreferenced running engine keeps its transport
	// and goroutines alive for the rest of the process.
	if !waitUntil(20*time.Second, func() bool {
		select {
		case <-afterSwitch.Done():
			return true
		default:
			return false
		}
	}) {
		t.Error("the engine live before the race never reached Done() — disconnect() lost track of it")
	}
}

// TestSwitchCountry_LosingTheRaceDoesNotCancelTheLiveEngineContext is the
// second check-then-act blocker the #183 review found, one level up from the
// engine swap: switchCountry read engineCancel at the top and fired it before
// re-checking ownership.
//
// Why that is wrong is a consequence of a deliberate decision elsewhere.
// watchMeshRecovery adopts with cancel == nil ON PURPOSE, so a mesh-walk rebuild
// keeps the session's ORIGINAL context — which means engineCancel can point at
// the context a currently-live engine is running on. The old comment asserted
// the opposite ("nothing else holds that context").
//
// The interleaving is pinned, not raced. gateEngineRebuild parks the switch
// inside its own construct-and-start window; the mesh-walk adoption is performed
// there, so the switch provably resumes into a session it no longer owns. It
// then loses adoptEngine's re-check and returns — and the assertion is that the
// live engine's context is STILL LIVE. Reverting the fix (restoring the early
// oldCancel()) cancels it before the gate is ever reached, so this fails outright
// rather than flakily.
//
// The consequence being prevented is not a crash: eng2 keeps serving SOCKS on a
// cancelled context, so traffic flows until the first path drop and then never
// recovers, with the tray still reading "Protected". Fail-closed, but a
// permanent silent hang behind a lying status line — which is why the assertion
// is on ctx.Err() rather than on anything converging.
//
// Fast: nothing here connects. The switch never reaches Connect, because it
// loses the adoption first.
func TestSwitchCountry_LosingTheRaceDoesNotCancelTheLiveEngineContext(t *testing.T) {
	// Order matters: t.Cleanup runs LIFO, and resetConnectionState's teardown
	// stops engines and closes a tunnel, which reaches logEvent/logLine. Redirect
	// the log FIRST so that teardown still writes into the temp file rather than
	// the developer's real %APPDATA%\Bacchus\bacchus.log — a clean run happens to
	// be contained either way, but a failing one is exactly when the teardown has
	// something to say.
	redirectEventLogForTest(t)
	resetConnectionState(t)

	// An address nothing answers on. Start only opens the UDP sockets; it is
	// Connect that would need a coordinator, and this test never gets there.
	dead := deadCoordinatorAddr(t)
	setTestConfig(Config{Coordinators: []string{dead}})

	newIdleEngine := func(label string) *core.Engine {
		eng, err := core.New(core.Config{
			Roles:        []string{core.RoleClient},
			SocksAddr:    socksAddr,
			Geo:          testCountry,
			Coordinators: []string{dead},
			OnEvent:      testEventSink(t, label),
		})
		if err != nil {
			t.Fatalf("core.New(%s): %v", label, err)
		}
		return eng
	}

	// eng1 is the session's engine; ctx1/cancel1 is the context it runs on and
	// the one a mesh-walk rebuild would keep using.
	eng1 := newIdleEngine("eng1")
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	seedLiveSession(eng1, cancel1, testCountry)
	t.Cleanup(eng1.Stop)

	// eng2 stands in for the engine a concurrent mesh-walk recovery rebuilds and
	// adopts. It is never started — adoptEngine only stores it, and the losing
	// switch must not touch it.
	eng2 := newIdleEngine("eng2")
	t.Cleanup(eng2.Stop)

	pickCountryInTray(testCountryAlt)
	entered, release := gateEngineRebuild(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		switchCountry()
	}()

	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("switchCountry never reached its engine-rebuild window")
	}

	// The mesh-walk adoption, exactly as watchMeshRecovery performs it: the
	// engine changes, the context deliberately does not.
	if !adoptEngine(eng1, eng2, nil, "") {
		t.Fatal("the stand-in mesh-walk adoption did not win — the test never set up the race it is about")
	}
	close(release)

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("switchCountry never returned after losing the adoption")
	}

	// The assertion. eng2 is live and running on ctx1; a switch that lost the
	// session has no business cancelling it.
	if err := ctx1.Err(); err != nil {
		t.Errorf("the live engine's context was cancelled by a switch that lost the session (%v) — "+
			"eng2 keeps its SOCKS listener bound but its reconnect loop is dead, so traffic flows until the "+
			"first path drop and then never recovers, with the tray still reading Protected", err)
	}
	mu.Lock()
	liveEngine, liveCancel := engine, engineCancel
	mu.Unlock()
	if liveEngine != eng2 {
		t.Errorf("engine = %p, want the mesh-walk replacement %p — the losing switch overwrote it", liveEngine, eng2)
	}
	// engineCancel must still be the session's original: the losing switch never
	// adopted, so it never had a replacement context to install.
	if liveCancel == nil {
		t.Error("engineCancel was cleared by a switch that lost the session")
	}
}

// TestConnect_LosingTheRaceDoesNotStrandAnEngine covers the third instance of
// the same check-then-act shape, which the #183 review found unfixed in
// connect() after adoptEngine had been introduced for the other two.
//
// connect() checks engine != nil, releases mu, then spends seconds in
// clientEngineConfig/core.New/Start before assigning. The tray dispatches
// `go connect()` per click and hides the Connect item only INSIDE connect(),
// after that check, so two rapid clicks both pass it. Unconditional assignment
// then means the second one overwrites the first, and the harm is not the lost
// pointer: the overwritten engine is still running and still holds socksAddr,
// which is a fixed package constant rather than an ephemeral port, so every
// later Connect fails to bind for the rest of the process. Only Quit recovers.
//
// The interleaving is pinned through newCoreEngine, the same seam the switch
// tests use: the second connect parks inside its own construct window while a
// competing session is published, then resumes into a session it does not own.
//
// Reverting connect() to the unconditional assignment fails this on the
// engine-identity assertion; leaving the assignment guarded but dropping
// adoptEngine's own next.Stop() fails it on the Done() assertion.
func TestConnect_LosingTheRaceDoesNotStrandAnEngine(t *testing.T) {
	// Order matters: t.Cleanup runs LIFO, and resetConnectionState's teardown
	// stops engines and closes a tunnel, which reaches logEvent/logLine. Redirect
	// the log FIRST so that teardown still writes into the temp file rather than
	// the developer's real %APPDATA%\Bacchus\bacchus.log — a clean run happens to
	// be contained either way, but a failing one is exactly when the teardown has
	// something to say.
	redirectEventLogForTest(t)
	resetConnectionState(t)

	dead := deadCoordinatorAddr(t)
	setTestConfig(Config{Coordinators: []string{dead}})
	pickCountryInTray(testCountry)

	// The engine a competing connect() publishes while this one is parked.
	winner, err := core.New(core.Config{
		Roles:        []string{core.RoleClient},
		SocksAddr:    socksAddr,
		Geo:          testCountry,
		Coordinators: []string{dead},
		OnEvent:      testEventSink(t, "winner"),
	})
	if err != nil {
		t.Fatalf("core.New(winner): %v", err)
	}
	t.Cleanup(winner.Stop)

	// Capture the engine the losing connect() builds, so the test can assert it
	// was actually stopped rather than merely dropped.
	var loser *core.Engine
	entered, release := gateEngineRebuild(t)
	orig := newCoreEngine
	newCoreEngine = func(cfg core.Config) (*core.Engine, error) {
		eng, err := orig(cfg)
		loser = eng
		return eng, err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		connect()
	}()

	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("connect() never reached its engine-construct window")
	}

	// A competing connect() wins the session while this one is parked.
	if !adoptEngine(nil, winner, func() {}, testCountry) {
		t.Fatal("the stand-in competing connect did not win — the test never set up the race it is about")
	}
	close(release)

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("connect() never returned after losing the session")
	}

	mu.Lock()
	live := engine
	mu.Unlock()
	if live != winner {
		t.Errorf("engine = %p, want the connect that won the session %p — the loser published over it, and the winner's engine is now untracked while still holding %s",
			live, winner, socksAddr)
	}
	if loser == nil {
		t.Fatal("the losing connect never built an engine — the gate did not do what this test assumes")
	}
	if loser == winner {
		t.Fatal("loser and winner are the same engine — the test did not create two")
	}
	// Stopped, not merely dropped: an unreferenced running engine keeps its
	// SOCKS listener and goroutines alive for the rest of the process.
	if !waitUntil(20*time.Second, func() bool {
		select {
		case <-loser.Done():
			return true
		default:
			return false
		}
	}) {
		t.Errorf("the losing connect's engine never reached Done() — it is still running unreferenced, holding %s", socksAddr)
	}
}

// TestSwitchCountryReusesTheLiveTunnelsExcluder covers the #183 review's
// "correct but untested" finding: reinstating the freshly-minted excluder left
// the whole suite green.
//
// The distinction is invisible to any assertion about switchCountry's outcome,
// which is why it needed its own test. Exclusion routes and kill-switch allow
// entries are only installed once goLive/armAllowlist have run against a
// RUNNING tunnel, and tunnel.Close() only reaps the excluder the tunnel itself
// holds. A newly minted one sits at routesLive=false/armed=false forever, so
// reserve() silently installs nothing and the new engine's reality underlay
// address is never carved out of the tunnel it is riding under — the session
// still comes up, still passes traffic, and quietly loses the property that
// makes reality safe on this client at all (issue #109).
//
// So the assertion is on identity: the OnUnderlayDial the rebuilt engine is
// given must reach the excluder the live tunnel holds, not some other one.
// Proven by calling it and observing which excluder recorded the address.
func TestSwitchCountryReusesTheLiveTunnelsExcluder(t *testing.T) {
	redirectEventLogForTest(t)
	resetConnectionState(t)

	dead := deadCoordinatorAddr(t)
	setTestConfig(Config{Coordinators: []string{dead}})

	eng, err := core.New(core.Config{
		Roles:        []string{core.RoleClient},
		SocksAddr:    socksAddr,
		Geo:          testCountry,
		Coordinators: []string{dead},
		OnEvent:      testEventSink(t, "excluder"),
	})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	t.Cleanup(eng.Stop)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	live := seedLiveSession(eng, cancel, testCountry)

	// Capture the config the rebuild is handed, then refuse to build, so the
	// test stops before any engine starts. What is under test is the config.
	var handed core.Config
	orig := newCoreEngine
	newCoreEngine = func(cfg core.Config) (*core.Engine, error) {
		handed = cfg
		return nil, errors.New("stop here: the config is what this test is about")
	}
	t.Cleanup(func() { newCoreEngine = orig })

	pickCountryInTray(testCountryAlt)
	switchCountry()

	if handed.OnUnderlayDial == nil {
		t.Fatal("the rebuilt engine was given no OnUnderlayDial — a reality underlay address would never be excluded from the tunnel it rides under (issue #109)")
	}
	// Call it and see which excluder heard about it. The live tunnel's excluder
	// is the only correct answer; a freshly minted one would leave the live
	// tunnel's set empty.
	const underlay = "192.0.2.44:443"
	handed.OnUnderlayDial(underlay)
	if live.excluder == nil {
		t.Fatal("the seeded tunnel has no excluder — the fixture, not the code, is wrong")
	}
	got := live.excluder.reserved()
	found := false
	for _, ip := range got {
		if strings.Contains(ip, "192.0.2.44") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("OnUnderlayDial did not reach the LIVE tunnel's excluder (it recorded %v) — a freshly minted one installs nothing (routesLive=false, armed=false) and is never reaped by tunnel.Close()", got)
	}
}

// TestSwitchCountry_DisconnectDuringConnectDoesNotClaimProtected closes the last
// of the #183 review's "correct but untested" findings, and it needed a new seam
// to close: gateEngineRebuild parks the rebuild BEFORE adoptEngine, so control
// never reached the post-Connect re-check and deleting that check left the suite
// green.
//
// connectEngine is that seam. Parking there puts the test in the one window the
// check exists for: the session has already been handed to the new engine, and
// Connect — the longest step of the three — is in flight when the user hits
// Disconnect. Without the re-check, the switch returns and publishes
// "Protected — <country>" over the "Disconnected" that disconnect() correctly
// set, which is the belief-safety failure again: the tray claims a session that
// was torn down while it was talking.
func TestSwitchCountry_DisconnectDuringConnectDoesNotClaimProtected(t *testing.T) {
	redirectEventLogForTest(t)
	resetConnectionState(t)

	dead := deadCoordinatorAddr(t)
	setTestConfig(Config{Coordinators: []string{dead}})

	eng, err := core.New(core.Config{
		Roles:        []string{core.RoleClient},
		SocksAddr:    socksAddr,
		Geo:          testCountry,
		Coordinators: []string{dead},
		OnEvent:      testEventSink(t, "post-connect"),
	})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	t.Cleanup(eng.Stop)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	seedLiveSession(eng, cancel, testCountry)
	setStatus("Protected — " + testCountry)

	// Park inside Connect, AFTER adoptEngine has handed the session over.
	// Returning nil on release: the point is a successful Connect racing a
	// disconnect, not a failed one (that path is abortSession's, tested above).
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var connected *core.Engine
	origConnect := connectEngine
	connectEngine = func(ctx context.Context, e *core.Engine) error {
		connected = e
		entered <- struct{}{}
		<-release
		return nil
	}
	t.Cleanup(func() { connectEngine = origConnect })

	pickCountryInTray(testCountryAlt)
	done := make(chan struct{})
	go func() {
		defer close(done)
		switchCountry()
	}()

	select {
	case <-entered:
	case <-time.After(30 * time.Second):
		t.Fatal("switchCountry never reached Connect — adoptEngine did not hand the session over")
	}
	disconnect()
	close(release)

	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("switchCountry never returned")
	}

	// The assertion: what the client is telling the user.
	if got := currentStatus(); got != "Disconnected" {
		t.Errorf("status after a disconnect during the switch's Connect is %q, want %q — the switch claimed a session the user had already ended",
			got, "Disconnected")
	}
	mu.Lock()
	liveEngine, liveTunnel := engine, activeTunnel
	mu.Unlock()
	if liveEngine != nil || liveTunnel != nil {
		t.Errorf("connection state was republished after disconnect: engine-set=%v tunnel-set=%v", liveEngine != nil, liveTunnel != nil)
	}
	// The adopted-but-discarded engine must be stopped, not left running.
	if connected == nil {
		t.Fatal("the gate never captured the engine being connected")
	}
	if !waitUntil(20*time.Second, func() bool {
		select {
		case <-connected.Done():
			return true
		default:
			return false
		}
	}) {
		t.Errorf("the discarded engine never reached Done() — it is still running, holding %s", socksAddr)
	}
}

// deadCoordinatorAddr returns a loopback UDP address with nothing listening on
// it: bind, read the port, close. Good enough for a test that only needs Start
// to succeed and never sends a datagram anyone must answer.
func deadCoordinatorAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a dead coordinator port: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// echoThrough runs one real SOCKS5 CONNECT + echo round trip and checks the
// payload came back intact, so a caller asserts on traffic rather than on a
// nil error from something internal.
func echoThrough(socks, target, payload string) error {
	got, err := socksEchoRoundTrip(socks, target, []byte(payload))
	if err != nil {
		return err
	}
	if string(got) != payload {
		return fmt.Errorf("echo mismatch: got %q, want %q", got, payload)
	}
	return nil
}

// setTestConfig replaces the package cfg global the way the Settings dialog's
// Save handler does — under mu, since connect()/switchExit() snapshot it.
func setTestConfig(c Config) {
	mu.Lock()
	cfg = c
	mu.Unlock()
}
