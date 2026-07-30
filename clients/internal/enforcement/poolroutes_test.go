package enforcement

import (
	"errors"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// opRecorder captures the route/allowlist side effects a poolExcluder would
// perform, in order, instead of shelling out to real Windows routing/firewall —
// so these tests assert the ordering logic without touching the machine.
type opRecorder struct {
	mu      sync.Mutex
	routes  []string // IPs excluded via the gateway, in call order
	allows  []string // IPs added to the live kill-switch allowlist, in call order
	removes []string // IPs reaped via removeFn, in call order (issue #117 self-reap)
}

func (r *opRecorder) exclude(_ gatewayInfo, ip string) {
	r.mu.Lock()
	r.routes = append(r.routes, ip)
	r.mu.Unlock()
}

func (r *opRecorder) allow(ip string) {
	r.mu.Lock()
	r.allows = append(r.allows, ip)
	r.mu.Unlock()
}

func (r *opRecorder) remove(ips []string) {
	r.mu.Lock()
	r.removes = append(r.removes, ips...)
	r.mu.Unlock()
}

func (r *opRecorder) snapshotRoutes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.routes...)
}

func (r *opRecorder) snapshotAllows() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.allows...)
}

func (r *opRecorder) snapshotRemoves() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.removes...)
}

func newTestExcluder() (*poolExcluder, *opRecorder) {
	r := &opRecorder{}
	pe := &poolExcluder{
		seen:      map[string]bool{},
		excludeFn: r.exclude,
		allowFn:   r.allow,
		removeFn:  r.remove,
		// Default gatewayFn "succeeds" with the same zero-value gatewayInfo
		// these tests already pass to goLive — opRecorder.exclude discards its
		// gatewayInfo argument entirely, so no existing assertion depends on
		// this value; tests of the refresh behavior itself (issue #117)
		// override it explicitly.
		gatewayFn: func() (gatewayInfo, error) { return gatewayInfo{}, nil },
	}
	return pe, r
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestPoolExcluderPreTunnelRecordsThenGoLiveInstalls proves the initial-connect
// ordering: a reality address reserved before the tunnel is up is only recorded,
// and goLive (which startTunnel calls BEFORE the split-default route flips)
// installs its exclusion route. That is what carves the underlay out before the
// route flip could capture it.
func TestPoolExcluderPreTunnelRecordsThenGoLiveInstalls(t *testing.T) {
	pe, rec := newTestExcluder()

	pe.reserve("203.0.113.10:443")
	if got := rec.snapshotRoutes(); len(got) != 0 {
		t.Fatalf("pre-tunnel reserve installed a route early: %v (must only record until goLive)", got)
	}
	if got := pe.reserved(); !reflect.DeepEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("reserved() = %v, want the recorded IP", got)
	}

	pe.goLive(gatewayInfo{})
	if got := rec.snapshotRoutes(); !reflect.DeepEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("goLive did not install the reserved route before the flip: %v", got)
	}
}

// TestPoolExcluderFailoverReExcludesNewAddress is the leak-focused proof for the
// #109 "handle the failover timing window" requirement: once the tunnel is up
// and the kill-switch armed, a mid-session failover to a NEW exit must exclude
// and allow-list that new address live, on the dial path. Reverting reserve()'s
// live-install branch (the `if p.routesLive` early-return, or the p.allowFn call)
// makes this fail — the new underlay would then be left to loop into / be
// blocked by the tunnel.
func TestPoolExcluderFailoverReExcludesNewAddress(t *testing.T) {
	pe, rec := newTestExcluder()

	// Initial connect: reserve the first exit, bring the tunnel up, arm.
	pe.reserve("203.0.113.10:443")
	pe.goLive(gatewayInfo{})
	var initialAllowlist []string
	if err := pe.armAllowlist(func(poolIPs []string) error {
		initialAllowlist = poolIPs
		return nil
	}); err != nil {
		t.Fatalf("armAllowlist: %v", err)
	}
	if !contains(initialAllowlist, "203.0.113.10") {
		t.Fatalf("initial allowlist %v missing the first underlay", initialAllowlist)
	}

	// Mid-session failover: a different exit is dialed. Its address must be
	// excluded AND allow-listed live, right now.
	pe.reserve("198.51.100.20:443")

	if !contains(rec.snapshotRoutes(), "198.51.100.20") {
		t.Fatalf("failover did not exclude the new underlay route: %v", rec.snapshotRoutes())
	}
	if !contains(rec.snapshotAllows(), "198.51.100.20") {
		t.Fatalf("failover did not allow-list the new underlay under the armed kill-switch: %v", rec.snapshotAllows())
	}
	// The first exit was in the initial snapshot, so it must NOT be double-added
	// to the live allowlist.
	if contains(rec.snapshotAllows(), "203.0.113.10") {
		t.Fatalf("first underlay was live-refreshed as well as snapshotted: %v", rec.snapshotAllows())
	}
}

// TestPoolExcluderArmAtomicity pins the #73-style split: an address reserved
// BEFORE arming lands in the initial allowlist snapshot and is not also
// live-refreshed; an address reserved AFTER arming takes the live-refresh path.
// Every address is on exactly one path, never neither (the leak) nor both.
func TestPoolExcluderArmAtomicity(t *testing.T) {
	pe, rec := newTestExcluder()

	pe.reserve("203.0.113.10:443") // before tunnel
	pe.goLive(gatewayInfo{})
	pe.reserve("203.0.113.11:443") // after goLive, before arm

	var snap []string
	if err := pe.armAllowlist(func(poolIPs []string) error {
		snap = append([]string(nil), poolIPs...)
		return nil
	}); err != nil {
		t.Fatalf("armAllowlist: %v", err)
	}
	sort.Strings(snap)
	if want := []string{"203.0.113.10", "203.0.113.11"}; !reflect.DeepEqual(snap, want) {
		t.Fatalf("initial snapshot = %v, want both pre-arm underlays %v", snap, want)
	}
	// Nothing was live-refreshed before arming.
	if got := rec.snapshotAllows(); len(got) != 0 {
		t.Fatalf("allowlist refreshed before arming: %v", got)
	}

	pe.reserve("203.0.113.12:443") // after arm — live path only
	if got := rec.snapshotAllows(); !reflect.DeepEqual(got, []string{"203.0.113.12"}) {
		t.Fatalf("post-arm reserve did not take the live allowlist path exactly once: %v", got)
	}
}

// TestPoolExcluderDedup proves an address is excluded once no matter how many
// times it's dialed — a reality session re-dials the same exit for every stream,
// so reserve() must stay a cheap no-op after the first time.
func TestPoolExcluderDedup(t *testing.T) {
	pe, rec := newTestExcluder()
	pe.goLive(gatewayInfo{})

	pe.reserve("203.0.113.10:443")
	pe.reserve("203.0.113.10:443")
	pe.reserve("203.0.113.10:443")

	if got := rec.snapshotRoutes(); !reflect.DeepEqual(got, []string{"203.0.113.10"}) {
		t.Fatalf("route installed more than once for the same address: %v", got)
	}
}

// TestPoolExcluderNoKillSwitchNoAllowlist proves that without the kill-switch
// (armAllowlist never called) a failover still gets its route but touches no
// allowlist — there is none.
func TestPoolExcluderNoKillSwitchNoAllowlist(t *testing.T) {
	pe, rec := newTestExcluder()
	pe.goLive(gatewayInfo{})

	pe.reserve("203.0.113.10:443")

	if got := rec.snapshotRoutes(); !contains(got, "203.0.113.10") {
		t.Fatalf("route not installed: %v", got)
	}
	if got := rec.snapshotAllows(); len(got) != 0 {
		t.Fatalf("allowlist touched with no kill-switch armed: %v", got)
	}
}

// TestPoolExcluderIgnoresUnparseableAddr proves a malformed underlay address is a
// safe no-op (it neither records nor installs), so a bad answer can't wedge the
// dial path.
func TestPoolExcluderIgnoresUnparseableAddr(t *testing.T) {
	pe, rec := newTestExcluder()
	pe.goLive(gatewayInfo{})

	pe.reserve("")                // empty
	pe.reserve("203.0.113.10")    // no port
	pe.reserve("not-an-endpoint") // junk, no port

	if got := rec.snapshotRoutes(); len(got) != 0 {
		t.Fatalf("unparseable addresses produced routes: %v", got)
	}
	if got := pe.reserved(); len(got) != 0 {
		t.Fatalf("unparseable addresses were recorded: %v", got)
	}
}

// TestPoolExcluderArmError proves an enableKillSwitch failure surfaces and leaves
// the excluder un-armed, so a later reserve doesn't wrongly assume a live
// allowlist exists.
func TestPoolExcluderArmError(t *testing.T) {
	pe, rec := newTestExcluder()
	pe.goLive(gatewayInfo{})

	want := errors.New("boom")
	if err := pe.armAllowlist(func([]string) error { return want }); !errors.Is(err, want) {
		t.Fatalf("armAllowlist error = %v, want %v", err, want)
	}
	pe.reserve("203.0.113.10:443")
	if got := rec.snapshotAllows(); len(got) != 0 {
		t.Fatalf("reserve refreshed the allowlist after a failed arm: %v", got)
	}
}

// TestPoolExcluderReservesIPv6Address is the IPv6-exclude proof (issue #117):
// a reality exit address that resolves to an IPv6 literal must flow through
// the same live-install path as an IPv4 one, not be silently dropped
// (resolveExclusions alone is IPv4-only). Reverting reserve()'s
// resolveExclusionsV6 call makes this fail: ips would be empty and excludeFn
// would never run.
func TestPoolExcluderReservesIPv6Address(t *testing.T) {
	pe, rec := newTestExcluder()
	pe.goLive(gatewayInfo{})

	pe.reserve("[2001:db8::1]:443")

	if !contains(rec.snapshotRoutes(), "2001:db8::1") {
		t.Fatalf("IPv6 exit address was not excluded: %v", rec.snapshotRoutes())
	}
	if !contains(pe.reserved(), "2001:db8::1") {
		t.Fatalf("IPv6 exit address was not recorded: %v", pe.reserved())
	}
}

// TestPoolExcluderDoesNotHoldLockAcrossExcludeFn is the lock-narrowing proof
// (issue #117): a slow excludeFn (standing in for a slow PowerShell shell-out)
// must not stall a concurrent call needing mu, like reserved() (which
// startTunnel's failure cleanup and tunnel.Close() both call). Reverting
// reserve() to hold mu for its whole body (the pre-#117 shape) makes this
// test time out instead of completing promptly, since reserved() would then
// block until excludeFn returns.
func TestPoolExcluderDoesNotHoldLockAcrossExcludeFn(t *testing.T) {
	pe, _ := newTestExcluder()
	pe.goLive(gatewayInfo{})

	excludeStarted := make(chan struct{})
	unblockExclude := make(chan struct{})
	pe.excludeFn = func(gatewayInfo, string) {
		close(excludeStarted)
		<-unblockExclude
	}

	reserveDone := make(chan struct{})
	go func() {
		pe.reserve("203.0.113.10:443") // blocks inside excludeFn until unblockExclude closes
		close(reserveDone)
	}()
	<-excludeStarted // reserve() is now inside the blocked excludeFn call

	reservedDone := make(chan []string, 1)
	go func() { reservedDone <- pe.reserved() }()

	select {
	case <-reservedDone:
		// mu was free — reserve() is not holding it across the shell-out.
	case <-time.After(2 * time.Second):
		t.Fatal("reserved() blocked while excludeFn was in flight — reserve() is still holding mu across the shell-out")
	}

	close(unblockExclude)
	<-reserveDone
}

// TestPoolExcluderSelfReapsRouteInstalledAfterDisable is the orphaned-route
// proof (issue #117): narrowing reserve()'s lock (above) reopens a window
// where startTunnel's failure cleanup (or tunnel.Close()) can disable() and
// take its final removeRoutes(reserved()) snapshot while a concurrent
// reserve()'s install is still in flight, unlocked — landing after the
// snapshot and orphaning a route nothing is tracking. reserve() must reap
// that route itself once it observes closed. Reverting the post-install
// closed check (or disable() itself) makes this test see no removeFn call.
func TestPoolExcluderSelfReapsRouteInstalledAfterDisable(t *testing.T) {
	pe, rec := newTestExcluder()
	pe.goLive(gatewayInfo{})

	excludeStarted := make(chan struct{})
	pe.excludeFn = func(gw gatewayInfo, ip string) {
		rec.exclude(gw, ip)
		close(excludeStarted)
		<-time.After(50 * time.Millisecond) // simulate a shell-out slow enough for disable() to land first
	}

	reserveDone := make(chan struct{})
	go func() {
		pe.reserve("203.0.113.10:443")
		close(reserveDone)
	}()

	<-excludeStarted // the install landed (recorded in rec.routes)...
	pe.disable()     // ...and now the excluder is torn down before reserve() returns.
	<-reserveDone

	if got := rec.snapshotRemoves(); !contains(got, "203.0.113.10") {
		t.Fatalf("reserve() did not self-reap its install after disable(): removes = %v", got)
	}
}

// waitForGatewayRefreshIdle blocks until pe's background gateway refresh
// (triggerGatewayRefresh) is not in flight, or fails the test after 2s.
// Same-package (not exported) access to pe.mu/pe.gwRefreshing is a
// test-only convenience for deterministic synchronization; production code
// never reads them directly.
func waitForGatewayRefreshIdle(t *testing.T, pe *poolExcluder) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		pe.mu.Lock()
		idle := !pe.gwRefreshing
		pe.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("background gateway refresh never went idle")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestPoolExcluderReserveDoesNotBlockOnGatewayRefresh is the off-dial-path
// proof (issue #123c): reserve()'s live-install path must not shell out to
// defaultGateway synchronously — a slow gatewayFn (standing in for a slow
// PowerShell spawn) must not stall the dial reserve() guards. Reverting to a
// synchronous gatewayFn call inside reserve() makes this test time out
// instead of completing promptly, since reserve() would then block until
// gatewayFn returns.
func TestPoolExcluderReserveDoesNotBlockOnGatewayRefresh(t *testing.T) {
	pe, rec := newTestExcluder()
	pe.goLive(gatewayInfo{nextHop: "192.168.1.1", ifIndex: 1, ifAlias: "Wi-Fi"})

	release := make(chan struct{})
	pe.gatewayFn = func() (gatewayInfo, error) {
		<-release // would hang reserve() forever if it were still called synchronously
		return gatewayInfo{}, nil
	}
	defer close(release)

	done := make(chan struct{})
	go func() {
		pe.reserve("203.0.113.50:443")
		close(done)
	}()

	select {
	case <-done:
		// reserve() returned promptly — it did not wait on the slow gatewayFn.
	case <-time.After(2 * time.Second):
		t.Fatal("reserve() blocked on gatewayFn — the gateway resolve is still synchronous on the dial path")
	}
	if !contains(rec.snapshotRoutes(), "203.0.113.50") {
		t.Fatalf("reserve() did not install a route while its background gateway refresh was in flight: %v", rec.snapshotRoutes())
	}
}

// TestPoolExcluderBackgroundRefreshUpdatesGatewayForNextInstall is the
// eventual-freshness proof (issue #123c): reserve() no longer re-resolves the
// gateway itself, but the background refresh it triggers must still keep
// p.gw current for whichever reserve() comes next — otherwise moving the
// resolve off the dial path would silently resurrect the #117 stale-gateway
// bug (a moved laptop's failover routing an exclusion via a next-hop that no
// longer exists, for the rest of the session instead of just one call).
func TestPoolExcluderBackgroundRefreshUpdatesGatewayForNextInstall(t *testing.T) {
	pe, rec := newTestExcluder()
	staleGW := gatewayInfo{nextHop: "192.168.1.1", ifIndex: 1, ifAlias: "Wi-Fi"}
	pe.goLive(staleGW)

	freshGW := gatewayInfo{nextHop: "192.168.2.1", ifIndex: 4, ifAlias: "Wi-Fi 2"}
	refreshed := make(chan struct{})
	var once sync.Once
	pe.gatewayFn = func() (gatewayInfo, error) {
		once.Do(func() { close(refreshed) })
		return freshGW, nil
	}

	pe.reserve("203.0.113.30:443") // live install: triggers the background refresh

	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("background gateway refresh was never attempted")
	}
	waitForGatewayRefreshIdle(t, pe)

	var gotGW gatewayInfo
	pe.excludeFn = func(gw gatewayInfo, ip string) { gotGW = gw; rec.exclude(gw, ip) }
	pe.reserve("203.0.113.31:443") // a different address — .30 is already in p.seen

	if gotGW != freshGW {
		t.Fatalf("excludeFn saw gateway %+v, want the background-refreshed %+v (not goLive's stale %+v)", gotGW, freshGW, staleGW)
	}
}

// TestPoolExcluderBackgroundRefreshFailureKeepsLastKnownGateway proves a
// failed background refresh (a transient PowerShell hiccup) leaves p.gw at
// its last-known-good value for the next reserve(), rather than clobbering it
// with a zero-value gatewayInfo (which would route every subsequent
// exclusion via no next-hop at all).
func TestPoolExcluderBackgroundRefreshFailureKeepsLastKnownGateway(t *testing.T) {
	pe, rec := newTestExcluder()
	staleGW := gatewayInfo{nextHop: "192.168.1.1", ifIndex: 1, ifAlias: "Wi-Fi"}
	pe.goLive(staleGW)

	attempted := make(chan struct{})
	var once sync.Once
	pe.gatewayFn = func() (gatewayInfo, error) {
		once.Do(func() { close(attempted) })
		return gatewayInfo{}, errors.New("boom")
	}

	pe.reserve("203.0.113.40:443") // triggers the (failing) background refresh

	select {
	case <-attempted:
	case <-time.After(2 * time.Second):
		t.Fatal("background gateway refresh was never attempted")
	}
	waitForGatewayRefreshIdle(t, pe)

	var gotGW gatewayInfo
	pe.excludeFn = func(gw gatewayInfo, ip string) { gotGW = gw; rec.exclude(gw, ip) }
	pe.reserve("203.0.113.41:443")

	if gotGW != staleGW {
		t.Fatalf("excludeFn saw gateway %+v after a failed background refresh, want the fallback %+v", gotGW, staleGW)
	}
}

// TestPoolExcluderTriggerGatewayRefreshDedupsConcurrentCalls proves a second
// triggerGatewayRefresh call, made while the first is still in flight, does
// not spawn a second gatewayFn call — a burst of reserve() calls for several
// new addresses at once (a multi-address reality answer) must not spawn one
// redundant PowerShell process per address. The three calls here are
// synchronous from the test's own goroutine, so the first is guaranteed to
// have set gwRefreshing before the second and third run (issue #123c).
func TestPoolExcluderTriggerGatewayRefreshDedupsConcurrentCalls(t *testing.T) {
	pe, _ := newTestExcluder()

	var calls int32
	entered := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	pe.gatewayFn = func() (gatewayInfo, error) {
		atomic.AddInt32(&calls, 1)
		once.Do(func() { close(entered) })
		<-release
		return gatewayInfo{}, nil
	}

	pe.triggerGatewayRefresh()
	select {
	case <-entered: // the first call is now blocked inside gatewayFn, holding gwRefreshing
	case <-time.After(2 * time.Second):
		t.Fatal("gatewayFn was never called")
	}

	pe.triggerGatewayRefresh() // must observe gwRefreshing already true and skip
	pe.triggerGatewayRefresh() // same

	close(release)
	waitForGatewayRefreshIdle(t, pe)

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("gatewayFn called %d times for 3 back-to-back triggerGatewayRefresh calls while the first was in flight, want exactly 1", got)
	}
}

// TestPoolExcluderSkipsAllowlistForInstallReapedAfterDisable is the
// firewall-rule-residual proof (issue #123b): when a reserve()'s route
// install races past disable()'s teardown snapshot (same window as
// TestPoolExcluderSelfReapsRouteInstalledAfterDisable) under an ARMED
// kill-switch, the reaped install must not also add a live allowlist entry —
// installing one for an address already known to be torn down just leaves a
// duplicate-DisplayName Bacchus-Allow-Remotes rule for the next teardown's
// group sweep to find, with no self-reap of its own. Reverting allowFn's
// gate on the post-excludeFn closed check (moving the `if armed` block back
// to before that check) makes this test observe an allow call.
func TestPoolExcluderSkipsAllowlistForInstallReapedAfterDisable(t *testing.T) {
	pe, rec := newTestExcluder()
	pe.goLive(gatewayInfo{})
	if err := pe.armAllowlist(func([]string) error { return nil }); err != nil {
		t.Fatalf("armAllowlist: %v", err)
	}

	excludeStarted := make(chan struct{})
	pe.excludeFn = func(gw gatewayInfo, ip string) {
		rec.exclude(gw, ip)
		close(excludeStarted)
		<-time.After(50 * time.Millisecond) // simulate a shell-out slow enough for disable() to land first
	}

	reserveDone := make(chan struct{})
	go func() {
		pe.reserve("203.0.113.20:443")
		close(reserveDone)
	}()

	<-excludeStarted // the route install landed (recorded in rec.routes)...
	pe.disable()     // ...and now the excluder is torn down before reserve() returns.
	<-reserveDone

	if got := rec.snapshotRemoves(); !contains(got, "203.0.113.20") {
		t.Fatalf("reserve() did not self-reap the route after disable(): removes = %v", got)
	}
	if got := rec.snapshotAllows(); contains(got, "203.0.113.20") {
		t.Fatalf("reserve() installed a kill-switch allow rule for an address it already reaped the route for: allows = %v", got)
	}
}
