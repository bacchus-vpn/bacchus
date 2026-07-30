// Ordering tests for the re-pointed bring-up/teardown sequence.
//
// tunnel.go is the file ADR-0039 costed as "orchestration only" and bacchus#59
// re-pointed rather than moved: it used to call routes.go/killswitch.go by
// name and now calls them through osNet. The behaviour that had to survive
// that is not "the same functions get called" — it is the ORDER they get
// called in, and what happens to the ones that already ran when a later step
// fails. Every one of those orderings is a fix that was made once, after the
// original shipped, in response to a real leak or race.
//
// Because osNet is portable, so are these: a fake implementation records the
// sequence, so the guarantees are asserted on every push on Linux CI rather
// than only where PowerShell exists. That is deliberate. Two of the three
// platforms that will implement this interface do not exist yet, and these
// are the tests that tell [E9] and [E10] what "correct" means.
package enforcement

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeOS records every osNet call in order, and can be told to fail one of
// them so the unwind path can be driven.
type fakeOS struct {
	mu   sync.Mutex
	ops  []string
	dev  *memTun
	gw   gatewayInfo
	fail map[string]error
}

func newFakeOS() *fakeOS {
	return &fakeOS{
		dev:  newMemTun(),
		gw:   gatewayInfo{nextHop: "192.0.2.1", ifIndex: 7, ifAlias: "Ethernet"},
		fail: map[string]error{},
	}
}

func (f *fakeOS) rec(op string) {
	f.mu.Lock()
	f.ops = append(f.ops, op)
	f.mu.Unlock()
}

func (f *fakeOS) seq() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.ops...)
}

func (f *fakeOS) defaultGateway() (gatewayInfo, error) {
	f.rec("defaultGateway")
	return f.gw, f.fail["defaultGateway"]
}

func (f *fakeOS) addExclusionRoutes(prefixes []string, _ gatewayInfo) {
	for _, p := range prefixes {
		f.rec("exclude " + p)
	}
}

func (f *fakeOS) addExclusionRoutesV6(prefixes []string, _ gatewayInfo) {
	for _, p := range prefixes {
		f.rec("excludeV6 " + p)
	}
}

func (f *fakeOS) addInclusionRoutes(prefixes []string, _ string) {
	for _, p := range prefixes {
		f.rec("include " + p)
	}
}

func (f *fakeOS) removeRoutes(prefixes []string) {
	for _, p := range prefixes {
		f.rec("remove " + p)
	}
}

func (f *fakeOS) createTUN() (tun.Device, error) {
	f.rec("createTUN")
	if err := f.fail["createTUN"]; err != nil {
		return nil, err
	}
	return f.dev, nil
}

func (f *fakeOS) configureTunInterface(addr string, _ int) error {
	f.rec("configureTun " + addr)
	return f.fail["configureTun"]
}

func (f *fakeOS) addSplitDefaultRoute(addr string) error {
	f.rec("splitDefault " + addr)
	return f.fail["splitDefault"]
}

func (f *fakeOS) disablePhysicalIPv6(alias string) { f.rec("disableIPv6 " + alias) }
func (f *fakeOS) enablePhysicalIPv6(alias string)  { f.rec("enableIPv6 " + alias) }

func (f *fakeOS) enableKillSwitch(control, bypass []string) error {
	f.rec("enableKillSwitch control=" + strings.Join(control, ",") + " bypass=" + strings.Join(bypass, ","))
	return f.fail["enableKillSwitch"]
}

func (f *fakeOS) disableKillSwitch()                 { f.rec("disableKillSwitch") }
func (f *fakeOS) recoverKillSwitch()                 { f.rec("recoverKillSwitch") }
func (f *fakeOS) refreshKillSwitchAllowIP(ip string) { f.rec("refreshAllow " + ip) }

// indexOf returns the position of the first op with the given prefix, or -1.
func indexOf(ops []string, prefix string) int {
	for i, op := range ops {
		if strings.HasPrefix(op, prefix) {
			return i
		}
	}
	return -1
}

func mustBefore(t *testing.T, ops []string, first, second, why string) {
	t.Helper()
	i, j := indexOf(ops, first), indexOf(ops, second)
	if i < 0 {
		t.Fatalf("%q never happened; sequence was %v", first, ops)
	}
	if j < 0 {
		t.Fatalf("%q never happened; sequence was %v", second, ops)
	}
	if i > j {
		t.Errorf("%q happened after %q, but must come first: %s\nsequence: %v", first, second, why, ops)
	}
}

func testPolicy(killSwitch bool, mode string, bypass []string) Policy {
	return Policy{
		Coordinators: []string{"192.0.2.10:51820"}, // TEST-NET-1 (RFC 5737)
		STUNURL:      "stun:192.0.2.11:3478",
		TURNURL:      "turn:192.0.2.12:3478",
		DNSUpstream:  "192.0.2.53:53",
		Bypass:       bypass,
		BypassMode:   mode,
		KillSwitch:   killSwitch,
	}
}

func startForTest(t *testing.T, f *fakeOS, p Policy) (*tunnel, error) {
	t.Helper()
	bp := newBypassPolicy(p.BypassMode, p.Bypass)
	pe := newPoolExcluder(f)
	return startTunnel(f, nil, p, bp, pe, reserveLoopbackAddr(t))
}

// TestBringUpExcludesTheControlPlaneBeforeTheRouteFlips is the ordering the
// whole exclusion mechanism rests on. The tunnel's own signalling rides the
// physical interface; if the split-default route is installed before the
// coordinator/STUN/TURN exclusions exist, the session's own transport is
// captured by the route it just installed and the connection dies with it
// (issue #6). Same reasoning for the bypass set (issue #64's exclude half)
// and for the pool's already-dialled underlays (issue #109).
func TestBringUpExcludesTheControlPlaneBeforeTheRouteFlips(t *testing.T) {
	f := newFakeOS()
	tn, err := startForTest(t, f, testPolicy(false, BypassModeExclude, []string{"198.51.100.0/24"}))
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	t.Cleanup(tn.Close)

	ops := f.seq()
	mustBefore(t, ops, "exclude 192.0.2.10", "splitDefault",
		"a coordinator captured by the tunnel's own default route kills the session carrying it (issue #6)")
	mustBefore(t, ops, "exclude 198.51.100.0/24", "splitDefault",
		"a bypass destination must be carved out before anything can capture it, never after")
	mustBefore(t, ops, "createTUN", "splitDefault",
		"the split-default route points at an adapter that has to exist first")
}

// TestBringUpArmsTheKillSwitchLast covers parity item 2's timing half. The
// machine flips to fail-closed only once the tunnel is actually carrying
// traffic — after the netstack is up — and before Start returns, so there is
// no window in which routes point at the tunnel while the lockdown is not in
// force.
func TestBringUpArmsTheKillSwitchLast(t *testing.T) {
	f := newFakeOS()
	tn, err := startForTest(t, f, testPolicy(true, BypassModeExclude, nil))
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	t.Cleanup(tn.Close)

	ops := f.seq()
	if i := indexOf(ops, "enableKillSwitch"); i < 0 {
		t.Fatalf("kill-switch was never armed; sequence: %v", ops)
	} else if i != len(ops)-1 {
		t.Errorf("kill-switch armed at step %d of %d, want last — anything after it runs on a fail-closed machine\nsequence: %v", i, len(ops), ops)
	}
	mustBefore(t, ops, "splitDefault", "enableKillSwitch",
		"the lockdown must not be armed before the routes it is protecting exist")

	// The control-plane allowlist has to carry the same endpoints the routes
	// excluded, or the lockdown blocks the session's own signalling.
	armed := ops[len(ops)-1]
	for _, want := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		if !strings.Contains(armed, want) {
			t.Errorf("kill-switch allowlist %q is missing control-plane endpoint %s — arming would cut the session's own transport", armed, want)
		}
	}
}

// TestFailedBringUpOrphansNothing is parity item 5's second clause, and the
// one a port is most likely to lose: "never orphaned if bring-up fails
// mid-flight". A half-installed tunnel that returns an error while leaving
// routes behind, IPv6 disabled, or a TUN device open leaves the user with a
// broken network and no component that believes it owns the mess.
func TestFailedBringUpOrphansNothing(t *testing.T) {
	f := newFakeOS()
	f.fail["splitDefault"] = errors.New("simulated route failure")

	_, err := startForTest(t, f, testPolicy(true, BypassModeExclude, []string{"198.51.100.0/24"}))
	if err == nil {
		t.Fatal("startTunnel succeeded despite a failing split-default route")
	}

	ops := f.seq()
	// Everything that was installed has to come back out.
	for _, prefix := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "198.51.100.0/24"} {
		if indexOf(ops, "remove "+prefix) < 0 {
			t.Errorf("route for %s was installed but never removed after bring-up failed\nsequence: %v", prefix, ops)
		}
	}
	if indexOf(ops, "disableIPv6") >= 0 && indexOf(ops, "enableIPv6") < 0 {
		t.Errorf("IPv6 was disabled on the physical adapter and never re-enabled after bring-up failed — the user is left without IPv6 and nothing owns restoring it\nsequence: %v", ops)
	}
	if !f.dev.isClosed() {
		t.Error("the TUN device was left open after bring-up failed")
	}
	if indexOf(ops, "enableKillSwitch") >= 0 {
		t.Errorf("the kill-switch was armed even though bring-up failed — that is a machine left fail-closed with no tunnel\nsequence: %v", ops)
	}
}

// TestIncludeModeNeverInstallsASplitDefault is issue #64, which is the bug
// this mode exists because of: include mode captures nothing by default and
// pulls only the listed set in. Installing a split-default here recaptures
// every "direct" dial straight back into the tunnel it was meant to avoid.
func TestIncludeModeNeverInstallsASplitDefault(t *testing.T) {
	f := newFakeOS()
	tn, err := startForTest(t, f, testPolicy(false, BypassModeInclude, []string{"198.51.100.0/24"}))
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}
	t.Cleanup(tn.Close)

	ops := f.seq()
	if i := indexOf(ops, "splitDefault"); i >= 0 {
		t.Errorf("include mode installed a split-default route (issue #64): everything not in the include set would loop back into the tunnel\nsequence: %v", ops)
	}
	if indexOf(ops, "include 198.51.100.0/24") < 0 {
		t.Errorf("include mode never routed its include set into the tunnel adapter, so nothing would be captured at all\nsequence: %v", ops)
	}
	// The control plane is still excluded in include mode — it is excluded
	// "in both modes" precisely because the tunnel's own signalling must
	// never depend on which mode the user picked.
	if indexOf(ops, "exclude 192.0.2.10") < 0 {
		t.Errorf("include mode skipped the control-plane exclusions\nsequence: %v", ops)
	}
}

// TestCloseRestoresEgressBeforeRemovingTheTunnel is ADR-0014's teardown rule,
// and tunnel.Close's own doc: the kill-switch is lifted FIRST, so egress is
// restored before the thing that was carrying it goes away. Reversed, the
// machine spends the teardown fail-closed over a tunnel that no longer
// exists.
func TestCloseRestoresEgressBeforeRemovingTheTunnel(t *testing.T) {
	f := newFakeOS()
	tn, err := startForTest(t, f, testPolicy(true, BypassModeExclude, nil))
	if err != nil {
		t.Fatalf("startTunnel: %v", err)
	}

	f.mu.Lock()
	f.ops = nil // isolate the teardown sequence
	f.mu.Unlock()
	tn.Close()

	ops := f.seq()
	mustBefore(t, ops, "disableKillSwitch", "remove",
		"egress has to be restored before the routes carrying it are torn down (ADR-0014)")
	mustBefore(t, ops, "disableKillSwitch", "enableIPv6",
		"the lockdown is lifted first, then the adapter state is restored")
	for _, prefix := range []string{"192.0.2.10", "192.0.2.11", "192.0.2.12"} {
		if indexOf(ops, "remove "+prefix) < 0 {
			t.Errorf("Close left the exclusion route for %s behind\nsequence: %v", prefix, ops)
		}
	}
	if !f.dev.isClosed() {
		t.Error("Close left the TUN device open")
	}
}
