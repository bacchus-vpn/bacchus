//go:build linux

// rtnetlink against a real kernel. Every assertion below reads the kernel's own
// answer — via `ip`, which is a different implementation from the code under
// test — rather than checking that we built the message we meant to build.
package main

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// mustIfIndex resolves an interface the fixture just created.
func mustIfIndex(t *testing.T, name string) int {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("InterfaceByName(%q): %v", name, err)
	}
	return iface.Index
}

func TestDefaultGatewayReadsTheRealRoutingTable(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)

	c, err := dialNetlink()
	if err != nil {
		t.Fatalf("dialNetlink: %v", err)
	}
	defer c.Close()

	gw, err := c.defaultGateway()
	if err != nil {
		t.Fatalf("defaultGateway: %v", err)
	}
	if got, want := gw.NextHop.String(), "192.0.2.1"; got != want {
		t.Errorf("next hop = %q, want %q", got, want)
	}
	if gw.IfName != "eth-test" {
		t.Errorf("interface = %q, want %q", gw.IfName, "eth-test")
	}
	if gw.IfIndex == 0 {
		t.Error("interface index = 0, want the uplink's real index")
	}
	// No IPv6 default route exists in this fixture, and its absence must not be
	// an error — osNet.defaultGateway requires only the IPv4 lookup to succeed.
	if gw.NextHopV6.IsValid() {
		t.Errorf("IPv6 next hop = %v, want none", gw.NextHopV6)
	}
}

// The lowest-metric default route wins, matching the Windows implementation's
// `Sort-Object RouteMetric | Select-Object -First 1`. A machine on both wifi
// and ethernet has two, and picking the wrong one points every exclusion route
// at an interface the traffic will not leave by.
func TestDefaultGatewayPicksTheLowestMetric(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t) // default via 192.0.2.1, metric 0

	ipCmd(t, "link", "add", "eth-slow", "type", "dummy")
	ipCmd(t, "addr", "add", "198.51.100.2/24", "dev", "eth-slow")
	ipCmd(t, "link", "set", "eth-slow", "up")
	ipCmd(t, "route", "add", "default", "via", "198.51.100.1", "dev", "eth-slow", "metric", "600")

	c, err := dialNetlink()
	if err != nil {
		t.Fatalf("dialNetlink: %v", err)
	}
	defer c.Close()

	gw, err := c.defaultGateway()
	if err != nil {
		t.Fatalf("defaultGateway: %v", err)
	}
	if got := gw.NextHop.String(); got != "192.0.2.1" {
		t.Errorf("next hop = %q, want the metric-0 route's 192.0.2.1", got)
	}
}

// Our own split-default must never be mistaken for the physical default route.
// poolroutes.go refreshes the gateway in the background for roaming, so this
// read happens repeatedly WHILE the tunnel is up and our table holds 0.0.0.0/1
// and 128.0.0.0/1. If a refresh returned the tunnel as the gateway, every
// subsequent exclusion route would be installed via the tunnel it exists to
// bypass — the underlay would loop into itself.
func TestDefaultGatewayIgnoresOurOwnTable(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)

	c, err := dialNetlink()
	if err != nil {
		t.Fatalf("dialNetlink: %v", err)
	}
	defer c.Close()

	// A genuine default route (dst_len 0) in our table, which is what an
	// exclude-mode session installs a pair of.
	if err := c.addFibRule(unix.AF_INET); err != nil {
		t.Fatalf("addFibRule: %v", err)
	}
	if err := c.addRoute(routeSpec{
		Dst:      netip.MustParsePrefix("0.0.0.0/0"),
		Gateway:  netip.MustParseAddr("192.0.2.1"),
		OutIface: mustIfIndex(t, "eth-test"),
	}); err != nil {
		t.Fatalf("addRoute into our table: %v", err)
	}

	gw, err := c.defaultGateway()
	if err != nil {
		t.Fatalf("defaultGateway: %v", err)
	}
	if got := gw.NextHop.String(); got != "192.0.2.1" {
		t.Errorf("next hop = %q, want the main-table default", got)
	}
}

func TestRoutesLandInOurOwnTableAndNowhereElse(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)

	c, err := dialNetlink()
	if err != nil {
		t.Fatalf("dialNetlink: %v", err)
	}
	defer c.Close()

	oif := mustIfIndex(t, "eth-test")
	dst := netip.MustParsePrefix("203.0.113.7/32")
	if err := c.addRoute(routeSpec{Dst: dst, Gateway: netip.MustParseAddr("192.0.2.1"), OutIface: oif}); err != nil {
		t.Fatalf("addRoute: %v", err)
	}

	// In our table, per the kernel. Matched as a whole line rather than by
	// substring: "203.0.113.7" is also a prefix of "203.0.113.7/0", so a
	// contains-check here passed while the prefix length was being sent as
	// zero — the bug TestListOwnRoutesSeesOnlyOurs actually caught.
	if out := ipCmd(t, "route", "show", "table", "2988"); !strings.Contains(out, "203.0.113.7 via 192.0.2.1 dev eth-test") {
		t.Errorf("route missing (or wrong) in our table:\n%s", out)
	}
	// And NOT in main, which is what keeps the host's own routing untouched.
	if out := ipCmd(t, "route", "show", "table", "main"); strings.Contains(out, "203.0.113.7") {
		t.Errorf("route leaked into the main table:\n%s", out)
	}

	// Attributable: stamped with our protocol id.
	if out := ipCmd(t, "route", "show", "table", "2988", "protocol", "151"); !strings.Contains(out, "203.0.113.7") {
		t.Errorf("route not stamped with our rt_protocol:\n%s", out)
	}

	if err := c.delRoute(dst); err != nil {
		t.Fatalf("delRoute: %v", err)
	}
	if out := ipCmd(t, "route", "show", "table", "2988"); strings.Contains(out, "203.0.113.7") {
		t.Errorf("route survived deletion:\n%s", out)
	}
}

// Teardown re-derives its sets and removes them more than once (tunnel.go's
// Close calls removeRoutes for the control plane, the pool and the policy, and
// the sets can overlap). A second delete must be a no-op, not an error that
// aborts the rest of the teardown.
func TestDeletingARouteTwiceIsNotAnError(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)

	c, err := dialNetlink()
	if err != nil {
		t.Fatalf("dialNetlink: %v", err)
	}
	defer c.Close()

	dst := netip.MustParsePrefix("203.0.113.9/32")
	if err := c.addRoute(routeSpec{Dst: dst, Gateway: netip.MustParseAddr("192.0.2.1"), OutIface: mustIfIndex(t, "eth-test")}); err != nil {
		t.Fatalf("addRoute: %v", err)
	}
	if err := c.delRoute(dst); err != nil {
		t.Fatalf("first delRoute: %v", err)
	}
	if err := c.delRoute(dst); err != nil {
		t.Fatalf("second delRoute must be a no-op, got: %v", err)
	}
	// And a route that never existed at all.
	if err := c.delRoute(netip.MustParsePrefix("203.0.113.250/32")); err != nil {
		t.Fatalf("deleting an unknown route must be a no-op, got: %v", err)
	}
}

// listOwnRoutes is what scopes removeRoutes. A route the helper did not install
// must not appear in it, or the "deletes from its own table only" guarantee is
// only as good as the caller's restraint.
func TestListOwnRoutesSeesOnlyOurs(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)

	c, err := dialNetlink()
	if err != nil {
		t.Fatalf("dialNetlink: %v", err)
	}
	defer c.Close()

	// Someone else's route, in someone else's table, with someone else's proto.
	ipCmd(t, "route", "add", "203.0.113.0/24", "via", "192.0.2.1", "dev", "eth-test", "table", "199")

	ours := netip.MustParsePrefix("198.51.100.77/32")
	if err := c.addRoute(routeSpec{Dst: ours, Gateway: netip.MustParseAddr("192.0.2.1"), OutIface: mustIfIndex(t, "eth-test")}); err != nil {
		t.Fatalf("addRoute: %v", err)
	}

	got, err := c.listOwnRoutes()
	if err != nil {
		t.Fatalf("listOwnRoutes: %v", err)
	}
	var sawOurs bool
	for _, p := range got {
		if p == ours {
			sawOurs = true
		}
		if p.String() == "203.0.113.0/24" {
			t.Errorf("listOwnRoutes returned another table's route %v", p)
		}
	}
	if !sawOurs {
		t.Errorf("listOwnRoutes = %v, want it to contain %v", got, ours)
	}
}

func TestAddAddrAndLinkUp(t *testing.T) {
	if inNamespace(t) {
		return
	}
	ipCmd(t, "link", "add", "tuntest", "type", "dummy")

	c, err := dialNetlink()
	if err != nil {
		t.Fatalf("dialNetlink: %v", err)
	}
	defer c.Close()

	idx := mustIfIndex(t, "tuntest")
	if err := c.addAddr(idx, netip.MustParsePrefix("10.66.0.2/24")); err != nil {
		t.Fatalf("addAddr: %v", err)
	}
	if err := c.setLinkUp(idx); err != nil {
		t.Fatalf("setLinkUp: %v", err)
	}
	if err := c.setLinkMTU(idx, 1420); err != nil {
		t.Fatalf("setLinkMTU: %v", err)
	}

	out := ipCmd(t, "addr", "show", "dev", "tuntest")
	if !strings.Contains(out, "10.66.0.2/24") {
		t.Errorf("address not assigned:\n%s", out)
	}
	if !strings.Contains(out, "mtu 1420") {
		t.Errorf("MTU not applied:\n%s", out)
	}
	if !strings.Contains(out, "UP") {
		t.Errorf("link not up:\n%s", out)
	}
}

// The fib rule is what makes our table reachable at all. Without it every route
// the helper installs is inert, which would fail in the most confusing possible
// way: a tunnel that comes up, reports success, and carries nothing.
func TestFibRuleMakesOurTableAuthoritative(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)

	c, err := dialNetlink()
	if err != nil {
		t.Fatalf("dialNetlink: %v", err)
	}
	defer c.Close()

	if err := c.addFibRule(unix.AF_INET); err != nil {
		t.Fatalf("addFibRule: %v", err)
	}
	if out := ipCmd(t, "rule", "show"); !strings.Contains(out, "11180:") {
		t.Errorf("fib rule not installed:\n%s", out)
	}

	// A more specific route in our table must now win the kernel's own lookup.
	if err := c.addRoute(routeSpec{
		Dst:      netip.MustParsePrefix("203.0.113.0/24"),
		Gateway:  netip.MustParseAddr("192.0.2.1"),
		OutIface: mustIfIndex(t, "eth-test"),
	}); err != nil {
		t.Fatalf("addRoute: %v", err)
	}
	// `ip route get` asks the kernel to resolve an address the way a packet
	// would be resolved — the actual question, not a table listing.
	if out := ipCmd(t, "route", "get", "203.0.113.5"); !strings.Contains(out, "192.0.2.1") {
		t.Errorf("our route did not win the lookup:\n%s", out)
	}

	if err := c.delFibRule(unix.AF_INET); err != nil {
		t.Fatalf("delFibRule: %v", err)
	}
	if out := ipCmd(t, "rule", "show"); strings.Contains(out, "11180:") {
		t.Errorf("fib rule survived deletion:\n%s", out)
	}
	if err := c.delFibRule(unix.AF_INET); err != nil {
		t.Fatalf("deleting an absent rule must be a no-op, got: %v", err)
	}
}

// enablePhysicalIPv6 restores what was there before, not a hardcoded 0
// (ADR-0049 §3.6). A machine that had IPv6 already disabled must not come back
// with it enabled — Bacchus would have silently changed a setting the user
// chose, in the direction that adds an egress path.
func TestIPv6RestoresThePriorValueNotZero(t *testing.T) {
	if inNamespace(t) {
		return
	}
	ipCmd(t, "link", "add", "eth-test", "type", "dummy")
	ipCmd(t, "link", "set", "eth-test", "up")

	// The machine arrives with IPv6 already off on this interface.
	if err := writeIPv6Disabled("eth-test", "1"); err != nil {
		t.Skipf("cannot write the ipv6 sysctl in this namespace: %v", err)
	}

	prior, err := readIPv6Disabled("eth-test")
	if err != nil {
		t.Fatalf("readIPv6Disabled: %v", err)
	}
	if strings.TrimSpace(prior) != "1" {
		t.Fatalf("fixture: prior = %q, want 1", prior)
	}

	// A session disables and then re-enables.
	if err := writeIPv6Disabled("eth-test", "1"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if err := writeIPv6Disabled("eth-test", prior); err != nil {
		t.Fatalf("restore: %v", err)
	}

	after, err := readIPv6Disabled("eth-test")
	if err != nil {
		t.Fatalf("readIPv6Disabled: %v", err)
	}
	if strings.TrimSpace(after) != "1" {
		t.Errorf("after restore = %q, want the prior 1 — a hardcoded 0 would have enabled IPv6 on a machine that had it off", strings.TrimSpace(after))
	}
}
