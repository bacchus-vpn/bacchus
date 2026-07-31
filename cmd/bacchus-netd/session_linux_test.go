//go:build linux

// A whole session, end to end, against a real kernel — and the two assertions
// the existing traffic test cannot reach.
//
// clients/internal/enforcement/traffic_test.go is parity item 8 as it can be
// asked on Windows: a real byte through a real exit, over a SIMULATED TUN
// (memtun_test.go), which is what lets it run unelevated on every push. Its
// file doc is careful about the resulting gap — "Not covered: whether the OS
// actually hands this device the packets in the first place, which is the route
// table's job."
//
// That gap is exactly what a network namespace closes, and it is the reason
// ADR-0049 says a netns is valuable as a test harness even though it is useless
// as a split-tunnel mechanism. Here the TUN is real, the routes are real, and
// the question asked is the one no Go test on Windows can ask: given the routes
// this helper installed, does the kernel actually deliver a packet into the
// tunnel device, and does the armed kill-switch actually stop one leaving?
package main

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bacchus-vpn/bacchus/cmd/bacchus-netd/netdwire"
)

// bringUp runs the same sequence tunnel.go's startTunnel runs, over the real
// protocol, and returns the TUN descriptor the helper passed back.
//
// Deliberately in the order tunnel.go uses. The helper must not own bring-up
// order — that ordering is pinned by tunnel_test.go against a fake osNet and
// Linux inherits it — so this test drives the order from outside, the way the
// portable code does.
func bringUp(t *testing.T, c *net.UnixConn, token string) int {
	t.Helper()

	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbDefaultGateway, Token: token}); !rep.OK {
		t.Fatalf("default-gateway: %s", rep.Error)
	}

	// createTUN's reply carries a descriptor out of band, so it needs the
	// fd-aware read rather than send().
	if err := netdwire.WriteFrame(c, &netdwire.Request{
		Version: netdwire.Version, Verb: netdwire.VerbCreateTUN, Token: token,
	}); err != nil {
		t.Fatalf("write create-tun: %v", err)
	}
	rep, fd, err := netdwire.ReadReplyWithFD(c)
	if err != nil {
		t.Fatalf("read create-tun reply: %v", err)
	}
	if !rep.OK {
		t.Fatalf("create-tun: %s", rep.Error)
	}
	if fd < 0 {
		t.Fatal("create-tun succeeded but sent no descriptor")
	}
	t.Cleanup(func() { unix.Close(fd) })

	if rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbConfigureTUN, Token: token, Addr: "10.66.0.2", PrefixLen: 24,
	}); !rep.OK {
		t.Fatalf("configure-tun: %s", rep.Error)
	}
	return fd
}

// The descriptor crosses the boundary and is usable by its receiver. This is
// ADR-0049 §5's whole claim, and the correction recorded in tundev.go: the
// device is created without IFF_VNET_HDR and its MTU is set by the helper, so
// the receiving side needs no capability at all.
func TestTUNDescriptorCrossesTheBoundaryUsable(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)
	fd := bringUp(t, c, token)

	// The interface exists, is up, and carries the address and MTU the helper
	// gave it — none of which the receiver could have done for itself.
	out := ipCmd(t, "addr", "show", "dev", tunName)
	for _, want := range []string{"10.66.0.2/24", "mtu 1420", "UP"} {
		if !strings.Contains(out, want) {
			t.Errorf("TUN device is missing %q:\n%s", want, out)
		}
	}

	// And the descriptor is a working one: writing a packet into it succeeds.
	// This is the half that failed before the IFF_VNET_HDR correction — with
	// that flag set, wireguard-go's Write rejects tun2socks.go's offset of 0
	// outright, so every outbound packet would have been dropped with "invalid
	// offset" while every state-level check stayed green.
	if _, err := unix.Write(fd, syntheticIPv4UDP(t, "10.66.0.2", "10.66.0.1", 5000, 5001)); err != nil {
		t.Errorf("writing to the received descriptor: %v", err)
	}
}

// THE test this lane exists to be able to write. With the split-default
// installed, a packet the machine sends to an arbitrary destination must be
// delivered by the KERNEL into the tunnel device.
//
// Nothing about this is assertable on Windows: routes_windows.go's calls go
// through PowerShell and the tests there can only check that the right cmdlets
// were invoked in the right order (ADR-0039's amendment records the live
// elevated run as outstanding, and #88 still holds it). Here the assertion is
// the packet itself.
func TestSplitDefaultActuallyCapturesTrafficIntoTheTun(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)
	fd := bringUp(t, c, token)

	if rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbAddSplitDefaultRoute, Token: token, Addr: "10.66.0.2",
	}); !rep.OK {
		t.Fatalf("add-split-default-route: %s", rep.Error)
	}

	// The kernel's own answer about where this destination goes.
	if out := ipCmd(t, "route", "get", "203.0.113.5"); !strings.Contains(out, tunName) {
		t.Fatalf("the kernel does not route 203.0.113.5 into %s:\n%s", tunName, out)
	}

	// Now the real question: send a datagram and watch it arrive on the device.
	got := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := unix.Read(fd, buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			got <- pkt
		}
	}()

	conn, err := net.Dial("udp", "203.0.113.5:9999")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("captured?")); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.After(3 * time.Second)
	for {
		select {
		case pkt := <-got:
			dst, ok := ipv4Dst(pkt)
			if !ok {
				continue // IPv6 RA/MLD chatter from bringing the link up
			}
			if dst == netip.MustParseAddr("203.0.113.5") {
				return // the packet reached the tunnel device
			}
		case <-deadline:
			t.Fatal("no packet for 203.0.113.5 arrived on the TUN device: the routes are installed but the kernel is not delivering into the tunnel")
		}
	}
}

// Parity item 8's leak half, at the level a namespace can prove: with the
// kill-switch armed, a packet to a destination that is not allow-listed must
// not leave the physical interface — and one that is allow-listed must.
//
// The memtun traffic test cannot ask this. It has no firewall and no real
// interface; it can prove the netstack drops rather than falls back, which is a
// different and also necessary property. This proves the OS-level filter that
// is supposed to hold when the process is gone.
func TestArmedKillSwitchBlocksUnlistedEgressAndPermitsListed(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)
	_ = bringUp(t, c, token)

	// Allow one control-plane address, exactly as a session would.
	if rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbEnableKillSwitch, Token: token,
		Control: []string{"192.0.2.50"},
	}); !rep.OK {
		t.Fatalf("enable-kill-switch: %s", rep.Error)
	}

	// Not allow-listed: the kernel refuses to send it. A locally-generated
	// packet meeting an nftables drop returns EPERM to the sending socket,
	// which is the observable form of "it did not leave".
	if err := sendUDPTo(t, "198.51.100.77:9999"); err == nil {
		t.Error("a packet to an unlisted address left the machine with the kill-switch armed")
	}

	// Allow-listed: it goes.
	if err := sendUDPTo(t, "192.0.2.50:9999"); err != nil {
		t.Errorf("a packet to an ALLOW-LISTED address was blocked: %v — the lockdown would take the session's own control plane down with it", err)
	}

	// A late-learned bypass address becomes permitted without any rule being
	// rebuilt (ADR-0049 §8), so there is no window in which the addresses this
	// allowlist covers are uncovered.
	if rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbRefreshAllowIP, Token: token, IP: "198.51.100.77",
	}); !rep.OK {
		t.Fatalf("refresh-kill-switch-allow-ip: %s", rep.Error)
	}
	if err := sendUDPTo(t, "198.51.100.77:9999"); err != nil {
		t.Errorf("a freshly learned bypass address is still blocked: %v", err)
	}
}

// The lockdown must survive the client dying. That is parity item 2's whole
// point and ADR-0049 §8's ruling: the helper marks the session orphaned and
// KEEPS the filter, because a killed client is exactly the case a kill-switch
// exists for. A helper that tidied up on disconnect would lift the protection
// at the moment it is most needed.
func TestLockdownSurvivesTheClientDisconnecting(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	path := startHelper(t)
	c := dialHelper(t, path)
	token := open(t, c)
	_ = bringUp(t, c, token)

	if rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbEnableKillSwitch, Token: token, Control: []string{"192.0.2.50"},
	}); !rep.OK {
		t.Fatalf("enable-kill-switch: %s", rep.Error)
	}

	// The client dies without saying anything: close the connection outright.
	c.Close()
	waitFor(t, 2*time.Second, func() bool {
		return strings.Contains(nftCmd(t, "list", "ruleset"), "table inet bacchus")
	})

	if out := nftCmd(t, "list", "ruleset"); !strings.Contains(out, "policy drop") {
		t.Fatalf("the lockdown was lifted when the client died:\n%s", out)
	}
	if err := sendUDPTo(t, "198.51.100.77:9999"); err == nil {
		t.Error("traffic leaked after the client died with the kill-switch armed")
	}

	// And the next client reaps it, which is parity item 3: a user whose last
	// session was killed is offline before they touch anything, so the lockdown
	// has to come off when they next launch.
	next := dialHelper(t, path)
	_ = open(t, next)
	if out := nftCmd(t, "list", "ruleset"); strings.Contains(out, "table inet bacchus") {
		t.Errorf("the next session did not reap the orphaned lockdown:\n%s", out)
	}
}

// A clean disconnect is not a crash, and must not be treated as one: Close
// leaves nothing behind.
func TestCleanCloseLeavesNoState(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)
	_ = bringUp(t, c, token)

	if rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbAddExclusionRoutes, Token: token, Prefixes: []string{"192.0.2.50/32"},
	}); !rep.OK {
		t.Fatalf("add-exclusion-routes: %s", rep.Error)
	}
	if rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbRemoveRoutes, Token: token, Prefixes: []string{"192.0.2.50/32"},
	}); !rep.OK {
		t.Fatalf("remove-routes: %s", rep.Error)
	}
	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbClose, Token: token}); !rep.OK {
		t.Fatalf("close: %s", rep.Error)
	}

	if out := ipCmd(t, "route", "show", "table", "2988"); strings.TrimSpace(out) != "" {
		t.Errorf("routes survived a clean close:\n%s", out)
	}
	if out := nftCmd(t, "list", "ruleset"); strings.Contains(out, "table inet bacchus") {
		t.Errorf("firewall state survived a clean close:\n%s", out)
	}
}

// ADR-0049 §3.6, at the level the client actually reaches it: the helper
// captures the physical interface's prior IPv6 setting and restores THAT, not a
// hardcoded 0. A machine that had IPv6 disabled before Bacchus ran must not come
// back with it enabled — that would be Bacchus silently changing a setting the
// user chose, in the direction that adds an egress path.
//
// Driven through the protocol rather than against writeIPv6Disabled directly,
// because the capture is the part that can be got wrong: the value has to be
// read before the write and kept for the life of the session, and only a
// request-level test sees that.
func TestIPv6IsRestoredToItsCapturedValueThroughTheProtocol(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)

	// This machine arrives with IPv6 already disabled on the uplink.
	if err := writeIPv6Disabled("eth-test", "1"); err != nil {
		t.Skipf("cannot write the ipv6 sysctl in this namespace: %v", err)
	}

	c := dialHelper(t, startHelper(t))
	token := open(t, c)
	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbDefaultGateway, Token: token}); !rep.OK {
		t.Fatalf("default-gateway: %s", rep.Error)
	}

	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbDisablePhysicalIPv6, Token: token}); !rep.OK {
		t.Fatalf("disable-physical-ipv6: %s", rep.Error)
	}
	if got := readIPv6Or(t, "eth-test"); got != "1" {
		t.Errorf("after disable, disable_ipv6 = %q, want 1", got)
	}

	// A second disable in the same session must not overwrite the captured
	// value with our own "1" — tunnel.go can call this more than once, and
	// losing the real prior value here is how the restore silently becomes a
	// hardcoded 0.
	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbDisablePhysicalIPv6, Token: token}); !rep.OK {
		t.Fatalf("second disable-physical-ipv6: %s", rep.Error)
	}

	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbEnablePhysicalIPv6, Token: token}); !rep.OK {
		t.Fatalf("enable-physical-ipv6: %s", rep.Error)
	}
	if got := readIPv6Or(t, "eth-test"); got != "1" {
		t.Errorf("after restore, disable_ipv6 = %q, want the captured 1 — a hardcoded 0 would have enabled IPv6 on a machine that had it off", got)
	}
}

// And the other direction: a machine that had IPv6 enabled gets it back.
func TestIPv6IsReEnabledWhenItStartedEnabled(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	if err := writeIPv6Disabled("eth-test", "0"); err != nil {
		t.Skipf("cannot write the ipv6 sysctl in this namespace: %v", err)
	}

	c := dialHelper(t, startHelper(t))
	token := open(t, c)
	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbDefaultGateway, Token: token}); !rep.OK {
		t.Fatalf("default-gateway: %s", rep.Error)
	}
	// Disabled TWICE, and this is the case that makes the capture rule
	// observable. Starting from "0", a helper that re-captured on each call
	// would read its own "1" the second time and restore that — leaving IPv6
	// off on a machine that had it on, with no error anywhere. Starting from
	// "1" (the test above) both captures agree and the bug is invisible, which
	// is why the two directions are separate tests rather than one.
	for i := 0; i < 2; i++ {
		if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbDisablePhysicalIPv6, Token: token}); !rep.OK {
			t.Fatalf("disable-physical-ipv6 #%d: %s", i+1, rep.Error)
		}
		if got := readIPv6Or(t, "eth-test"); got != "1" {
			t.Fatalf("IPv6 was not disabled for the tunnel's lifetime: %q", got)
		}
	}

	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbEnablePhysicalIPv6, Token: token}); !rep.OK {
		t.Fatalf("enable-physical-ipv6: %s", rep.Error)
	}
	if got := readIPv6Or(t, "eth-test"); got != "0" {
		t.Errorf("after restore, disable_ipv6 = %q, want 0 — the user's IPv6 never came back", got)
	}
}

func readIPv6Or(t *testing.T, ifName string) string {
	t.Helper()
	v, err := readIPv6Disabled(ifName)
	if err != nil {
		t.Fatalf("readIPv6Disabled(%s): %v", ifName, err)
	}
	return strings.TrimSpace(v)
}

// -------------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------------

// sendUDPTo reports whether one datagram could be sent. With an nftables drop
// in the output chain the kernel rejects the send outright, so the error is the
// observation.
func sendUDPTo(t *testing.T, addr string) error {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("leak?"))
	return err
}

// ipv4Dst returns the destination of an IPv4 packet.
func ipv4Dst(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(pkt[16:20])), true
}

// syntheticIPv4UDP builds a minimal well-formed IPv4/UDP packet, to prove a
// descriptor is writable rather than merely open.
func syntheticIPv4UDP(t *testing.T, src, dst string, sport, dport uint16) []byte {
	t.Helper()
	s, err := netip.ParseAddr(src)
	if err != nil {
		t.Fatalf("src: %v", err)
	}
	d, err := netip.ParseAddr(dst)
	if err != nil {
		t.Fatalf("dst: %v", err)
	}
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[2], pkt[3] = 0x00, 28
	pkt[8] = 64               // TTL
	pkt[9] = unix.IPPROTO_UDP //
	copy(pkt[12:16], s.AsSlice())
	copy(pkt[16:20], d.AsSlice())
	pkt[20], pkt[21] = byte(sport>>8), byte(sport)
	pkt[22], pkt[23] = byte(dport>>8), byte(dport)
	pkt[24], pkt[25] = 0x00, 8 // UDP length
	return pkt
}

// waitFor polls until cond holds or the budget runs out. Used where the thing
// being waited on is another goroutine noticing a closed connection.
func waitFor(t *testing.T, budget time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}
