//go:build linux

// The served-egress carve-out (ADR-0053, bacchus#109), asserted at the level
// bacchus#109 asks for: PACKETS, not routing table entries.
//
// The bar the card sets is "served traffic observed leaving the physical
// interface under this machine's own address, while the user's own traffic is
// still in the tunnel and the kill-switch is still armed". Routes and rules
// existing is state; a state-level test here would pass against a carve-out
// that the kernel then declines to apply, and getting this wrong does not
// break the tunnel — it makes the exit opt-in's disclosure false, which is
// worse than the feature being unavailable. So every assertion below reads a
// frame off a wire or a packet out of a TUN.
//
// # The rig
//
//	veth1  <-- an AF_PACKET socket here IS "the wire"
//	  |
//	veth0  192.0.2.2/24, default via 192.0.2.1   <-- "physical"
//	tun-bacchus  10.7.0.1/24, split-default in table 0xBAC  <-- "tunnel"
//
// veth is a pipe: a frame the kernel transmits on veth0 arrives on veth1, so a
// raw socket bound to veth1 observes exactly what left the physical interface,
// with no interpretation in between. The TUN descriptor is held open and read
// the same way, so "went into the tunnel" is also an observed packet rather
// than an inference from a counter.
//
// The peer, 203.0.113.7, is documentation space (RFC 5737) and nothing answers
// for it. That is deliberate: none of these tests needs a completed handshake,
// only the first packet, and a rig that cannot reach anything real is a rig
// that cannot pass by accident.
//
// # What a namespace cannot prove, stated at the same volume
//
// This is a synthetic network. A real desktop has NetworkManager, a physical
// driver, a distribution's own nftables ruleset already loaded, and — the one
// that matters most here — a public address behind a NAT that somebody has to
// have forwarded a port through. Passing these means the mechanism is right on
// this kernel, not that a volunteer's exit is reachable from the internet.
// bacchus#59 and bacchus#107 were honest about exactly this distinction and so
// is this file.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bacchus-vpn/bacchus/cmd/bacchus-netd/netdwire"
)

const (
	physAddr  = "192.0.2.2"
	physCIDR  = "192.0.2.2/24"
	physGW    = "192.0.2.1"
	peerAddr  = "203.0.113.7"
	tunTestIP = "10.7.0.1"
)

// servedRig is one built-up namespace: a physical interface with a wire to
// watch, a tunnel with the split-default installed, and the helper's own
// netlink pool to drive.
type servedRig struct {
	nl     *netlinkPool
	tunFD  int
	wire   *rawWire // AF_PACKET on veth1
	physMA net.HardwareAddr
	peerMA net.HardwareAddr
}

// buildServedRig arranges the world of the diagram above using the helper's OWN
// route and rule primitives for the tunnel half — so what these tests exercise
// is the code that ships, not a re-creation of it with `ip`. The physical half
// is built with `ip`, which keeps the fixture an independent implementation
// from the thing being asserted.
func buildServedRig(t *testing.T) *servedRig {
	t.Helper()

	ipCmd(t, "link", "set", "lo", "up")
	ipCmd(t, "link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
	ipCmd(t, "addr", "add", physCIDR, "dev", "veth0")
	ipCmd(t, "link", "set", "veth0", "up")
	ipCmd(t, "link", "set", "veth1", "up")
	ipCmd(t, "route", "add", "default", "via", physGW, "dev", "veth0")
	// A permanent neighbour entry so an outbound packet is framed and put on
	// the wire immediately. Without it the kernel holds the first packet while
	// it ARPs for a gateway that does not exist, and the test would be
	// asserting on ARP rather than on the thing it is about.
	ipCmd(t, "neigh", "add", physGW, "lladdr", "02:00:00:00:00:01", "dev", "veth0", "nud", "permanent")

	rig := &servedRig{nl: &netlinkPool{}}
	rig.physMA = mustHardwareAddr(t, "veth0")
	rig.peerMA = mustHardwareAddr(t, "veth1")

	fd, tunIndex, err := createTUN(rig.nl)
	if err != nil {
		t.Fatalf("createTUN: %v", err)
	}
	rig.tunFD = fd
	t.Cleanup(func() { closeFD(fd) })

	err = rig.nl.do(func(c *nlConn) error {
		if err := c.addAddr(tunIndex, netip.MustParsePrefix(tunTestIP+"/24")); err != nil {
			return err
		}
		if err := c.setLinkUp(tunIndex); err != nil {
			return err
		}
		// The split-default, in the helper's own table, reached by the helper's
		// own fib rule. This is what makes the tunnel authoritative for
		// everything, and therefore what the carve-out has to get past.
		for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := c.addRoute(routeSpec{Dst: netip.MustParsePrefix(p), OutIface: tunIndex}); err != nil {
				return err
			}
		}
		return c.addFibRule(unix.AF_INET)
	})
	if err != nil {
		t.Fatalf("build the tunnel half: %v", err)
	}

	rig.wire = openRawWire(t, "veth1")
	return rig
}

// carveOut installs the served-egress rule for this process's uid, which is
// what the helper does with the uid SO_PEERCRED gave it.
func (r *servedRig) carveOut(t *testing.T) {
	t.Helper()
	err := r.nl.do(func(c *nlConn) error {
		return c.addServedRule(netip.MustParseAddr(physAddr), uint32(os.Getuid()))
	})
	if err != nil {
		t.Fatalf("addServedRule: %v", err)
	}
}

// arm arms the kill-switch exactly as handleEnableKillSwitch does, with the
// served source folded in when serving is true. Nothing is allow-listed beyond
// what a real session gets, so a packet that gets out here got out through a
// rule this change added rather than through a hole in the fixture.
func (r *servedRig) arm(t *testing.T, serving bool) {
	t.Helper()
	tunIndex := mustIfIndex(t, tunName)
	lo := mustIfIndex(t, "lo")
	spec := killSwitchSpec{TunIfIndex: tunIndex, LoIfIndex: lo}
	if serving {
		spec.ServedSrc = netip.MustParseAddr(physAddr)
	}
	c, err := dialNftables()
	if err != nil {
		t.Fatalf("dialNftables: %v", err)
	}
	defer c.Close()
	if err := c.enableKillSwitch(spec); err != nil {
		t.Fatalf("enableKillSwitch: %v", err)
	}
	t.Cleanup(func() { _ = c.deleteTable() })
}

// -------------------------------------------------------------------------
// The tests
// -------------------------------------------------------------------------

// TestServedTrafficLeavesThePhysicalInterface is bacchus#109's acceptance bar
// in one function, and the three assertions are one claim each:
//
//  1. a served socket's packet is SEEN on the wire, with this machine's own
//     address as its source — the exit disclosure's "under YOUR own IP";
//  2. the same packet is NOT in the tunnel — it is not being carried out under
//     the upstream exit's address;
//  3. an ordinary unbound socket's packet IS in the tunnel and is NOT on the
//     wire — the volunteer's own traffic is still protected.
//
// The kill-switch is armed throughout. Without the nftables half of the
// carve-out the served packet is dropped by the volunteer's own lockdown and
// (1) fails, so this covers both halves rather than only the routing one.
func TestServedTrafficLeavesThePhysicalInterface(t *testing.T) {
	if inNamespace(t) {
		return
	}
	rig := buildServedRig(t)
	rig.carveOut(t)
	rig.arm(t, true)

	// The served dial: a socket that binds this machine's own address, which is
	// what core.Engine.dialServed does when enforcement has handed it a source.
	dialFrom(t, physAddr, peerAddr+":443")

	got := rig.wire.awaitSYN(t, peerAddr, 443)
	if got == nil {
		t.Fatal("no served packet reached the physical interface. " +
			"Other people's traffic is not leaving under this machine's address, which is what the exit opt-in promises")
	}
	if got.src != physAddr {
		t.Errorf("served packet left with source %s, want %s — the disclosure names this machine's address", got.src, physAddr)
	}
	if p := readTUN(t, rig.tunFD, peerAddr, 200*time.Millisecond); p != nil {
		t.Errorf("served packet to %s also entered the tunnel (src %s): it would egress at the UPSTREAM exit's address", peerAddr, p.src)
	}

	// The volunteer's own traffic, to a different destination so the two cannot
	// be confused: an ordinary socket, binding nothing.
	const ownDst = "198.51.100.9"
	dialFrom(t, "", ownDst+":443")

	if p := readTUN(t, rig.tunFD, ownDst, 2*time.Second); p == nil {
		t.Errorf("the volunteer's own packet to %s never entered the tunnel", ownDst)
	}
	if p := rig.wire.awaitSYN(t, ownDst, 443); p != nil {
		t.Errorf("the volunteer's own packet to %s left the physical interface with source %s. "+
			"The carve-out is leaking the user's own traffic out of their tunnel", ownDst, p.src)
	}
}

// TestWithoutTheCarveOutServedTrafficStaysInTheTunnel is the negative control,
// and it is the one that makes the test above mean anything. Same rig, same
// source-bound socket, no fib rule — and the packet must go into the tunnel.
//
// Without this, a rig whose "physical" path happened to work for every packet
// would pass the test above while proving nothing. It also pins the fact that
// binding a source address is NOT by itself a carve-out: the routing rule is
// load bearing, and a change that dropped it would be caught here rather than
// in the field.
func TestWithoutTheCarveOutServedTrafficStaysInTheTunnel(t *testing.T) {
	if inNamespace(t) {
		return
	}
	rig := buildServedRig(t)
	rig.arm(t, false)

	dialFrom(t, physAddr, peerAddr+":443")

	if p := readTUN(t, rig.tunFD, peerAddr, 2*time.Second); p == nil {
		t.Error("a source-bound packet did not enter the tunnel without the carve-out; the rig is not reproducing the problem #109 exists to fix")
	}
	if p := rig.wire.awaitSYN(t, peerAddr, 443); p != nil {
		t.Errorf("a source-bound packet reached the physical interface with no served rule installed (src %s). "+
			"Binding the source is not supposed to be sufficient on its own", p.src)
	}
}

// TestAnAdvertisedExitCanAnswerAnInboundDial is the other half of what made
// serving-while-routed impossible, and it is a different failure from the
// egress one: an exit whose replies follow the default route into the TUN
// registers itself and then serves nobody.
//
// A SYN is injected onto the wire from a peer address that is not local, so the
// reply has to be routed rather than short-circuited through the `local` table.
// The assertion is that the SYN-ACK comes back OUT on the wire under this
// machine's own address — which is only possible if the accepted socket's reply
// took the carve-out.
//
// Note what this proves beyond the egress test: nothing binds the listener to
// physAddr. The reply matches the rule because an inbound connection ARRIVES on
// this machine's address and the accepted socket therefore already has it as
// its local address. That inheritance is a kernel property this asserts rather
// than assumes, and it is why core does not bind its exit listener.
func TestAnAdvertisedExitCanAnswerAnInboundDial(t *testing.T) {
	if inNamespace(t) {
		return
	}
	rig := buildServedRig(t)
	rig.carveOut(t)
	rig.arm(t, true)

	// The wildcard listener core.Engine.Start opens for the exit role.
	ln, err := net.Listen("tcp", ":20000")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	rig.wire.injectSYN(t, rig.peerMA, rig.physMA, peerAddr, physAddr, 41234, 20000)

	rep := rig.wire.awaitFrom(t, physAddr, peerAddr, 20000)
	if rep == nil {
		t.Fatal("the advertised exit never answered an inbound dial on the physical interface. " +
			"It would register as an exit and serve nobody, which is the silent under-registration validateVolunteer exists to refuse")
	}
	if !rep.syn || !rep.ack {
		t.Errorf("reply flags syn=%v ack=%v, want a SYN-ACK", rep.syn, rep.ack)
	}
}

// TestRevokingTheCarveOutPutsTheTrafficBack drives the disconnect path: after
// revoke, a served socket's packet must be back in the tunnel.
//
// This is the property the crash path depends on (ADR-0053 §5). The helper
// drops the carve-out when a client dies while deliberately HOLDING the
// kill-switch, and "drops" has to mean the traffic actually stops taking it,
// not that a rule was deleted somewhere.
func TestRevokingTheCarveOutPutsTheTrafficBack(t *testing.T) {
	if inNamespace(t) {
		return
	}
	rig := buildServedRig(t)
	rig.carveOut(t)
	rig.arm(t, true)

	if err := rig.nl.do(func(c *nlConn) error { return c.delServedRule() }); err != nil {
		t.Fatalf("delServedRule: %v", err)
	}
	if out := ipCmd(t, "rule", "show"); strings.Contains(out, physAddr) {
		t.Errorf("the served rule survived its own removal:\n%s", out)
	}

	dialFrom(t, physAddr, peerAddr+":443")
	if p := rig.wire.awaitSYN(t, peerAddr, 443); p != nil {
		t.Errorf("served traffic still left the physical interface after the carve-out was revoked (src %s)", p.src)
	}
}

// TestTheCarveOutIsScopedToTheClientsUid asserts the narrowing the uid selector
// buys, using the kernel's own route resolution for a uid this test cannot
// actually run as.
//
// This one is deliberately not a packet test, and the reason is a limit rather
// than a preference: becoming another uid inside the namespace would need a
// second mapped uid and a fork, and what would be proved is a routing decision
// the kernel will state directly. `ip route get ... uid N` asks it for exactly
// the lookup it would perform for that user's socket.
//
// What it pins is ADR-0053 §4's bound on the blast radius: the carve-out
// reaches processes of the VOLUNTEERING user that bind this address, and not
// every process on the machine.
func TestTheCarveOutIsScopedToTheClientsUid(t *testing.T) {
	if inNamespace(t) {
		return
	}
	rig := buildServedRig(t)
	rig.carveOut(t)

	mine := ipCmd(t, "route", "get", peerAddr, "from", physAddr, "uid", fmt.Sprint(os.Getuid()))
	if !strings.Contains(mine, "veth0") {
		t.Errorf("this uid's served lookup did not resolve to the physical interface:\n%s", mine)
	}
	other := ipCmd(t, "route", "get", peerAddr, "from", physAddr, "uid", "31337")
	if strings.Contains(other, "veth0") {
		t.Errorf("another uid binding this machine's address took the carve-out too:\n%s", other)
	}
	if !strings.Contains(other, tunName) {
		t.Errorf("another uid's lookup did not stay in the tunnel:\n%s", other)
	}
}

// -------------------------------------------------------------------------
// The protocol's own rules, over the real socket
// -------------------------------------------------------------------------

// TestAllowServedEgressNamesTheAddressToBind is ADR-0053 §3's whole wire
// contract in one assertion: nothing crosses inward, and what comes back is the
// address core has to bind.
//
// The empty request matters as much as the reply. Every obvious encoding of a
// carve-out would have widened ADR-0049 §2's inward vocabulary — a firewall
// mark, a table id, a source address, a uid — and none of them does, because
// the helper derives all four itself.
func TestAllowServedEgressNamesTheAddressToBind(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)

	rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbAllowServedEgress, Token: token})
	if !rep.OK {
		t.Fatalf("allow-served-egress: %s", rep.Error)
	}
	if rep.ServedSource != physAddr {
		t.Errorf("ServedSource = %q, want %q — this is the address core binds, and a wrong one serves through the tunnel", rep.ServedSource, physAddr)
	}
	if out := ipCmd(t, "rule", "show"); !strings.Contains(out, physAddr) {
		t.Errorf("no served rule was installed:\n%s", out)
	}
}

// TestServedEgressIsRefusedAfterTheKillSwitchIsArmed pins the ordering
// constraint the helper enforces rather than silently reorders.
//
// The filter allowance is built into the same transaction as the drop policy,
// so a lockdown armed without one has no set for a later carve-out to add
// itself to. Granting the routing half anyway would produce an exit that is
// advertised, routed, and silently unable to answer, because its own kill-
// switch drops what it serves. A refusal says so.
func TestServedEgressIsRefusedAfterTheKillSwitchIsArmed(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)
	_ = bringUp(t, c, token)

	if rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbEnableKillSwitch, Token: token, Control: []string{"192.0.2.50"},
	}); !rep.OK {
		t.Fatalf("enable-kill-switch: %s", rep.Error)
	}

	rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbAllowServedEgress, Token: token})
	if rep.OK {
		t.Fatal("the helper granted a carve-out after arming. The route would exist and the lockdown would drop every packet that took it")
	}
	if rep.Code != netdwire.CodeBadRequest {
		t.Errorf("refusal code = %q, want %q", rep.Code, netdwire.CodeBadRequest)
	}
	if out := ipCmd(t, "rule", "show"); strings.Contains(out, physAddr) {
		t.Errorf("a refused carve-out installed its rule anyway:\n%s", out)
	}
}

// TestTheCarveOutIsDroppedWhenTheClientDiesButTheLockdownIsHeld is ADR-0053
// §5's asymmetry, and it is the test that would catch someone "fixing" the
// inconsistency by making both halves behave the same.
//
// A client that dies HOLDS the kill-switch, because holding it fails closed —
// that is ADR-0049 §8 and TestLockdownSurvivesTheClientDisconnecting pins it.
// The carve-out goes the other way for the same underlying rule: the process
// that was serving is dead, so nothing needs it, and an allowance nobody is
// using is a hole in a lockdown that is otherwise being kept deliberately.
func TestTheCarveOutIsDroppedWhenTheClientDiesButTheLockdownIsHeld(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)
	_ = bringUp(t, c, token)

	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbAllowServedEgress, Token: token}); !rep.OK {
		t.Fatalf("allow-served-egress: %s", rep.Error)
	}
	if rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbEnableKillSwitch, Token: token, Control: []string{"192.0.2.50"},
	}); !rep.OK {
		t.Fatalf("enable-kill-switch: %s", rep.Error)
	}

	// The client dies without saying anything.
	c.Close()
	waitFor(t, 2*time.Second, func() bool {
		return !strings.Contains(ipCmd(t, "rule", "show"), physAddr)
	})

	if out := ipCmd(t, "rule", "show"); strings.Contains(out, physAddr) {
		t.Errorf("the carve-out outlived the client that asked for it:\n%s", out)
	}
	// The other half of the asymmetry, asserted in the same test so the two
	// cannot drift into agreeing with each other.
	if out := nftCmd(t, "list", "ruleset"); !strings.Contains(out, "policy drop") {
		t.Errorf("the lockdown was lifted when the client died; only the carve-out should have been:\n%s", out)
	}
}

// -------------------------------------------------------------------------
// Rig plumbing: raw frames, and reading the tunnel
// -------------------------------------------------------------------------

// pkt is the handful of fields these tests assert on.
type pkt struct {
	src, dst string
	sport    uint16
	dport    uint16
	syn, ack bool
}

// rawWire is an AF_PACKET socket on one interface: what actually crossed it.
type rawWire struct {
	fd int
}

func openRawWire(t *testing.T, ifname string) *rawWire {
	t.Helper()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Fatalf("AF_PACKET socket: %v", err)
	}
	idx := mustIfIndex(t, ifname)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  idx,
	}); err != nil {
		unix.Close(fd)
		t.Fatalf("bind AF_PACKET to %s: %v", ifname, err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return &rawWire{fd: fd}
}

// awaitSYN waits for a TCP packet to dst:dport, or returns nil once the wire
// has gone quiet. Both outcomes are assertions somewhere above, so the timeout
// is generous where a packet is expected and the caller passes a destination
// nothing else in the rig uses.
func (w *rawWire) awaitSYN(t *testing.T, dst string, dport uint16) *pkt {
	t.Helper()
	return w.await(t, func(p *pkt) bool { return p.dst == dst && p.dport == dport }, 2*time.Second)
}

// awaitFrom waits for a packet FROM src to dst with the given source port —
// the reply direction.
func (w *rawWire) awaitFrom(t *testing.T, src, dst string, sport uint16) *pkt {
	t.Helper()
	return w.await(t, func(p *pkt) bool {
		return p.src == src && p.dst == dst && p.sport == sport
	}, 2*time.Second)
}

func (w *rawWire) await(t *testing.T, match func(*pkt) bool, timeout time.Duration) *pkt {
	t.Helper()
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for {
		n, err := readUntil(w.fd, buf, deadline)
		if err != nil {
			t.Fatalf("read from the wire: %v", err)
		}
		if n == 0 {
			return nil
		}
		// 14 bytes of Ethernet, then IPv4.
		if n < 14 || binary.BigEndian.Uint16(buf[12:14]) != unix.ETH_P_IP {
			continue
		}
		if p := parseIPv4TCP(buf[14:n]); p != nil && match(p) {
			return p
		}
	}
}

// injectSYN puts a TCP SYN on the wire as if it had come from a remote peer.
func (w *rawWire) injectSYN(t *testing.T, srcMAC, dstMAC net.HardwareAddr, src, dst string, sport, dport uint16) {
	t.Helper()
	frame := append(append(append([]byte{}, dstMAC...), srcMAC...), 0x08, 0x00)
	frame = append(frame, buildSYN(src, dst, sport, dport)...)
	if err := unix.Sendto(w.fd, frame, 0, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  mustIfIndex(t, "veth1"),
		Halen:    6,
		Addr:     [8]byte{dstMAC[0], dstMAC[1], dstMAC[2], dstMAC[3], dstMAC[4], dstMAC[5]},
	}); err != nil {
		t.Fatalf("inject a SYN: %v", err)
	}
}

// readTUN reads packets out of the tunnel device until one is bound for dst.
// Returns nil on timeout, which is an assertion in both directions above.
func readTUN(t *testing.T, fd int, dst string, timeout time.Duration) *pkt {
	t.Helper()
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 2048)
	for {
		n, err := readUntil(fd, buf, deadline)
		if err != nil {
			t.Fatalf("read from the tunnel: %v", err)
		}
		if n == 0 {
			return nil
		}
		// IFF_NO_PI, so what is read is the bare IP packet.
		if p := parseIPv4TCP(buf[:n]); p != nil && p.dst == dst {
			return p
		}
	}
}

// dialFrom opens one TCP connection, binding src as the source address when it
// is non-empty. The dial is expected to fail — nothing answers in this rig —
// and the packet it emitted on the way is the whole point.
func dialFrom(t *testing.T, src, dst string) {
	t.Helper()
	d := net.Dialer{Timeout: 300 * time.Millisecond}
	if src != "" {
		d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
	}
	if c, err := d.Dial("tcp", dst); err == nil {
		c.Close()
	}
}

func parseIPv4TCP(b []byte) *pkt {
	if len(b) < 20 || b[0]>>4 != 4 || b[9] != unix.IPPROTO_TCP {
		return nil
	}
	ihl := int(b[0]&0x0f) * 4
	if len(b) < ihl+14 {
		return nil
	}
	tcp := b[ihl:]
	flags := tcp[13]
	return &pkt{
		src:   net.IP(b[12:16]).String(),
		dst:   net.IP(b[16:20]).String(),
		sport: binary.BigEndian.Uint16(tcp[0:2]),
		dport: binary.BigEndian.Uint16(tcp[2:4]),
		syn:   flags&0x02 != 0,
		ack:   flags&0x10 != 0,
	}
}

// buildSYN assembles a minimal IPv4+TCP SYN with both checksums, because the
// kernel drops a packet whose checksums do not add up and a test whose injected
// SYN is silently discarded would look exactly like an exit that cannot answer.
func buildSYN(src, dst string, sport, dport uint16) []byte {
	s, d := net.ParseIP(src).To4(), net.ParseIP(dst).To4()

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], 0x1000)
	tcp[12] = 5 << 4 // data offset, no options
	tcp[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240)

	pseudo := make([]byte, 0, 12+len(tcp))
	pseudo = append(pseudo, s...)
	pseudo = append(pseudo, d...)
	pseudo = append(pseudo, 0, unix.IPPROTO_TCP, 0, byte(len(tcp)))
	pseudo = append(pseudo, tcp...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = unix.IPPROTO_TCP
	copy(ip[12:16], s)
	copy(ip[16:20], d)
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip))

	return append(ip, tcp...)
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// readUntil reads one message from fd, waiting no longer than deadline, and
// reports n == 0 when the deadline passed with nothing to read.
//
// poll(2) rather than SO_RCVTIMEO, because one of the two descriptors these
// tests read is a TUN character device and not a socket at all — setsockopt on
// it fails with ENOTSOCK. poll works on both, so there is one path rather than
// two.
func readUntil(fd int, buf []byte, deadline time.Time) (int, error) {
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return 0, nil
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, int(left.Milliseconds())+1)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, err
		}
		if n == 0 {
			return 0, nil
		}
		n, err = unix.Read(fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return 0, err
		}
		return n, nil
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func mustHardwareAddr(t *testing.T, name string) net.HardwareAddr {
	t.Helper()
	iface, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("InterfaceByName(%q): %v", name, err)
	}
	return iface.HardwareAddr
}
