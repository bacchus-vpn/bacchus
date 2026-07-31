//go:build linux

// rtnetlink: routes, addresses and links, spoken directly to the kernel.
//
// ADR-0049 §4 rules out shelling out to `ip`, and the reason is not taste. This
// process is root. The entire value of the privilege boundary is that no string
// from the unprivileged side can become an instruction, and exec reintroduces
// exactly that — plus PATH, LD_PRELOAD and argv quoting — into a root process's
// trust surface. Here a prefix from the client is parsed into a netip.Prefix by
// the caller and reaches the kernel as four or sixteen bytes in a typed
// attribute. There is no string for it to be smuggled through, which makes the
// injection class unrepresentable rather than merely tested against.
//
// Hand-rolled against golang.org/x/sys/unix rather than taking
// vishvananda/netlink. See the package doc in main.go for that argument; the
// short form is that what this file needs from rtnetlink is small, fixed and
// stable — four message types and a dump — and every one of its operations is
// asserted against a real kernel in rtnetlink_linux_test.go.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// routeTable is the routing table every route this helper installs lives
	// in, and the only table it will ever delete from (ADR-0049 §3.4). A
	// dedicated table plus the fib rule below is what makes "the helper refuses
	// to delete a route it did not install" a structural property rather than a
	// promise: a compromised client cannot use removeRoutes to tear up the
	// host's routing, or another VPN's, because there is nothing of theirs in
	// here to delete.
	routeTable = 0xBAC

	// routeProto is the rtm_protocol stamped on every route, so even within our
	// own table an entry is attributable.
	//
	// 151 rather than a rounder number because rtm_protocol is a registry, not
	// a free byte: rtnetlink.h assigns 0-18, 42, 99, and 186-192 (BGP, ISIS,
	// OSPF, RIP, EIGRP). 186 was the first choice here and it is RTPROT_BGP —
	// on a machine running FRR or BIRD our routes would have been
	// indistinguishable from the routing daemon's, which is the exact
	// attributability the dedicated id exists to provide. 151 sits in the
	// unassigned 100-185 span.
	routeProto = 151

	// rulePriority places our table ahead of `main` (32766) and behind `local`
	// (0). Ahead of main is what lets the split-default override the physical
	// default without removing it; behind local is why loopback keeps working
	// and why no route here can capture 127.0.0.0/8 — the reason DNS to
	// systemd-resolved's 127.0.0.53 cannot be intercepted by routing at all,
	// which is bacchus#104 and deliberately not solved here.
	rulePriority = 0x2BAC
)

// nlConn is one netlink socket. Not safe for concurrent use — each caller
// takes one for the duration of a request, which the pool below manages.
type nlConn struct {
	fd  int
	seq uint32
}

func dialNetlink() (*nlConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	return &nlConn{fd: fd}, nil
}

func (c *nlConn) Close() error { return unix.Close(c.fd) }

// exec sends one request and waits for its acknowledgement. Every message this
// helper sends sets NLM_F_ACK, so a silent failure is not possible: either the
// kernel reports success or this returns the errno it gave.
func (c *nlConn) exec(msgType, flags uint16, body []byte) error {
	_, err := c.execDump(msgType, flags|unix.NLM_F_ACK, body)
	return err
}

// execDump sends one request and collects every reply up to NLMSG_DONE or the
// acknowledgement.
func (c *nlConn) execDump(msgType, flags uint16, body []byte) ([]syscall.NetlinkMessage, error) {
	c.seq++
	seq := c.seq

	msg := make([]byte, unix.NLMSG_HDRLEN+len(body))
	binary.NativeEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.NativeEndian.PutUint16(msg[4:6], msgType)
	binary.NativeEndian.PutUint16(msg[6:8], flags|unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(msg[8:12], seq)
	binary.NativeEndian.PutUint32(msg[12:16], 0) // pid: kernel fills in
	copy(msg[unix.NLMSG_HDRLEN:], body)

	if err := unix.Sendto(c.fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, fmt.Errorf("netlink send: %w", err)
	}

	var out []syscall.NetlinkMessage
	buf := make([]byte, 64*1024)
	for {
		n, _, err := unix.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, fmt.Errorf("netlink receive: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("netlink parse: %w", err)
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				// The payload's first four bytes are a negative errno; zero is
				// the plain acknowledgement every NLM_F_ACK request gets.
				if len(m.Data) < 4 {
					return nil, errors.New("netlink: truncated error message")
				}
				code := int32(binary.NativeEndian.Uint32(m.Data[0:4]))
				if code == 0 {
					return out, nil
				}
				return nil, unix.Errno(-code)
			default:
				// Copy the payload. ParseNetlinkMessage returns Data slices
				// that ALIAS buf, and a dump of the routing table arrives in
				// several datagrams — so without this, the next Recvfrom
				// overwrites every message already collected. The failure is
				// silent and data-dependent: it needs a table big enough to
				// span two reads, which a developer's namespace with three
				// routes never is and a real desktop always is.
				data := make([]byte, len(m.Data))
				copy(data, m.Data)
				out = append(out, syscall.NetlinkMessage{Header: m.Header, Data: data})
				if flags&unix.NLM_F_DUMP == 0 {
					return out, nil
				}
			}
		}
	}
}

// attr encodes one netlink attribute, padded to a 4-byte boundary.
func attr(typ uint16, data []byte) []byte {
	l := unix.SizeofRtAttr + len(data)
	b := make([]byte, (l+unix.NLA_ALIGNTO-1) & ^(unix.NLA_ALIGNTO-1))
	binary.NativeEndian.PutUint16(b[0:2], uint16(l))
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[unix.SizeofRtAttr:], data)
	return b
}

func attrU32(typ uint16, v uint32) []byte {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return attr(typ, b[:])
}

// netlinkPool hands out netlink sockets. defaultGateway is refreshed from a
// background goroutine while the dial path may be installing an exclusion route
// (poolroutes.go's roaming refresh, old #117/#123c), so the helper genuinely
// serves overlapping work and a single shared socket would interleave two
// request/reply exchanges on one sequence space.
type netlinkPool struct {
	mu   sync.Mutex
	free []*nlConn
}

func (p *netlinkPool) get() (*nlConn, error) {
	p.mu.Lock()
	if n := len(p.free); n > 0 {
		c := p.free[n-1]
		p.free = p.free[:n-1]
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()
	return dialNetlink()
}

func (p *netlinkPool) put(c *nlConn) {
	p.mu.Lock()
	// Bounded so a burst of concurrent requests cannot leave a large number of
	// sockets resident for the rest of the helper's life.
	if len(p.free) < 8 {
		p.free = append(p.free, c)
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	c.Close()
}

func (p *netlinkPool) do(fn func(*nlConn) error) error {
	c, err := p.get()
	if err != nil {
		return err
	}
	defer p.put(c)
	return fn(c)
}

// -------------------------------------------------------------------------
// Routes
// -------------------------------------------------------------------------

// routeSpec is one route to install. Exactly one of Gateway and OutIface
// carries the next hop: a route via a gateway is scope-universe, a route out an
// interface is scope-link. Nothing here is a string.
type routeSpec struct {
	Dst      netip.Prefix
	Gateway  netip.Addr // zero when the route is on-link
	OutIface int
}

func (c *nlConn) addRoute(spec routeSpec) error {
	return c.routeOp(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, spec)
}

func (c *nlConn) delRoute(dst netip.Prefix) error {
	err := c.routeOp(unix.RTM_DELROUTE, 0, routeSpec{Dst: dst})
	// Deleting a route that is not there is the normal case on teardown: the
	// portable half re-derives its sets and removes them more than once (see
	// tunnel.go's Close), and an already-removed route is the intended end
	// state, not a failure.
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func (c *nlConn) routeOp(msgType uint16, extraFlags uint16, spec routeSpec) error {
	family := uint8(unix.AF_INET)
	if spec.Dst.Addr().Is6() {
		family = unix.AF_INET6
	}

	scope := uint8(unix.RT_SCOPE_UNIVERSE)
	if msgType == unix.RTM_NEWROUTE && !spec.Gateway.IsValid() {
		scope = unix.RT_SCOPE_LINK
	}
	if msgType == unix.RTM_DELROUTE {
		// Matching, not creating: leave scope unspecified so the kernel matches
		// whichever scope the route was installed with.
		scope = unix.RT_SCOPE_NOWHERE
	}

	body := make([]byte, 0, 128)
	hdr := make([]byte, unix.SizeofRtMsg)
	hdr[0] = family
	hdr[1] = uint8(spec.Dst.Bits())
	hdr[2] = 0 // src_len
	hdr[3] = 0 // tos
	// Table ids above 255 do not fit rtm_table; RTA_TABLE below carries the
	// real value and this field must read RT_TABLE_UNSPEC when it does.
	hdr[4] = unix.RT_TABLE_UNSPEC
	hdr[5] = routeProto
	hdr[6] = scope
	hdr[7] = unix.RTN_UNICAST
	body = append(body, hdr...)

	body = append(body, attr(unix.RTA_DST, spec.Dst.Addr().AsSlice())...)
	body = append(body, attrU32(unix.RTA_TABLE, routeTable)...)
	if spec.Gateway.IsValid() {
		body = append(body, attr(unix.RTA_GATEWAY, spec.Gateway.AsSlice())...)
	}
	if spec.OutIface > 0 {
		body = append(body, attrU32(unix.RTA_OIF, uint32(spec.OutIface))...)
	}

	return c.exec(msgType, extraFlags, body)
}

// listOwnRoutes dumps every route in this helper's table. Used by teardown and
// by orphan reaping, and it is why removeRoutes can be scoped: the set of
// routes we may delete is exactly the set this returns.
func (c *nlConn) listOwnRoutes() ([]netip.Prefix, error) {
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_UNSPEC
	msgs, err := c.execDump(unix.RTM_GETROUTE, unix.NLM_F_DUMP, body)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for i := range msgs {
		m := msgs[i]
		if m.Header.Type != unix.RTM_NEWROUTE || len(m.Data) < unix.SizeofRtMsg {
			continue
		}
		proto := m.Data[5]
		if proto != routeProto {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			continue
		}
		table := uint32(m.Data[4])
		var dst netip.Addr
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.RTA_TABLE:
				if len(a.Value) >= 4 {
					table = binary.NativeEndian.Uint32(a.Value)
				}
			case unix.RTA_DST:
				dst, _ = netip.AddrFromSlice(a.Value)
			}
		}
		if table != routeTable || !dst.IsValid() {
			continue
		}
		out = append(out, netip.PrefixFrom(dst, int(m.Data[1])))
	}
	return out, nil
}

// -------------------------------------------------------------------------
// The fib rule that makes our table reachable
// -------------------------------------------------------------------------

// addFibRule directs lookups at our table ahead of `main`. Without it every
// route above is inert — a table nothing consults.
func (c *nlConn) addFibRule(family uint8) error {
	return c.fibRuleOp(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, family)
}

func (c *nlConn) delFibRule(family uint8) error {
	err := c.fibRuleOp(unix.RTM_DELRULE, 0, family)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func (c *nlConn) fibRuleOp(msgType uint16, extraFlags uint16, family uint8) error {
	body := make([]byte, 0, 64)
	hdr := make([]byte, unix.SizeofRtMsg) // fib_rule_hdr shares rtmsg's layout
	hdr[0] = family
	hdr[4] = unix.RT_TABLE_UNSPEC
	hdr[7] = unix.FR_ACT_TO_TBL
	body = append(body, hdr...)
	body = append(body, attrU32(unix.FRA_TABLE, routeTable)...)
	body = append(body, attrU32(unix.FRA_PRIORITY, rulePriority)...)

	err := c.exec(msgType, extraFlags, body)
	if msgType == unix.RTM_NEWRULE && errors.Is(err, unix.EEXIST) {
		return nil // already ours from this session
	}
	return err
}

// -------------------------------------------------------------------------
// Addresses and links
// -------------------------------------------------------------------------

func (c *nlConn) addAddr(ifIndex int, addr netip.Prefix) error {
	body := make([]byte, 0, 64)
	hdr := make([]byte, unix.SizeofIfAddrmsg)
	family := uint8(unix.AF_INET)
	if addr.Addr().Is6() {
		family = unix.AF_INET6
	}
	hdr[0] = family
	hdr[1] = uint8(addr.Bits())
	hdr[2] = 0 // flags
	hdr[3] = unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(hdr[4:8], uint32(ifIndex))
	body = append(body, hdr...)
	body = append(body, attr(unix.IFA_LOCAL, addr.Addr().AsSlice())...)
	body = append(body, attr(unix.IFA_ADDRESS, addr.Addr().AsSlice())...)

	err := c.exec(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, body)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func (c *nlConn) setLinkUp(ifIndex int) error {
	body := make([]byte, unix.SizeofIfInfomsg)
	body[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(body[4:8], uint32(ifIndex))
	binary.NativeEndian.PutUint32(body[8:12], unix.IFF_UP)  // flags
	binary.NativeEndian.PutUint32(body[12:16], unix.IFF_UP) // change mask
	return c.exec(unix.RTM_NEWLINK, 0, body)
}

// setLinkMTU is why the TUN's MTU is the helper's job. See tundev.go: the
// unprivileged client cannot set it, so the descriptor it receives must arrive
// with the MTU already correct.
func (c *nlConn) setLinkMTU(ifIndex, mtu int) error {
	body := make([]byte, 0, 32)
	hdr := make([]byte, unix.SizeofIfInfomsg)
	hdr[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(hdr[4:8], uint32(ifIndex))
	body = append(body, hdr...)
	body = append(body, attrU32(unix.IFLA_MTU, uint32(mtu))...)
	return c.exec(unix.RTM_NEWLINK, 0, body)
}

// -------------------------------------------------------------------------
// Reading the default route
// -------------------------------------------------------------------------

// gatewayInfo mirrors the enforcement package's type of the same name. It is
// produced HERE and only here — ADR-0049 §2's central narrowing — and crosses
// outward to the client, never inward as an authority.
type gatewayInfo struct {
	NextHop   netip.Addr
	IfIndex   int
	IfName    string
	NextHopV6 netip.Addr
}

// defaultGateway reads the current best (lowest-metric) IPv4 default route,
// plus that same interface's IPv6 default route if it has one. Only the IPv4
// lookup is required to succeed, matching osNet.defaultGateway's contract.
func (c *nlConn) defaultGateway() (gatewayInfo, error) {
	v4, err := c.bestDefault(unix.AF_INET)
	if err != nil {
		return gatewayInfo{}, err
	}
	if !v4.gw.IsValid() {
		return gatewayInfo{}, errors.New("no IPv4 default route")
	}
	info := gatewayInfo{NextHop: v4.gw, IfIndex: v4.oif}

	iface, err := net.InterfaceByIndex(v4.oif)
	if err != nil {
		return gatewayInfo{}, fmt.Errorf("default route interface %d: %w", v4.oif, err)
	}
	info.IfName = iface.Name

	// Best-effort, exactly as on Windows: most networks and most of the
	// tunnel's lifetime have no IPv6 default route, and its absence is not an
	// error.
	if v6, err := c.bestDefault(unix.AF_INET6); err == nil && v6.gw.IsValid() && v6.oif == v4.oif {
		info.NextHopV6 = v6.gw
	}
	return info, nil
}

type defaultRoute struct {
	gw     netip.Addr
	oif    int
	metric uint32
}

func (c *nlConn) bestDefault(family uint8) (defaultRoute, error) {
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = family
	msgs, err := c.execDump(unix.RTM_GETROUTE, unix.NLM_F_DUMP, body)
	if err != nil {
		return defaultRoute{}, err
	}

	best := defaultRoute{metric: ^uint32(0)}
	found := false
	for i := range msgs {
		m := msgs[i]
		if m.Header.Type != unix.RTM_NEWROUTE || len(m.Data) < unix.SizeofRtMsg {
			continue
		}
		// A default route is dst_len 0. Skip anything in a table other than
		// main/unspec so our own split-default cannot be mistaken for the
		// physical one on a refresh mid-session — which would make the gateway
		// point at the tunnel it is supposed to bypass.
		if m.Data[1] != 0 {
			continue
		}
		table := uint32(m.Data[4])
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			continue
		}
		var gw netip.Addr
		var oif int
		metric := uint32(0)
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.RTA_GATEWAY:
				gw, _ = netip.AddrFromSlice(a.Value)
			case unix.RTA_OIF:
				if len(a.Value) >= 4 {
					oif = int(binary.NativeEndian.Uint32(a.Value))
				}
			case unix.RTA_PRIORITY:
				if len(a.Value) >= 4 {
					metric = binary.NativeEndian.Uint32(a.Value)
				}
			case unix.RTA_TABLE:
				if len(a.Value) >= 4 {
					table = binary.NativeEndian.Uint32(a.Value)
				}
			}
		}
		if table != unix.RT_TABLE_MAIN {
			continue
		}
		if !gw.IsValid() || oif == 0 {
			continue
		}
		if !found || metric < best.metric {
			best = defaultRoute{gw: gw, oif: oif, metric: metric}
			found = true
		}
	}
	if !found {
		return defaultRoute{}, fmt.Errorf("no default route for family %d", family)
	}
	return best, nil
}

// -------------------------------------------------------------------------
// The one sysctl this helper touches
// -------------------------------------------------------------------------

// ipv6DisablePath is built from an interface name the helper derived itself
// (gatewayInfo.IfName, read from the kernel's own routing table), never from
// anything the client sent. ADR-0049 §9 names this as the only sysctl outside
// the helper's reach-set, and "the one physical interface" is load bearing:
// the name is not a parameter.
func ipv6DisablePath(ifName string) string {
	return "/proc/sys/net/ipv6/conf/" + ifName + "/disable_ipv6"
}

// readIPv6Disabled captures the prior value so enablePhysicalIPv6 can restore
// it. ADR-0049 §3.6: a machine that had IPv6 disabled before Bacchus ran must
// not come back with it enabled, so this is a captured value and never a
// hardcoded 0.
func readIPv6Disabled(ifName string) (string, error) {
	b, err := os.ReadFile(ipv6DisablePath(ifName))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func writeIPv6Disabled(ifName, value string) error {
	return os.WriteFile(ipv6DisablePath(ifName), []byte(value), 0o644)
}
