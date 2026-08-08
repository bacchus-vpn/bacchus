//go:build linux

// DNS capture: pointing the machine's resolver at the tunnel, and putting it
// back.
//
// # Why this is not a routing problem
//
// Everything else in this helper moves packets by editing the routing table.
// DNS cannot be done that way, and the reason is worth stating precisely
// because the obvious fix looks like it should work and does not.
//
// On a systemd-resolved machine /etc/resolv.conf points at 127.0.0.53. That is
// loopback, and the kernel consults the `local` table before ours, so no
// split-default can capture it (rtnetlink.go's rulePriority comment says the
// same thing from the routing side). That much was already recorded.
//
// The part that was assumed rather than measured, and that decides the
// mechanism, is what resolved does NEXT. Its own upstream query is sent on a
// socket scoped to the link the DNS server belongs to, and link scoping
// overrides the routing table: the packet leaves the physical interface even
// though `ip route get` says the tunnel. Measured on Ubuntu 26.04 with systemd
// 259, driving the real resolved inside a network namespace with a split
// default installed — the route said `via tun0`, and nftables counted six
// UDP/53 packets out the physical link and zero into the tunnel. So the
// upstream hop is not reachable by routing either, and any mechanism that
// tries to win by installing a better route is answering the wrong question.
//
// ADR-0051 records the measurement, the two mechanisms it ruled out, and the
// argument for the one below.
//
// # What this does
//
//  1. With resolved present: give the TUN link its own DNS server and a "~."
//     routing domain, so resolved's own scope selection picks the tunnel, and
//     then revoke the physical link's default-route flag so it stops being
//     consulted for names outside its own domains. Both halves are needed.
//     The first alone still leaks — measured: resolved queries every matching
//     scope in parallel, so the physical link keeps getting asked.
//  2. With no resolved: rewrite /etc/resolv.conf to point at the tunnel.
//
// Either way the address the resolver is pointed at is one the helper derives
// from the TUN it created, and the interceptor rewrites every query's
// destination anyway (tun2socks.go), so it only has to be an address that
// lands in the TUN. Nothing about the machine's DNS configuration crosses the
// privilege boundary inward — see ADR-0049 §2 and ADR-0051 §2.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/bacchus-vpn/bacchus/core/atomicfile"
	"github.com/godbus/dbus/v5"
)

const (
	// resolvedBus is the well-known name systemd-resolved owns. Its presence
	// on the bus is how this file decides which of the two mechanisms applies:
	// asking the bus is cheaper and more honest than probing for a unit file
	// or stat-ing a socket, both of which can exist while resolved is not
	// actually running.
	resolvedBus  = "org.freedesktop.resolve1"
	resolvedPath = "/org/freedesktop/resolve1"
	resolvedMgr  = "org.freedesktop.resolve1.Manager"
	resolvedLink = "org.freedesktop.resolve1.Link"

	// dnsCallTimeout bounds every bus call. ADR-0049 §3.7 requires a deadline
	// on every request, and this one is reached from inside splittunnel.go's
	// arm() lock like the rest. Under requestDeadline so the helper answers
	// late rather than not at all.
	dnsCallTimeout = 3 * time.Second
)

// resolvConf is the fallback's target.
//
// A var only so tests can point at a temp directory — the same escape hatch
// netdSocket is on the client side, and constrained the same way: nothing at
// runtime reads it from a config file, an environment variable or a flag. That
// distinction is the whole of ADR-0049 §2 for this file. A path this process
// would accept from a client is a path a compromised client could aim at
// something else, and this process writes it as root.
var resolvConf = "/etc/resolv.conf"

// dnsState is everything needed to undo a capture. It is stored on the session
// so that the disconnect path can restore without the client asking, which is
// the property that makes this safe to do at all: a resolver left pointing
// into a dead tunnel is a machine with no DNS, so unlike the kill-switch it is
// restored on crash rather than held. See ADR-0051 §4.
type dnsState struct {
	captured bool

	// viaResolved distinguishes the two mechanisms, so release undoes what
	// capture actually did rather than re-deciding and possibly deciding
	// differently — resolved could have stopped or started in between.
	viaResolved bool

	// The resolved path. physDefaultRoute is the flag's value BEFORE we
	// cleared it, restored verbatim rather than assumed to have been true —
	// the same rule ADR-0049 §3.6 sets for the IPv6 sysctl, and for the same
	// reason: a machine that had it off must not come back with it on.
	tunIndex         int
	physIndex        int
	physDefaultRoute bool

	// The resolv.conf path. Exactly one of these is set: a symlink is restored
	// as a symlink to the same target, a regular file byte for byte.
	resolvWasSymlink bool
	resolvTarget     string
	resolvContent    []byte
	resolvMode       os.FileMode
}

// captureDNS points the machine's resolver at the tunnel.
func (h *helper) captureDNS(sess *session) error {
	if sess.dns.captured {
		return nil // idempotent: a client that asks twice gets one capture
	}
	if sess.tunIndex == 0 || !sess.tunAddr.IsValid() {
		return errors.New("no configured TUN to point the resolver at")
	}

	sink := tunDNSSink(sess.tunAddr)

	conn, err := dbus.SystemBusPrivate()
	if err == nil {
		if err := dbusReady(conn); err != nil {
			conn.Close()
		} else {
			defer conn.Close()
			if running, _ := busNameHasOwner(conn, resolvedBus); running {
				return h.captureViaResolved(conn, sess, sink)
			}
		}
	}

	h.log("systemd-resolved is not on the bus; capturing DNS by rewriting %s", resolvConf)
	return h.captureViaResolvConf(sess, sink)
}

// releaseDNS restores whatever captureDNS changed. Best-effort by contract:
// every step is attempted even if an earlier one failed, because a partial
// restore is worse than a noisy one.
func (h *helper) releaseDNS(sess *session) {
	if sess == nil || !sess.dns.captured {
		return
	}
	if sess.dns.viaResolved {
		h.releaseViaResolved(sess)
	} else {
		h.releaseViaResolvConf(sess)
	}
	sess.dns = dnsState{}
}

// -------------------------------------------------------------------------
// systemd-resolved, over D-Bus
// -------------------------------------------------------------------------

// captureViaResolved installs the per-link configuration measured to work.
//
// Both halves matter and the order does too: the tunnel's scope is created
// before the physical link's is demoted, so there is no window in which the
// machine has no default DNS scope at all.
func (h *helper) captureViaResolved(conn *dbus.Conn, sess *session, sink netip.Addr) error {
	ctx, cancel := context.WithTimeout(context.Background(), dnsCallTimeout)
	defer cancel()

	mgr := conn.Object(resolvedBus, dbus.ObjectPath(resolvedPath))

	// The TUN gets a server and a "~." routing domain. "~." is encoded as the
	// root domain with routing-only set: it makes this link's resolver a
	// candidate for every name, which is what displaces the physical link's.
	if err := mgr.CallWithContext(ctx, resolvedMgr+".SetLinkDNS", 0,
		int32(sess.tunIndex), []linkAddress{{Family: afInet, Address: sink.AsSlice()}},
	).Store(); err != nil {
		return fmt.Errorf("point the tunnel link's resolver at %s: %w", sink, err)
	}
	if err := mgr.CallWithContext(ctx, resolvedMgr+".SetLinkDomains", 0,
		int32(sess.tunIndex), []linkDomain{{Domain: ".", RoutingOnly: true}},
	).Store(); err != nil {
		return fmt.Errorf("give the tunnel link a ~. routing domain: %w", err)
	}

	sess.dns.tunIndex = sess.tunIndex
	sess.dns.viaResolved = true
	sess.dns.captured = true

	// Now demote the physical link. Its prior value is read first so release
	// can restore it rather than guess; if it cannot be read, assume the
	// default (true), which is the value that makes a restore harmless.
	if sess.haveGW && sess.gw.IfIndex > 0 {
		prior, err := linkDefaultRoute(ctx, conn, sess.gw.IfIndex)
		if err != nil {
			h.log("could not read the physical link's default-route flag (%v); assuming it was set", err)
			prior = true
		}
		if err := mgr.CallWithContext(ctx, resolvedMgr+".SetLinkDefaultRoute", 0,
			int32(sess.gw.IfIndex), false,
		).Store(); err != nil {
			// Not fatal on its own: the tunnel's scope is installed, so DNS
			// works. What is lost is the guarantee that nothing is ALSO asked
			// on the physical link, which the kill-switch would drop anyway
			// when armed. Reported loudly because with the kill-switch off it
			// is exactly the leak this card exists to close.
			h.log("WARNING: the tunnel's resolver is installed but the physical link could not be demoted (%v); queries may still be attempted on it", err)
			return nil
		}
		sess.dns.physIndex = sess.gw.IfIndex
		sess.dns.physDefaultRoute = prior
	}
	return nil
}

func (h *helper) releaseViaResolved(sess *session) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsCallTimeout)
	defer cancel()

	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		h.log("cannot reach the system bus to restore DNS: %v", err)
		return
	}
	defer conn.Close()
	if err := dbusReady(conn); err != nil {
		h.log("cannot reach the system bus to restore DNS: %v", err)
		return
	}
	mgr := conn.Object(resolvedBus, dbus.ObjectPath(resolvedPath))

	// The physical link first: it is the one whose state outlives the tunnel.
	// The TUN's own configuration disappears with the device, so failing to
	// revert it is harmless, while leaving the physical link demoted is a
	// machine that resolves nothing once the tunnel is gone.
	if sess.dns.physIndex > 0 {
		if err := mgr.CallWithContext(ctx, resolvedMgr+".SetLinkDefaultRoute", 0,
			int32(sess.dns.physIndex), sess.dns.physDefaultRoute,
		).Store(); err != nil {
			h.log("WARNING: could not restore the physical link's default-route flag: %v", err)
		}
	}
	if sess.dns.tunIndex > 0 {
		// RevertLink rather than clearing the fields one by one: the link is
		// going away, and revert is the operation resolved documents for
		// "forget everything set on this link".
		if err := mgr.CallWithContext(ctx, resolvedMgr+".RevertLink", 0,
			int32(sess.dns.tunIndex),
		).Store(); err != nil {
			// Expected when the TUN is already gone — resolved drops a link's
			// configuration with the link. Logged at the same level as
			// anything else rather than specially suppressed, because the
			// alternative is suppressing a real failure that looks like it.
			h.log("reverting the tunnel link's resolver configuration: %v", err)
		}
	}
}

// linkDefaultRoute reads one link's DefaultRoute property.
func linkDefaultRoute(ctx context.Context, conn *dbus.Conn, ifIndex int) (bool, error) {
	mgr := conn.Object(resolvedBus, dbus.ObjectPath(resolvedPath))
	var path dbus.ObjectPath
	if err := mgr.CallWithContext(ctx, resolvedMgr+".GetLink", 0, int32(ifIndex)).Store(&path); err != nil {
		return false, err
	}
	v, err := conn.Object(resolvedBus, path).GetProperty(resolvedLink + ".DefaultRoute")
	if err != nil {
		return false, err
	}
	b, ok := v.Value().(bool)
	if !ok {
		return false, fmt.Errorf("DefaultRoute is %T, not a bool", v.Value())
	}
	return b, nil
}

// linkAddress is one entry of SetLinkDNS's a(iay) argument.
type linkAddress struct {
	Family  int32
	Address []byte
}

// linkDomain is one entry of SetLinkDomains's a(sb) argument. RoutingOnly is
// the "~" prefix resolvectl shows: the domain steers which link answers a
// name, without becoming a search suffix.
type linkDomain struct {
	Domain      string
	RoutingOnly bool
}

const afInet = 2 // AF_INET, as resolved's D-Bus API spells it

// dbusReady completes the handshake on a private connection. SystemBusPrivate
// deliberately returns one that has not authenticated, so both steps are ours.
func dbusReady(conn *dbus.Conn) error {
	if err := conn.Auth(nil); err != nil {
		return err
	}
	return conn.Hello()
}

// busNameHasOwner asks whether anyone owns a well-known name.
func busNameHasOwner(conn *dbus.Conn, name string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsCallTimeout)
	defer cancel()
	var owned bool
	err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, name).Store(&owned)
	return owned, err
}

// -------------------------------------------------------------------------
// The no-resolved fallback
// -------------------------------------------------------------------------

// captureViaResolvConf is the mechanism for a machine running neither resolved
// nor anything else that owns /etc/resolv.conf.
//
// It is crude and it is bounded: it only captures resolvers that read that
// file, which is every glibc lookup on such a machine, and nothing that talks
// to a local daemon over an API instead. On a machine with no resolved there
// is no such daemon in the path, which is exactly the case this branch runs in.
func (h *helper) captureViaResolvConf(sess *session, sink netip.Addr) error {
	// Capture the prior state precisely enough to put it back. A symlink is
	// the common shape even without resolved (resolvconf, NetworkManager), and
	// replacing one with a regular file and then "restoring" a regular file
	// would silently detach the machine from whatever manages it.
	fi, err := os.Lstat(resolvConf)
	switch {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(resolvConf)
		if err != nil {
			return fmt.Errorf("read the existing %s symlink: %w", resolvConf, err)
		}
		sess.dns.resolvWasSymlink = true
		sess.dns.resolvTarget = target
	case err == nil:
		content, err := os.ReadFile(resolvConf)
		if err != nil {
			return fmt.Errorf("read the existing %s: %w", resolvConf, err)
		}
		sess.dns.resolvContent = content
		sess.dns.resolvMode = fi.Mode().Perm()
	case os.IsNotExist(err):
		// Nothing there. Recorded as "no content and not a symlink", which
		// release turns back into "remove what we wrote".
	default:
		return fmt.Errorf("stat %s: %w", resolvConf, err)
	}

	body := fmt.Sprintf("# Written by bacchus-netd while the tunnel is up.\n"+
		"# The previous configuration is restored when it goes down, including\n"+
		"# if this client crashes. See ADR-0051.\nnameserver %s\n", sink)

	if err := replaceFile(resolvConf, []byte(body), 0o644); err != nil {
		return fmt.Errorf("point %s at the tunnel: %w", resolvConf, err)
	}
	sess.dns.captured = true
	return nil
}

func (h *helper) releaseViaResolvConf(sess *session) {
	switch {
	case sess.dns.resolvWasSymlink:
		if err := os.Remove(resolvConf); err != nil && !os.IsNotExist(err) {
			h.log("WARNING: could not remove our %s before restoring the symlink: %v", resolvConf, err)
			return
		}
		if err := os.Symlink(sess.dns.resolvTarget, resolvConf); err != nil {
			h.log("WARNING: could not restore the %s symlink to %s: %v", resolvConf, sess.dns.resolvTarget, err)
		}
	case sess.dns.resolvContent != nil:
		mode := sess.dns.resolvMode
		if mode == 0 {
			mode = 0o644
		}
		if err := replaceFile(resolvConf, sess.dns.resolvContent, mode); err != nil {
			h.log("WARNING: could not restore %s: %v", resolvConf, err)
		}
	default:
		if err := os.Remove(resolvConf); err != nil && !os.IsNotExist(err) {
			h.log("WARNING: could not remove the %s we wrote: %v", resolvConf, err)
		}
	}
}

// replaceFile installs content at path with the given mode, through
// core/atomicfile: a complete file is staged in the same directory, flushed and
// renamed over the target, so a reader never sees a half-written resolv.conf and
// a crash mid-write cannot leave one. rename(2) within a directory is atomic;
// write-in-place is not, and this file is read by everything on the machine.
//
// It gained the FLUSH in issue #188 and that is the only behavioural change: a
// rename that becomes visible ahead of its bytes leaves /etc/resolv.conf empty,
// which is not "the previous resolver" but NO resolver — and this is the one
// caller whose target is a file the whole machine depends on and whose original
// contents live only in this process's memory until release puts them back.
//
// The MODE ORDERING did not change, and it is worth recording that it was right,
// because this writer looked like the odd one out and the other six were the
// ones that moved. mode here is 0644 — resolv.conf must be world-readable — and
// os.CreateTemp creates its file 0600, so applying the mode after the bytes is
// what keeps a half-written resolv.conf from being readable by every local user
// while it is being written. The writers that applied 0600 first were safe only
// because 0600 is not wider than what os.CreateTemp had already given them.
// core/atomicfile now applies perm after the bytes for everyone.
func replaceFile(path string, content []byte, mode os.FileMode) error {
	return atomicfile.Write(path, content, mode)
}

// -------------------------------------------------------------------------

// tunDNSSink picks the address the resolver is pointed at.
//
// It must not be the TUN's own address: that one is in the kernel's `local`
// table, so a query aimed at it would go to loopback and never reach the
// device. Any other address on the tunnel's subnet does reach it, and which
// one is immaterial — tun2socks.go's handleDNSUDP intercepts UDP/53 to every
// destination and substitutes the configured upstream, so this address is a
// destination the packet is addressed to, never one anything answers from.
//
// Host .53 of the TUN's /24, or .54 when the TUN itself holds .53.
func tunDNSSink(tunAddr netip.Addr) netip.Addr {
	b := tunAddr.As4()
	last := byte(53)
	if b[3] == last {
		last = 54
	}
	b[3] = last
	return netip.AddrFrom4(b)
}
