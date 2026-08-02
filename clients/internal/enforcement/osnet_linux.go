//go:build linux

// The Linux osNet: fourteen marshal-and-send stubs, and no privileged code.
//
// ADR-0049 §1 puts the whole privileged half in bacchus-netd. What is left here
// is a client for it, and the file is deliberately dull — every method encodes a
// typed request, writes it to the socket, and reads a typed reply. There is no
// netlink here, no nftables, no syscall that needs a capability, and nothing
// this file could do differently would make the machine more or less protected
// except by asking for the wrong thing.
//
// # The one thing that is easy to get wrong here
//
// osnet.go's error/no-error split is load bearing, and the type doc says so:
// the route mutators are best-effort and silent, while createTUN,
// configureTunInterface, addSplitDefaultRoute and enableKillSwitch return
// errors. ADR-0049's osNet map repeats the warning in the form it takes on this
// platform — "a stub that turns every socket error into a returned error
// changes the fail-closed posture the bar depends on."
//
// So a transport failure is NOT uniformly an error here. On a silent method it
// is logged and swallowed, exactly as a failed New-NetRoute is on Windows,
// because a missing exclusion route fails safe: the dial loops into the tunnel
// or is blocked by the kill-switch, it does not leak. On a fallible method it is
// returned, because a failure there means the tunnel is not carrying traffic and
// bring-up must unwind rather than continue. Getting this backwards in either
// direction is a real regression: swallowing an enableKillSwitch failure would
// leave a client reporting Protected over an unarmed machine, and returning an
// error from addExclusionRoutes would abort bring-up over a route that did not
// need to exist.
//
// # Why requests are serialized
//
// One connection is held for the life of the session, and requests take turns
// on it under a mutex. The connection is not just a transport: its EOF is how
// the helper learns the client died (ADR-0049 §6/§8), so there is exactly one
// and it lives as long as the session does.
//
// Serializing on it is safe because nothing in this package calls an osNet
// method from inside another one. The nesting that looks like it might —
// splittunnel.go's arm() wrapping poolroutes.go's armAllowlist() wrapping
// enableKillSwitch — is three closures deep in ONE osNet call, not three calls.
// The concurrency that genuinely exists is poolroutes.go's background gateway
// refresh racing a dial-path exclusion, and those simply queue: each is a
// single netlink operation on the far side, measured in microseconds. Every
// request also carries a deadline (netdDeadline), which is what keeps a
// wedged helper from turning old #73's lock into a hang.
package enforcement

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/bacchus-vpn/bacchus/cmd/bacchus-netd/netdwire"
)

// netdSocket is where bacchus-netd listens.
//
// A var only so tests can point at a helper on a temp path — the same escape
// hatch winOS.run is, and used the same way: nothing at runtime reads it from a
// config file, an environment variable or a flag. That matters. A socket path
// the client can be told to use is a socket path an attacker can tell it to
// use, and the entire boundary rests on the client talking to the real helper;
// an env var here would let any process that can set one in the GUI's
// environment impersonate root's side of this protocol.
var netdSocket = "/run/bacchus/netd.sock"

// netdDeadline bounds every round trip. See the package doc above and
// ADR-0049 §3.7: splittunnel.go's arm() holds bypassPolicy.mu across the
// install callback, so an unbounded request stalls every split-tunnel decision
// and every DNS interception behind it.
const netdDeadline = 5 * time.Second

// linuxOS is the osNet implementation. It owns the control connection.
type linuxOS struct {
	logf func(string, ...any)

	mu    sync.Mutex
	conn  *net.UnixConn
	token string
}

func (o *linuxOS) log(format string, args ...any) {
	if o.logf != nil {
		o.logf(format, args...)
	}
}

// connect opens the session and mints the token every later request carries.
func (o *linuxOS) connect() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.conn != nil {
		return nil
	}

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: netdSocket, Net: "unix"})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHelperUnreachable, err)
	}

	rep, err := o.roundTrip(conn, &netdwire.Request{
		Version: netdwire.Version,
		Verb:    netdwire.VerbOpen,
	})
	if err != nil {
		conn.Close()
		return fmt.Errorf("%w: %v", ErrHelperUnreachable, err)
	}
	if err := rep.Err(); err != nil {
		conn.Close()
		return translateRefusal(err)
	}
	o.conn, o.token = conn, rep.Token
	return nil
}

// close ends the session cleanly. Distinct from the connection simply dropping,
// which the helper reads as a crash and answers by HOLDING the lockdown.
func (o *linuxOS) close() {
	o.mu.Lock()
	conn, token := o.conn, o.token
	o.conn, o.token = nil, ""
	o.mu.Unlock()

	if conn == nil {
		return
	}
	_, _ = o.roundTrip(conn, &netdwire.Request{
		Version: netdwire.Version,
		Verb:    netdwire.VerbClose,
		Token:   token,
	})
	conn.Close()
}

// do is the round trip every method below funnels through.
func (o *linuxOS) do(req *netdwire.Request) (*netdwire.Reply, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.conn == nil {
		return nil, ErrHelperUnreachable
	}
	req.Version = netdwire.Version
	req.Token = o.token

	rep, err := o.roundTrip(o.conn, req)
	if err != nil {
		return nil, err
	}
	return rep, rep.Err()
}

// roundTrip writes one request and reads one reply on conn.
//
// The invariant it needs is EXCLUSIVE USE OF conn, which is not the same as
// "the caller holds mu", and the three callers satisfy it three different ways:
// do() holds mu because o.conn is shared; connect() is working on a conn it has
// not published yet; close() is working on one it has just unpublished. Naming
// this after the mutex would have described only one of them, and wrongly
// implied the other two were violating it.
func (o *linuxOS) roundTrip(conn *net.UnixConn, req *netdwire.Request) (*netdwire.Reply, error) {
	deadline := time.Now().Add(netdDeadline)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := netdwire.WriteFrame(conn, req); err != nil {
		return nil, err
	}
	return netdwire.ReadReply(conn)
}

// silent runs a request whose contract forbids returning an error, logging
// anything that goes wrong. This is the swallow half of the posture split.
func (o *linuxOS) silent(verb netdwire.Verb, req *netdwire.Request) {
	req.Verb = verb
	if _, err := o.do(req); err != nil {
		o.log("[tun] netd %s: %v", verb, err)
	}
}

// -------------------------------------------------------------------------
// The fourteen methods
// -------------------------------------------------------------------------

func (o *linuxOS) defaultGateway() (gatewayInfo, error) {
	rep, err := o.do(&netdwire.Request{Verb: netdwire.VerbDefaultGateway})
	if err != nil {
		return gatewayInfo{}, err
	}
	if rep.Gateway == nil {
		return gatewayInfo{}, errors.New("netd returned no gateway")
	}
	// gatewayInfo crosses OUTWARD only (ADR-0049 §2). The value assembled here
	// is used by the portable code and handed back to this package's own
	// methods, but it is never sent to the helper — every method below that
	// takes a gatewayInfo simply drops it, because the helper already has the
	// value it produced.
	return gatewayInfo{
		nextHop:   rep.Gateway.NextHop,
		ifIndex:   rep.Gateway.IfIndex,
		ifAlias:   rep.Gateway.IfAlias,
		nextHopV6: rep.Gateway.NextHopV6,
	}, nil
}

// addExclusionRoutes drops gw deliberately. See ADR-0049 §2: every gatewayInfo
// in this package originates from osn.defaultGateway() and from nowhere else,
// so one arriving at the helper would always be an echo of what the helper just
// produced. Sending it would turn a value with no information the helper lacks
// into a parameter it has to trust.
func (o *linuxOS) addExclusionRoutes(prefixes []string, _ gatewayInfo) {
	if len(prefixes) == 0 {
		return
	}
	o.silent(netdwire.VerbAddExclusionRoutes, &netdwire.Request{Prefixes: prefixes})
}

func (o *linuxOS) addExclusionRoutesV6(prefixes []string, _ gatewayInfo) {
	if len(prefixes) == 0 {
		return
	}
	o.silent(netdwire.VerbAddExclusionRoutesV6, &netdwire.Request{Prefixes: prefixes})
}

// addInclusionRoutes drops tunNextHop for the same reason: the helper created
// the TUN and knows its address, and a next hop from the client is a next hop
// of the client's choosing.
func (o *linuxOS) addInclusionRoutes(prefixes []string, _ string) {
	if len(prefixes) == 0 {
		return
	}
	o.silent(netdwire.VerbAddInclusionRoutes, &netdwire.Request{Prefixes: prefixes})
}

func (o *linuxOS) removeRoutes(prefixes []string) {
	if len(prefixes) == 0 {
		return
	}
	o.silent(netdwire.VerbRemoveRoutes, &netdwire.Request{Prefixes: prefixes})
}

// createTUN asks the helper to create the device and hand back its descriptor,
// then wraps it here.
//
// CreateUnmonitoredTUNFromFD, not CreateTUNFromFile, and the difference is not
// cosmetic: CreateTUNFromFile ends in an SIOCSIFMTU ioctl that needs
// CAP_NET_ADMIN, so on a descriptor handed to an unprivileged process it fails
// with EPERM and no device. The helper sets the MTU before handing the fd over.
// See cmd/bacchus-netd/tundev.go, which records this as a correction to
// ADR-0049 §5's mechanism.
func (o *linuxOS) createTUN() (tun.Device, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.conn == nil {
		return nil, ErrHelperUnreachable
	}

	if err := o.conn.SetDeadline(time.Now().Add(netdDeadline)); err != nil {
		return nil, err
	}
	if err := netdwire.WriteFrame(o.conn, &netdwire.Request{
		Version: netdwire.Version,
		Verb:    netdwire.VerbCreateTUN,
		Token:   o.token,
	}); err != nil {
		return nil, err
	}

	rep, fd, err := netdwire.ReadReplyWithFD(o.conn)
	if err != nil {
		return nil, err
	}
	if err := rep.Err(); err != nil {
		unixClose(fd)
		return nil, translateRefusal(err)
	}
	if fd < 0 {
		return nil, errors.New("netd reported a TUN device but sent no descriptor")
	}

	// From here the descriptor's owner is the Device: CreateUnmonitoredTUNFromFD
	// wraps the raw number in an os.File of its own, and dev.Close() is what
	// closes it. On failure it is ours to close, or the device stays up with
	// nothing reading it.
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	if err != nil {
		unixClose(fd)
		return nil, fmt.Errorf("wrap the TUN descriptor from netd: %w", err)
	}
	return dev, nil
}

func (o *linuxOS) configureTunInterface(addr string, prefixLen int) error {
	_, err := o.do(&netdwire.Request{
		Verb:      netdwire.VerbConfigureTUN,
		Addr:      addr,
		PrefixLen: prefixLen,
	})
	return err
}

func (o *linuxOS) addSplitDefaultRoute(addr string) error {
	_, err := o.do(&netdwire.Request{Verb: netdwire.VerbAddSplitDefaultRoute, Addr: addr})
	return err
}

// disablePhysicalIPv6 drops ifAlias: the helper disables IPv6 on the interface
// its own default-route read returned, not on one the client named. ADR-0049
// §9 leans on that — "change any sysctl outside
// net.ipv6.conf.<the one physical interface>.disable_ipv6" is only a bounded
// claim because the interface is not a parameter.
func (o *linuxOS) disablePhysicalIPv6(_ string) {
	o.silent(netdwire.VerbDisablePhysicalIPv6, &netdwire.Request{})
}

func (o *linuxOS) enablePhysicalIPv6(_ string) {
	o.silent(netdwire.VerbEnablePhysicalIPv6, &netdwire.Request{})
}

func (o *linuxOS) enableKillSwitch(control, bypass []string) error {
	_, err := o.do(&netdwire.Request{
		Verb:    netdwire.VerbEnableKillSwitch,
		Control: control,
		Bypass:  bypass,
	})
	return err
}

func (o *linuxOS) disableKillSwitch() {
	o.silent(netdwire.VerbDisableKillSwitch, &netdwire.Request{})
}

func (o *linuxOS) recoverKillSwitch() {
	o.silent(netdwire.VerbRecoverKillSwitch, &netdwire.Request{})
}

func (o *linuxOS) refreshKillSwitchAllowIP(ip string) {
	o.silent(netdwire.VerbRefreshAllowIP, &netdwire.Request{IP: ip})
}

// captureDNS sends no parameters at all, which is the narrowest this file gets
// and is the point. ADR-0049 §2 fixes the inward vocabulary at prefixes, an
// address, an allowlist and a token; a DNS verb is exactly the kind of thing
// that would have widened it, because the obvious encodings carry an interface
// name, a unit name or /etc/resolv.conf's path. None of them needs to: the
// helper created the TUN, so it already knows the interface and the address,
// and osnet.go's method doc explains why the address the resolver is pointed at
// is derivable rather than chosen. See ADR-0051 §2.
func (o *linuxOS) captureDNS() error {
	_, err := o.do(&netdwire.Request{Verb: netdwire.VerbCaptureDNS})
	return err
}

// releaseDNS is silent, and unlike disableKillSwitch it is not the only thing
// standing between the machine and its prior state. The helper restores the
// resolver when the session ends however it ends, including a client that died
// without sending this (ADR-0051 §4). This is the tidy path, not the safety
// net — which is why a transport failure here is logged rather than returned.
func (o *linuxOS) releaseDNS() {
	o.silent(netdwire.VerbReleaseDNS, &netdwire.Request{})
}

// unixClose closes a raw descriptor we still own.
func unixClose(fd int) {
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}
