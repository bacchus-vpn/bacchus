//go:build linux

// The privileged half: one session at a time, gated on peer credentials,
// executing primitives and owning no policy.
//
// The single most important constraint on this file is negative. ADR-0049's
// testing section states it plainly: **the helper executes primitives and must
// not own bring-up order.** tunnel.go's sequencing — control-plane exclusions
// before the route flip, the kill-switch armed last, a failed bring-up
// orphaning nothing, include mode never installing a split-default, Close
// restoring egress before removing the tunnel — is pinned by tunnel_test.go's
// five orderings against a fake osNet, and Linux inherits every one of them by
// running the same portable code. A helper that "helpfully" armed the
// kill-switch as part of installing routes, or that tore down routes when the
// TUN went away, would move a pinned ordering onto the one side no existing
// test covers. So each handler below does exactly what its verb says and
// nothing adjacent to it.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bacchus-vpn/bacchus/cmd/bacchus-netd/netdwire"
)

// requestDeadline bounds every request, and it is not tidiness — ADR-0049 §3.7.
// splittunnel.go's arm() holds bypassPolicy.mu across the install callback, the
// lock learn() and direct() also take. On Linux that callback is a socket round
// trip, so an unbounded helper would stall every split-tunnel decision behind
// it and turn old #73's fix into a hang. Comfortably under tun2socks.go's 10s
// DNS read deadline, so a stalled helper surfaces as a failed request before it
// surfaces as a failed lookup.
const requestDeadline = 5 * time.Second

// session is one client's enforcement session. At most one exists at a time.
type session struct {
	token string
	uid   uint32

	tunIndex int
	tunAddr  netip.Addr // as configured by configureTunInterface

	// gw is the last gatewayInfo this helper produced. Requests that would
	// otherwise need a gateway from the client read it from here instead —
	// ADR-0049 §2's narrowing, which is why no gatewayInfo crosses inward.
	gw      gatewayInfo
	haveGW  bool
	ipv6For string // interface whose IPv6 setting we changed
	ipv6Was string // its value before we changed it

	// dns is what captureDNS changed and how to put it back (dns.go,
	// ADR-0051). It lives on the session for the same reason ipv6Was does:
	// the disconnect path has to be able to undo it without the client, and
	// the client is by then gone.
	dns dnsState

	killSwitchArmed bool

	// servedSrc is this machine's own address once served egress has been
	// carved out of the tunnel for this session (ADR-0053, bacchus#109), and
	// invalid otherwise. Held here rather than recomputed because the two
	// places that must undo the carve-out — a clean revoke and the disconnect
	// path — have to remove exactly the rule and set element that were
	// installed, and by disconnect time the client that asked for them is gone.
	servedSrc netip.Addr
}

// helper is the whole privileged service.
type helper struct {
	nl           *netlinkPool
	logf         func(string, ...any)
	allowNoLogin bool

	// sessionCheck asks whether a uid owns an active local session. Injected
	// rather than called by name for the same reason winOS.run is: the tests
	// that drive this helper run inside a user namespace as uid 0, which owns
	// no logind session on the host, so with the real check nothing past the
	// front door could ever be exercised. In production it is nil and
	// uidHasActiveSession runs. Note what this does NOT bypass — checkPeer's
	// policy, including how it treats an unanswerable logind, stays under test
	// via TestRefusesAPeerWithNoActiveSession, which calls the real function.
	sessionCheck func(uid uint32) (bool, error)

	mu   sync.Mutex
	sess *session
}

func newHelper(logf func(string, ...any), allowNoLogin bool) *helper {
	return &helper{nl: &netlinkPool{}, logf: logf, allowNoLogin: allowNoLogin}
}

func (h *helper) log(format string, args ...any) {
	if h.logf != nil {
		h.logf(format, args...)
	}
}

// serve handles one client connection for its whole lifetime.
//
// The connection IS the session's lifetime signal. ADR-0049 §6 rejects
// exec-per-operation partly on this: enforcement is a session, not a series of
// independent operations, and with no resident privileged side nothing knows a
// half-built state exists if the GUI dies. Here, EOF is the crash signal.
func (h *helper) serve(conn *net.UnixConn) {
	defer conn.Close()

	cred, err := netdwire.PeerCred(conn)
	if err != nil {
		h.log("refusing a connection whose credentials could not be read: %v", err)
		_ = netdwire.WriteFrame(conn, netdwire.Failf(netdwire.CodeDenied, "peer credentials unavailable"))
		return
	}
	if err := h.checkPeer(cred); err != nil {
		h.log("refusing uid %d: %v", cred.Uid, err)
		_ = netdwire.WriteFrame(conn, netdwire.Failf(netdwire.CodeDenied, "%v", err))
		return
	}

	for {
		// The deadline covers the wait for the NEXT request too, which would be
		// wrong for a protocol where the client is expected to idle. It is right
		// here because the client holds this connection for the life of a
		// session and the helper must notice a dead client; see below.
		_ = conn.SetReadDeadline(time.Time{})

		req, err := netdwire.ReadRequest(conn)
		if err != nil {
			var perr *netdwire.ProtocolError
			if errors.As(err, &perr) {
				// A malformed frame is refused by name and the connection
				// continues: a client that sent one bad request has not
				// necessarily lost its session, and dropping the connection
				// would orphan a live lockdown over a typo.
				_ = conn.SetWriteDeadline(time.Now().Add(requestDeadline))
				_ = netdwire.WriteFrame(conn, netdwire.Failf(perr.Code, "%s", perr.Message))
				continue
			}
			// EOF or a transport error: the client is gone.
			h.clientGone(cred.Uid)
			return
		}

		_ = conn.SetWriteDeadline(time.Now().Add(requestDeadline))
		if err := h.dispatch(conn, cred, req); err != nil {
			h.log("dropping connection for uid %d: %v", cred.Uid, err)
			h.clientGone(cred.Uid)
			return
		}
	}
}

// clientGone is the disconnect path. ADR-0049 §8: a client that dies while the
// kill-switch is armed HOLDS the lockdown. Parity item 2 asks for a filter that
// survives a killed process, and the client being killed is precisely that
// case — lifting it here would make the kill-switch useless in the one scenario
// it exists for. The session is marked orphaned and reaped on the next Open.
func (h *helper) clientGone(uid uint32) {
	h.mu.Lock()
	sess := h.sess
	h.sess = nil
	h.mu.Unlock()

	if sess == nil {
		return
	}

	// DNS is restored on BOTH paths below, before either of them decides what
	// to do about the lockdown, and it is the one piece of session state that
	// is never held past a crash. The kill-switch is held deliberately because
	// holding it fails closed; a resolver still pointed into a tunnel that no
	// longer has anything reading it fails to a machine that resolves nothing,
	// which is not a safer state, it is just a broken one. ADR-0051 §4.
	h.releaseDNS(sess)

	// The served-egress carve-out goes on both paths too, and unlike DNS it is
	// dropped for the same reason the kill-switch below is held: because that
	// is the direction that fails closed. The process that was serving is dead,
	// so nothing needs the carve-out any more, and an allowance nobody is using
	// is a hole in a lockdown that is otherwise being kept deliberately. See
	// ADR-0053 §5 — the asymmetry with the line below is the point, not an
	// inconsistency.
	h.revokeServedEgress(sess)

	if sess.killSwitchArmed {
		h.log("client uid %d disconnected with the kill-switch armed: holding the lockdown (it is lifted by the next Open, or a reboot)", uid)
		return
	}
	// Nothing armed: tidy our own routes so an unclean exit does not leave a
	// table behind. The kill-switch case deliberately does not do this — the
	// routes are what the allowlist is written against.
	h.log("client uid %d disconnected; removing our routes", uid)
	h.reapRoutes()
	h.restoreIPv6(sess)
}

// checkPeer is ADR-0049 §3.1. SO_PEERCRED is attached by the kernel and cannot
// be forged by an unprivileged process, so this is a credential check rather
// than a claim.
//
// Group membership is deliberately NOT the question. A uid in the `bacchus`
// group is a packaging decision; whether that uid owns an active local session
// is the question actually being asked, and on a multi-user machine they are
// very different. logind answers it.
// There is deliberately no special case for uid 0. An earlier draft refused
// root outright, which reads as defensive and is not: a root process can
// already replace this binary, ptrace the GUI, or make the same netlink calls
// itself, so refusing it protects nothing while breaking a root console login,
// which is a genuine active session. The rule is the one the record states, and
// it applies to every uid equally.
func (h *helper) checkPeer(cred *unix.Ucred) error {
	check := h.sessionCheck
	if check == nil {
		check = uidHasActiveSession
	}
	active, err := check(cred.Uid)
	if err != nil {
		if h.allowNoLogin {
			h.log("logind state unavailable (%v) and -allow-without-logind is set: accepting uid %d on socket permissions alone", err, cred.Uid)
			return nil
		}
		return fmt.Errorf("cannot confirm uid %d owns a local session (%v); a non-systemd host must be packaged with -allow-without-logind", cred.Uid, err)
	}
	if !active {
		return fmt.Errorf("uid %d does not own an active local session", cred.Uid)
	}
	return nil
}

// uidHasActiveSession asks logind whether this uid is logged in locally.
//
// Read from /run/systemd/users/<uid> rather than over D-Bus. An earlier
// version of this comment justified that by the cost of a D-Bus client
// library; dns.go now links one, so that reason no longer holds and is not
// worth pretending to. The reason that does hold is the path this runs on:
// this is the connection-accept gate, and a file read cannot block on a bus
// that is starting, wedged, or not yet reachable, where a method call can.
// The file is logind's own published state and its STATE= field carries the
// same value `loginctl show-user` reports.
//
// Both "active" and "online" are accepted, and ADR-0049 §3.1's amendment
// records why, because the code and the record disagreed until bacchus#111
// made them agree. In short: for a uid, "active" means it owns at least one
// session that is its seat's foreground session OR has no seat at all, and
// "online" means it owns sessions but none of them is currently foreground —
// which is what a user who has been switched away from by fast user switching,
// or by a VT switch, looks like. Refusing "online" would disconnect that user
// mid-session for going to the background. It is deliberately in.
//
// What neither state implies is a seat, and that is the real gap #111 found
// between §3.1's wording and this function. A seatless session — an SSH login,
// a cron job — reports "active", not "online", because logind treats a session
// with no seat as unconditionally active. So narrowing this to "active" would
// not exclude a remote login; it would only exclude the switched-away local
// user. Excluding remote logins is a different question with a different
// primitive (the SEATS= field), and §3.1 no longer claims this gate answers it.
func uidHasActiveSession(uid uint32) (bool, error) {
	if _, err := os.Stat("/run/systemd/users"); err != nil {
		return false, fmt.Errorf("logind is not running: %w", err)
	}
	b, err := os.ReadFile(fmt.Sprintf("/run/systemd/users/%d", uid))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // logind is running and has never seen this uid
		}
		return false, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "STATE=") {
			continue
		}
		switch strings.TrimSpace(strings.TrimPrefix(line, "STATE=")) {
		case "active", "online":
			return true, nil
		default:
			// "lingering", "closing" and "offline" are deliberately not
			// enough, and the discriminator is presence, not seats — an
			// earlier comment here said a lingering user "has no seat, which
			// is the whole point of asking", which is not what separates
			// these. A lingering uid is one that is NOT logged in but still
			// has user services running; a closing one is NOT logged in with
			// processes still winding down. Neither is a person at the
			// machine, and this gate is asking whether one is.
			return false, nil
		}
	}
	return false, nil
}

// dispatch handles one request. The returned error means "drop the connection";
// a refusal the client should see is written as a reply and returns nil.
func (h *helper) dispatch(conn *net.UnixConn, cred *unix.Ucred, req *netdwire.Request) error {
	// Open and Close bracket a session; everything else needs a valid token.
	switch req.Verb {
	case netdwire.VerbOpen:
		return h.reply(conn, h.handleOpen(cred))
	case netdwire.VerbClose:
		return h.reply(conn, h.handleClose(req))
	}

	sess, fail := h.authorize(req)
	if fail != nil {
		return h.reply(conn, fail)
	}

	switch req.Verb {
	case netdwire.VerbDefaultGateway:
		return h.reply(conn, h.handleDefaultGateway(sess))
	case netdwire.VerbAddExclusionRoutes:
		return h.reply(conn, h.handleExclusionRoutes(sess, req, false))
	case netdwire.VerbAddExclusionRoutesV6:
		return h.reply(conn, h.handleExclusionRoutes(sess, req, true))
	case netdwire.VerbAddInclusionRoutes:
		return h.reply(conn, h.handleInclusionRoutes(sess, req))
	case netdwire.VerbRemoveRoutes:
		return h.reply(conn, h.handleRemoveRoutes(sess, req))
	case netdwire.VerbCreateTUN:
		return h.handleCreateTUN(conn, sess)
	case netdwire.VerbConfigureTUN:
		return h.reply(conn, h.handleConfigureTUN(sess, req))
	case netdwire.VerbAddSplitDefaultRoute:
		return h.reply(conn, h.handleSplitDefaultRoute(sess, req))
	case netdwire.VerbDisablePhysicalIPv6:
		return h.reply(conn, h.handleDisableIPv6(sess))
	case netdwire.VerbEnablePhysicalIPv6:
		return h.reply(conn, h.handleEnableIPv6(sess))
	case netdwire.VerbEnableKillSwitch:
		return h.reply(conn, h.handleEnableKillSwitch(sess, req))
	case netdwire.VerbDisableKillSwitch:
		return h.reply(conn, h.handleDisableKillSwitch(sess))
	case netdwire.VerbRecoverKillSwitch:
		return h.reply(conn, h.handleRecoverKillSwitch())
	case netdwire.VerbRefreshAllowIP:
		return h.reply(conn, h.handleRefreshAllowIP(sess, req))
	case netdwire.VerbCaptureDNS:
		return h.reply(conn, h.handleCaptureDNS(sess))
	case netdwire.VerbReleaseDNS:
		return h.reply(conn, h.handleReleaseDNS(sess))
	case netdwire.VerbAllowServedEgress:
		return h.reply(conn, h.handleAllowServedEgress(sess))
	case netdwire.VerbRevokeServedEgress:
		return h.reply(conn, h.handleRevokeServedEgress(sess))
	default:
		return h.reply(conn, netdwire.Failf(netdwire.CodeUnknownVerb, "unknown verb %q", req.Verb))
	}
}

func (h *helper) reply(conn *net.UnixConn, rep *netdwire.Reply) error {
	return netdwire.WriteFrame(conn, rep)
}

// authorize resolves the session a mutating request belongs to.
func (h *helper) authorize(req *netdwire.Request) (*session, *netdwire.Reply) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sess == nil {
		return nil, netdwire.Failf(netdwire.CodeNoSession, "no session is open; send %q first", netdwire.VerbOpen)
	}
	if req.Token == "" {
		return nil, netdwire.Failf(netdwire.CodeBadToken, "request carries no session token")
	}
	// Constant-time is not the point — the token is 32 bytes of crypto/rand and
	// the peer is already credential-gated — but an equality check on a secret
	// is cheap to do properly.
	if subtleCompare(req.Token, h.sess.token) != 1 {
		return nil, netdwire.Failf(netdwire.CodeBadToken, "session token does not match the open session")
	}
	return h.sess, nil
}

// handleOpen starts a session, reaping any orphan first.
func (h *helper) handleOpen(cred *unix.Ucred) *netdwire.Reply {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.sess != nil {
		// ADR-0049 §3.2: a second client gets EBUSY, not a second tunnel. The
		// client that armed the kill-switch is the only one that can lift it.
		return netdwire.Failf(netdwire.CodeBusy, "another session is already open (uid %d)", h.sess.uid)
	}

	// Parity item 3, as the helper reaping its OWN orphan: a lockdown left by a
	// crashed prior session is ours by name, so there is no heuristic about
	// whose firewall state it is.
	h.reapOrphan()

	tok, err := newToken()
	if err != nil {
		return netdwire.Failf(netdwire.CodeInternal, "could not mint a session token: %v", err)
	}
	h.sess = &session{token: tok, uid: cred.Uid}
	h.log("session opened for uid %d", cred.Uid)
	return &netdwire.Reply{OK: true, Token: tok}
}

func (h *helper) handleClose(req *netdwire.Request) *netdwire.Reply {
	h.mu.Lock()
	sess := h.sess
	if sess == nil {
		h.mu.Unlock()
		return &netdwire.Reply{OK: true} // already closed: idempotent
	}
	if subtleCompare(req.Token, sess.token) != 1 {
		h.mu.Unlock()
		return netdwire.Failf(netdwire.CodeBadToken, "session token does not match the open session")
	}
	h.sess = nil
	h.mu.Unlock()

	// The clean path restores DNS too. A client that closed properly has
	// usually sent VerbReleaseDNS already, which makes this a no-op; one that
	// closed without it has not, and the resolver is not something to leave
	// changed because the client forgot.
	h.releaseDNS(sess)

	h.log("session closed for uid %d", sess.uid)
	return &netdwire.Reply{OK: true}
}

// reapOrphan lifts a lockdown and clears routes left by a session whose client
// died. Caller holds mu, and h.sess is nil.
func (h *helper) reapOrphan() {
	c, err := dialNftables()
	if err == nil {
		defer c.Close()
		if armed, err := c.tableExists(); err == nil && armed {
			h.log("reaping a kill-switch left behind by a crashed session")
			if err := c.deleteTable(); err != nil {
				h.log("could not lift the stale lockdown: %v", err)
			}
		}
	}
	h.reapRoutes()
}

// reapRoutes removes every route in our own table and the fib rules that point
// at it. Scoped by construction: listOwnRoutes only ever returns routes stamped
// with our protocol id in our table.
func (h *helper) reapRoutes() {
	err := h.nl.do(func(c *nlConn) error {
		routes, err := c.listOwnRoutes()
		if err != nil {
			return err
		}
		for _, p := range routes {
			if err := c.delRoute(p); err != nil {
				h.log("could not remove %v: %v", p, err)
			}
		}
		_ = c.delFibRule(unix.AF_INET)
		_ = c.delFibRule(unix.AF_INET6)
		// The served-egress carve-out too (ADR-0053): it is one more fib rule
		// at a priority this helper owns, and an orphaned one would keep
		// sending a dead session's source address straight past the tunnel.
		_ = c.delServedRule()
		return nil
	})
	if err != nil {
		h.log("route cleanup: %v", err)
	}
}

func (h *helper) restoreIPv6(sess *session) {
	if sess.ipv6For == "" {
		return
	}
	if err := writeIPv6Disabled(sess.ipv6For, sess.ipv6Was); err != nil {
		h.log("could not restore IPv6 on %s: %v", sess.ipv6For, err)
	}
}

// -------------------------------------------------------------------------
// Handlers
// -------------------------------------------------------------------------

func (h *helper) handleDefaultGateway(sess *session) *netdwire.Reply {
	var info gatewayInfo
	err := h.nl.do(func(c *nlConn) error {
		var err error
		info, err = c.defaultGateway()
		return err
	})
	if err != nil {
		return netdwire.Failf(netdwire.CodeInternal, "read default route: %v", err)
	}

	// Cached so later requests can use it without the client ever sending one
	// back. A session's gateway is re-derived on every call, not frozen at
	// Open: poolroutes.go refreshes it in the background precisely so a roam
	// onto a new network is noticed.
	h.mu.Lock()
	sess.gw, sess.haveGW = info, true
	h.mu.Unlock()

	return &netdwire.Reply{OK: true, Gateway: &netdwire.Gateway{
		NextHop:   info.NextHop.String(),
		IfIndex:   info.IfIndex,
		IfAlias:   info.IfName,
		NextHopV6: addrOrEmpty(info.NextHopV6),
	}}
}

func (h *helper) handleExclusionRoutes(sess *session, req *netdwire.Request, v6 bool) *netdwire.Reply {
	h.mu.Lock()
	gw, have := sess.gw, sess.haveGW
	h.mu.Unlock()
	if !have {
		return netdwire.Failf(netdwire.CodeBadRequest, "no gateway has been read in this session yet")
	}

	nextHop := gw.NextHop
	if v6 {
		// A no-op without an IPv6 next hop, exactly as on Windows: there is then
		// nothing to route an exclusion via, and physical IPv6 is disabled while
		// the tunnel is up, so an unexcluded IPv6 dial fails closed.
		if !gw.NextHopV6.IsValid() {
			return &netdwire.Reply{OK: true}
		}
		nextHop = gw.NextHopV6
	}

	prefixes, bad := parsePrefixes(req.Prefixes, v6)
	if bad != nil {
		return bad
	}
	h.installRoutes(prefixes, routeSpec{Gateway: nextHop, OutIface: gw.IfIndex})
	return &netdwire.Reply{OK: true}
}

func (h *helper) handleInclusionRoutes(sess *session, req *netdwire.Request) *netdwire.Reply {
	h.mu.Lock()
	tunIndex := sess.tunIndex
	h.mu.Unlock()
	if tunIndex == 0 {
		return netdwire.Failf(netdwire.CodeBadRequest, "no TUN device exists in this session yet")
	}
	prefixes, bad := parsePrefixes(req.Prefixes, false)
	if bad != nil {
		return bad
	}
	// On-link via the tunnel: no next hop, which is why the client never sends
	// one (ADR-0049 §2).
	h.installRoutes(prefixes, routeSpec{OutIface: tunIndex})
	return &netdwire.Reply{OK: true}
}

// installRoutes is best-effort per prefix, matching osNet's contract: the route
// mutators are silent, because a missing exclusion route fails safe — the dial
// loops into the tunnel or is blocked, it does not leak.
func (h *helper) installRoutes(prefixes []netip.Prefix, base routeSpec) {
	_ = h.nl.do(func(c *nlConn) error {
		for _, p := range prefixes {
			spec := base
			spec.Dst = p
			if err := c.addRoute(spec); err != nil {
				h.log("could not add route %v: %v", p, err)
			}
		}
		return nil
	})
}

func (h *helper) handleRemoveRoutes(sess *session, req *netdwire.Request) *netdwire.Reply {
	prefixes, bad := parsePrefixes(req.Prefixes, false)
	if bad != nil {
		return bad
	}
	v6, bad6 := parsePrefixes(req.Prefixes, true)
	if bad6 == nil {
		prefixes = append(prefixes, v6...)
	}

	// ADR-0049 §3.4: deletes from our own table only. A prefix the helper never
	// installed is simply not there to delete, and delRoute treats an absent
	// route as success — so this cannot be used to tear up the host's routing
	// or another VPN's, no matter what the client asks for.
	_ = h.nl.do(func(c *nlConn) error {
		for _, p := range prefixes {
			if err := c.delRoute(p); err != nil {
				h.log("could not remove route %v: %v", p, err)
			}
		}
		return nil
	})
	return &netdwire.Reply{OK: true}
}

func (h *helper) handleCreateTUN(conn *net.UnixConn, sess *session) error {
	fd, ifIndex, err := createTUN(h.nl)
	if err != nil {
		return h.reply(conn, netdwire.Failf(netdwire.CodeInternal, "create TUN device: %v", err))
	}

	h.mu.Lock()
	sess.tunIndex = ifIndex
	h.mu.Unlock()

	// The descriptor and the reply travel in one sendmsg. If the handover
	// fails, close our copy: the device exists only as long as a descriptor
	// does, so a dropped handover with our copy left open would leave an
	// interface up with nothing reading it.
	if err := netdwire.SendReplyWithFD(conn, &netdwire.Reply{OK: true, TUNCreated: true}, fd); err != nil {
		closeFD(fd)
		return fmt.Errorf("hand over the TUN descriptor: %w", err)
	}
	closeFD(fd) // the client holds its own now
	h.log("created %s (index %d) and passed its descriptor to uid %d", tunName, ifIndex, sess.uid)
	return nil
}

func (h *helper) handleConfigureTUN(sess *session, req *netdwire.Request) *netdwire.Reply {
	h.mu.Lock()
	tunIndex := sess.tunIndex
	h.mu.Unlock()
	if tunIndex == 0 {
		return netdwire.Failf(netdwire.CodeBadRequest, "no TUN device exists in this session yet")
	}

	addr, err := netip.ParseAddr(req.Addr)
	if err != nil || !addr.Is4() {
		return netdwire.Failf(netdwire.CodeBadRequest, "not an IPv4 address: %q", req.Addr)
	}
	if req.PrefixLen < 0 || req.PrefixLen > 32 {
		return netdwire.Failf(netdwire.CodeBadRequest, "prefix length %d out of range", req.PrefixLen)
	}

	err = h.nl.do(func(c *nlConn) error {
		if err := c.addAddr(tunIndex, netip.PrefixFrom(addr, req.PrefixLen)); err != nil {
			return fmt.Errorf("assign %s: %w", req.Addr, err)
		}
		if err := c.setLinkUp(tunIndex); err != nil {
			return fmt.Errorf("bring %s up: %w", tunName, err)
		}
		// The fib rule is installed here rather than at Open because this is the
		// first moment the table has anything worth consulting, and because a
		// failed bring-up that never got this far leaves no rule behind.
		if err := c.addFibRule(unix.AF_INET); err != nil {
			return fmt.Errorf("install the routing rule: %w", err)
		}
		return nil
	})
	if err != nil {
		return netdwire.Failf(netdwire.CodeInternal, "%v", err)
	}

	h.mu.Lock()
	sess.tunAddr = addr
	h.mu.Unlock()
	return &netdwire.Reply{OK: true}
}

func (h *helper) handleSplitDefaultRoute(sess *session, req *netdwire.Request) *netdwire.Reply {
	h.mu.Lock()
	tunIndex, tunAddr := sess.tunIndex, sess.tunAddr
	h.mu.Unlock()
	if tunIndex == 0 || !tunAddr.IsValid() {
		return netdwire.Failf(netdwire.CodeBadRequest, "the TUN device is not configured in this session yet")
	}
	// The address is redundant — the helper configured it — so it is checked
	// for agreement rather than used. That turns a parameter the protocol would
	// otherwise have to trust into a consistency check (ADR-0049 §3.5).
	if got, err := netip.ParseAddr(req.Addr); err != nil || got != tunAddr {
		return netdwire.Failf(netdwire.CodeBadRequest,
			"split-default address %q does not match this session's TUN address", req.Addr)
	}

	err := h.nl.do(func(c *nlConn) error {
		for _, p := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := c.addRoute(routeSpec{Dst: netip.MustParsePrefix(p), OutIface: tunIndex}); err != nil {
				return fmt.Errorf("add split-default route %s: %w", p, err)
			}
		}
		return nil
	})
	if err != nil {
		return netdwire.Failf(netdwire.CodeInternal, "%v", err)
	}
	return &netdwire.Reply{OK: true}
}

func (h *helper) handleDisableIPv6(sess *session) *netdwire.Reply {
	h.mu.Lock()
	gw, have := sess.gw, sess.haveGW
	h.mu.Unlock()
	if !have {
		return &netdwire.Reply{OK: true} // silent contract: nothing to do
	}

	prior, err := readIPv6Disabled(gw.IfName)
	if err != nil {
		h.log("could not read the IPv6 setting on %s: %v", gw.IfName, err)
		return &netdwire.Reply{OK: true}
	}
	if err := writeIPv6Disabled(gw.IfName, "1"); err != nil {
		h.log("could not disable IPv6 on %s: %v", gw.IfName, err)
		return &netdwire.Reply{OK: true}
	}

	h.mu.Lock()
	// Captured only on the FIRST disable: a second call in the same session
	// would otherwise record our own "1" as the prior value and lose the real
	// one, so a machine that started with IPv6 enabled would never get it back.
	if sess.ipv6For == "" {
		sess.ipv6For, sess.ipv6Was = gw.IfName, prior
	}
	h.mu.Unlock()
	return &netdwire.Reply{OK: true}
}

func (h *helper) handleEnableIPv6(sess *session) *netdwire.Reply {
	h.mu.Lock()
	sessCopy := *sess
	sess.ipv6For, sess.ipv6Was = "", ""
	h.mu.Unlock()
	// ADR-0049 §3.6: restores the captured prior value, never a hardcoded 0.
	h.restoreIPv6(&sessCopy)
	return &netdwire.Reply{OK: true}
}

func (h *helper) handleEnableKillSwitch(sess *session, req *netdwire.Request) *netdwire.Reply {
	h.mu.Lock()
	tunIndex := sess.tunIndex
	h.mu.Unlock()
	if tunIndex == 0 {
		return netdwire.Failf(netdwire.CodeBadRequest, "no TUN device exists in this session yet")
	}

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return netdwire.Failf(netdwire.CodeInternal, "find loopback: %v", err)
	}

	h.mu.Lock()
	servedSrc := sess.servedSrc
	h.mu.Unlock()

	spec := killSwitchSpec{TunIfIndex: tunIndex, LoIfIndex: lo.Index, ServedSrc: servedSrc}
	for _, list := range [][]string{req.Control, req.Bypass} {
		for _, entry := range list {
			addr, prefix, err := parseHostOrPrefix(entry)
			if err != nil {
				return netdwire.Failf(netdwire.CodeBadRequest, "allowlist entry %q: %v", entry, err)
			}
			if addr.IsValid() {
				spec.Hosts = append(spec.Hosts, addr)
			} else if prefix.IsValid() {
				spec.Nets = append(spec.Nets, prefix)
			}
		}
	}
	// Loopback is always allowed: the netstack dials the client's own SOCKS
	// server over it. Windows adds 127.0.0.0/8 to the remote allowlist for the
	// same reason; here the `oif lo` rule covers it, and this is belt and
	// braces for a loopback destination reached on another interface.
	spec.Nets = append(spec.Nets, netip.MustParsePrefix("127.0.0.0/8"))

	c, err := dialNftables()
	if err != nil {
		return netdwire.Failf(netdwire.CodeInternal, "netfilter socket: %v", err)
	}
	defer c.Close()

	// Clear any stale lockdown first so we arm onto a known-clean state rather
	// than layering onto our own leftovers.
	if armed, err := c.tableExists(); err == nil && armed {
		_ = c.deleteTable()
	}
	if err := c.enableKillSwitch(spec); err != nil {
		// Fail-closed means the tunnel must not continue believing it is
		// protected. Leave nothing half-armed behind.
		_ = c.deleteTable()
		return netdwire.Failf(netdwire.CodeInternal, "arm the kill-switch: %v", err)
	}

	h.mu.Lock()
	sess.killSwitchArmed = true
	h.mu.Unlock()
	h.log("kill-switch armed with %d host(s) and %d network(s) allowed", len(spec.Hosts), len(spec.Nets))
	return &netdwire.Reply{OK: true}
}

func (h *helper) handleDisableKillSwitch(sess *session) *netdwire.Reply {
	c, err := dialNftables()
	if err != nil {
		h.log("netfilter socket: %v", err)
		return &netdwire.Reply{OK: true} // silent contract
	}
	defer c.Close()
	if err := c.deleteTable(); err != nil {
		h.log("could not lift the kill-switch: %v", err)
	}
	h.mu.Lock()
	sess.killSwitchArmed = false
	h.mu.Unlock()
	return &netdwire.Reply{OK: true}
}

func (h *helper) handleRecoverKillSwitch() *netdwire.Reply {
	c, err := dialNftables()
	if err != nil {
		h.log("netfilter socket: %v", err)
		return &netdwire.Reply{OK: true}
	}
	defer c.Close()

	armed, err := c.tableExists()
	if err != nil {
		h.log("could not check for a stale lockdown: %v", err)
		return &netdwire.Reply{OK: true}
	}
	if !armed {
		return &netdwire.Reply{OK: true} // idempotent, the common case
	}

	h.mu.Lock()
	live := h.sess != nil && h.sess.killSwitchArmed
	h.mu.Unlock()
	if live {
		// Somebody else's live lockdown, not an orphan. Recover must never lift
		// a lockdown that is actually in force.
		return &netdwire.Reply{OK: true}
	}
	h.log("lifting a kill-switch left behind by a crashed session")
	if err := c.deleteTable(); err != nil {
		h.log("could not lift the stale lockdown: %v", err)
	}
	h.reapRoutes()
	return &netdwire.Reply{OK: true}
}

func (h *helper) handleRefreshAllowIP(sess *session, req *netdwire.Request) *netdwire.Reply {
	h.mu.Lock()
	armed := sess.killSwitchArmed
	h.mu.Unlock()
	if !armed {
		// Best-effort by contract: a no-op when the kill-switch is not armed.
		return &netdwire.Reply{OK: true}
	}
	addr, err := netip.ParseAddr(req.IP)
	if err != nil || !addr.Is4() {
		return netdwire.Failf(netdwire.CodeBadRequest, "not an IPv4 address: %q", req.IP)
	}

	c, err := dialNftables()
	if err != nil {
		h.log("netfilter socket: %v", err)
		return &netdwire.Reply{OK: true}
	}
	defer c.Close()
	if err := c.refreshAllowIP(addr); err != nil {
		h.log("could not add %v to the live allowlist: %v", addr, err)
	}
	return &netdwire.Reply{OK: true}
}

// handleCaptureDNS points the machine's resolver at the tunnel.
//
// It refuses before the TUN is configured rather than deferring, because the
// address it points the resolver at is derived from the TUN's own — a capture
// installed earlier would name an address that is not yet on any interface,
// and the failure would show up as "DNS silently does not work" rather than as
// a refused request.
func (h *helper) handleCaptureDNS(sess *session) *netdwire.Reply {
	if err := h.captureDNS(sess); err != nil {
		return netdwire.Failf(netdwire.CodeInternal, "capture DNS: %v", err)
	}
	h.log("DNS captured for uid %d", sess.uid)
	return &netdwire.Reply{OK: true}
}

// handleReleaseDNS restores it. Always succeeds: the restore is best-effort by
// contract on the client side too (osnet_linux.go's releaseDNS is silent), and
// there is nothing a client could usefully do with a failure that this process
// has not already logged.
func (h *helper) handleReleaseDNS(sess *session) *netdwire.Reply {
	h.releaseDNS(sess)
	return &netdwire.Reply{OK: true}
}

// handleAllowServedEgress carves this machine's own egress out of the tunnel so
// a volunteered relay or exit can serve while the device is routed (ADR-0053,
// bacchus#109), and answers with the address the client's served sockets must
// bind for it to apply to them.
//
// The gateway is re-read here rather than taken from sess.gw. That is not
// caution about staleness — handleExclusionRoutes is happy with the cached one
// — it is that this handler needs something the cache does not hold: the
// interface's own ADDRESS, which is a second lookup on the index the read
// returns. Doing both at once keeps the index and the address from disagreeing
// if the machine roamed between them.
//
// It returns an error rather than succeeding quietly when there is no routable
// address to bind, and that is the fail-closed direction: a client told "served
// egress is carved out" that then binds nothing would egress through the tunnel
// under the upstream exit's address, with the exit checkbox's disclosure saying
// otherwise. Refusing here fails the connect instead, which is bacchus#109's
// whole point.
// The carve-out must be taken out BEFORE the kill-switch is armed, and this
// refuses rather than reorders when it is not. The filter allowance is built
// into the same transaction as the drop policy (nft.go), so the set it looks up
// does not exist on a lockdown armed without one — meaning a carve-out granted
// afterwards would install a route whose traffic the volunteer's own kill-switch
// then drops. Refusing says so; succeeding would leave an exit that is
// advertised, routed, and silently unable to answer. tunnel.go's bring-up
// already arms last, so nothing in-tree reaches this.
func (h *helper) handleAllowServedEgress(sess *session) *netdwire.Reply {
	h.mu.Lock()
	armed := sess.killSwitchArmed
	h.mu.Unlock()
	if armed {
		return netdwire.Failf(netdwire.CodeBadRequest,
			"served egress must be carved out before the kill-switch is armed, not after")
	}

	var src netip.Addr
	err := h.nl.do(func(c *nlConn) error {
		gw, err := c.defaultGateway()
		if err != nil {
			return err
		}
		src, err = physicalSource(gw)
		if err != nil {
			return err
		}
		return c.addServedRule(src, sess.uid)
	})
	if err != nil {
		return netdwire.Failf(netdwire.CodeInternal, "carve served egress out of the tunnel: %v", err)
	}

	h.mu.Lock()
	sess.servedSrc = src
	h.mu.Unlock()

	h.log("served egress carved out for uid %d under %s", sess.uid, src)
	return &netdwire.Reply{OK: true, ServedSource: src.String()}
}

// handleRevokeServedEgress puts it back. Silent by contract on the client side
// (osnet_linux.go), so this always reports success and logs what went wrong.
func (h *helper) handleRevokeServedEgress(sess *session) *netdwire.Reply {
	h.revokeServedEgress(sess)
	return &netdwire.Reply{OK: true}
}

// revokeServedEgress withdraws the carve-out: the fib rule first, then the
// filter allowance.
//
// That order is the fail-closed one and it is not interchangeable. Dropping the
// route first means the served traffic has nowhere to go the moment the
// allowance is still there; dropping the allowance first would leave a window
// where the route still carries traffic the lockdown now blocks — which is
// harmless — but also one where a revoke that fails halfway leaves a live route
// with no allowance rather than an allowance with no route. Both halves are
// best-effort, so which residue a partial failure leaves is a real choice: a
// route to nowhere leaks nothing, a hole in the filter does.
func (h *helper) revokeServedEgress(sess *session) {
	h.mu.Lock()
	src := sess.servedSrc
	sess.servedSrc = netip.Addr{}
	h.mu.Unlock()
	if !src.IsValid() {
		return
	}

	if err := h.nl.do(func(c *nlConn) error { return c.delServedRule() }); err != nil {
		h.log("could not remove the served-egress rule: %v", err)
	}

	c, err := dialNftables()
	if err != nil {
		h.log("netfilter socket: %v", err)
		return
	}
	defer c.Close()
	if err := c.revokeServedEgress(src); err != nil {
		h.log("could not withdraw the served-egress allowance: %v", err)
	}
}

// -------------------------------------------------------------------------
// Parsing: every string from the client stops here
// -------------------------------------------------------------------------

// parsePrefixes turns the client's strings into typed prefixes, dropping any
// that do not belong to the requested family. Anything unparseable is a refusal
// rather than a skip: ADR-0049 §3.3 makes parsing the boundary, and silently
// dropping an entry would leave the client believing a destination is excluded
// when nothing excludes it.
func parsePrefixes(entries []string, wantV6 bool) ([]netip.Prefix, *netdwire.Reply) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		addr, prefix, err := parseHostOrPrefix(e)
		if err != nil {
			return nil, netdwire.Failf(netdwire.CodeBadRequest, "prefix %q: %v", e, err)
		}
		if addr.IsValid() {
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		if prefix.Addr().Is6() != wantV6 {
			continue
		}
		out = append(out, prefix)
	}
	return out, nil
}

// parseHostOrPrefix accepts a bare address or a CIDR, and returns exactly one
// of them. netip.Parse* rather than any string manipulation: the parsed value
// is what reaches netlink, and there is no path by which the original string
// becomes part of an instruction.
func parseHostOrPrefix(s string) (netip.Addr, netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, netip.Prefix{}, errors.New("empty")
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), netip.Prefix{}, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, errors.New("not an IP address or CIDR")
	}
	return netip.Addr{}, p.Masked(), nil
}

func addrOrEmpty(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// subtleCompare is a constant-time string comparison returning 1 on equality.
func subtleCompare(a, b string) int {
	if len(a) != len(b) {
		return 0
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	if v == 0 {
		return 1
	}
	return 0
}
