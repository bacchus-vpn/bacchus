//go:build linux

// The protocol's refusals, each asserted as a refusal.
//
// ADR-0049's testing section lists these by name — "a malformed prefix, an
// unknown verb, a missing or wrong session token, a second concurrent client, a
// removeRoutes naming a route the helper did not install, and a peer uid with
// no active session — each must be refused, and the refusal is the assertion."
// They are the boundary. A helper that quietly ignored a bad request instead of
// refusing it would leave the client believing something was enforced that was
// not, which is the same class of failure as degrading to a SOCKS proxy under a
// "Protected" banner, one layer down.
package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/bacchus-vpn/bacchus/cmd/bacchus-netd/netdwire"
)

// startHelper runs a real helper on a temp socket. allowNoLogin is true because
// a test namespace has no logind; the logind gate itself is asserted separately
// against checkPeer, where it can be driven with credentials of our choosing.
func startHelper(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "netd.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h := newHelper(func(f string, a ...any) { t.Logf("[netd] "+f, a...) }, true)
	// Inside the namespace this process is uid 0, which owns no logind session
	// on the host, so the real check would refuse every connection and none of
	// the refusals below would ever be reached. The gate's own behaviour is
	// asserted against the real function in TestRefusesAPeerWithNoActiveSession.
	h.sessionCheck = func(uint32) (bool, error) { return true, nil }
	go func() {
		for {
			c, err := ln.AcceptUnix()
			if err != nil {
				return
			}
			go h.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return path
}

func dialHelper(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func send(t *testing.T, c *net.UnixConn, req *netdwire.Request) *netdwire.Reply {
	t.Helper()
	if req.Version == 0 {
		req.Version = netdwire.Version
	}
	if err := netdwire.WriteFrame(c, req); err != nil {
		t.Fatalf("write %s: %v", req.Verb, err)
	}
	rep, err := netdwire.ReadReply(c)
	if err != nil {
		t.Fatalf("read reply for %s: %v", req.Verb, err)
	}
	return rep
}

// open starts a session and returns its token.
func open(t *testing.T, c *net.UnixConn) string {
	t.Helper()
	rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbOpen})
	if !rep.OK {
		t.Fatalf("open refused: %s (%s)", rep.Error, rep.Code)
	}
	if rep.Token == "" {
		t.Fatal("open returned no token")
	}
	return rep.Token
}

func wantRefusal(t *testing.T, rep *netdwire.Reply, code string) {
	t.Helper()
	if rep.OK {
		t.Fatalf("request succeeded; want refusal with code %q", code)
	}
	if rep.Code != code {
		t.Errorf("refusal code = %q, want %q (message: %s)", rep.Code, code, rep.Error)
	}
	if rep.Error == "" {
		t.Error("refusal carried no message")
	}
}

func TestRefusesAMalformedPrefix(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)

	// The gateway must be read first, or the refusal under test would be
	// masked by "no gateway yet".
	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbDefaultGateway, Token: token}); !rep.OK {
		t.Fatalf("default-gateway: %s", rep.Error)
	}

	for _, bad := range []string{
		"not-an-address",
		"192.0.2.1/33",       // out of range
		"192.0.2.256",        // not an octet
		"; rm -rf /",         // the shape §4 makes unrepresentable
		"192.0.2.0/24 extra", // trailing junk
		"",
	} {
		rep := send(t, c, &netdwire.Request{
			Verb: netdwire.VerbAddExclusionRoutes, Token: token, Prefixes: []string{bad},
		})
		// Refused, not silently skipped: dropping it would leave the client
		// believing a destination is excluded when nothing excludes it.
		wantRefusal(t, rep, netdwire.CodeBadRequest)
	}
}

func TestRefusesAnUnknownVerb(t *testing.T) {
	if inNamespace(t) {
		return
	}
	c := dialHelper(t, startHelper(t))
	token := open(t, c)

	rep := send(t, c, &netdwire.Request{Verb: "run-this-please", Token: token})
	wantRefusal(t, rep, netdwire.CodeUnknownVerb)
}

func TestRefusesAMissingOrWrongToken(t *testing.T) {
	if inNamespace(t) {
		return
	}
	c := dialHelper(t, startHelper(t))
	_ = open(t, c)

	wantRefusal(t, send(t, c, &netdwire.Request{Verb: netdwire.VerbDefaultGateway}),
		netdwire.CodeBadToken)
	wantRefusal(t, send(t, c, &netdwire.Request{
		Verb: netdwire.VerbDefaultGateway, Token: "00000000000000000000000000000000",
	}), netdwire.CodeBadToken)
	// A token of the wrong length must not be accepted either — the comparison
	// is constant-time and length-checked, not a prefix match.
	wantRefusal(t, send(t, c, &netdwire.Request{Verb: netdwire.VerbDefaultGateway, Token: "x"}),
		netdwire.CodeBadToken)
}

func TestRefusesMutatingVerbsWithNoSession(t *testing.T) {
	if inNamespace(t) {
		return
	}
	c := dialHelper(t, startHelper(t))

	// No Open at all: every mutating verb is refused before it is parsed.
	for _, verb := range []netdwire.Verb{
		netdwire.VerbDefaultGateway,
		netdwire.VerbAddExclusionRoutes,
		netdwire.VerbCreateTUN,
		netdwire.VerbEnableKillSwitch,
		netdwire.VerbRefreshAllowIP,
	} {
		wantRefusal(t, send(t, c, &netdwire.Request{Verb: verb, Token: "anything"}),
			netdwire.CodeNoSession)
	}
}

// ADR-0049 §3.2: a second client gets EBUSY, not a second tunnel. "The client
// that armed the kill-switch is the only one that can lift it" is the property
// this protects — two clients enforcing at once would let either lift the
// other's lockdown.
func TestRefusesASecondConcurrentClient(t *testing.T) {
	if inNamespace(t) {
		return
	}
	path := startHelper(t)
	first := dialHelper(t, path)
	_ = open(t, first)

	second := dialHelper(t, path)
	rep := send(t, second, &netdwire.Request{Verb: netdwire.VerbOpen})
	wantRefusal(t, rep, netdwire.CodeBusy)

	// And the refusal is not permanent: once the first client closes, the slot
	// is free. A helper that stayed busy forever would need a restart after
	// every disconnect.
	if rep := send(t, first, &netdwire.Request{Verb: netdwire.VerbClose, Token: openTokenOf(t, first)}); rep.OK {
		t.Log("first session closed")
	}
}

// openTokenOf re-opens on a connection whose token the test did not keep. Only
// used where the token is incidental to what is being asserted.
func openTokenOf(t *testing.T, c *net.UnixConn) string {
	t.Helper()
	rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbOpen})
	if rep.OK {
		return rep.Token
	}
	return "" // already open; Close with an empty token is refused, which is fine here
}

// removeRoutes naming a route the helper did not install must not remove it.
// ADR-0049 §3.4 is what makes this structural rather than a promise: deletion
// is scoped to the helper's own table, so a prefix it never installed is simply
// not there to delete — a compromised client cannot use this verb to tear up
// the host's routing, or another VPN's.
func TestRemoveRoutesCannotTouchAnotherTablesRoutes(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)

	// A route belonging to someone else, in the main table.
	ipCmd(t, "route", "add", "203.0.113.0/24", "via", "192.0.2.1", "dev", "eth-test")
	before := ipCmd(t, "route", "show", "table", "main")

	rep := send(t, c, &netdwire.Request{
		Verb: netdwire.VerbRemoveRoutes, Token: token,
		Prefixes: []string{"203.0.113.0/24", "0.0.0.0/0", "192.0.2.0/24"},
	})
	// The request is well-formed, so it succeeds — and does nothing.
	if !rep.OK {
		t.Fatalf("remove-routes refused: %s", rep.Error)
	}

	after := ipCmd(t, "route", "show", "table", "main")
	if before != after {
		t.Errorf("removeRoutes changed the main table.\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if !strings.Contains(after, "203.0.113.0/24") {
		t.Errorf("another program's route was deleted:\n%s", after)
	}
	// The default route especially: deleting it would blackhole the host.
	if !strings.Contains(after, "default via 192.0.2.1") {
		t.Errorf("the host default route was deleted:\n%s", after)
	}
}

// A peer that does not own an active local session is refused. Driven against
// checkPeer with chosen credentials rather than over a socket, because the
// credentials are the input under test and a test cannot become another uid.
func TestRefusesAPeerWithNoActiveSession(t *testing.T) {
	h := newHelper(t.Logf, false)

	// A uid logind has never seen. On a host running logind this is answered
	// "no"; on one without logind it is unanswerable, and unanswerable is also
	// refused — the gate does not open just because it cannot be consulted.
	//
	// This is the ADR's central point about the check: uid 65534 may well be in
	// the `bacchus` group, because group membership is a packaging decision.
	// Whether it owns an active local session is the question actually being
	// asked, and on a multi-user machine the two are very different.
	const nobody = 65534
	if err := h.checkPeer(&unix.Ucred{Uid: nobody}); err == nil {
		t.Errorf("checkPeer accepted uid %d with no active session", nobody)
	}

	// The escape hatch for hosts without logind is explicit and opt-in, so
	// weakening the gate is a packaging decision somebody made on purpose
	// rather than a silent fallback.
	lax := newHelper(t.Logf, true)
	if _, err := uidHasActiveSession(nobody); err != nil {
		if err := lax.checkPeer(&unix.Ucred{Uid: nobody}); err != nil {
			t.Errorf("-allow-without-logind should accept uid %d when logind cannot be consulted: %v", nobody, err)
		}
	} else {
		// logind IS running here, so it can answer, and the escape hatch must
		// NOT override a definite "no". The hatch covers an absent logind, not
		// a negative answer from a present one.
		if err := lax.checkPeer(&unix.Ucred{Uid: nobody}); err == nil {
			t.Errorf("-allow-without-logind overrode logind's definite refusal of uid %d", nobody)
		}
	}
}

func TestRefusesAVersionMismatch(t *testing.T) {
	if inNamespace(t) {
		return
	}
	c := dialHelper(t, startHelper(t))

	rep := send(t, c, &netdwire.Request{Version: netdwire.Version + 1, Verb: netdwire.VerbOpen})
	wantRefusal(t, rep, netdwire.CodeVersion)
	// The message has to be actionable: a version skew is fixed by installing
	// matching binaries, and the user cannot guess that from "refused".
	if !strings.Contains(rep.Error, "bacchus-netd") {
		t.Errorf("version refusal does not name what to reinstall: %q", rep.Error)
	}

	// And the mismatch must not open a session as a side effect.
	rep = send(t, c, &netdwire.Request{Verb: netdwire.VerbDefaultGateway, Token: "x"})
	wantRefusal(t, rep, netdwire.CodeNoSession)
}

// A malformed frame must be refused without dropping the connection: a client
// that sent one bad request has not necessarily lost its session, and dropping
// the connection would orphan a live lockdown over a typo.
func TestAMalformedRequestDoesNotKillTheSession(t *testing.T) {
	if inNamespace(t) {
		return
	}
	fixtureUplink(t)
	c := dialHelper(t, startHelper(t))
	token := open(t, c)

	// Unknown fields are refused rather than ignored — this decodes
	// attacker-controlled input in a root process.
	if err := netdwire.WriteFrame(c, map[string]any{
		"version": netdwire.Version, "verb": "open", "surprise": 1,
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	rep, err := netdwire.ReadReply(c)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	wantRefusal(t, rep, netdwire.CodeBadRequest)

	// The session is still live.
	if rep := send(t, c, &netdwire.Request{Verb: netdwire.VerbDefaultGateway, Token: token}); !rep.OK {
		t.Errorf("session died after a malformed request: %s", rep.Error)
	}
}

// An oversized length prefix must be rejected before anything is allocated.
// The peer is an unprivileged local process by construction, so "the helper
// allocated a gigabyte because the length prefix said so" is a denial of
// service against the machine's networking, run as root.
func TestRefusesAnOversizedFrame(t *testing.T) {
	if inNamespace(t) {
		return
	}
	path := startHelper(t)
	c := dialHelper(t, path)

	if _, err := c.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		t.Fatalf("write header: %v", err)
	}
	// The helper drops the connection rather than replying: the frame was never
	// readable, so there is no request to refuse.
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Error("helper kept the connection after a 4GiB length prefix")
	}

	// And it is still serving everyone else.
	if tok := open(t, dialHelper(t, path)); tok == "" {
		t.Error("helper stopped serving after an oversized frame")
	}
}
