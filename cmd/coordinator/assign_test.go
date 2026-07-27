package main

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// Country-scoped exit assignment (issue #146) and country-granularity backpressure
// (issue #147), ADR-0042.

// loadExit fabricates n live sessions against an exit, the way real connects would, so
// a test can put an exit under load without standing up n clients.
func loadExit(t *testing.T, exitID string, n int) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < n; i++ {
		sessions[exitID+"-s"+string(rune('a'+i))] = &session{exitID: exitID, lastSeen: time.Now()}
	}
}

// TestConnectNamesACountryAndTheReplyNamesTheChosenExit is the shape of #146: the client
// asks for a place, the coordinator answers with a node. The exit id on the reply is not
// informational — an exit's id IS its Noise static public key (ADR-0009), so without it
// the client cannot bring up the end-to-end channel at all.
func TestConnectNamesACountryAndTheReplyNamesTheChosenExit(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, client := fakePeer(t), fakePeer(t)

	registerExit("e1", "NL", "203.0.113.10:20000", exit)

	connectCountry("NL", "direct", client)
	reply := recvWire(t, client, time.Second)
	if reply.Type != "session" {
		t.Fatalf("connect by country replied %q (%s), want a session", reply.Type, reply.Reason)
	}
	if reply.ExitID != "e1" {
		t.Errorf("session reply ExitID = %q; want e1 — without it the client cannot key its Noise handshake", reply.ExitID)
	}
	// The session is attributed to the exit, which is what makes load observable.
	mu.Lock()
	defer mu.Unlock()
	s := sessions[reply.Session]
	if s == nil || s.exitID != "e1" {
		t.Errorf("session is not attributed to the chosen exit: %+v", s)
	}
}

// TestEveryPairingPathNamesTheChosenExit covers all THREE session-reply sites at once —
// direct, peer-relay, and the TURN fallback.
//
// One test per path is not the same as this test. A client falls through the paths in
// order, so a reply site that quietly stopped carrying the exit id would be masked by
// the next one succeeding: an end-to-end test still sees a working connection, just via
// a different disposition. (Exactly that happened here — a mutation removing ExitID
// from the direct reply was caught by nothing, because the client fell through to the
// TURN fallback and connected anyway.) Enumerating the sites in one place is what makes
// each individually load-bearing.
func TestEveryPairingPathNamesTheChosenExit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      string
		withRelay bool
		wantRelay string
	}{
		{name: "direct", mode: "direct"},
		{name: "peer relay", mode: "relay", withRelay: true, wantRelay: relayPeer},
		{name: "TURN fallback", mode: "relay", wantRelay: relayTURN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetRegistry(t)
			setPC(t)
			exit, client := fakePeer(t), fakePeer(t)
			registerExit("e1", "NL", "203.0.113.10:20000", exit)
			if tc.withRelay {
				registerRelay("r1", fakePeer(t))
			}

			connectCountry("NL", tc.mode, client)
			reply := recvWire(t, client, time.Second)
			if reply.Type != "session" {
				t.Fatalf("connect replied %q (%s), want a session", reply.Type, reply.Reason)
			}
			if reply.Relay != tc.wantRelay {
				t.Fatalf("relay disposition = %q, want %q — this case is not exercising the path it claims to", reply.Relay, tc.wantRelay)
			}
			if reply.ExitID != "e1" {
				t.Errorf("session reply on the %s path omitted the exit id (%q); an exit's id IS its Noise static key, so the client cannot open a stream without it", tc.name, reply.ExitID)
			}
		})
	}
}

// TestExactExitPinningIsGone: a connect that names an exit and no country gets nothing.
// This is #146's central removal — no pinning for anyone, not as a tier perk (the §5.1
// "stable can pin an exit" reward is superseded) and not as a debug affordance.
func TestExactExitPinningIsGone(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, client := fakePeer(t), fakePeer(t)

	registerExit("e1", "NL", "203.0.113.10:20000", exit)

	// The pre-#146 request shape, verbatim: an exit id, no country.
	handle(wire{Type: "connect", ExitID: "e1", Mode: "direct"}, client.LocalAddr().(*net.UDPAddr))
	reply := recvWire(t, client, time.Second)
	if reply.Type != "error" {
		t.Fatalf("a connect naming an exit id was honoured (%q); pinning must be gone from the wire", reply.Type)
	}
	if reply.Reason != string(refuseNoCountry) {
		t.Errorf("refusal reason = %q; want %q", reply.Reason, refuseNoCountry)
	}
	// Non-vacuity: the same exit IS reachable by naming its country, so the refusal
	// above is about the request shape and not about a broken fixture.
	connectCountry("NL", "direct", client)
	if reply := recvWire(t, client, time.Second); reply.Type != "session" {
		t.Fatalf("control: naming the country did not work either (%q) — the fixture is broken", reply.Type)
	}
}

// TestAssignmentPrefersTheRoomierExit: the load term discriminates. Both exits declare
// nothing and are unrated, so they tie on capacity — and today that is every exit in the
// fleet — leaving the session count, which this coordinator observed itself, as the only
// thing separating them.
func TestAssignmentPrefersTheRoomierExit(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	busyPeer, idlePeer := fakePeer(t), fakePeer(t)

	registerExit("busy", "NL", "203.0.113.10:20000", busyPeer)
	registerExit("idle", "NL", "203.0.113.11:20000", idlePeer)
	loadExit(t, "busy", 4) // 4 sessions: more than an octave worse than idle

	// Repeated, because the choice among indistinguishable candidates is random: the
	// loaded exit must never win, not merely usually lose.
	for i := 0; i < 40; i++ {
		e, refusal := chooseExit("NL", nil, time.Now())
		if refusal != refuseNone {
			t.Fatalf("chooseExit refused with %q", refusal)
		}
		if e.id != "idle" {
			t.Fatalf("chose the loaded exit %q on attempt %d; the load term is not ranking", e.id, i)
		}
	}

	// Self-correction: once the idle exit carries comparable load, it stops being the
	// automatic winner. This is the property that keeps ranking from piling every
	// client onto one node.
	loadExit(t, "idle", 4)
	seen := map[string]bool{}
	for i := 0; i < 60; i++ {
		e, _ := chooseExit("NL", nil, time.Now())
		seen[e.id] = true
	}
	if len(seen) != 2 {
		t.Errorf("with both exits equally loaded only %v was ever chosen; equally-roomy exits must share", seen)
	}
}

// TestChooseExitDoesNotConcentrateOnOneNode guards ADR-0033's prohibition, carried over
// to exits: a DETERMINISTIC best-node pick would let a node collect every client's
// source address and timing, and would defeat cross-coordinator failover because every
// pool member would keep handing back the same node.
func TestChooseExitDoesNotConcentrateOnOneNode(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	a, b, c := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit("e-a", "NL", "203.0.113.10:20000", a)
	registerExit("e-b", "NL", "203.0.113.11:20000", b)
	registerExit("e-c", "NL", "203.0.113.12:20000", c)

	seen := map[string]int{}
	for i := 0; i < 300; i++ {
		e, refusal := chooseExit("NL", nil, time.Now())
		if refusal != refuseNone {
			t.Fatalf("chooseExit refused with %q", refusal)
		}
		seen[e.id]++
	}
	if len(seen) != 3 {
		t.Errorf("over 300 picks among three indistinguishable exits only %d distinct were chosen (%v); the pick is deterministic", len(seen), seen)
	}
}

// mintSessionFor fabricates a session assigned to exitID and held by client, as a real
// connect would, and returns its id. It is what a client later names in
// ExcludeSessions — a client can only exclude an exit it was actually given, so a test
// of exclusion has to go through an assignment to get one.
func mintSessionFor(t *testing.T, exitID string, client *net.UDPAddr) string {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	sid := "sid-" + exitID + "-" + client.String()
	sessions[sid] = &session{client: client, exitID: exitID, lastSeen: time.Now()}
	return sid
}

// TestExcludeSkipsTheExitAClientJustFailedOn: the retry path still works. A client that
// failed against an exit and names THAT SESSION is not handed the same exit again —
// the ADR-0035 relay-dedupe idea applied to exits.
func TestExcludeSkipsTheExitAClientJustFailedOn(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	a, b, c := fakePeer(t), fakePeer(t), fakePeer(t)
	client := fakePeer(t).LocalAddr().(*net.UDPAddr)

	registerExit("e-a", "NL", "203.0.113.10:20000", a)
	registerExit("e-b", "NL", "203.0.113.11:20000", b)
	registerExit("e-c", "NL", "203.0.113.12:20000", c)

	failed := mintSessionFor(t, "e-a", client)
	for i := 0; i < 60; i++ {
		e, refusal := chooseExit("NL", excludedExits(client, []string{failed}), time.Now())
		if refusal != refuseNone {
			t.Fatalf("chooseExit refused with %q while two non-excluded exits existed", refusal)
		}
		if e.id == "e-a" {
			t.Fatalf("returned the excluded exit e-a on attempt %d", i)
		}
	}
}

// TestExclusionCannotPinByNamingTheComplement is the security property, and the reason
// exclusion is expressed in sessions rather than exit ids.
//
// A client that could exclude by ID could name every exit but the one it wants and get
// that one deterministically — exact-exit pinning rebuilt out of its complement,
// undoing #146's central removal. Two independent guards stop it, and this asserts
// both from the outside: whatever a client sends, it must not be able to force a
// specific exit.
func TestExclusionCannotPinByNamingTheComplement(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	a, b, c := fakePeer(t), fakePeer(t), fakePeer(t)
	client := fakePeer(t).LocalAddr().(*net.UDPAddr)

	registerExit("e-a", "NL", "203.0.113.10:20000", a)
	registerExit("e-b", "NL", "203.0.113.11:20000", b)
	registerExit("e-c", "NL", "203.0.113.12:20000", c)

	// The strongest position the attacker can reach: it has actually been assigned,
	// and still holds, every exit except its target. Naming those sessions is the
	// most exclusion the protocol permits it to express.
	target := "e-c"
	held := []string{mintSessionFor(t, "e-a", client), mintSessionFor(t, "e-b", client)}

	seen := map[string]int{}
	for i := 0; i < 300; i++ {
		e, refusal := chooseExit("NL", excludedExits(client, held), time.Now())
		if refusal != refuseNone {
			t.Fatalf("chooseExit refused with %q; excluding must degrade to an ordinary assignment, not a refusal", refusal)
		}
		seen[e.id]++
	}
	if len(seen) < 2 {
		t.Fatalf("excluding all but %s produced only %v over 300 picks — exclusion is a pin", target, seen)
	}
	if seen[target] == 300 {
		t.Fatalf("every one of 300 picks returned the target %s; the exclusion floor is not holding", target)
	}
}

// TestExclusionIsIgnoredWhenItWouldLeaveNoChoice pins the floor directly: honouring an
// exclusion that would leave a single assignable exit is refused, and the exclusion is
// dropped WHOLE rather than partially applied.
//
// It must not refuse the connect. Refusing would tell the client its exclusion crossed
// the threshold, which is a one-bit oracle on how many assignable exits the country
// holds; repeated, it counts them.
func TestExclusionIsIgnoredWhenItWouldLeaveNoChoice(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	a, b := fakePeer(t), fakePeer(t)
	client := fakePeer(t).LocalAddr().(*net.UDPAddr)

	registerExit("e-a", "NL", "203.0.113.10:20000", a)
	registerExit("e-b", "NL", "203.0.113.11:20000", b)

	// Excluding one of two leaves one — below minCandidatesAfterExclude — so the
	// exclusion is dropped and both exits stay in play.
	held := []string{mintSessionFor(t, "e-a", client)}
	seen := map[string]int{}
	for i := 0; i < 300; i++ {
		e, refusal := chooseExit("NL", excludedExits(client, held), time.Now())
		if refusal != refuseNone {
			t.Fatalf("chooseExit refused with %q; a dropped exclusion must assign normally, never refuse", refusal)
		}
		seen[e.id]++
	}
	if seen["e-a"] == 0 {
		t.Errorf("the excluded exit was never returned over 300 picks (%v); with only one survivor the exclusion should have been dropped whole", seen)
	}

	// Non-vacuity: add a third exit and the very same exclusion IS honoured, so the
	// above is about the floor and not about exclusion being broken outright.
	c := fakePeer(t)
	registerExit("e-c", "NL", "203.0.113.12:20000", c)
	for i := 0; i < 60; i++ {
		e, _ := chooseExit("NL", excludedExits(client, held), time.Now())
		if e.id == "e-a" {
			t.Fatalf("with three exits the exclusion of e-a must be honoured, but it was returned on attempt %d", i)
		}
	}
}

// TestExclusionOnlyHonoursTheClientsOwnSessions: a session id names an exclusion only
// for the client that session was minted for. Without the binding, one client could
// name another's session — discovering, and steering around, an exit it was never
// given.
func TestExclusionOnlyHonoursTheClientsOwnSessions(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	a, b, c := fakePeer(t), fakePeer(t), fakePeer(t)
	owner := fakePeer(t).LocalAddr().(*net.UDPAddr)
	stranger := fakePeer(t).LocalAddr().(*net.UDPAddr)

	registerExit("e-a", "NL", "203.0.113.10:20000", a)
	registerExit("e-b", "NL", "203.0.113.11:20000", b)
	registerExit("e-c", "NL", "203.0.113.12:20000", c)

	sid := mintSessionFor(t, "e-a", owner)

	if got := excludedExits(owner, []string{sid}); !got["e-a"] {
		t.Fatalf("the session's own client could not exclude through it: %v", got)
	}
	if got := excludedExits(stranger, []string{sid}); len(got) != 0 {
		t.Errorf("a different client excluded through someone else's session: %v", got)
	}
	// An unknown session id excludes nothing, rather than erroring — a reaped session
	// degrades to no exclusion, which is an ordinary assignment.
	if got := excludedExits(owner, []string{"no-such-session"}); len(got) != 0 {
		t.Errorf("an unknown session id produced an exclusion: %v", got)
	}
}

// TestExclusionListIsCapped: the length bound is a resource guard, so one datagram
// cannot make this coordinator build an arbitrarily large set. The security property
// is the session binding above, not this.
func TestExclusionListIsCapped(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	client := fakePeer(t).LocalAddr().(*net.UDPAddr)

	var sids []string
	for i := 0; i < maxExcludeSessions+3; i++ {
		id := "e-" + string(rune('a'+i))
		peer := fakePeer(t)
		registerExit(id, "NL", "203.0.113.10:20000", peer)
		sids = append(sids, mintSessionFor(t, id, client))
	}
	if got := excludedExits(client, sids); len(got) > maxExcludeSessions {
		t.Errorf("excludedExits honoured %d sessions; the cap is %d", len(got), maxExcludeSessions)
	}
	// Non-vacuity: a list at the cap is honoured in full, so the cap truncates rather
	// than discarding.
	if got := excludedExits(client, sids[:maxExcludeSessions]); len(got) != maxExcludeSessions {
		t.Errorf("a list exactly at the cap honoured only %d of %d", len(got), maxExcludeSessions)
	}
}

// TestUnknownCountryAndBusyCountryAreDistinguished: #147 requires the client be able to
// tell "busy, try another country" from "that country does not exist", because they call
// for different behaviour. Both facts are already in the country list the same client
// just fetched, so naming them reveals nothing new.
func TestUnknownCountryAndBusyCountryAreDistinguished(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	full1, full2, client := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExitLimits("f1", "NL", "203.0.113.10:20000", 0, quotaExhausted, full1)
	registerExitLimits("f2", "NL", "203.0.113.11:20000", 0, quotaExhausted, full2)

	connectCountry("NL", "direct", client)
	reply := recvWire(t, client, time.Second)
	if reply.Reason != string(refuseCountryBusy) || reply.Country != "NL" {
		t.Errorf("a country whose every exit is exhausted refused with (%q, %q); want (%q, NL)", reply.Reason, reply.Country, refuseCountryBusy)
	}

	connectCountry("FR", "direct", client)
	reply = recvWire(t, client, time.Second)
	if reply.Reason != string(refuseNoCountry) {
		t.Errorf("an unknown country refused with %q; want %q", reply.Reason, refuseNoCountry)
	}

	// A malformed country is answered the same way an unknown one is: there is nothing
	// to be busy about.
	connectCountry("Netherlands", "direct", client)
	if reply := recvWire(t, client, time.Second); reply.Reason != string(refuseNoCountry) {
		t.Errorf("a malformed country refused with %q; want %q", reply.Reason, refuseNoCountry)
	}
}

// TestBusyCountryStaysInTheList is the difference #147 depends on. The pre-#146 list
// dropped a withheld exit entirely; a country that vanishes cannot be labelled busy, so
// the user would see it disappear rather than be told to try another.
func TestBusyCountryStaysInTheList(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	spent, client := fakePeer(t), fakePeer(t)

	registerExitLimits("e1", "NL", "203.0.113.10:20000", 0, quotaExhausted, spent)

	requestList(client)
	reply := recvWire(t, client, time.Second)
	info, ok := countryIn(reply, "NL")
	if !ok {
		t.Fatalf("a fully-exhausted country vanished from the list: %+v — it cannot be reported busy", reply.Countries)
	}
	if !info.Busy || info.Available != 0 || info.Exits != 1 {
		t.Errorf("country entry = %+v; want 1 exit, 0 available, busy", info)
	}
}

// TestCountryListRevealsNoExitIdentities pins the privacy half of #146: pinning was a
// small tracking handle, and the per-exit list was the raw material for it. The
// aggregate must carry counts, never identities.
func TestCountryListRevealsNoExitIdentities(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	a, b, client := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit("secret-exit-alpha", "NL", "203.0.113.10:20000", a)
	registerExit("secret-exit-beta", "NL", "203.0.113.11:20000", b)

	requestList(client)
	reply := recvWire(t, client, time.Second)
	wantCountry(t, reply, "NL", 2, 2)

	// Assert on the ENCODED datagram, not the struct: a field added later that leaks an
	// id would slip past a field-by-field check.
	raw, err := json.Marshal(reply)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, id := range []string{"secret-exit-alpha", "secret-exit-beta"} {
		if strings.Contains(string(raw), id) {
			t.Errorf("exit id %q appears in the list reply: %s", id, raw)
		}
	}
	// The exits' advertised addresses must not leak either.
	if strings.Contains(string(raw), "203.0.113.") {
		t.Errorf("an exit address appears in the list reply: %s", raw)
	}
}

// TestPingIsAnUnfedSeam states the honest position on #146's per-country ping: the field
// exists so a client can render it the moment it is fed, and it carries nothing today
// because the only honest source is the clients themselves, whose reporting path is not
// in this lane. A number derived from something else — this coordinator's own RTT to
// each exit — would look plausible and measure the wrong thing.
func TestPingIsAnUnfedSeam(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, client := fakePeer(t), fakePeer(t)

	registerExit("e1", "NL", "203.0.113.10:20000", exit)
	requestList(client)
	reply := recvWire(t, client, time.Second)

	info, _ := countryIn(reply, "NL")
	if info.PingMs != 0 {
		t.Errorf("PingMs = %d; want 0 — the seam is unfed and must not be filled with a proxy", info.PingMs)
	}
	// Being omitempty, an unfed ping must not even appear on the wire.
	raw, _ := json.Marshal(reply)
	if strings.Contains(string(raw), "pingMs") {
		t.Errorf("pingMs present on the wire while unfed: %s", raw)
	}
}

// TestShareFullnessGateWouldRefuseIfEnabled proves #147's share-based trigger is real
// machinery rather than dead code, and — with the SAME fixture — that it is off as
// shipped. It is the mirror of TestServeFloorGateWouldExcludeIfEnabled.
func TestShareFullnessGateWouldRefuseIfEnabled(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	p := setRatings(t)
	exit, client := fakePeer(t), fakePeer(t)

	// An exit with a DECLARED cap, measured, and carrying load: the only shape the
	// share test can bite on.
	registerExitLimits("e1", "NL", "203.0.113.10:20000", uint64(p.Ceiling), quotaOK, exit)
	feedUntrustedToCeiling(t, "e1", p)
	loadExit(t, "e1", 4)

	// As shipped (minShare zero): assignable.
	if e, refusal := chooseExit("NL", nil, time.Now()); e == nil || refusal != refuseNone {
		t.Fatalf("with minShare at its shipped zero, a loaded exit was refused: (%v, %q)", e, refusal)
	}
	requestList(client)
	wantCountry(t, recvWire(t, client, time.Second), "NL", 1, 1)

	// Enabled with a floor the loaded exit cannot meet: refused, and the country reads
	// busy. The floor is deliberately far above ceiling/(4+1) rather than computed from
	// it, so this cannot silently pass by arithmetic coincidence.
	minShare = p.Ceiling
	t.Cleanup(func() { minShare = 0 })

	if e, refusal := chooseExit("NL", nil, time.Now()); e != nil || refusal != refuseCountryBusy {
		t.Errorf("with the share floor raised, chooseExit returned (%v, %q); want a country-busy refusal — the gate is dead code", e, refusal)
	}
	requestList(client)
	wantCountry(t, recvWire(t, client, time.Second), "NL", 1, 0)
}

// TestUncappedAndUNRATEDExitIsNeverFull — and, critically, that a RATED one is not
// exempt.
//
// The opt-in promise declared limits make (#143) covers an operator who declared
// nothing AND about whom nothing is known. It is narrower than it reads, because
// RatingStore.Usable(0, measured) returns `measured`: a declared zero means "uncapped"
// and does not survive a measurement. So an exit that declared nothing but has
// received any capacity report is rated, carries a finite usable rate, and IS subject
// to the share floor — which under ADR-0041 ("measurement IS serving") is the whole
// serving fleet.
//
// The second half is the one that matters. The earlier version of this test asserted
// only the first, and passed while never feeding a rating — so it would have gone on
// passing if the exemption had silently widened to cover every exit, which is exactly
// the claim ADR-0042 used to make and which was false.
func TestUncappedAndUnratedExitIsNeverFullButARatedOneIs(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	unrated, rated := fakePeer(t), fakePeer(t)

	p := setRatings(t)
	registerExit("unrated", "NL", "203.0.113.10:20000", unrated) // declares nothing, measured never
	registerExit("rated", "SE", "203.0.113.11:20000", rated)     // declares nothing, but measured
	loadExit(t, "unrated", 50)
	loadExit(t, "rated", 50)
	feedUntrustedToCeiling(t, "rated", p)

	// A floor equal to the whole ceiling: unmeetable by any exit carrying even one
	// session, since a share is ceiling/(n+1). Taken from the params rather than
	// computed from the exit's own rating, so the assertion is not derived from the
	// value under test.
	minShare = p.Ceiling
	t.Cleanup(func() { minShare = 0 })

	if e, refusal := chooseExit("NL", nil, time.Now()); e == nil || refusal != refuseNone {
		t.Errorf("an uncapped, UNRATED exit was refused under a raised share floor: (%v, %q); declared limits are opt-in", e, refusal)
	}
	if e, refusal := chooseExit("SE", nil, time.Now()); e != nil || refusal != refuseCountryBusy {
		t.Errorf("an uncapped but RATED exit survived a floor it cannot meet: (%v, %q); raising minShare DOES reach the measured fleet", e, refusal)
	}
}

// TestRankingDecaysUniformlyAcrossDispositions is the reaper/ranking interaction, and
// the one that pins what the load term actually measures.
//
// `sessions` is a signaling-rendezvous cache, not a tunnel registry: nothing refreshes
// lastSeen once ICE gathering finishes, so a live tunnel goes quiet and ages out.
// Ranking is therefore near-uniform in steady state, which is survivable — but only if
// it is uniform. prune EXEMPTS peer-relay sessions (their liveness is their relay's),
// so counting the raw map gave a relay-serving exit a permanent load figure while its
// direct-serving neighbour read zero, systematically deprioritising exactly the exits
// carrying relayed traffic.
//
// Both halves are asserted. The second fails against a count that reads the map
// directly.
func TestRankingDecaysUniformlyAcrossDispositions(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	directPeer, relayedPeer := fakePeer(t), fakePeer(t)

	registerExit("direct-exit", "NL", "203.0.113.10:20000", directPeer)
	registerExit("relayed-exit", "NL", "203.0.113.11:20000", relayedPeer)

	now := time.Now()
	mu.Lock()
	sessions["s-direct"] = &session{exitID: "direct-exit", lastSeen: now}
	// relayID set: prune deliberately never reaps this one (issue #96/#105).
	sessions["s-relayed"] = &session{exitID: "relayed-exit", relayID: "r1", lastSeen: now}
	mu.Unlock()

	if load := exitSessions(now); load["direct-exit"] != 1 || load["relayed-exit"] != 1 {
		t.Fatalf("fresh sessions on both paths counted %v; want 1 each — relay-mode load must be observable too", load)
	}

	// One sessionTTL later, with neither session having sent further signaling — the
	// steady state of a healthy tunnel.
	later := now.Add(sessionTTL + time.Second)
	load := exitSessions(later)
	if load["direct-exit"] != 0 {
		t.Errorf("a silent direct session still counted after sessionTTL: %v", load)
	}
	if load["relayed-exit"] != 0 {
		t.Errorf("a silent PEER-RELAY session still counted after sessionTTL (%v) — it survives prune by design, so ranking must apply its own recency bound or relay-serving exits are permanently deprioritised", load)
	}

	// And the consequence: neither exit is favoured over the other once both have
	// decayed, so a relay-serving exit is not sunk beneath a direct-serving one.
	seen := map[string]int{}
	for i := 0; i < 300; i++ {
		e, refusal := chooseExit("NL", nil, later)
		if refusal != refuseNone {
			t.Fatalf("chooseExit refused with %q", refusal)
		}
		seen[e.id]++
	}
	if len(seen) != 2 {
		t.Errorf("after both sessions decayed only %v was ever chosen; the relay-serving exit is being deprioritised", seen)
	}
}

// TestRelayModeAlsoAttributesTheSessionToItsExit: load must be observable on every
// path, not only the direct one, or a peer-relayed fleet would look permanently idle
// and the ranking would stop working exactly where relays are used.
func TestRelayModeAlsoAttributesTheSessionToItsExit(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, relay, client := fakePeer(t), fakePeer(t), fakePeer(t)

	registerExit("e1", "NL", "203.0.113.10:20000", exit)
	registerRelay("r1", relay)

	connectCountry("NL", "relay", client)
	reply := recvWire(t, client, time.Second)
	if reply.Relay != relayPeer {
		t.Fatalf("setup: relay disposition = %q, want %q", reply.Relay, relayPeer)
	}
	if reply.ExitID != "e1" {
		t.Errorf("a peer-relay session reply omitted the exit id (%q); the client still terminates E2E at the exit", reply.ExitID)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := exitSessions(time.Now())["e1"]; got != 1 {
		t.Errorf("exit load after a peer-relay connect = %d; want 1 — relay-mode sessions must count too", got)
	}
}
