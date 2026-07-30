package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/capacity"
	"github.com/bacchus-vpn/bacchus/core/policy"
)

// Tier-limit enforcement (issue #58, ADR-0048).
//
// These tests are written to be MUTATION-CHECKED, which is the bar the issue sets:
// a tier system whose tests have never been seen to deny anything is not testing
// enforcement. Each of the three enforcement points names, in its own doc, the
// single edit that must make it fail — remove the priority scaling, the
// endpoint-quality floor, or the speed cap on the assignment, and exactly one named
// test below goes red.

// tierCred mints a client credential carrying a (trust, plan) pair.
//
// It builds and signs the Credential directly rather than calling admission.Issue,
// and that is the point rather than a shortcut: Issue deliberately does not stamp
// Trust or Plan, because nothing in this repository is the account service (see the
// Credential fields' docs). A test that could mint a tiered credential through the
// public issuer would be testing a capability this repo must not have.
func tierCred(t *testing.T, priv ed25519.PrivateKey, subject, trust, plan string) string {
	t.Helper()
	now := time.Now()
	c := admission.Credential{
		Version:   admission.CredentialVersion,
		Serial:    "00000000000000ff",
		Subject:   subject,
		Roles:     []admission.Role{admission.RoleClient},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Hour),
		Trust:     trust,
		Plan:      plan,
	}
	signed, err := admission.Sign(priv, c)
	if err != nil {
		t.Fatalf("sign credential: %v", err)
	}
	return admission.Encode(signed)
}

// tierPolicy installs the frozen fixture policy for one test. Its rows are the ones
// both repositories' conformance fixtures carry: ephemeral/"" at 10 Mbit / priority
// 1 / class 1, stable/"" at 50 Mbit / 5 / 2, stable/"pro" at 200 Mbit / 9 / 3.
func tierPolicy(t *testing.T) policy.Policy {
	t.Helper()
	p := fixturePolicy(t)
	if len(p.Tiers) == 0 {
		t.Fatal("fixture policy carries no tiers — these tests would prove nothing")
	}
	withPolicyState(t, true, &p)
	return p
}

// withExitClass feeds the endpoint-class oracle for one test. Production never sets
// it (see exitClass), so this is the only thing that can make the floor bite.
func withExitClass(t *testing.T, f func(string) (int, bool)) {
	t.Helper()
	prev := exitClass
	exitClass = f
	t.Cleanup(func() { exitClass = prev })
}

// withMinShare flips the network-wide fullness floor for one test, the same way
// TestServeFloorGateWouldExcludeIfEnabled flips serveFloor. Production ships it at
// zero, which makes the whole fullness test inert; without flipping it, priority
// cannot be observed to do anything at all.
func withMinShare(t *testing.T, r capacity.Rate) {
	t.Helper()
	prev := minShare
	minShare = r
	t.Cleanup(func() { minShare = prev })
}

// tierFix is the fixture nearly every test below needs: admission on, one exit
// registered in NL, a client peer, and the authority key both node and client
// credentials are minted from.
//
// It carries the private key because a test that registers a SECOND node has to mint
// that node's credential from the same authority — with admission enabled a register
// without one is rejected, which would silently leave the test with an empty registry
// and a refusal it would then misread as the behaviour under test.
type tierFix struct {
	priv   ed25519.PrivateKey
	exit   *net.UDPConn
	client *net.UDPConn
	cred   string // the client's credential, carrying the (trust, plan) pair
}

func tieredClient(t *testing.T, trust, plan string) tierFix {
	t.Helper()
	resetRegistry(t)
	setPC(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	setAdmission(t, pub, nil)
	f := tierFix{priv: priv, exit: fakePeer(t), client: fakePeer(t), cred: tierCred(t, priv, "acct-1", trust, plan)}
	f.registerExit(t, "e1", "203.0.113.10:20000", 0, f.exit)
	return f
}

// registerExit registers a credentialed exit in NL.
func (f tierFix) registerExit(t *testing.T, id, tcpAddr string, speedCap uint64, from *net.UDPConn) {
	t.Helper()
	_, enc := issueCred(t, f.priv, id, admission.RoleExit)
	handle(wire{Type: "register", Role: "exit", ID: id, Country: "NL", Addr: tcpAddr, SpeedCap: speedCap, QuotaState: quotaOK, Cred: enc},
		from.LocalAddr().(*net.UDPAddr))
	mu.Lock()
	defer mu.Unlock()
	if exits[id] == nil {
		t.Fatalf("exit %s did not register — the fixture is empty and every assertion below would be vacuous", id)
	}
}

// registerRelay registers a credentialed relay.
func (f tierFix) registerRelay(t *testing.T, id string, from *net.UDPConn) {
	t.Helper()
	_, enc := issueCred(t, f.priv, id, admission.RoleRelay)
	handle(wire{Type: "register", Role: "relay", ID: id, Cred: enc}, from.LocalAddr().(*net.UDPAddr))
	mu.Lock()
	defer mu.Unlock()
	if relays[id] == nil {
		t.Fatalf("relay %s did not register", id)
	}
}

// connect drives one credentialed connect for this fixture's client and returns the
// reply. cred overrides the fixture's own credential when non-empty, which is how a
// test drives two different tiers against one registry.
func (f tierFix) connect(t *testing.T, cred, mode string) wire {
	t.Helper()
	if cred == "" {
		cred = f.cred
	}
	dialConnect(wire{Country: "NL", Mode: mode, Cred: cred}, f.client.LocalAddr().(*net.UDPAddr))
	return recvWire(t, f.client, time.Second)
}

// list drives one credentialed list and returns the reply.
func (f tierFix) list(t *testing.T) wire {
	t.Helper()
	handle(wire{Type: "list", Cred: f.cred}, f.client.LocalAddr().(*net.UDPAddr))
	return recvWire(t, f.client, time.Second)
}

// wantAssign reads the assignment the coordinator sent to a forwarder. It is the
// datagram the tier's speed cap rides, so every cap assertion below reads it here
// rather than inferring the cap from the client's own session reply — the client is
// deliberately never told what it was capped at.
func wantAssign(t *testing.T, peer *net.UDPConn) wire {
	t.Helper()
	m := recvWire(t, peer, time.Second)
	if m.Type != "assign" {
		t.Fatalf("forwarder received %q, want an assign", m.Type)
	}
	return m
}

// ---------------------------------------------------------------------------
// The fail directions (ADR-0048 §3). Two questions, two answers.
// ---------------------------------------------------------------------------

// TestUnknownTierPairRefusesTheAssignment is the case ADR-0006 decision 5 exists
// for, and the one an operator actually hits.
//
// A zero TierLimit reads as UNCAPPED on two of its three fields, so a permissive
// fallback would hand full speed and unrestricted endpoint access to precisely the
// credential nobody signed a row for — silently, and at the moment someone ships a
// plan and forgets the policy. This test is what stands between that and a fallback
// looking like a reasonable kindness to a future reader.
//
// MUTATION: make resolveTier return tierLimits{} instead of refuseUnknownTier on a
// failed lookup and this goes red — the connect is answered with a session.
func TestUnknownTierPairRefusesTheAssignment(t *testing.T) {
	f := tieredClient(t, "stable", "plan-nobody-signed")
	tierPolicy(t)

	reply := f.connect(t, "", "direct")
	if reply.Type != "error" {
		t.Fatalf("connect with an unsigned (trust, plan) pair replied %q — a tier nobody signed a policy row for was ASSIGNED", reply.Type)
	}
	if reply.Reason != string(refuseUnknownTier) {
		t.Errorf("refusal reason = %q, want %q", reply.Reason, refuseUnknownTier)
	}
}

// TestPreTierCredentialIsRefusedNotDefaulted is the same rule reached by the route
// a real fleet takes to it.
//
// Every credential minted before #58 carries an EMPTY Trust, and the policy's rows
// are keyed by a closed vocabulary with no empty member — so no signable policy can
// admit them. Turning policy on ahead of re-issuing credentials therefore refuses
// every connect. That is the intended behaviour and it needs to be pinned, because
// it is the exact pressure under which someone adds a "just for old credentials"
// fallback row and reopens the hole above.
func TestPreTierCredentialIsRefusedNotDefaulted(t *testing.T) {
	f := tieredClient(t, "", "")
	tierPolicy(t)

	reply := f.connect(t, "", "direct")
	if reply.Type != "error" || reply.Reason != string(refuseUnknownTier) {
		t.Fatalf("a pre-#58 credential (no trust) was answered %q/%q; want an %q refusal", reply.Type, reply.Reason, refuseUnknownTier)
	}
}

// TestUnknownTierPairRefusesTheCountryList: the list is refused too, because
// exitAssignable is the single definition of assignable and a coordinator that
// cannot resolve a tier cannot honestly compute Available for it. Answering with an
// error leaves the client to rotate (ADR-0020) rather than act on a figure that
// will not hold.
func TestUnknownTierPairRefusesTheCountryList(t *testing.T) {
	f := tieredClient(t, "stable", "plan-nobody-signed")
	tierPolicy(t)

	reply := f.list(t)
	if reply.Type != "error" || reply.Reason != string(refuseUnknownTier) {
		t.Fatalf("list with an unsigned pair replied %q/%q; want an %q refusal", reply.Type, reply.Reason, refuseUnknownTier)
	}
}

// TestNoPolicyConfiguredAssignsUnshaped is the OTHER fail direction, and it
// deliberately answers the opposite way. -policy-root-pubkey has always been
// opt-in; a deployment that never adopted signed policy has not opted out of tier
// limits, it has not opted into the mechanism that carries them. Refusing here
// would turn signed policy into a hard requirement to boot as a side effect of this
// lane.
func TestNoPolicyConfiguredAssignsUnshaped(t *testing.T) {
	f := tieredClient(t, "stable", "pro")
	withPolicyState(t, false, nil)

	reply := f.connect(t, "", "direct")
	if reply.Type != "session" {
		t.Fatalf("connect with no policy configured replied %q (%s); want a session — this is the pre-policy status quo", reply.Type, reply.Reason)
	}
	if assign := wantAssign(t, f.exit); assign.SessionCapBps != 0 {
		t.Errorf("unpoliced coordinator stamped a cap of %d bps; want none", assign.SessionCapBps)
	}
}

// TestAdmissionDisabledAssignsUnshaped is the third state, and the one that is
// neither of the two the issue names. With admission off there is no credential, so
// there is no pair — that is NO key, not an unknown one, and conflating them would
// stop a coordinator that works today over a feature it is not configured for.
// warnTierEnforcementIsOff is what keeps it from being silent.
func TestAdmissionDisabledAssignsUnshaped(t *testing.T) {
	resetRegistry(t)
	setPC(t)
	exit, client := fakePeer(t), fakePeer(t)
	registerExit("e1", "NL", "203.0.113.10:20000", exit)
	tierPolicy(t) // policy held, admissionVerifier left nil

	if admissionVerifier != nil {
		t.Fatal("premise broken: admission is enabled, so this is not the open-network case")
	}
	dialConnect(wire{Country: "NL", Mode: "direct"}, client.LocalAddr().(*net.UDPAddr))
	if reply := recvWire(t, client, time.Second); reply.Type != "session" {
		t.Fatalf("open-network connect replied %q (%s); want a session", reply.Type, reply.Reason)
	}
	if assign := wantAssign(t, exit); assign.SessionCapBps != 0 {
		t.Errorf("stamped a cap of %d bps with no credential to resolve a tier from", assign.SessionCapBps)
	}
}

// ---------------------------------------------------------------------------
// Enforcement point 1 of 3: the speed cap rides the assignment.
// ---------------------------------------------------------------------------

// TestResolvedSpeedCapRidesTheAssignment: the coordinator resolves (trust, plan)
// through the policy and sends the RESULT to the exit. The exit never sees the
// credential, which is the privacy property ADR-0048 §4 records — a credential's
// Serial is a stable per-device identifier and the exit is the one party that sees
// the user's traffic.
//
// MUTATION: drop SessionCapBps from the direct assign in main.go and this goes red.
func TestResolvedSpeedCapRidesTheAssignment(t *testing.T) {
	f := tieredClient(t, "stable", "pro")
	p := tierPolicy(t)

	want, err := p.Limits(policy.TrustStable, "pro")
	if err != nil {
		t.Fatalf("fixture has no stable/pro row: %v", err)
	}
	if reply := f.connect(t, "", "direct"); reply.Type != "session" {
		t.Fatalf("connect replied %q (%s)", reply.Type, reply.Reason)
	}
	assign := wantAssign(t, f.exit)
	if assign.SessionCapBps != want.SpeedCapBps {
		t.Errorf("assign carried %d bps; want the policy's %d for stable/pro — the exit shapes to this number and nothing else",
			assign.SessionCapBps, want.SpeedCapBps)
	}
}

// TestSpeedCapIsThePolicysNumberNotTheCredentialsClaim is the whole reason the
// limits moved into the signed policy (ADR-0043's #67 amendment): a lower tier gets
// the lower number even though its credential is signed by the same authority. The
// credential carries a KEY, never a value, so there is nothing in it to inflate.
func TestSpeedCapIsThePolicysNumberNotTheCredentialsClaim(t *testing.T) {
	f := tieredClient(t, "ephemeral", "")
	p := tierPolicy(t)

	want, err := p.Limits(policy.TrustEphemeral, "")
	if err != nil {
		t.Fatalf("fixture has no ephemeral row: %v", err)
	}
	if reply := f.connect(t, "", "direct"); reply.Type != "session" {
		t.Fatalf("connect replied %q (%s)", reply.Type, reply.Reason)
	}
	if got := wantAssign(t, f.exit).SessionCapBps; got != want.SpeedCapBps {
		t.Errorf("ephemeral session capped at %d bps; want %d", got, want.SpeedCapBps)
	}
	if want.SpeedCapBps == 0 {
		t.Fatal("the fixture's ephemeral row is uncapped, so this test cannot distinguish enforcement from its absence")
	}
}

// TestPeerRelayAssignCarriesTheSessionCap pins issue #74's ruling: a peer-relayed
// session IS shaped, at the relay. The assign goes to a node that terminates
// nothing — but it moves every byte, so it is the one party on that path able to
// pace them, and shaping there tells the exit nothing whatsoever, which is what
// leaves ADR-0048 §4's linkability property untouched rather than traded away.
//
// This replaces a test asserting the exact opposite: that a peer-relay assign
// carried no cap, because a splicing forwarder "could not shape the session even if
// it wanted to". That was ADR-0048 §5's original reading and it was wrong about what
// a forwarder can do; #74 superseded it. The inversion is deliberate and is the
// record of the change.
//
// MUTATION: drop SessionCapBps from the peer-relay assign in main.go and this goes
// red — a relay-mode client silently gets the node's aggregate cap, not its tier's.
func TestPeerRelayAssignCarriesTheSessionCap(t *testing.T) {
	f := tieredClient(t, "stable", "pro")
	relay := fakePeer(t)
	f.registerRelay(t, "r1", relay)
	p := tierPolicy(t)

	want, err := p.Limits(policy.TrustStable, "pro")
	if err != nil {
		t.Fatalf("fixture has no stable/pro row: %v", err)
	}
	if want.SpeedCapBps == 0 {
		t.Fatal("the fixture's stable/pro row is uncapped, so this test cannot distinguish enforcement from its absence")
	}

	if reply := f.connect(t, "", "relay"); reply.Type != "session" {
		t.Fatalf("relay-mode connect replied %q (%s)", reply.Type, reply.Reason)
	}
	assign := wantAssign(t, relay)
	if assign.ExitAddr == "" {
		t.Fatal("premise broken: this is not the peer-relay path (no exitAddr), so the test proves nothing")
	}
	if assign.SessionCapBps != want.SpeedCapBps {
		t.Errorf("peer-relay assign carried %d bps; want the tier's %d bps — the relay cannot shape what it was not told",
			assign.SessionCapBps, want.SpeedCapBps)
	}
}

// TestChainedPeerRelayAssignCarriesTheSessionCap is the INVERSE of the test that
// stood here, and the inversion is the record of issue #84.
//
// What stood here pinned the opposite: a chained assign carried no cap, on the ground
// that the client assembled the path and this coordinator does not know where it
// terminates (ADR-0042 §9), so there was no session it could account for. The name and
// the assertion were both flipped rather than deleted, exactly as #74 flipped
// TestPeerRelayAssignCarriesNoSessionCap, because a decision reversed silently leaves
// nothing behind saying it was ever made.
//
// What did not survive contact: that argument was about ACCOUNTING for a path, and
// what an assign does is PACE its entry. Only the first needs the exit. The chain's
// head terminates nothing but carries every byte, which is #74's own reason for
// shaping at the relay, and ADR-0042 §9 is untouched — the coordinator still does not
// learn the terminating exit.
//
// What made it urgent rather than tidy: a chained connect reaches the SAME peer-relay
// branch as any other relayed session, so the zeroing meant a capped user who turned
// relay chaining on in their client got a session with no tier ceiling at all. The cap
// was opt-out via a client setting.
//
// MUTATION: restore `if chained { sessionCap = 0 }` and this goes red.
func TestChainedPeerRelayAssignCarriesTheSessionCap(t *testing.T) {
	f := tieredClient(t, "stable", "pro")
	relay := fakePeer(t)
	f.registerRelay(t, "r1", relay)
	p := tierPolicy(t)

	want, err := p.Limits(policy.TrustStable, "pro")
	if err != nil {
		t.Fatalf("fixture has no stable/pro row: %v", err)
	}
	if want.SpeedCapBps == 0 {
		t.Fatal("the fixture's stable/pro row is uncapped, so this test cannot distinguish enforcement from its absence")
	}

	// A chaining client names its own first hop and no country at all (ADR-0042 §9).
	// "e1" is the exit tieredClient registered; here it is a peeling hop instead.
	dialConnect(wire{FirstHop: "e1", Mode: "relay", Cred: f.cred}, f.client.LocalAddr().(*net.UDPAddr))
	reply := recvWire(t, f.client, time.Second)
	if reply.Type != "session" {
		t.Fatalf("chained connect replied %q (%s)", reply.Type, reply.Reason)
	}
	assign := wantAssign(t, relay)
	if assign.ExitAddr == "" {
		t.Fatal("premise broken: this is not the peer-relay path (no exitAddr), so the test proves nothing")
	}
	if assign.SessionCapBps != want.SpeedCapBps {
		t.Errorf("chained assign carried %d bps; want the tier's %d bps — chaining is a client setting and must not be a way out of the tier's ceiling",
			assign.SessionCapBps, want.SpeedCapBps)
	}
	// The reply the CLIENT gets is unchanged by #84: still no exit named, because this
	// coordinator still does not know where the chain terminates. Capping the entry
	// did not teach it, which is the whole claim that ADR-0042 §9 survives.
	if reply.ExitID != "" {
		t.Errorf("chained session reply named exit %q; the coordinator must not assert an exit for a path whose exit it does not know (ADR-0042 §9)", reply.ExitID)
	}
}

// ---------------------------------------------------------------------------
// Enforcement point 2 of 3: the endpoint-quality floor.
// ---------------------------------------------------------------------------

// TestEndpointQualityFloorWithholdsALowClassExit is the floor actually DENYING,
// which is the half that makes it enforcement rather than decoration.
//
// MUTATION: remove the meetsEndpointQuality call from exitAssignable and this goes
// red — the connect is answered with a session from an exit below the tier's class.
func TestEndpointQualityFloorWithholdsALowClassExit(t *testing.T) {
	f := tieredClient(t, "stable", "pro") // fixture: endpoint_quality 3
	tierPolicy(t)
	withExitClass(t, func(string) (int, bool) { return 1, true })

	reply := f.connect(t, "", "direct")
	if reply.Type != "error" || reply.Reason != string(refuseCountryBusy) {
		t.Fatalf("a class-1 exit was offered to a class-3 tier: reply %q/%q", reply.Type, reply.Reason)
	}

	// And the same exit IS assignable once it clears the floor, so the test is
	// distinguishing the class rather than observing a broken fixture.
	withExitClass(t, func(string) (int, bool) { return 3, true })
	if reply := f.connect(t, "", "direct"); reply.Type != "session" {
		t.Fatalf("a class-3 exit was refused to a class-3 tier: %q (%s)", reply.Type, reply.Reason)
	}
}

// TestEndpointQualityFloorDoesNotFenceAnUnclassifiedExit is the guard that keeps
// this from being a fleet-stranding change, and it is the same shape as
// TestUntrustedRatingNeverFencesANode next door.
//
// No class source is fed in this build, and the frozen policy fixtures BOTH
// repositories test against carry endpoint_quality 1, 2 and 3 on every row. If an
// unclassified exit read as class 0, the first realistic policy anyone signed would
// refuse every connect in the fleet. An unclassified endpoint is not a bad endpoint,
// exactly as an unmeasured node is not a slow node (design §5.3).
func TestEndpointQualityFloorDoesNotFenceAnUnclassifiedExit(t *testing.T) {
	f := tieredClient(t, "stable", "pro")
	p := tierPolicy(t)

	// The premise: the tier really does demand a class above zero.
	limit, err := p.Limits(policy.TrustStable, "pro")
	if err != nil || limit.EndpointQuality <= 0 {
		t.Fatalf("premise broken: stable/pro demands endpoint quality %d (err %v); this test proves nothing", limit.EndpointQuality, err)
	}
	if exitClass != nil {
		t.Fatal("exitClass is fed in this build — production must ship it nil")
	}
	if reply := f.connect(t, "", "direct"); reply.Type != "session" {
		t.Fatalf("an unclassified exit was fenced by the endpoint-quality floor: %q (%s) — this is a fleet-wide outage", reply.Type, reply.Reason)
	}
}

// ---------------------------------------------------------------------------
// Enforcement point 3 of 3: priority scales the fullness floor.
// ---------------------------------------------------------------------------

// TestPriorityAdmitsWhereALowerTierIsRefused is priority denying and admitting on
// the same exit, in the same state, differing only in the signed tier row.
//
// minShare ships at zero, which makes the fullness test inert for everyone, so this
// flips it exactly as TestServeFloorGateWouldExcludeIfEnabled flips serveFloor. The
// exit is loaded until its projected share sits BETWEEN the high tier's scaled floor
// and the low tier's — that gap is the whole mechanism.
//
// MUTATION: pass minShare instead of tierMinShare(l) to capacity.Full in
// exitAssignable and this goes red — the priority-9 tier is refused alongside the
// priority-1 tier.
func TestPriorityAdmitsWhereALowerTierIsRefused(t *testing.T) {
	f := tieredClient(t, "stable", "pro")
	credLow := tierCred(t, f.priv, "acct-2", "ephemeral", "")  // priority 1
	credHigh := tierCred(t, f.priv, "acct-1", "stable", "pro") // priority 9

	// The exit declares 8 Mbit and carries 7 sessions, so one more would project
	// 1 Mbit. A floor of 4 Mbit refuses the low tier (4 Mbit / 1) and admits the high
	// one (4 Mbit / 9 = 444 kbit). Re-registered BEFORE the policy is installed: the
	// fixture policy carries a min_serving_version and this fixture's registers carry
	// no release, so a register after it would be fenced rather than admitted.
	resetRegistry(t)
	exit := fakePeer(t)
	f.registerExit(t, "e1", "203.0.113.10:20000", uint64(8*capacity.Mbit), exit)
	loadExit(t, "e1", 7)
	withMinShare(t, 4*capacity.Mbit)

	p := tierPolicy(t)
	high, err := p.Limits(policy.TrustStable, "pro")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	low, err := p.Limits(policy.TrustEphemeral, "")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if high.Priority <= low.Priority {
		t.Fatalf("premise broken: priorities %d vs %d do not differ in the tested direction", high.Priority, low.Priority)
	}

	if reply := f.connect(t, credLow, "direct"); reply.Type != "error" || reply.Reason != string(refuseCountryBusy) {
		t.Fatalf("the priority-%d tier was assigned an exit too full for it: %q/%q", low.Priority, reply.Type, reply.Reason)
	}
	if reply := f.connect(t, credHigh, "direct"); reply.Type != "session" {
		t.Fatalf("the priority-%d tier was refused where its priority should have admitted it: %q (%s)", high.Priority, reply.Type, reply.Reason)
	}
}

// TestPriorityIsInertAtTheShippedMinShare pins that none of the above changes
// anything for anyone today. minShare is zero as shipped, and zero divided by any
// priority is zero, so every tier clears every exit — the same "live machinery with
// the gate off" state the serve floor is in.
func TestPriorityIsInertAtTheShippedMinShare(t *testing.T) {
	if minShare != 0 {
		t.Fatalf("minShare ships at %s, not zero — the fullness test is live and this lane changed assignment for everyone", minShare)
	}
	for _, pr := range []int{0, 1, 5, 9} {
		if got := tierMinShare(tierLimits{TierLimit: policy.TierLimit{Priority: pr}}); got != 0 {
			t.Errorf("tierMinShare(priority %d) = %s, want 0", pr, got)
		}
	}
}

// TestPriorityZeroTakesTheNetworkFloorUnchanged: a tier gets relief by being named
// in a signed row, never by omission. Priority 0 — an unset field — must not read as
// an infinite entitlement.
func TestPriorityZeroTakesTheNetworkFloorUnchanged(t *testing.T) {
	withMinShare(t, 4*capacity.Mbit)
	if got := tierMinShare(tierLimits{}); got != 4*capacity.Mbit {
		t.Errorf("tierMinShare(zero tier) = %s, want the network floor %s", got, 4*capacity.Mbit)
	}
	if got := tierMinShare(tierLimits{TierLimit: policy.TierLimit{Priority: 9}}); got != 4*capacity.Mbit/9 {
		t.Errorf("tierMinShare(priority 9) = %s, want %s", got, 4*capacity.Mbit/9)
	}
}

// ---------------------------------------------------------------------------
// The invariant exitAssignable exists for.
// ---------------------------------------------------------------------------

// TestCountryListAgreesWithTheConnectUnderATier: the aggregate a client is shown is
// computed under the SAME limits the connect will enforce, so Available can never
// promise what connect then refuses. This is the reason the tier is threaded through
// exitAssignable rather than applied at the connect alone.
func TestCountryListAgreesWithTheConnectUnderATier(t *testing.T) {
	f := tieredClient(t, "stable", "pro")
	tierPolicy(t)
	withExitClass(t, func(string) (int, bool) { return 1, true }) // below the tier's floor

	list := f.list(t)
	info, found := countryIn(list, "NL")
	if !found {
		t.Fatalf("NL absent from the list: %+v", list.Countries)
	}
	if info.Exits != 1 {
		t.Errorf("Exits = %d, want 1 — the network's shape is not per-tier", info.Exits)
	}
	if info.Available != 0 || !info.Busy {
		t.Fatalf("NL reports %d available (busy=%v) to a tier no exit in it clears", info.Available, info.Busy)
	}
	if reply := f.connect(t, "", "direct"); reply.Reason != string(refuseCountryBusy) {
		t.Errorf("list said busy and connect answered %q — the aggregate and the assignment disagree", reply.Reason)
	}
}

// ---------------------------------------------------------------------------
// Wire contract.
// ---------------------------------------------------------------------------

// TestSessionCapWireContract pins this binary's copy of the assignment field
// against core's. cmd/coordinator deliberately does not import core (see wire's
// doc), so the field exists twice and nothing but this test stops the two drifting
// — the same arrangement TestQuotaStateWireContract uses for the quota literals.
func TestSessionCapWireContract(t *testing.T) {
	b, err := json.Marshal(wire{Type: "assign", Session: "s1", SessionCapBps: 200_000_000})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got, ok := m["sessionCapBps"]; !ok || got != float64(200_000_000) {
		t.Fatalf("the assignment's cap is not on the wire as sessionCapBps: %s", b)
	}
}

// TestUnshapedAssignIsByteIdenticalToAPreTierOne is what makes this additive: a
// coordinator with no tier to apply sends exactly the datagram it sent before #58,
// so an exit predating this change is unaffected and one that postdates it reads
// zero and builds no limiter.
func TestUnshapedAssignIsByteIdenticalToAPreTierOne(t *testing.T) {
	b, err := json.Marshal(wire{Type: "assign", Session: "s1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["sessionCapBps"]; ok {
		t.Errorf("sessionCapBps present on an unshaped assign: %s", b)
	}
}
