package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/capacity"
)

// The attested-sample feed and the coordinator-side estimator (issue #158). These drive
// the real handle() with crafted capacity-reports and assert: a valid report moves the
// estimate; an invalid one moves nothing; a rating survives the registry's wholesale
// re-register (design §8.6); and — the load-bearing one — landing the feed does NOT
// strand the fleet, because the serve floor is off (design §8.6).

var feedEpoch = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

// testCapacityParams tunes the estimator for a test harness where every fake peer is on
// loopback and so collapses to a single observed AS (/24): MinASes 1 lets that one AS
// move the estimate, CeilingASes 1 releases the provisional ceiling at once. It does NOT
// touch Ceiling/Floor/RiseFactor — the numbers the tests assert against stay the
// production ones.
func testCapacityParams() capacity.Params {
	p := capacity.DefaultParams()
	p.MinASes = 1
	p.CeilingASes = 1
	return p
}

// setRatings installs a fresh rating store (test params) and a deterministic clock for
// the duration of a test, restoring the pre-#158 nil default after — so the coordinator's
// other tests, which never set up ratings, are unaffected.
func setRatings(t *testing.T) capacity.Params {
	t.Helper()
	p := testCapacityParams()
	store, err := capacity.NewRatingStore(p, ratingIdleTTL)
	if err != nil {
		t.Fatalf("NewRatingStore: %v", err)
	}
	ratings = store
	prevClock := capacityNow
	capacityNow = func() time.Time { return feedEpoch }
	t.Cleanup(func() { ratings = nil; capacityNow = prevClock })
	return p
}

// mintReceipt produces a genuinely co-signed receipt (ADR-0021) for exitID by running the
// real exit and client accounting halves over an in-memory pipe, and returns it with the
// client key needed to sign the capacity-report.
func mintReceipt(t *testing.T, exitID string, bytesN uint64, intervalSec uint32) (accounting.Receipt, ed25519.PrivateKey) {
	t.Helper()
	_, exitKey, _ := ed25519.GenerateKey(rand.Reader)
	_, clientKey, _ := ed25519.GenerateKey(rand.Reader)
	a, b := net.Pipe()
	type res struct {
		r   accounting.Receipt
		err error
	}
	ch := make(chan res, 1)
	go func() {
		r, err := accounting.ClientCosign(b, clientKey, bytesN)
		ch <- res{r, err}
	}()
	if _, err := accounting.ExitPropose(a, exitKey, exitID, "sess-"+exitID, 0, intervalSec, bytesN); err != nil {
		t.Fatalf("ExitPropose: %v", err)
	}
	got := <-ch
	if got.err != nil {
		t.Fatalf("ClientCosign: %v", got.err)
	}
	_ = a.Close()
	_ = b.Close()
	return got.r, clientKey
}

// report crafts a valid capacity-report wire message for exitID.
func report(t *testing.T, exitID string, bytesN uint64, intervalSec uint32, saturated bool, cred string) wire {
	t.Helper()
	r, clientKey := mintReceipt(t, exitID, bytesN, intervalSec)
	r.Saturated = saturated
	return wire{Type: "capacity-report", Receipt: &r, ReportSig: accounting.SignReport(clientKey, r), Cred: cred}
}

// issueVouchedCred mints a client credential a real person vouched for (issue #157) —
// the signal the account service will eventually stamp and nothing in this repo does. The
// tests construct it directly to prove the trusted-stream seam is wired.
func issueVouchedCred(t *testing.T, priv ed25519.PrivateKey, subject string) string {
	t.Helper()
	now := time.Now()
	c := admission.Credential{
		Version:   admission.CredentialVersion,
		Serial:    "vouched-test",
		Subject:   subject,
		Roles:     []admission.Role{admission.RoleClient},
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(time.Hour),
		Vouched:   true,
	}
	signed, err := admission.Sign(priv, c)
	if err != nil {
		t.Fatalf("Sign vouched credential: %v", err)
	}
	return admission.Encode(signed)
}

// feedUntrustedToCeiling drives nodeID's untrusted rating up to the ceiling by directly
// observing sustained saturated attestation on the store's own clock. Returns the ceiling
// the store's params clamp to, so a caller asserts against it without re-deriving it.
func feedUntrustedToCeiling(t *testing.T, nodeID string, p capacity.Params) capacity.Rate {
	t.Helper()
	now := feedEpoch
	s := capacity.Sample{Throughput: 100 * capacity.Mbit, Saturated: true, Attester: "att-" + nodeID, AS: "as-" + nodeID}
	for i := 0; i < 30; i++ {
		ratings.Observe(nodeID, false, s, now)
		ratings.Advance(now)
		now = now.Add(p.Window)
	}
	got, ok := ratings.Measured(nodeID)
	if !ok || got != p.Ceiling {
		t.Fatalf("setup: %s measured %s (ok=%v) after sustained attestation; want the ceiling %s", nodeID, got, ok, p.Ceiling)
	}
	return p.Ceiling
}

// TestCapacityReportMovesTheEstimate is the wire path end to end: a valid report handled by
// handle() reaches the exit's rating and, once the window closes, moves it off Floor.
func TestCapacityReportMovesTheEstimate(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	p := setRatings(t)
	client := fakePeer(t)

	handle(report(t, "exit-1", 5_000_000, 60, true, ""), client.LocalAddr().(*net.UDPAddr))
	ratings.Advance(feedEpoch) // close the window the report landed in

	got, ok := ratings.Measured("exit-1")
	if !ok {
		t.Fatal("a valid capacity-report created no rating; the feed did not reach the estimator")
	}
	if got <= p.Floor {
		t.Fatalf("measured = %s after a saturated report; want it moved off Floor %s", got, p.Floor)
	}
}

// TestCapacityReportRejectsBadCosignature: a receipt whose byte count was changed after
// co-signing fails Verify and is dropped, so no rating is created.
func TestCapacityReportRejectsBadCosignature(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	setRatings(t)
	client := fakePeer(t)

	m := report(t, "exit-1", 5_000_000, 60, true, "")
	m.Receipt.Bytes = 9_000_000 // invalidates both co-signatures at once
	handle(m, client.LocalAddr().(*net.UDPAddr))
	ratings.Advance(feedEpoch)

	if _, ok := ratings.Measured("exit-1"); ok {
		t.Fatal("a report with an invalid co-signature created a rating; Verify was not enforced")
	}
}

// TestCapacityReportRejectsFlippedSaturation: flipping the saturation bit after the client
// signed the report breaks the report signature, so the sample is dropped — a node holding
// the receipt cannot inflate itself by asserting saturation the client did not.
func TestCapacityReportRejectsFlippedSaturation(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	setRatings(t)
	client := fakePeer(t)

	m := report(t, "exit-1", 5_000_000, 60, false, "") // client signed saturated=false
	m.Receipt.Saturated = true                         // a node flips it to inflate
	handle(m, client.LocalAddr().(*net.UDPAddr))
	ratings.Advance(feedEpoch)

	if _, ok := ratings.Measured("exit-1"); ok {
		t.Fatal("a report with a flipped saturation bit created a rating; VerifyReport was not enforced")
	}
}

// TestRatingSurvivesWholesaleReRegister is §8.6's whole reason the map is separate: a
// node's rating must NOT live on the registry entry, because register replaces that entry
// wholesale every heartbeat. Feed a rating, re-register the exit, and the rating is
// unchanged.
func TestRatingSurvivesWholesaleReRegister(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	p := setRatings(t)
	exit := fakePeer(t)

	registerExitLimits("exit-1", "nl", "203.0.113.10:20000", 0, quotaOK, exit)
	measured := feedUntrustedToCeiling(t, "exit-1", p)

	// The exact churn that would reset a rating stored on the entry: a fresh register.
	registerExitLimits("exit-1", "nl", "203.0.113.10:20000", 0, quotaOK, exit)

	got, ok := ratings.Measured("exit-1")
	if !ok || got != measured {
		t.Fatalf("rating after re-register = %s (ok=%v); want %s unchanged — it was reset by the wholesale entry replace", got, ok, measured)
	}
}

// TestFleetSurvivesTheFeedLanding is the CRITICAL guard the task and design §8.6 demand:
// with every node fed up to the ceiling and the serve floor OFF (its shipped zero), the
// assignment surfaces still offer every non-exhausted node. If any measured-based gate
// were live, the whole fleet — pinned at the ceiling because the trusted stream is unfed —
// would be stranded.
func TestFleetSurvivesTheFeedLanding(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	p := setRatings(t)
	exitA, exitB, relay, client := fakePeer(t), fakePeer(t), fakePeer(t), fakePeer(t)

	registerExitLimits("exit-a", "nl", "203.0.113.10:20000", 0, quotaOK, exitA)
	registerExitLimits("exit-b", "de", "203.0.113.11:20000", 0, quotaOK, exitB)
	registerRelayLimits("relay-1", 0, quotaOK, relay)

	// Land the feed: every node clamped to the ceiling (untrusted, trusted unfed).
	feedUntrustedToCeiling(t, "exit-a", p)
	feedUntrustedToCeiling(t, "exit-b", p)
	feedUntrustedToCeiling(t, "relay-1", p)

	requestList(client)
	reply := recvWire(t, client, time.Second)
	// Both exits still assignable, each in its own country.
	wantCountry(t, reply, "NL", 1, 1)
	wantCountry(t, reply, "DE", 1, 1)
	if pickRelay("") == nil {
		t.Fatal("pickRelay returned nothing after the feed landed; a measured gate stranded the relay tier")
	}
	// And the country-scoped assignment surface itself still assigns (issue #146): a
	// ceiling-clamped rating must not make chooseExit refuse. This is the #147 half of
	// the same guard — a fed fleet must not read as "every country is busy".
	for _, cc := range []string{"NL", "DE"} {
		if e, refusal := chooseExit(cc, nil, time.Now(), tierLimits{}); e == nil || refusal != refuseNone {
			t.Errorf("chooseExit(%s) refused with %q after the feed landed; the fleet is stranded at the assignment surface", cc, refusal)
		}
	}
}

// TestServeFloorGateWouldExcludeIfEnabled proves the gate is real machinery, not dead
// code: with the SAME fully-fed fleet, raising serveFloor above the ceiling withholds
// every exit — which is exactly why it must ship at zero (TestFleetSurvivesTheFeedLanding).
func TestServeFloorGateWouldExcludeIfEnabled(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	p := setRatings(t)
	exit, client := fakePeer(t), fakePeer(t)

	registerExitLimits("exit-1", "nl", "203.0.113.10:20000", 0, quotaOK, exit)
	feedUntrustedToCeiling(t, "exit-1", p) // measured == ceiling

	serveFloor = p.Ceiling + 1 // a floor no unfed-trusted node can clear
	t.Cleanup(func() { serveFloor = 0 })

	requestList(client)
	// The country is still LISTED — that is #147's requirement — but with nothing
	// available in it, which is how the withholding now shows up.
	wantCountry(t, recvWire(t, client, time.Second), "NL", 1, 0)
	if e, refusal := chooseExit("NL", nil, time.Now(), tierLimits{}); e != nil || refusal != refuseCountryBusy {
		t.Fatalf("chooseExit with the serve floor above the ceiling returned (%v, %q); want a country-busy refusal — the gate does not actually filter on measured", e, refusal)
	}
}

// TestVouchedReportFeedsTrustedStream proves the #157 seam is wired: a report from a
// VOUCHED account feeds the trusted estimate (which can exceed the ceiling), while an
// unvouched one feeds only untrusted (clamped). Nothing in this repo issues a vouched
// credential — the test constructs one — so in production the trusted stream stays empty.
func TestVouchedReportFeedsTrustedStream(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	p := setRatings(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	setAdmission(t, pub, nil)
	client := fakePeer(t)
	src := client.LocalAddr().(*net.UDPAddr)

	vouched := issueVouchedCred(t, priv, "acct-1")
	for i := 0; i < 30; i++ {
		handle(report(t, "exit-v", 100_000_000, 60, true, vouched), src)
		ratings.Advance(feedEpoch.Add(time.Duration(i) * p.Window))
	}
	st, ok := ratings.Status("exit-v")
	if !ok {
		t.Fatal("no rating for the vouched-attested exit")
	}
	if st.Trusted.Estimate <= p.Ceiling {
		t.Fatalf("trusted estimate = %s from vouched attestation; a vouched stream must be able to exceed the ceiling %s", st.Trusted.Estimate, p.Ceiling)
	}
	if st.Measured != st.Trusted.Estimate {
		t.Fatalf("Measured = %s did not follow the trusted estimate %s where it exists", st.Measured, st.Trusted.Estimate)
	}
}

// TestUnvouchedReportStaysUntrusted is the other half of the seam and the whole v1
// posture: an admitted-but-unvouched attester can never lift a node above the ceiling, so
// its trusted stream stays at Floor and the ceiling clamp holds.
func TestUnvouchedReportStaysUntrusted(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	p := setRatings(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	setAdmission(t, pub, nil)
	client := fakePeer(t)
	src := client.LocalAddr().(*net.UDPAddr)

	_, unvouched := issueCred(t, priv, "acct-1", admission.RoleClient) // Issue never sets Vouched
	for i := 0; i < 30; i++ {
		handle(report(t, "exit-u", 100_000_000, 60, true, unvouched), src)
		ratings.Advance(feedEpoch.Add(time.Duration(i) * p.Window))
	}
	st, ok := ratings.Status("exit-u")
	if !ok {
		t.Fatal("no rating for the unvouched-attested exit")
	}
	if st.Trusted.Estimate != p.Floor {
		t.Fatalf("trusted estimate = %s from an UNVOUCHED attester; it must stay at Floor %s (the trusted stream is unfed)", st.Trusted.Estimate, p.Floor)
	}
	if st.Measured != p.Ceiling {
		t.Fatalf("measured = %s; an unvouched attester saturating the node should reach exactly the ceiling %s, never past it", st.Measured, p.Ceiling)
	}
}
