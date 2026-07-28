package main

import (
	"context"
	"encoding/hex"
	"net"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/asn"
	"github.com/bacchus-vpn/bacchus/core/capacity"
)

// The attested-sample feed and the coordinator-side capacity estimator (issue #158;
// design node-capacity.md §9-1). #144 built core/capacity.Estimator and proved its
// gaming-resistance bounds; nothing fed it. This is the piece that makes it RUN:
//
//   - a "capacity-report" message, client -> coordinator (handleCapacityReport), each
//     carrying a co-signed usage receipt (ADR-0021) plus the one bit only the client
//     has — was I demand-saturated (design §5.3) — bound to the co-signing client by
//     accounting.SignReport so a node cannot forge or flip it;
//   - a per-node rating map with its OWN lifecycle (capacity.RatingStore), because the
//     registry replaces node entries wholesale every ~10s and rating state cannot live
//     on an entry that is rebuilt from scratch each heartbeat (design §8.6);
//   - capacity.Usable = min(declared, measured), computed at the assignment surfaces
//     (measuredUsable) — but NOT gated on: with the trusted stream unfed every rating
//     clamps to the ceiling, so a serve floor would strand the whole fleet. Enabling
//     that floor is #145's call, deliberately not made here (design §8.6).
//
// The estimator carries TWO ratings per node (issue #157, design §8.1.1): `trusted`,
// fed only by vouched attesters and the one the coordinator uses where it exists, and
// `untrusted`, fed by anyone and clamped to the ceiling. In THIS build the trusted
// stream is permanently empty — vouched-ness rides the admission credential
// (attesterIsVouched), and no issuer in this repo stamps it — so every sample is
// untrusted and every rating sits at or below the ceiling. That is the decision working,
// not a gap: forging the cheap signal buys exactly what silence buys.

// ratings holds the coordinator's per-node capacity estimates. Nil until setupRatings
// runs in main (so the read loop and assignment surfaces are all nil-safe before then,
// and the coordinator tests that never call setupRatings see the pre-#158 behaviour).
// It has its own lock; the handler and the assignment surfaces call it while holding mu,
// the Advance loop calls it without — the lock order is always mu -> ratings' lock,
// never the reverse, so the two never deadlock.
var ratings *capacity.RatingStore

// capacityNow is the clock the capacity feed stamps samples and window ticks with. It is
// a var only so a test can drive the estimator deterministically — matching how
// core/capacity takes `now` at every entry point for exactly the same reason. Production
// leaves it at time.Now.
var capacityNow = time.Now

// ratingIdleTTL evicts a node's rating after this long with no report. It is a couple of
// the estimator's decay half-lives, so a rating has already decayed back to Floor (and
// is therefore worthless to keep) well before eviction drops it — eviction is memory
// hygiene for departed nodes, not a rating decision (design §8.6).
const ratingIdleTTL = 48 * time.Hour

// capacityParams is the estimator configuration the coordinator runs. The starting
// values and their reasoning are core/capacity.DefaultParams / ADR-0040; the coordinator
// does not diverge from them.
func capacityParams() capacity.Params { return capacity.DefaultParams() }

// setupRatings builds the rating store. A construction error is fatal to the caller: a
// coordinator told to run the capacity feed with unusable params must not fall through
// to silently not measuring anything.
func setupRatings() error {
	r, err := capacity.NewRatingStore(capacityParams(), ratingIdleTTL)
	if err != nil {
		return err
	}
	ratings = r
	return nil
}

// ratingsAdvanceLoop closes the estimator's scoring window on every node once per
// Params.Window and evicts idle ratings (capacity.RatingStore.Advance). Decay only
// moves on a tick, so this must run whether or not any report arrived — an unticked
// estimator holds a stale rating forever (the "fast in March, still rated in July"
// failure decay exists to prevent).
func ratingsAdvanceLoop(ctx context.Context) {
	if ratings == nil {
		return
	}
	t := time.NewTicker(capacityParams().Window)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ratings.Advance(capacityNow())
		}
	}
}

// handleCapacityReport turns one client capacity-report into a sample and feeds it to the
// reported exit's rating. It is deliberately silent — a report is fire-and-forget, and a
// reply would only give an attacker an oracle and leak that a report was processed. Every
// rejection below simply drops the sample.
//
// Called from handle under mu; it touches no registry map, only the ratings store (its
// own lock), so holding mu is not required for correctness — it is simply where the
// dispatch already is, and the crypto here is microseconds.
func handleCapacityReport(m wire, src *net.UDPAddr) {
	if ratings == nil || m.Receipt == nil {
		return
	}
	ok, vouched := attesterIsVouched(m)
	if !ok {
		return // admission is on and this report's client credential did not verify
	}
	r := *m.Receipt
	// The receipt's throughput is worthless unless BOTH parties co-signed it — that is
	// what stops a node (or a client) unilaterally inventing a fast sample (design §5.2).
	if err := r.Verify(); err != nil {
		return
	}
	// And the saturation bit is worthless unless the co-signing CLIENT asserted it: this
	// is what stops a node that holds the receipt from flipping the bit to inflate itself
	// (issue #158). VerifyReport is a separate proof from the co-signature.
	if err := accounting.VerifyReport(r, m.ReportSig); err != nil {
		return
	}
	as := observedAS(src, asnTable)
	if as == "" {
		return // no attributable AS: an uncappable sample is a hole, not a kindness (design §6.4)
	}
	ratings.Observe(r.ExitID, vouched, sampleFrom(r, as), capacityNow())
}

// attesterIsVouched reports whether a report may proceed and, if so, whether its attester
// is VOUCHED — the split that routes a sample to the trusted vs. untrusted estimate
// (issue #157). Vouched-ness rides the admission credential the coordinator already
// verifies, because the coordinator cannot import the private account/vouch service that
// sets it (design §8.1.1 seam).
//
//   - Admission disabled (open network): the report is accepted but is UNTRUSTED — with
//     no credential there is nothing to read vouched-ness from.
//   - Admission enabled: the report's client credential must verify (else it is dropped,
//     silently, like list/connect but with no reject reply), and its Vouched marker
//     decides the stream.
//
// In this build no issuer stamps Vouched, so the second return is always false and the
// trusted stream stays empty. The seam is here; the account service feeds it later.
func attesterIsVouched(m wire) (ok, vouched bool) {
	if admissionVerifier == nil {
		return true, false
	}
	cred, err := admissionVerifier.Verify(m.Cred, time.Now(), admission.RoleClient, "")
	if err != nil {
		return false, false
	}
	return true, cred.IsVouched()
}

// sampleFrom builds a capacity sample from a verified receipt and the coordinator-
// observed attester AS. Throughput is the receipt's bytes-per-interval in bits/s; the
// attester is the client accounting key that co-signed (hex), so a single attester's
// influence can be capped (design §6.4). A zero interval yields zero throughput rather
// than a divide — a saturated zero is itself meaningful (design §5.3), an unsaturated
// one is dropped by the estimator anyway.
func sampleFrom(r accounting.Receipt, as string) capacity.Sample {
	var tp capacity.Rate
	if r.IntervalSec > 0 {
		tp = capacity.Rate(r.Bytes * 8 / uint64(r.IntervalSec))
	}
	return capacity.Sample{
		Throughput: tp,
		Saturated:  r.Saturated,
		Attester:   hex.EncodeToString(r.ClientAcctPub),
		AS:         as,
	}
}

// observedAS derives an attester's autonomous system from the source address the
// coordinator OBSERVED the report arrive from — never a client self-report, exactly as
// Entry.Ingress trusts an observed IP but not a claimed one (design §6.2). The AS is the
// unit of Sybil cost (one AS, one vote; design §6.4), so letting a client state its own
// would make that cost zero.
//
// It resolves that address against an independent AS table (core/asn, issue #23) when
// one is staged. That is the real ASN lookup ADR-0041 line 173 recorded as required
// before the TRUSTED stream is fed: the ~4:1 AS bound is denominated in autonomous
// systems, so until the AS is an actual AS the bound is denominated in a proxy.
//
// # The prefix mask is now the NAMED fallback, not the silent default
//
// With no table staged it still masks the IP to a routing prefix (/24 v4, /48 v6) as a
// "same-network" proxy, which is exactly what this function did before #23. The change
// is that this is now the fallback branch of a function whose primary answer is a real
// AS, rather than the only thing it ever does — asFallback says so in its name, and a
// caller reading a key can tell which it got.
//
// Telling them apart matters, and not only for readability. The estimator counts
// DISTINCT AS values to decide whether a node has been attested widely enough to rise
// past the ceiling (capacity.Params.CeilingASes), so the two forms are not
// interchangeable inputs: one real AS spread across several /24s counts as several
// "ASes" under the mask and as one under the table. The mask therefore makes the
// ceiling EASIER to reach than the AS bound intends. That was tolerable while only the
// untrusted stream was fed — it clamps to the ceiling regardless, so the proxy only
// affects how readily an honest node reaches it, never how far an attacker can push
// past it — and it is precisely what stops being tolerable when the trusted stream is
// fed. The two key spaces are kept syntactically disjoint (asn.AS renders "AS64496",
// the fallback renders a CIDR) so a mixed window is visible rather than silent.
func observedAS(src *net.UDPAddr, lookup asn.Lookup) string {
	if src == nil || src.IP == nil {
		return ""
	}
	if a, ok := asn.OfAddr(lookup, src.IP); ok {
		return a.String()
	}
	return asFallback(src.IP)
}

// asFallback is the pre-#23 behaviour, kept and named: the observed IP masked to a
// routing prefix as a coarse "same-network" stand-in for an AS.
//
// It is reached when no table is staged, and also when a staged table cannot place the
// address — which on a local stack is every node, since they all register from
// loopback and no AS announces 127.0.0.0/8. Returning a masked prefix there rather than
// nothing is deliberate: an empty AS makes handleCapacityReport DROP the sample as
// unattributable, so failing to fall back would silently stop the capacity feed on
// every developer box and in the smoke stack.
func asFallback(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

// measuredUsable is capacity.Usable(declared, measured) for a node — the min(declared,
// measured) contract (design §5/§8.6), and the production caller that seam lacked. The
// assignment surfaces call it so the measured rating is applied where declared limits
// already are.
//
// It does NOT gate. With the trusted stream unfed, every rating clamps to the ceiling, so
// filtering assignment on this number would reject every node and strand the fleet
// (design §8.6). Whether `usable` must clear a serve floor is issue #145's policy call,
// which this lane deliberately does not make and does not enable — the machinery ships
// with that gate OFF (TestFleetSurvivesTheFeedLanding). Returns declared unchanged when
// nothing feeds it: no ratings store, or a node with no rating yet (an unmeasured node is
// not a slow node, design §5.3).
func measuredUsable(nodeID string, declared uint64) uint64 {
	if ratings == nil {
		return declared
	}
	return uint64(ratings.Usable(nodeID, capacity.Rate(declared)))
}

// serveFloor is issue #145's serve-eligibility floor, and it is OFF in this lane (the
// zero value). It is the bar a node's usable rating must clear to be assigned; #145
// decides its value, which is POLICY, not a constant — a 2 Mbit exit is worthless in one
// region and the only one in another (design §6.5).
//
// It MUST stay zero here. With the trusted stream unfed every rating clamps to the
// ceiling, so ANY floor above zero rejects every node and strands the whole fleet
// (design §8.6). It is a var rather than a const only so a test can flip it to prove the
// gate is real machinery (TestServeFloorGateWouldExcludeIfEnabled), not dead code —
// production never sets it. This is "the machinery, with the gate off": the feed and the
// gate land together (§8.6), the gate off, and TestFleetSurvivesTheFeedLanding proves
// that landing does not strand anyone.
var serveFloor capacity.Rate

// meetsServeFloor reports whether a node's usable rating clears serveFloor, so the
// assignment surfaces (list, pickRelay) can apply capacity.Usable where they already
// apply the declared quota. With serveFloor at its shipped zero, a Rate is always >= 0,
// so this is always true and gates nothing — the exhausted-quota filter (issue #143) is
// still the only thing that withholds a node.
func meetsServeFloor(nodeID string, declared uint64) bool {
	return capacity.Rate(measuredUsable(nodeID, declared)) >= serveFloor
}
