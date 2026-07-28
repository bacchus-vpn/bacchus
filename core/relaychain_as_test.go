package core

import (
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/asn"
)

// AS-diverse hop selection (issue #23, ADR-0044).
//
// The property under test is a REJECTION: a chain that would place two hops in one
// autonomous system must not be built while a diverse alternative exists. A
// diversity control whose tests only ever watch it accept is not testing anything,
// so every test here is written to fail if the corresponding check is removed —
// see the mutation notes on each.
//
// Every address below is documentation space (RFC 5737 / RFC 3849) and every AS is a
// documentation AS (RFC 5398), resolved through core/asn's synthetic fixture. The
// fixture deliberately maps 192.0.2.0/26 and 198.51.100.0/26 to the SAME AS64496,
// which is the Sybil shape: one network behind two entries in different /24s that
// share no visible label.

func asFixture(t *testing.T) asn.Lookup {
	t.Helper()
	tab, err := asn.Load("asn/testdata/table.tsv")
	if err != nil {
		t.Fatalf("loading the AS fixture: %v", err)
	}
	return tab
}

// asOf is the AS key a hop would be bucketed under, for assertions.
func asOf(t *testing.T, l asn.Lookup, dial string) string {
	t.Helper()
	a, ok := asn.OfHostPort(l, dial)
	if !ok {
		return unknownASKey
	}
	return a.String()
}

// TestSelectHopsRejectsTwoHopsInOneAS is the headline property of #23. Five
// candidates, three of which share AS64496 across two different /24s; a three-hop
// chain must come back with three distinct autonomous systems every time.
//
// Mutation: delete the `if needAS { ... usedAS[key] ... continue }` guard in
// selectHops and this fails — the shuffled pool hands out same-AS hops freely.
func TestSelectHopsRejectsTwoHopsInOneAS(t *testing.T) {
	lookup := asFixture(t)
	cand := []relayHop{
		// Three entries, two networks' worth of labels, ONE autonomous system.
		{id: "1", dial: "192.0.2.1:9001", pairable: true}, // AS64496
		{id: "2", dial: "192.0.2.2:9002", pairable: true}, // AS64496
		{id: "3", dial: "198.51.100.1:9003"},              // AS64496 — different /24, same AS
		{id: "4", dial: "192.0.2.65:9004"},                // AS64497
		{id: "5", dial: "192.0.2.130:9005"},               // AS64498
		{id: "6", dial: "203.0.113.1:9006"},               // AS64500
	}
	for i := 0; i < 60; i++ { // selection is randomized; the invariant must hold every time
		got, div, err := selectHops(cand, 3, "", lookup)
		if err != nil {
			t.Fatalf("selectHops: %v", err)
		}
		seen := map[string]bool{}
		for _, h := range got {
			key := asOf(t, lookup, h.dial)
			if seen[key] {
				t.Fatalf("two hops in %s in one chain: %v — one network sees both ends of the chain", key, dials(got))
			}
			seen[key] = true
		}
		if div.degraded() {
			t.Fatalf("reported degradation on a chain the directory CAN make AS-diverse: %s", div.describe())
		}
		if div.resolved != 3 || div.unresolved != 0 {
			t.Fatalf("div = %+v, want 3 resolved and 0 unresolved", div)
		}
	}
}

// TestSelectHopsCatchesOneOperatorBehindUnlabeledEntries is the gap #23 was filed
// for, stated as the issue states it: operator diversity is INERT here (no entry
// carries a tag), so the AS check is the only thing standing between the client and
// a chain routed twice through one network.
//
// Mutation: remove the AS guard and this fails; it is the operator tag's absence
// that makes it a clean test of the AS control alone.
func TestSelectHopsCatchesOneOperatorBehindUnlabeledEntries(t *testing.T) {
	lookup := asFixture(t)
	cand := []relayHop{
		{id: "sybil-a", dial: "192.0.2.1:9001", pairable: true}, // AS64496
		{id: "sybil-b", dial: "198.51.100.1:9002"},              // AS64496, and nothing on the wire says so
		{id: "honest", dial: "203.0.113.1:9003"},                // AS64500
	}
	for i := 0; i < 60; i++ {
		got, _, err := selectHops(cand, 2, "", lookup)
		if err != nil {
			t.Fatalf("selectHops: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d hops, want 2", len(got))
		}
		if asOf(t, lookup, got[0].dial) == asOf(t, lookup, got[1].dial) {
			t.Fatalf("both hops in one AS: %v — a Sybil behind two unlabeled entries was not detected", dials(got))
		}
	}
}

// TestHopASKeyPoolsUnresolved pins the pooled bucket directly, at the function that
// produces it.
//
// It is tested here rather than only through selectHops because selectHops' `!resolved`
// guard currently subsumes it: unresolved hops cannot satisfy a diversity pass at all,
// so the bucket value never reaches the usedAS comparison, and a mutation giving every
// unknown hop a unique key changes no selection outcome today. That makes the pooling
// belt-and-braces — and belt-and-braces that nothing checks is just dead code waiting
// to be "cleaned up".
//
// It earns its place because hopASKey is a general answer to "what bucket is this hop
// in", and a caller that reads it WITHOUT the guard must still get a safe answer. Making
// the bucket function safe by construction beats relying on every future caller to
// remember the guard — but only if the property is pinned, which is what this does.
//
// Mutation: return `unknownASKey + h.id` from hopASKey and this fails; no other test
// does.
func TestHopASKeyPoolsUnresolved(t *testing.T) {
	lookup := asFixture(t)
	a, aok := hopASKey(relayHop{id: "a", dial: "192.0.2.200:1"}, lookup)
	b, bok := hopASKey(relayHop{id: "b", dial: "203.0.113.200:2"}, lookup)
	if aok || bok {
		t.Fatalf("both addresses must be unresolvable: got (%q,%v) and (%q,%v)", a, aok, b, bok)
	}
	if a != b {
		t.Errorf("two unresolved hops got distinct buckets %q and %q; unknown must pool into ONE, or an attacker mints diversity by using address space the table does not cover", a, b)
	}
	// And the pooled bucket must not be able to collide with a resolved answer.
	resolved, ok := hopASKey(relayHop{id: "c", dial: "192.0.2.1:3"}, lookup)
	if !ok {
		t.Fatal("192.0.2.1 must resolve")
	}
	if resolved == a {
		t.Errorf("the unknown bucket %q collides with a resolved AS key", a)
	}
}

// TestUnknownASIsPooledNotDiverse pins the ACCOUNTING for a chain built entirely from
// hops the table cannot place: it is still built (refusing outright is the worse
// trade), every hop is counted as unresolved, and the chain is reported degraded
// rather than passing for a diverse one.
//
// Mutation: make hopASKey return a unique key per unknown hop AND make degraded()
// drop `|| d.unresolved > 0` and this fails. Either alone does not, because the two
// are independent guards that both catch this shape — the pooled bucket sets
// asRepeated, and the unresolved count sets degraded directly.
// TestHopASKeyPoolsUnresolved and TestChainLeaningOnAnUnplaceableHopIsDegraded pin
// them one at a time.
func TestUnknownASIsPooledNotDiverse(t *testing.T) {
	lookup := asFixture(t)
	// Three candidates the table cannot place, all in gaps of the fixture, plus one
	// it can. A 2-hop chain must not be able to claim two distinct ASes out of the
	// unresolvable ones.
	cand := []relayHop{
		{id: "u1", dial: "192.0.2.200:9001", pairable: true}, // gap -> unknown
		{id: "u2", dial: "198.51.100.200:9002"},              // gap -> unknown
		{id: "u3", dial: "203.0.113.200:9003"},               // gap -> unknown
	}
	for i := 0; i < 40; i++ {
		got, div, err := selectHops(cand, 2, "", lookup)
		if err != nil {
			t.Fatalf("selectHops: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d hops, want 2", len(got))
		}
		// The chain is still built — refusing outright is the worse trade — but it
		// must be REPORTED as degraded, not pass for a diverse one.
		if !div.degraded() {
			t.Fatal("two unresolved hops were accepted as AS-diverse; unknown must pool into one bucket")
		}
		if div.unresolved != 2 || div.resolved != 0 {
			t.Fatalf("div = %+v, want 2 unresolved and 0 resolved", div)
		}
	}
}

// TestUnknownASNeverBeatsAResolvedAlternative: pooling unknown is only half the
// decision. The other half is that a hop the table CAN place must be preferred while
// one is available, so an attacker cannot push an honest resolved hop out of the
// chain by supplying unmapped candidates.
func TestUnknownASNeverBeatsAResolvedAlternative(t *testing.T) {
	lookup := asFixture(t)
	cand := []relayHop{
		{id: "head", dial: "192.0.2.1:9001", pairable: true}, // AS64496
		{id: "unknown-a", dial: "192.0.2.200:9002"},          // gap
		{id: "unknown-b", dial: "198.51.100.200:9003"},       // gap
		{id: "resolved", dial: "203.0.113.1:9004"},           // AS64500
	}
	for i := 0; i < 60; i++ {
		got, div, err := selectHops(cand, 2, "", lookup)
		if err != nil {
			t.Fatalf("selectHops: %v", err)
		}
		if div.degraded() {
			t.Fatalf("degraded when a resolved, AS-distinct hop was available: %s (%v)", div.describe(), dials(got))
		}
		if got[1].id != "resolved" {
			t.Fatalf("second hop = %q (%s), want the resolvable AS64500 hop — an unknown hop must not displace a resolved one",
				got[1].id, got[1].dial)
		}
	}
}

// TestChainLeaningOnAnUnplaceableHopIsDegraded isolates the `unresolved > 0` term of
// degraded(), which no other test reaches on its own.
//
// One resolved hop and one the table cannot place, and the chain needs both. No
// bucket visibly repeats — the unknown bucket differs from AS64496 — so asRepeated
// stays false and the ONLY thing standing between this chain and a clean bill of
// health is the unresolved count. That matters because the claim the control makes is
// "these hops are in different networks", and about the unplaceable hop that claim was
// never established: it may well sit in AS64496 too.
//
// Mutation: drop `|| d.unresolved > 0` from degraded() and this fails.
func TestChainLeaningOnAnUnplaceableHopIsDegraded(t *testing.T) {
	lookup := asFixture(t)
	cand := []relayHop{
		{id: "head", dial: "192.0.2.1:9001", pairable: true}, // AS64496
		{id: "unplaceable", dial: "192.0.2.200:9002"},        // a gap — no alternative exists
	}
	got, div, err := selectHops(cand, 2, "", lookup)
	if err != nil {
		t.Fatalf("selectHops refused rather than falling back: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d hops, want 2", len(got))
	}
	if div.asRepeated {
		t.Fatalf("div = %+v, want asRepeated false — no bucket repeats here, which is the point", div)
	}
	if div.resolved != 1 || div.unresolved != 1 {
		t.Fatalf("div = %+v, want 1 resolved and 1 unresolved", div)
	}
	if !div.degraded() {
		t.Fatal("a chain leaning on a hop the table could not place reported itself as AS-diverse; that diversity was never established")
	}
	if msg := div.describe(); !strings.Contains(msg, "could not be placed") {
		t.Errorf("describe() = %q, want it to name the unplaceable hop", msg)
	}
}

// TestSelectHopsKeepsOperatorDiversityWithNoASTable is a regression guard on the
// ladder's shape, and it pins a mistake that is easy to make and silent when made.
//
// With no table every hop resolves to unknown and pools into one bucket, so no pass
// demanding AS distinctness can place anything. A ladder of just
// (AS+operator, AS, neither) would therefore fall straight through to unconstrained
// and switch OFF the operator diversity that has been running since #124 — adding a
// control by removing one, on every deployment, silently. The rung where operator
// diversity stands alone is what stops that.
//
// Mutation: delete the `needOp := pass == 0 || pass == 2` rung (make it pass == 0
// only) and this fails.
func TestSelectHopsKeepsOperatorDiversityWithNoASTable(t *testing.T) {
	cand := []relayHop{
		{id: "1", dial: "192.0.2.1:9001", operator: "acme", pairable: true},
		{id: "2", dial: "192.0.2.2:9002", operator: "acme"},
		{id: "3", dial: "192.0.2.3:9003", operator: "acme"},
		{id: "4", dial: "192.0.2.4:9004", operator: "globex"},
		{id: "5", dial: "192.0.2.5:9005", operator: "initech"},
	}
	// nil lookup is exactly what every build ships with today (ADR-0044).
	for _, lookup := range []asn.Lookup{nil, (*asn.Table)(nil)} {
		for i := 0; i < 40; i++ {
			got, div, err := selectHops(cand, 3, "", lookup)
			if err != nil {
				t.Fatalf("selectHops: %v", err)
			}
			seen := map[string]bool{}
			for _, h := range got {
				if seen[h.operator] {
					t.Fatalf("with no AS table, operator diversity stopped being enforced: two hops from %q in %v", h.operator, dials(got))
				}
				seen[h.operator] = true
			}
			if !div.degraded() || div.resolved != 0 {
				t.Fatalf("div = %+v, want a reported degradation with nothing resolved", div)
			}
		}
	}
}

// TestSelectHopsNeverTradesASForOperator pins the rung ordering. The directory can
// supply AS diversity but NOT operator diversity; the chain must keep the
// load-bearing control and give up the advisory one, never the reverse.
//
// Mutation: remove the `needAS := pass == 0 || pass == 1` rung (make it pass == 0
// only) and this fails — pass 1 disappears, and the fill drops to the
// operator-distinct rung, which cannot be satisfied either, and then to
// unconstrained, losing AS diversity that was available.
func TestSelectHopsNeverTradesASForOperator(t *testing.T) {
	lookup := asFixture(t)
	cand := []relayHop{
		// One operator, three genuinely distinct networks.
		{id: "1", dial: "192.0.2.1:9001", operator: "acme", pairable: true}, // AS64496
		{id: "2", dial: "192.0.2.65:9002", operator: "acme"},                // AS64497
		{id: "3", dial: "192.0.2.130:9003", operator: "acme"},               // AS64498
	}
	for i := 0; i < 40; i++ {
		got, div, err := selectHops(cand, 3, "", lookup)
		if err != nil {
			t.Fatalf("selectHops: %v", err)
		}
		seen := map[string]bool{}
		for _, h := range got {
			key := asOf(t, lookup, h.dial)
			if seen[key] {
				t.Fatalf("gave up AS diversity that was available: two hops in %s (%v)", key, dials(got))
			}
			seen[key] = true
		}
		if div.asRepeated {
			t.Fatalf("reported an AS repeat on an AS-diverse chain: %+v", div)
		}
		if !div.opRepeated {
			t.Fatalf("div = %+v, want the operator repeat recorded — it is what was actually given up", div)
		}
	}
}

// TestSelectHopsFallsBackRatherThanRefusing: the degradation is a BEHAVIOUR, not an
// error path. A directory that cannot supply AS diversity still yields a chain —
// refusing outright on a small mesh would be the worse trade, exactly as operator
// diversity already reasons — and the weakening is reported instead of hidden.
func TestSelectHopsFallsBackRatherThanRefusing(t *testing.T) {
	lookup := asFixture(t)
	cand := []relayHop{
		{id: "1", dial: "192.0.2.1:9001", pairable: true}, // AS64496
		{id: "2", dial: "192.0.2.2:9002"},                 // AS64496
		{id: "3", dial: "198.51.100.1:9003"},              // AS64496
	}
	got, div, err := selectHops(cand, 3, "", lookup)
	if err != nil {
		t.Fatalf("selectHops refused to build a chain rather than falling back: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d hops, want 3", len(got))
	}
	if !div.degraded() {
		t.Fatal("a chain with all three hops in one AS was not reported as degraded")
	}
	if div.resolved != 3 || div.unresolved != 0 {
		t.Fatalf("div = %+v, want 3 resolved, 0 unresolved", div)
	}
	if msg := div.describe(); !strings.Contains(msg, "RELAXED") || !strings.Contains(msg, "share one network") {
		t.Errorf("describe() = %q, want it to name the relaxation and what it costs", msg)
	}
}

// TestHopDiversityDescribeDistinguishesNoTableFromCollision: the two degradations
// are different problems for different people — one is a distribution decision
// nobody has taken (ADR-0044), the other is an operator's directory to look at — so
// they must not read the same.
func TestHopDiversityDescribeDistinguishesNoTableFromCollision(t *testing.T) {
	noTable := hopDiversity{asRepeated: true, unresolved: 3}
	collision := hopDiversity{asRepeated: true, resolved: 3}
	mixed := hopDiversity{asRepeated: true, resolved: 1, unresolved: 2}

	if got := (hopDiversity{}).describe(); got != "" {
		t.Errorf("an undegraded chain described itself as %q, want empty", got)
	}
	if got := noTable.describe(); !strings.Contains(got, "no hop resolved to an autonomous system") {
		t.Errorf("no-table describe() = %q, want it to name that nothing resolved", got)
	}
	if got := collision.describe(); strings.Contains(got, "no table is loaded") {
		t.Errorf("collision describe() = %q, must not blame a missing table when one is working", got)
	}
	if got := mixed.describe(); !strings.Contains(got, "could not be placed") {
		t.Errorf("mixed describe() = %q, want it to name the unplaceable hops", got)
	}
	// A repeated operator ALONE is not worth reporting: it is advisory, and inert on
	// every deployment with no operators file, so raising it would fire constantly
	// while saying nothing about the load-bearing signal.
	if (hopDiversity{opRepeated: true, resolved: 3}).degraded() {
		t.Error("an operator repeat alone was reported as a degradation")
	}
}

// ---------- integration: the fallback is visible from buildChain ----------

// captureEvents collects what the engine emits, which is the only way a degraded
// chain is distinguishable from a strong one outside this package.
func captureEvents() (*Config, func() []Event) {
	var mu sync.Mutex
	var got []Event
	cfg := &Config{OnEvent: func(e Event) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, e)
	}}
	return cfg, func() []Event {
		mu.Lock()
		defer mu.Unlock()
		return append([]Event(nil), got...)
	}
}

func asChainDir(lookup asn.Lookup, hopDials ...string) (*relayDirectory, string) {
	exitID := hex.EncodeToString(make([]byte, 32))
	d := &relayDirectory{
		as:       lookup,
		exitAddr: map[string]string{exitID: "203.0.113.65:9443"},
		hops: []relayHop{
			{id: exitID, pub: make([]byte, 32), dial: "203.0.113.65:9443", country: "NL", pairable: true},
		},
	}
	// Only the exit carries the country, and that is what pins it: exitsIn filters
	// candidates on country, so leaving the peeling hops untagged keeps them out of
	// the terminating-exit draw while `pairable` still lets one head the chain.
	// Without it, chooseChainExit can pick a peeling candidate as the exit, quietly
	// removing it from the hop pool and dissolving the AS collision under test.
	for i, dial := range hopDials {
		d.hops = append(d.hops, relayHop{
			id: hex.EncodeToString([]byte{byte(i + 1)}), pub: make([]byte, 32),
			dial: dial, pairable: i == 0,
		})
	}
	return d, exitID
}

// TestBuildChainReportsASDegradation is the "visibly" half of #23's requirement: a
// weaker chain must not be indistinguishable from a strong one to everything outside
// selectHops.
//
// Mutation: delete the `if div.degraded() { e.emit(...) }` block in buildChain and
// this fails while every other test still passes — which is the point of having it.
func TestBuildChainReportsASDegradation(t *testing.T) {
	lookup := asFixture(t)

	t.Run("a staged table that could not keep two hops apart is an error-level report", func(t *testing.T) {
		cfg, events := captureEvents()
		cfg.RelayHops = 3
		e := &Engine{cfg: *cfg}
		// Both peeling candidates sit in AS64496, in different /24s.
		d, _ := asChainDir(lookup, "192.0.2.1:9001", "198.51.100.1:9002")
		e.relayDir.Store(d)
		if _, err := e.buildChain(3, "NL"); err != nil {
			t.Fatalf("buildChain: %v", err)
		}
		ev := findEvent(events(), "AS diversity")
		if ev == nil {
			t.Fatal("a chain with two hops in one AS was built and reported nothing")
		}
		if ev.Kind != EventError {
			t.Errorf("event kind = %q, want %q — a working table that could not separate two hops is actionable", ev.Kind, EventError)
		}
		if !strings.Contains(ev.Message, "RELAXED") {
			t.Errorf("message = %q, want it to say the control was relaxed", ev.Message)
		}
	})

	t.Run("no table at all reports at info, not error", func(t *testing.T) {
		cfg, events := captureEvents()
		cfg.RelayHops = 3
		e := &Engine{cfg: *cfg}
		d, _ := asChainDir(nil, "192.0.2.1:9001", "203.0.113.1:9002")
		e.relayDir.Store(d)
		if _, err := e.buildChain(3, "NL"); err != nil {
			t.Fatalf("buildChain: %v", err)
		}
		ev := findEvent(events(), "AS diversity")
		if ev == nil {
			t.Fatal("the no-table state reported nothing at all")
		}
		if ev.Kind != EventInfo {
			t.Errorf("event kind = %q, want %q — every build ships with no table, so this must not cry wolf", ev.Kind, EventInfo)
		}
		if !strings.Contains(ev.Message, "no hop resolved to an autonomous system") {
			t.Errorf("message = %q, want it to name the missing table", ev.Message)
		}
	})

	t.Run("an AS-diverse chain reports nothing", func(t *testing.T) {
		cfg, events := captureEvents()
		cfg.RelayHops = 3
		e := &Engine{cfg: *cfg}
		d, _ := asChainDir(lookup, "192.0.2.1:9001", "203.0.113.1:9002") // AS64496 + AS64500
		e.relayDir.Store(d)
		if _, err := e.buildChain(3, "NL"); err != nil {
			t.Fatalf("buildChain: %v", err)
		}
		if ev := findEvent(events(), "AS diversity"); ev != nil {
			t.Fatalf("an AS-diverse chain reported a degradation: %q", ev.Message)
		}
	})
}

func findEvent(evs []Event, substr string) *Event {
	for i := range evs {
		if strings.Contains(evs[i].Message, substr) {
			return &evs[i]
		}
	}
	return nil
}

func dials(hops []relayHop) []string {
	out := make([]string, 0, len(hops))
	for _, h := range hops {
		out = append(out, h.dial)
	}
	return out
}
