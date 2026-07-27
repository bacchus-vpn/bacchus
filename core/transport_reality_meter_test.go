package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/capacity"
	"golang.org/x/time/rate"
)

// exhaustedQuota returns a *capacity.Quota already past its declared cap, for the
// option-(c) tests. The cap (1000) is a bare literal — never LinkCrossings or any
// constant the code under test also reads — and it is exhausted by adding strictly
// more than it, so "exhausted" is asserted, not assumed.
func exhaustedQuota(t *testing.T, now time.Time) *capacity.Quota {
	t.Helper()
	q, err := capacity.NewQuota(capacity.Limits{MonthlyQuota: 1000, CycleDay: 1}, "", now)
	if err != nil {
		t.Fatalf("NewQuota: %v", err)
	}
	q.Add(2000, now) // > limit: spend it
	if !q.Exhausted(now) {
		t.Fatal("test setup: quota should be exhausted after spending past its cap")
	}
	return q
}

// freshQuota returns a large, unspent quota, for the counting tests where the point
// is what accrues rather than whether it is exhausted.
func freshQuota(t *testing.T, now time.Time) *capacity.Quota {
	t.Helper()
	q, err := capacity.NewQuota(capacity.Limits{MonthlyQuota: capacity.GB, CycleDay: 1}, "", now)
	if err != nil {
		t.Fatalf("NewQuota: %v", err)
	}
	return q
}

// TestSpliceReadersChargeLinkCrossings pins the accounting: a reverse-proxy leg
// (meterSplice) charges the quota for BOTH of a forwarded byte's link crossings, and a
// drain (countDrain) for the ONE crossing it makes. The multipliers below are literal
// 2 and 1 — the point of the test is that the code charges those numbers, so deriving
// them from LinkCrossings (the constant under test) would make it pass vacuously.
func TestSpliceReadersChargeLinkCrossings(t *testing.T) {
	now := time.Now()
	const n = 4096 // bytes pushed through each reader; a literal, unrelated to any cap

	// meterSplice, nil limiter (no pacing) so the copy is instant and the count is the
	// only thing under test. Both crossings => 2*n.
	q := freshQuota(t, now)
	sl := newRealitySpliceLimits(q, nil, context.Background())
	copied, err := io.Copy(io.Discard, sl.meterSplice(bytes.NewReader(make([]byte, n))))
	if err != nil || copied != n {
		t.Fatalf("meterSplice copy = %d,%v; want %d,nil", copied, err, n)
	}
	if got := q.Used(now); got != 2*n {
		t.Fatalf("meterSplice charged %d bytes; want %d (both link crossings of %d)", got, 2*n, n)
	}

	// countDrain charges once: the drained bytes only arrive, nothing is sent back.
	qd := freshQuota(t, now)
	sld := newRealitySpliceLimits(qd, nil, context.Background())
	copied, err = io.Copy(io.Discard, sld.countDrain(bytes.NewReader(make([]byte, n))))
	if err != nil || copied != n {
		t.Fatalf("countDrain copy = %d,%v; want %d,nil", copied, err, n)
	}
	if got := qd.Used(now); got != n {
		t.Fatalf("countDrain charged %d bytes; want %d (one crossing of %d)", got, n, n)
	}
}

// TestSpliceReaderNeverCutsOnExhaustion is the option-(c) invariant at the byte level:
// a metered splice reader keeps delivering every byte even when the quota is already
// spent. It is the deliberate opposite of quota.MeterForwarded, which returns
// ErrQuotaExhausted on the first read past the cap to tear a real session down —
// truncating a probe response mid-flight is the exact tell ADR-0027 exists to avoid,
// so the splice enforces exhaustion at admission (TestAdmitSpliceRefusesWhenExhausted),
// never here.
func TestSpliceReaderNeverCutsOnExhaustion(t *testing.T) {
	now := time.Now()
	q := exhaustedQuota(t, now)
	sl := newRealitySpliceLimits(q, nil, context.Background())

	const n = 8192
	copied, err := io.Copy(io.Discard, sl.meterSplice(bytes.NewReader(make([]byte, n))))
	if err != nil {
		t.Fatalf("metered splice reader returned an error on an exhausted quota (%v); it must never cut an in-flight splice", err)
	}
	if copied != n {
		t.Fatalf("metered splice delivered %d/%d bytes on an exhausted quota; a short copy is the mid-response truncation ADR-0027 forbids", copied, n)
	}
	// Sanity: the bytes were still counted (this is not "unmetered"), just not cut.
	if q.Used(now) == 0 {
		t.Fatal("metered splice on an exhausted quota counted nothing; it should still count, only never cut")
	}
}

// TestAdmitSpliceRefusesWhenExhausted is option (c) at the admission point: a new
// splice is refused once the declared quota is spent (the caller then drains rather
// than reverse-proxying), while an unexhausted node admits. This is the ONLY place
// exhaustion gates the splice — the copy legs never do (TestSpliceReaderNeverCutsOnExhaustion).
func TestAdmitSpliceRefusesWhenExhausted(t *testing.T) {
	now := time.Now()
	addr := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}

	spent := newRealitySpliceLimits(exhaustedQuota(t, now), nil, context.Background())
	if ok, _ := spent.admitSplice(addr, now); ok {
		t.Fatal("admitSplice admitted a NEW reverse-proxy on an exhausted quota; option (c) refuses it")
	}

	ok, release := newRealitySpliceLimits(freshQuota(t, now), nil, context.Background()).admitSplice(addr, now)
	if !ok {
		t.Fatal("admitSplice refused a splice on an unexhausted quota; only exhaustion or a per-IP flood should")
	}
	release()
}

// TestRealitySpliceMeteredEndToEnd proves the wiring: a metered responder's real
// reverse-proxy path (onUnauthenticated -> rawSplice) actually runs the bytes through
// the quota. An unauthenticated, chain-validating prober is spliced to a banner origin
// (as in TestRealityProberValidatesOriginChain) and, once it has read the origin's
// bytes, the node's quota shows a non-zero charge. Reverting rawSplice's meterSplice
// wrap back to a bare io.Copy leaves Used at zero and fails this.
func TestRealitySpliceMeteredEndToEnd(t *testing.T) {
	const sni = "origin.example"
	pool, originCert := issueOriginCert(t, sni, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil)
	originAddr := startBannerOrigin(t, &tls.Config{Certificates: []tls.Certificate{originCert}})

	now := time.Now()
	q := freshQuota(t, now)
	resp := newMeteredReality(t, sni, originAddr, q, nil)
	defer resp.close()

	raw, err := net.Dial("tcp", resp.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))

	tc := tls.Client(raw, &tls.Config{ServerName: sni, RootCAs: pool})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("prober could not validate the spliced origin chain: %v", err)
	}
	if _, err := tc.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write through splice: %v", err)
	}
	got := make([]byte, 64)
	n, _ := tc.Read(got)
	if !bytes.Contains(got[:n], []byte("HELLO")) {
		t.Fatalf("prober did not receive the origin banner; got %q", got[:n])
	}

	if used := q.Used(time.Now()); used == 0 {
		t.Fatal("a completed reverse-proxy splice charged nothing against the declared quota; the splice is unmetered (#163 regression)")
	}
}

// TestRealityExhaustedNodeDrainsInsteadOfProxying is option (c) end to end: once the
// operator's quota is spent, a new unauthenticated prober is NOT reverse-proxied to the
// origin (it would spend the operator's line amplifying a probe past the cap). It is
// drained instead — the same no-instant-close response ADR-0027 uses for an unreachable
// origin — so the prober's chain-validating handshake never completes. The control
// (a fresh quota, TestRealitySpliceMeteredEndToEnd) shows the same prober DOES validate,
// so this asserts the difference is the quota, not the setup.
func TestRealityExhaustedNodeDrainsInsteadOfProxying(t *testing.T) {
	const sni = "origin.example"
	pool, originCert := issueOriginCert(t, sni, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour), nil)
	originAddr := startBannerOrigin(t, &tls.Config{Certificates: []tls.Certificate{originCert}})

	now := time.Now()
	resp := newMeteredReality(t, sni, originAddr, exhaustedQuota(t, now), nil)
	defer resp.close()

	raw, err := net.Dial("tcp", resp.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))

	tc := tls.Client(raw, &tls.Config{ServerName: sni, RootCAs: pool})
	if err := tc.Handshake(); err == nil {
		t.Fatal("prober validated an origin chain against an EXHAUSTED reality node; option (c) must refuse the new reverse-proxy and drain")
	}
}

// TestSpliceGateRateLimitsPerIP pins the per-IP bound: one source IP may open only a
// burst of new reverse-proxy splices before it is refused (and drained), while a
// different IP is unaffected.
//
// What that bounds is per-IP connection CHURN — origin-side load and this gate's own
// bucket memory — not the time to exhaust a declared cap. This comment used to claim
// the latter, and the claim was false: the splice limiter is AGGREGATE, so a single
// continuously-renewed splice already spends the whole declared speed, and
// time-to-exhaust is quota / (2 × speedCap) whether the volume arrives from one address
// or a thousand. What prices the eviction attack is admitSplice, not this gate (#168;
// ADR-0027 and ADR-0041 carry the corrected wording, and this was its last stale copy).
//
// Burst 2 is a test literal; production splicePerIPBurst is exercised only through the
// gate's own field so a tuning change never silently voids this boundary.
func TestSpliceGateRateLimitsPerIP(t *testing.T) {
	now := time.Now()
	// A tiny per-IP rate so no token replenishes within a single `now`; burst 2.
	g := newSpliceGateWith(1<<20, rate.Limit(0.001), 2)

	admit := func(ip string) bool {
		ok, release := g.admit(ip, now)
		if ok {
			release() // return the concurrency slot; this test is about the per-IP rate
		}
		return ok
	}

	if !admit("198.51.100.9") || !admit("198.51.100.9") {
		t.Fatal("the first two splices from one IP should be admitted (burst = 2)")
	}
	if admit("198.51.100.9") {
		t.Fatal("a third splice from the same IP at the same instant should be refused (per-IP rate)")
	}
	if !admit("198.51.100.10") {
		t.Fatal("a different IP has its own bucket and should be admitted")
	}
}

// TestSpliceGateGlobalConcurrencyCap pins the global backstop: no more than
// maxConcurrent reverse-proxy splices run at once across ALL sources, independent of the
// per-IP rate, and a completed splice returns its slot. maxConcurrent 2 is a test literal.
func TestSpliceGateGlobalConcurrencyCap(t *testing.T) {
	now := time.Now()
	// A generous per-IP rate so the per-IP limiter never fires and concurrency is the
	// only thing under test; distinct IPs so per-IP buckets never interact.
	g := newSpliceGateWith(2, rate.Limit(1e9), 1<<20)

	ok1, rel1 := g.admit("192.0.2.1", now)
	ok2, _ := g.admit("192.0.2.2", now)
	if !ok1 || !ok2 {
		t.Fatal("the first two concurrent splices should be admitted (maxConcurrent = 2)")
	}
	if ok3, _ := g.admit("192.0.2.3", now); ok3 {
		t.Fatal("a third concurrent splice should be refused while two are in flight")
	}
	rel1() // one finishes, freeing a slot
	if ok4, rel4 := g.admit("192.0.2.4", now); !ok4 {
		t.Fatal("a slot freed by a completed splice should admit the next one")
	} else {
		rel4()
	}
}

// TestSpliceGateReleaseIsIdempotent guards the concurrency counter against a
// double-release (a defer plus an explicit call, say) driving it negative and silently
// widening the cap.
func TestSpliceGateReleaseIsIdempotent(t *testing.T) {
	now := time.Now()
	g := newSpliceGateWith(1, rate.Limit(1e9), 1<<20)
	ok, release := g.admit("192.0.2.50", now)
	if !ok {
		t.Fatal("first admit should succeed")
	}
	release()
	release() // second call must be a no-op, not a second decrement

	// The single slot is free again — and only once. Two back-to-back admits: the
	// first succeeds, the second is refused (cap 1), proving the counter is at 0 not -1.
	ok1, _ := g.admit("192.0.2.51", now)
	ok2, _ := g.admit("192.0.2.52", now)
	if !ok1 || ok2 {
		t.Fatalf("cap-1 gate after a double-release admitted %v then %v; want true then false", ok1, ok2)
	}
}

// TestSpliceGateEvictsIdleBuckets pins the per-IP map's lifecycle: a source not seen for
// spliceGateIdle is dropped, so the gate's memory tracks recently-active sources rather
// than every IP ever seen. Without the sweep's delete the bucket persists and the map
// grows unbounded under a flood from many addresses.
func TestSpliceGateEvictsIdleBuckets(t *testing.T) {
	start := time.Now()
	g := newSpliceGateWith(1<<20, rate.Limit(1e9), 8)

	ok, release := g.admit("198.51.100.1", start)
	if !ok {
		t.Fatal("first admit should succeed")
	}
	release()
	if _, tracked := g.perIP["198.51.100.1"]; !tracked {
		t.Fatal("an admitted IP should be tracked immediately after")
	}

	// Advance past the idle horizon AND the sweep interval, then touch the gate from a
	// different IP so a sweep runs. The stale bucket must be gone.
	later := start.Add(spliceGateIdle + spliceGateSweep + time.Second)
	ok, release = g.admit("198.51.100.2", later)
	if ok {
		release()
	}
	if _, tracked := g.perIP["198.51.100.1"]; tracked {
		t.Fatal("an IP idle past spliceGateIdle should have been evicted by the sweep")
	}
}

// TestRealitySpliceNilInertUnmetered is the opt-in guarantee: a node that declared
// neither a cap nor a quota (every node in today's fleet) builds no splice limits at
// all, and the nil handle admits, counts, and paces exactly nothing — so the splice
// paths behave byte-for-byte as they did before #163.
func TestRealitySpliceNilInertUnmetered(t *testing.T) {
	if sl := newRealitySpliceLimits(nil, nil, context.Background()); sl != nil {
		t.Fatalf("newRealitySpliceLimits(nil, nil) = %v; want nil (no declared limits => fully inert)", sl)
	}

	var sl *realitySpliceLimits // the nil handle the transport holds for an unmetered node
	if ok, release := sl.admitSplice(&net.TCPAddr{IP: net.ParseIP("192.0.2.1")}, time.Now()); !ok {
		t.Fatal("nil splice limits must always admit")
	} else {
		release() // must be a safe no-op
	}
	r := bytes.NewReader([]byte("abc"))
	if sl.meterSplice(r) != r {
		t.Fatal("nil meterSplice must return the reader unchanged")
	}
	if sl.countDrain(r) != r {
		t.Fatal("nil countDrain must return the reader unchanged")
	}
}

// newMeteredReality builds a responder bound to loopback with an impersonated origin and
// an explicit splice-limits handle, for the metered-path integration tests. A nil q and
// nil lim would make the handle itself nil (unmetered); callers pass a real quota.
func newMeteredReality(t *testing.T, sni, origin string, q *capacity.Quota, lim *capacity.Limiter) *realityTransport {
	t.Helper()
	resp, err := newRealityTransport(Config{RealityListen: "127.0.0.1:0", RealitySNI: sni, RealityProbeOrigin: origin}, nil)
	if err != nil {
		t.Fatalf("responder: %v", err)
	}
	resp.splice = newRealitySpliceLimits(q, lim, context.Background())
	if err := resp.ensureListener(); err != nil {
		t.Fatalf("ensureListener: %v", err)
	}
	return resp
}
