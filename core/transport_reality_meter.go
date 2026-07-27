package core

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core/capacity"
	"golang.org/x/time/rate"
)

// The reality transport's active-probing response (ADR-0027/ADR-0032) reverse-
// proxies unauthenticated connections to the impersonated origin so a censor's
// prober sees that origin, not a Bacchus node. Those bytes cross the operator's
// line — twice for a reverse-proxy leg (rawSplice/bridge), once for a drain
// (holdAndDrain) — and until issue #163 they crossed it UNMETERED: not counted
// against the declared monthly quota (#143/ADR-0040) and not paced by the declared
// speed cap. On a node running -transport reality that made "-monthly-quota is
// never exceeded" false, and handed an attacker a cheap, anonymous way to spend a
// residential volunteer's cap and get the node evicted (design §8.7).
//
// realitySpliceLimits closes that hole. It shares the engine's quota and limiter —
// one ISP bill, one uplink, exactly the forwarder's meter (core/forwarder.go) — but
// enforces them in the one shape ADR-0027 (camouflage fidelity), not #143 (billing),
// allows:
//
//   - It NEVER cuts a copy mid-stream. The forwarder's meter returns
//     ErrQuotaExhausted to tear a session down the instant the cap is spent;
//     truncating a probe response mid-flight is the exact "origin stops mid-response"
//     tell ADR-0027 exists to erase. So the copy legs only COUNT and PACE, they never
//     cut (meterSplice).
//   - Exhaustion is enforced at splice ADMISSION, not per byte (admitSplice, option
//     (c)): once the quota is spent a NEW splice is refused — degraded to a drain, the
//     same camouflaged response ADR-0027 already uses for an unreachable origin — while
//     any splice already in flight runs to completion untouched. Past exhaustion the
//     node is already evicted from serving real clients, so a reverse-proxy would spend
//     the operator's money purely on the attacker's probes; refusing to amplify is
//     strictly correct.
//   - A per-source-IP + global rate/concurrency gate (spliceGate) bounds how much
//     amplification is in flight at once, and the per-IP connection churn (and gate
//     memory) a flood costs. It does NOT raise the time a single source needs to exhaust
//     the cap, and the comment here used to claim it did: the limiter above is
//     AGGREGATE, so one active splice already saturates the whole declared speed, and
//     the per-IP rate (1/sec against a 30 s realityProbeTimeout lifetime) trivially
//     keeps one alive continuously. Time-to-exhaust is quota / (2 × speedCap) whether
//     the volume arrives from one address or a thousand. What makes the spend bounded at
//     all is admitSplice above, not this gate; the eviction attack is priced, not
//     closed, which ADR-0027/ADR-0041 state plainly.
//
// The whole type is nil when the operator declared no limits (the entire current
// datacenter fleet), so a node with no cap and no quota splices exactly as it did
// before #163 — the same opt-in guarantee #143 makes everywhere else.
type realitySpliceLimits struct {
	quota   *capacity.Quota   // nil-inert: shared with core/forwarder.go's meter
	limiter *capacity.Limiter // nil-inert: shared with core/forwarder.go's meter
	ctx     context.Context   // cancelled by Engine.Stop, so a paced drain unblocks at shutdown
	gate    *spliceGate
}

// attachRealitySplice injects the node's declared-limit enforcement into a reality
// transport so its camouflage splice is metered and gated (issue #163). It is a no-op
// for any other transport, and returns tr so it can wrap a newTransport call inline.
// Called at construction, before the transport accepts anything, so the field is set
// before any acceptLoop goroutine can read it. The engine's quota/limiter/limiterCtx
// are all built earlier in newEngine, so they are available here for every transport
// this engine builds — the single-transport one and each pooled one.
func (e *Engine) attachRealitySplice(tr Transport) Transport {
	if rt, ok := tr.(*realityTransport); ok {
		rt.splice = newRealitySpliceLimits(e.quota, e.limiter, e.limiterCtx)
	}
	return tr
}

// newRealitySpliceLimits builds the splice enforcement from the engine's already-
// constructed quota and limiter (core/engine.go builds both before the transport).
// It returns nil — fully inert — when the operator declared neither a speed cap nor
// a quota, which is every node in today's fleet: with no bill to protect and no
// quota to exhaust there is nothing for #163 to enforce, and keeping the splice paths
// byte-for-byte unchanged there is the same opt-in promise #143 makes.
func newRealitySpliceLimits(quota *capacity.Quota, limiter *capacity.Limiter, ctx context.Context) *realitySpliceLimits {
	if quota == nil && limiter == nil {
		return nil
	}
	return &realitySpliceLimits{quota: quota, limiter: limiter, ctx: ctx, gate: newSpliceGate()}
}

// admitSplice decides whether a NEW unauthenticated connection from remote may be
// reverse-proxied to the origin, or must fall back to the caller's holdAndDrain. It
// is the whole of option (c) plus the eviction defense, and it is the only place
// exhaustion is checked — never mid-copy.
//
// release must be called (defer) once the splice finishes so its concurrency slot is
// returned; it is a no-op on a denial. A nil receiver (no declared limits) always
// admits, so an unmetered node reverse-proxies exactly as before.
func (sl *realitySpliceLimits) admitSplice(remote net.Addr, now time.Time) (ok bool, release func()) {
	if sl == nil {
		return true, func() {}
	}
	// Option (c): once the declared quota is spent, do not open a new reverse-proxy.
	// quota is nil-safe (a cap-only node never exhausts and always reaches the gate).
	if sl.quota.Exhausted(now) {
		return false, func() {}
	}
	return sl.gate.admit(ipOf(remote), now)
}

// meterSplice wraps one reverse-proxy copy leg so its bytes are paced to the declared
// speed cap and counted against the declared monthly quota, both crossings
// (capacity.LinkCrossings) — the same accounting core/forwarder.go's meter applies to
// a forwarded byte, because a spliced byte spends the same uplink the same way. It
// never cuts: exhaustion is handled by admitSplice (see the type doc). A nil receiver
// returns r unchanged.
//
// Pacing is on the raw read count (one crossing), matching Limiter's convention;
// counting charges every crossing. The fixed handshake prefix a splice replays (the
// peeked ClientHello / consumed probe bytes) is deliberately not metered — it is a
// bounded per-connection constant, the same carve-out class as the Noise handshake
// the forwarder's meter already excludes, and the unbounded streamed body that
// follows is what this wraps.
func (sl *realitySpliceLimits) meterSplice(r io.Reader) io.Reader {
	if sl == nil {
		return r
	}
	paced := sl.limiter.LimitReads(sl.ctx, r)
	return &spliceCountReader{r: paced, q: sl.quota, crossings: capacity.LinkCrossings}
}

// countDrain wraps holdAndDrain's discard read so even the drained-inbound bytes are
// counted against the quota — once (they only arrive; nothing is sent back). It does
// not pace: a drain emits nothing, so there is nothing to shape, and coupling it to
// the serving limiter would let a probe flood slow real traffic for no camouflage
// benefit. Counting it is what makes "every reality byte is accounted" literally true
// (closing §8.7), not merely "every reverse-proxied one". A nil receiver returns r
// unchanged.
func (sl *realitySpliceLimits) countDrain(r io.Reader) io.Reader {
	if sl == nil {
		return r
	}
	return &spliceCountReader{r: r, q: sl.quota, crossings: 1}
}

// spliceCountReader counts every byte read through it against the quota, charging
// `crossings` per byte, and NEVER returns ErrQuotaExhausted. The absence of a cut is
// the point (see realitySpliceLimits): the quota is enforced at admission, not here,
// so an in-flight probe response is never truncated.
type spliceCountReader struct {
	r         io.Reader
	q         *capacity.Quota // nil-safe (Add is a no-op on nil)
	crossings int
}

func (s *spliceCountReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.q.Add(uint64(n)*uint64(s.crossings), time.Now())
	}
	return n, err
}

// --- per-IP + global splice admission gate (issue #163) --------------------

const (
	// spliceMaxConcurrent caps how many reverse-proxy splices run at once, across all
	// sources. A reverse-proxy leg is the amplifying path (the byte crosses the line
	// twice), so bounding their count bounds the worst-case instantaneous amplification
	// a flood inflicts, independent of the per-IP cap. Set far above any plausible rate
	// of genuine active probes — an ordinary :443 origin fields orders of magnitude more
	// real connections — so it only ever bites a flood.
	spliceMaxConcurrent = 512

	// splicePerIPPerSec / splicePerIPBurst bound how fast ONE source IP may open new
	// reverse-proxy splices. That bounds per-IP connection churn — origin-side load and
	// this gate's bucket memory — and NOT the time to exhaust a declared cap: because the
	// splice limiter is aggregate, a single continuously-renewed splice already spends the
	// whole declared speed (see realitySpliceLimits). A real active prober from one
	// address probes far slower than this, so an honest scanner is never throttled.
	splicePerIPPerSec = 1
	splicePerIPBurst  = 16

	// spliceGateSweep bounds how often the gate evicts idle per-IP buckets, so its
	// memory tracks recently-active sources rather than every IP ever seen, without
	// paying an O(n) sweep on every admission.
	spliceGateSweep = time.Minute
	spliceGateIdle  = 10 * time.Minute
)

// spliceGate rate-limits new reverse-proxy splices per source IP and caps their total
// concurrency (issue #163). It bounds the instantaneous amplification a probe flood
// inflicts and the per-IP churn (and memory) it costs, without touching a genuine,
// occasional active probe. It does not make a single uplink unable to exhaust a
// residential cap — the aggregate speed cap, not this gate, sets that clock (see
// realitySpliceLimits).
//
// Its three limits are fields, not consts read directly, so a test can exercise the
// mechanism with small values instead of looping to the production constant (and so a
// change to a production constant never silently invalidates a boundary test).
type spliceGate struct {
	maxConcurrent int
	perIPPerSec   rate.Limit
	perIPBurst    int

	mu         sync.Mutex
	perIP      map[string]*ipBucket
	concurrent int
	lastSweep  time.Time
}

type ipBucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// newSpliceGate builds the gate with the production limits.
func newSpliceGate() *spliceGate {
	return newSpliceGateWith(spliceMaxConcurrent, splicePerIPPerSec, splicePerIPBurst)
}

// newSpliceGateWith builds a gate with explicit limits, for tests.
func newSpliceGateWith(maxConcurrent int, perIPPerSec rate.Limit, perIPBurst int) *spliceGate {
	return &spliceGate{
		maxConcurrent: maxConcurrent,
		perIPPerSec:   perIPPerSec,
		perIPBurst:    perIPBurst,
		perIP:         map[string]*ipBucket{},
	}
}

// admit reports whether a new splice from ip may proceed, and returns a release to
// call when it finishes. A denial (global concurrency full, or this IP over its rate)
// returns a no-op release; the caller drains instead of reverse-proxying.
func (g *spliceGate) admit(ip string, now time.Time) (ok bool, release func()) {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.sweep(now)

	// Global concurrency first — cheap, and consumes no per-IP token on a full-house
	// denial.
	if g.concurrent >= g.maxConcurrent {
		return false, func() {}
	}
	b := g.perIP[ip]
	if b == nil {
		b = &ipBucket{lim: rate.NewLimiter(g.perIPPerSec, g.perIPBurst)}
		g.perIP[ip] = b
	}
	b.seen = now
	if !b.lim.AllowN(now, 1) {
		return false, func() {}
	}
	g.concurrent++
	var once sync.Once
	return true, func() {
		once.Do(func() {
			g.mu.Lock()
			g.concurrent--
			g.mu.Unlock()
		})
	}
}

// sweep drops per-IP buckets unused for spliceGateIdle, at most once per
// spliceGateSweep. Caller holds g.mu.
func (g *spliceGate) sweep(now time.Time) {
	if now.Sub(g.lastSweep) < spliceGateSweep {
		return
	}
	g.lastSweep = now
	for ip, b := range g.perIP {
		if now.Sub(b.seen) > spliceGateIdle {
			delete(g.perIP, ip)
		}
	}
}

// ipOf extracts the host (IP) part of a net.Addr for per-IP keying, tolerating both
// a *net.TCPAddr and the generic host:port string form.
func ipOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.IP.String()
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
