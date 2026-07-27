package capacity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrQuotaExhausted ends a transfer that would carry a node past its operator's
// declared monthly cap. It surfaces as the read error on a metered stream, which
// unwinds the io.Copy and tears the session down.
//
// Cutting a live session is the deliberately harsh choice, and it is the right
// one: the card's requirement is that the cap is NEVER exceeded, the overage is
// real money out of a volunteer's pocket, and "let in-flight sessions drain" is an
// UNBOUNDED overshoot (any number of sessions, each with any amount left to send).
// The cost is bounded on the other side — a cut client reconnects onto another
// exit through the pool's existing ladder (ADR-0028) and its auto-reconnect (issue
// #2), so the user loses a moment and the operator does not lose the bill.
var ErrQuotaExhausted = errors.New("capacity: declared monthly quota exhausted")

// Checkpointing bounds how much quota a crash can lose.
//
// Checkpointing every byte would put a disk write on the data path; checkpointing
// only at shutdown would make `kill -9` a free quota reset — and a quota a crash
// resets is not a quota. So the counter is checkpointed on whichever comes first:
// every granularity() bytes, every flushInterval of wall time, or the moment the
// quota is spent (see Add — that transition is the one that must never be lost).
const (
	// maxFlushGranularity caps the byte trigger for a large quota: 16 MB is ~0.004%
	// of a 400 GB cap, which is a rounding error on an ISP bill.
	maxFlushGranularity = 16 * MB
	// minFlushGranularity floors it so a tiny quota does not put a write on every
	// read.
	minFlushGranularity = 64 * KB
	// flushInterval bounds the case where a trickle of traffic would otherwise sit
	// uncheckpointed indefinitely, never reaching the byte trigger.
	flushInterval = 30 * time.Second
)

// granularity is the byte trigger for this quota, scaled to its size rather than
// fixed.
//
// A fixed 16 MB trigger is silently useless for a small quota: a node with a 1 MB
// cap spends it without ever reaching that trigger, and if it also spends it inside
// flushInterval it is never checkpointed at all, so a restart mints a fresh cycle.
// That is not a smaller version of the bug — it is the whole feature failing, and it
// was found by a smoke test rather than by the unit tests, which had all used a
// large quota and so always crossed the fixed trigger.
//
// Scaling to limit/64 keeps the worst-case loss at ~1.5% of the declared quota for
// any size, clamped to [64 KB, 16 MB].
func (q *Quota) granularity() Bytes {
	g := q.limit / 64
	if g < minFlushGranularity {
		g = minFlushGranularity
	}
	if g > maxFlushGranularity {
		g = maxFlushGranularity
	}
	return g
}

// Quota tracks bytes served against the operator's declared monthly cap (issue
// #143) and answers the one question the rest of the system asks: may this node
// still be given work?
//
// It is safe for concurrent use by the goroutines copying each direction of every
// session. The nil *Quota is valid and inert — Add is a no-op, Exhausted is
// always false — so a node with no declared quota passes nil and no call site
// needs a branch. (Same idiom as accounting.Counter, for the same reason.)
//
// # Why this persists
//
// The card's requirement is that the quota is NEVER exceeded. An in-memory
// counter makes `systemctl restart` mint a fresh month, so persistence is not a
// nicety here: without it the type does not implement its own headline
// requirement. State is checkpointed to disk and reloaded at startup; a restart
// resumes the cycle it was in.
//
// "Never" is true of everything that reaches this counter. It holds across every
// path the FORWARDER takes (see core/forwarder.go's meter), and — since issue #163 —
// across the reality transport's camouflage splice too, which now counts its bytes
// here through realitySpliceLimits (design §8.7). The one caveat is that the splice
// is enforced at ADMISSION, not per byte: a new splice is refused once the cap is
// spent, but one already in flight completes rather than being cut mid-response
// (cutting is the tell ADR-0027 exists to avoid). So "never exceeded" holds up to a
// bounded overshoot — whatever the in-flight splices drain before their timeout — not
// the unbounded, silent overshoot a node running -transport reality had before #163.
//
// # Whose clock
//
// Every entry point takes `now` from the caller. The node's own clock decides its
// own cycle, and that is sound precisely because the quota protects the node's
// own operator: a node whose clock lies only cheats itself out of (or into) its
// own ISP bill. There is nothing here for a remote party to attack, and nothing
// to synchronise.
type Quota struct {
	mu       sync.Mutex
	limit    Bytes
	cycleDay int

	used       Bytes
	cycleStart time.Time

	path        string    // "" = in-memory only (no persistence)
	flushedAt   Bytes     // `used` as of the last successful checkpoint
	flushedTime time.Time // wall time of the last successful checkpoint
	flushErr    error     // sticky: first checkpoint failure, surfaced by Err
}

// quotaState is the on-disk checkpoint. Deliberately tiny and human-readable:
// an operator debugging "why is my node not serving" must be able to cat this
// file and understand it, and edit it if their ISP moved their billing date.
type quotaState struct {
	CycleStart time.Time `json:"cycleStart"`
	Used       uint64    `json:"used"`
	// Limit and CycleDay are recorded for the human reading the file and are NOT
	// read back — the flags are the source of truth for the operator's intent, so
	// changing -monthly-quota takes effect immediately rather than being overridden
	// by a stale checkpoint.
	Limit    uint64 `json:"limit"`
	CycleDay int    `json:"cycleDay"`
}

// NewQuota builds a Quota for the declared limits, restoring prior usage from
// path if it exists. path may be "" to keep the counter in memory only, which is
// what a node with no declared quota (or a test) wants.
//
// A checkpoint from a previous cycle is discarded rather than carried forward:
// the cycle it belongs to has already reset. A checkpoint from the CURRENT cycle
// resumes, which is what makes a restart mid-cycle safe.
//
// A checkpoint from a LATER cycle than the clock believes in is not impossible
// state, and must not be discarded — it means the CLOCK is wrong, not the disk.
// This is the boot half of the same excursion rollover guards mid-process, and it
// is the half that actually bites the hardware this card targets: a Raspberry Pi
// with no RTC boots at whatever time it last knew (or 1970) BEFORE NTP has stepped
// it, and NewQuota runs in that window. Computing the cycle from the stale clock
// and then discarding the disk on a mismatch would zero a spent quota, checkpoint
// the zero on the first Add, and hand back a fresh month across a reboot — the
// exact failure persistence exists to close, reached without a crash. So a cycle
// only ever advances here too: trust the later of the two, which is the safe
// direction (it can only under-serve, never overshoot the operator's bill). Once
// NTP corrects the clock, rollover resolves it — an unchanged cycle keeps the
// usage, a genuinely new one resets.
//
// A missing file is not an error (first run). A corrupt one IS an error: silently
// starting from zero on unparseable state would turn "corrupt the state file"
// into "reset the quota", which is the failure mode persistence exists to close.
// An unreadable one is an error for the same reason — see the read below.
func NewQuota(l Limits, path string, now time.Time) (*Quota, error) {
	if l.MonthlyQuota == 0 {
		return nil, nil // no declared quota: the inert nil *Quota
	}
	day := l.CycleDay
	if day == 0 {
		day = 1
	}
	q := &Quota{
		limit:       l.MonthlyQuota,
		cycleDay:    day,
		cycleStart:  CycleStart(now, day),
		path:        path,
		flushedTime: now,
	}
	if path == "" {
		return q, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return q, nil // first run
		}
		return nil, fmt.Errorf("read quota state %s: %w", path, err)
	}
	var st quotaState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("parse quota state %s: %w (delete it to start a fresh cycle, accepting that this forgets usage already spent)", path, err)
	}
	if !st.CycleStart.Before(q.cycleStart) {
		// Equal: the ordinary mid-cycle restart, resume it.
		// After: the clock is stale (see above), so adopt the cycle the disk knows.
		// Before: a genuinely older cycle, already reset — leave used at zero.
		q.cycleStart = st.CycleStart
		q.used = Bytes(st.Used)
		q.flushedAt = q.used
	}
	return q, nil
}

// CycleStart returns the start of the billing cycle containing now for a cap that
// resets on the given day of the month: the most recent occurrence of that day at
// or before now.
//
// Exported because the coordinator-side tests and cmd/node's status output both
// need to agree with the node on where a cycle boundary falls, and re-deriving
// that arithmetic twice is how the two would drift.
//
// day is 1..28 (Limits.Validate enforces it), so the anchor always exists in
// every month including February and the month arithmetic below never has to
// handle a normalising overflow.
func CycleStart(now time.Time, day int) time.Time {
	if day < 1 {
		day = 1
	}
	y, m, _ := now.Date()
	c := time.Date(y, m, day, 0, 0, 0, 0, now.Location())
	if c.After(now) {
		c = c.AddDate(0, -1, 0) // the anchor this month is still ahead: we are in last month's cycle
	}
	return c
}

// rollover resets the counter if now has crossed FORWARD into a new billing cycle.
// Caller holds q.mu.
//
// The direction check is load-bearing. Resetting on any *change* of cycle start
// would let a BACKWARDS clock step zero a spent quota — and because the reset is
// checkpointed eagerly below, it would erase the real usage from disk, which is
// worse than a crash (a crash loses at most one granularity).
//
// This is not an adversarial concern, and the clock-trust argument in the type doc
// does not cover it: NTP is not lying for gain. It is ordinary behaviour on exactly
// the hardware this card targets — a Raspberry Pi with no RTC boots with a stale
// time, NTP steps it forward across the anchor day, and every reboot would mint a
// fresh month. Reached the same way by a VM suspend/resume or a dual-boot RTC skew.
//
// A cycle therefore only ever advances. A backwards excursion is ignored: the node
// keeps the usage it has already spent, which is the safe direction (it can only
// under-serve, never overshoot the operator's bill).
func (q *Quota) rollover(now time.Time) {
	cs := CycleStart(now, q.cycleDay)
	if !cs.After(q.cycleStart) {
		return
	}
	q.cycleStart = cs
	q.used = 0
	q.flushedAt = 0
	// Checkpoint the reset eagerly: a crash right after a rollover must not
	// resurrect the previous cycle's usage and strand the node for a month.
	q.checkpoint(now)
}

// Add records n bytes served. It is the only mutator on the data path, so it is
// deliberately cheap: a mutex, some arithmetic, and a checkpoint only when the
// granularity or interval says so.
func (q *Quota) Add(n uint64, now time.Time) {
	if q == nil || n == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.rollover(now)
	was := q.used >= q.limit
	q.used += Bytes(n)

	// The exhaustion transition is checkpointed the instant it happens, whatever the
	// triggers below say. It is the one piece of state whose loss defeats the whole
	// feature: a node that spends its quota and is killed before its next scheduled
	// checkpoint would come back believing the cycle is fresh, and "never exceeded"
	// would hold only until the next crash.
	if !was && q.used >= q.limit {
		q.checkpoint(now)
		return
	}
	if q.used-q.flushedAt >= q.granularity() || now.Sub(q.flushedTime) >= flushInterval {
		q.checkpoint(now)
	}
}

// Exhausted reports whether the declared quota for the current cycle is spent.
// This is the single bit the coordinator is told (as wire "quotaState"), and the
// bit the node's own admission path gates on.
func (q *Quota) Exhausted(now time.Time) bool {
	if q == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.rollover(now)
	return q.used >= q.limit
}

// Used returns bytes spent in the current cycle.
func (q *Quota) Used(now time.Time) Bytes {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.rollover(now)
	return q.used
}

// Remaining returns bytes left in the current cycle, saturating at zero.
func (q *Quota) Remaining(now time.Time) Bytes {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.rollover(now)
	if q.used >= q.limit {
		return 0
	}
	return q.limit - q.used
}

// LinkCrossings is how many times a byte this node FORWARDS crosses this node's
// link, and therefore how many times the operator's ISP meters it: once arriving,
// once leaving. A forwarder is a middle box — it originates nothing and terminates
// nothing — so every byte it handles is carried, and billed, twice.
//
// This is why a forwarded byte costs the quota 2. MonthlyQuota is the operator's ISP
// cap, and a residential cap — the population #143 exists to serve — meters both
// directions against one number. Counting each byte once would let a declared 400GB
// spend 800GB of a real 400GB cap: a 100% overshoot, silently, in precisely the
// direction that produces the overage bill this feature exists to prevent. Compare
// the 7.4% binary-vs-decimal overshoot that Bytes goes to some trouble to avoid —
// the same failure, an order of magnitude smaller.
//
// The flip side, which has to be said in the same breath or this reads as free: the
// quota is a budget in METERED bytes, so it also halves what a given declaration
// SERVES. 400GB declared carries ~200GB of user traffic. That is not a detail to
// leave to whoever reads this file — an operator who declares "the slice of my cap
// I choose to donate" and means 400GB of traffic now donates half of it, silently.
// Limits.MonthlyQuota, cmd/node's -monthly-quota help and docs/RUNNING.md all say so
// explicitly, and they have to keep saying so: an earlier version of this comment
// cited those three as saying "your ISP's data cap" while they actually said "your
// ISP's data cap, OR WHATEVER SLICE OF IT YOU CHOOSE TO DONATE" — quoting the half
// that supported the change and omitting the half it invalidated, without updating
// any of the three.
//
// The case this over-counts is a node billed for egress only, as most VPSes are;
// there the operator declares twice what they mean to donate. That asymmetry is
// deliberate. Over-counting costs a node that stops early; under-counting costs a
// volunteer an overage bill they did not agree to. #143 prefers under-serving every
// time, and the same preference decides the low quantile in Estimator.
const LinkCrossings = 2

// AddForwarded records n bytes forwarded through this node, charging every crossing
// of the operator's link (see LinkCrossings). It is the data-path entry point; Add
// is the primitive beneath it, and counts exactly the number it is handed.
func (q *Quota) AddForwarded(n uint64, now time.Time) {
	q.Add(n*LinkCrossings, now)
}

// MeterForwarded wraps a forwarded stream so every byte read through it counts
// against the quota — both of its link crossings, per LinkCrossings — AND the
// transfer stops with ErrQuotaExhausted once the cap is spent.
//
// It both counts and enforces, because the two cannot be usefully separated: a
// counter that notices the cap is blown but keeps serving is not a cap. This is
// the node-side backstop — the coordinator also stops assigning work to an
// exhausted node (see the register wire's quotaState), but that is an
// optimisation, and this is the guarantee. See Limiter's doc for why the node,
// not the coordinator, has to be the one holding it.
//
// Metering on read matches accounting.Counter's convention and holds for the same
// reason: every call site in core copies with io.Copy(dst, src), so wrapping the
// source sees each forwarded byte exactly once — and each of those bytes is then
// written out the node's other side, which is the second crossing this charges for
// without having to wrap the writer too.
//
// Note that this and accounting.Counter deliberately answer different questions and
// will not agree: a receipt claims what a session moved (ADR-0021), while this
// charges what the operator's ISP will bill for moving it. Expect this to read
// twice the receipt.
//
// now is a func rather than a value because a metered stream outlives the instant
// it was wrapped — a session can run for hours, across a cycle boundary.
func (q *Quota) MeterForwarded(r io.Reader, now func() time.Time) io.Reader {
	if q == nil {
		return r
	}
	return &quotaReader{r: r, q: q, now: now}
}

type quotaReader struct {
	r   io.Reader
	q   *Quota
	now func() time.Time
}

func (qr *quotaReader) Read(p []byte) (int, error) {
	// Check before reading: the overshoot is then bounded by whatever was already in
	// flight, rather than by one more full read per stream per check.
	if qr.q.Exhausted(qr.now()) {
		return 0, ErrQuotaExhausted
	}
	n, err := qr.r.Read(p)
	if n > 0 {
		qr.q.AddForwarded(uint64(n), qr.now())
	}
	return n, err
}

// checkpoint writes the current state to disk. Caller holds q.mu.
//
// Write-to-temp-then-rename, so a crash mid-write leaves the previous checkpoint
// intact rather than a truncated file that NewQuota would refuse to parse (which
// would strand the node until an operator deleted it).
//
// A failure is recorded in flushErr and does not stop the node: refusing to serve
// because a disk is full would turn a bookkeeping problem into an outage, and the
// in-memory counter still enforces the quota for this process's lifetime. Err
// surfaces it so cmd/node can log it loudly — a node whose checkpoints are
// failing is one whose quota will reset on restart, and the operator must hear
// about that before the bill does.
func (q *Quota) checkpoint(now time.Time) {
	if q.path == "" {
		q.flushedAt, q.flushedTime = q.used, now
		return
	}
	st := quotaState{CycleStart: q.cycleStart, Used: uint64(q.used), Limit: uint64(q.limit), CycleDay: q.cycleDay}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		q.flushErr = err
		return
	}
	tmp := q.path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(q.path), 0o755); err != nil {
		q.flushErr = err
		return
	}
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		q.flushErr = err
		return
	}
	if err := os.Rename(tmp, q.path); err != nil {
		q.flushErr = err
		return
	}
	q.flushedAt, q.flushedTime, q.flushErr = q.used, now, nil
}

// Flush checkpoints unconditionally. Called on shutdown so a clean stop loses
// nothing, and by tests.
func (q *Quota) Flush(now time.Time) error {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.checkpoint(now)
	return q.flushErr
}

// Err returns the last checkpoint error, or nil. Sticky until a checkpoint
// succeeds.
func (q *Quota) Err() error {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.flushErr
}

// String renders the quota for an operator-facing status line.
func (q *Quota) String() string {
	if q == nil {
		return "unmetered"
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	pct := 0.0
	if q.limit > 0 {
		pct = 100 * float64(q.used) / float64(q.limit)
	}
	return fmt.Sprintf("%s / %s (%.1f%%) this cycle, since %s", q.used, q.limit, pct, q.cycleStart.Format("2006-01-02"))
}
