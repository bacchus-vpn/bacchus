package capacity

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustQuota(t *testing.T, l Limits, path string, now time.Time) *Quota {
	t.Helper()
	q, err := NewQuota(l, path, now)
	if err != nil {
		t.Fatalf("NewQuota: %v", err)
	}
	if q == nil {
		t.Fatal("NewQuota returned nil for a node that declared a quota")
	}
	return q
}

// TestCycleStartAnchorsToTheBillingDay pins the detail that decides whether #143
// is usable by its target population at all: residential caps reset on the
// customer's BILLING day, not the 1st. An operator billed on the 17th whose node
// resets on the 1st sails past their real cap mid-cycle and eats the overage —
// the exact bill this card exists to prevent.
func TestCycleStartAnchorsToTheBillingDay(t *testing.T) {
	cases := []struct {
		now  string
		day  int
		want string
	}{
		// After this month's anchor: the cycle started this month.
		{"2026-07-20T12:00:00Z", 17, "2026-07-17T00:00:00Z"},
		// Before this month's anchor: we are still in LAST month's cycle.
		{"2026-07-05T12:00:00Z", 17, "2026-06-17T00:00:00Z"},
		// Exactly on the anchor: the new cycle has started.
		{"2026-07-17T00:00:00Z", 17, "2026-07-17T00:00:00Z"},
		{"2026-07-17T00:00:01Z", 17, "2026-07-17T00:00:00Z"},
		// A moment before: still the old one.
		{"2026-07-16T23:59:59Z", 17, "2026-06-17T00:00:00Z"},
		// Day 1 (the default) still works.
		{"2026-07-20T12:00:00Z", 1, "2026-07-01T00:00:00Z"},
		// January rolls back to December, across the year boundary.
		{"2026-01-05T12:00:00Z", 17, "2025-12-17T00:00:00Z"},
		// Day 28 in March rolls back to February — the reason the cap is 28.
		{"2026-03-05T12:00:00Z", 28, "2026-02-28T00:00:00Z"},
	}
	for _, c := range cases {
		now, _ := time.Parse(time.RFC3339, c.now)
		want, _ := time.Parse(time.RFC3339, c.want)
		if got := CycleStart(now, c.day); !got.Equal(want) {
			t.Errorf("CycleStart(%s, day=%d) = %s, want %s", c.now, c.day, got.Format(time.RFC3339), c.want)
		}
	}
}

func TestQuotaExhaustion(t *testing.T) {
	l := Limits{MonthlyQuota: 1000, CycleDay: 17}
	q := mustQuota(t, l, "", epoch)

	if q.Exhausted(epoch) {
		t.Fatal("a fresh quota must not be exhausted")
	}
	q.Add(999, epoch)
	if q.Exhausted(epoch) {
		t.Error("999/1000 must not be exhausted")
	}
	if got := q.Remaining(epoch); got != 1 {
		t.Errorf("Remaining = %d, want 1", got)
	}
	q.Add(1, epoch)
	if !q.Exhausted(epoch) {
		t.Error("1000/1000 must be exhausted — the cap is a ceiling, not a target")
	}
	if got := q.Remaining(epoch); got != 0 {
		t.Errorf("Remaining = %d, want 0 (saturating, not negative)", got)
	}
	// Overshoot must not wrap the unsigned remaining.
	q.Add(5000, epoch)
	if got := q.Remaining(epoch); got != 0 {
		t.Errorf("Remaining after overshoot = %d, want 0", got)
	}
}

// TestQuotaSurvivesRestart pins the requirement in the card's own words: the quota
// is NEVER exceeded. An in-memory counter makes `systemctl restart` mint a fresh
// month, so without persistence the type does not implement its headline promise.
func TestQuotaSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	l := Limits{MonthlyQuota: 1000, CycleDay: 17}

	q := mustQuota(t, l, path, epoch)
	q.Add(800, epoch)
	if err := q.Flush(epoch); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	// Restart, same cycle.
	q2 := mustQuota(t, l, path, epoch.Add(time.Hour))
	if got := q2.Used(epoch.Add(time.Hour)); got != 800 {
		t.Fatalf("after restart Used = %d, want 800 — a restart minted fresh quota", got)
	}
	q2.Add(200, epoch.Add(time.Hour))
	if !q2.Exhausted(epoch.Add(time.Hour)) {
		t.Error("the restarted node must still be exhausted at 1000/1000")
	}
}

// TestQuotaCheckpointsWithoutAnExplicitFlush pins that a CRASH (no clean
// shutdown, no Flush) cannot mint more than one granularity of fresh quota.
func TestQuotaCheckpointsWithoutAnExplicitFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	l := Limits{MonthlyQuota: 10 * GB, CycleDay: 17}

	q := mustQuota(t, l, path, epoch)
	// Push well past the granularity, never calling Flush — simulating a process that
	// is about to be killed.
	served := 5 * q.granularity()
	q.Add(uint64(served), epoch)

	// A brand-new Quota reading the same file is the post-crash node.
	crashed := mustQuota(t, l, path, epoch)
	lost := served - crashed.Used(epoch)
	if lost > q.granularity() {
		t.Errorf("a crash lost %s of quota, more than the %s granularity bound", lost, q.granularity())
	}
	if crashed.Used(epoch) == 0 {
		t.Error("a crash lost ALL quota accounting — checkpointing never fired")
	}
}

// TestSmallQuotaIsCheckpointedToo is the regression test for the bug the #143
// smoke test caught, which every unit test here had missed.
//
// The byte trigger was a FIXED 16 MB. A node with a small declared quota spends it
// without ever reaching that trigger, and if it also spends it faster than the 30s
// interval it is never checkpointed at all — so a restart mints a fresh cycle and
// "never exceeded" is defeated by `systemctl restart`, which is the exact failure
// persistence exists to prevent.
//
// The unit tests missed it because they all used a LARGE quota (10 GB above), which
// always crosses a fixed 16 MB trigger. The smoke test used a 1 MB quota — a real
// operator's shape, not a test's — and the file was simply never written.
//
// The trigger now scales with the quota (granularity), so a cap of any size is
// checkpointed proportionally.
func TestSmallQuotaIsCheckpointedToo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	l := Limits{MonthlyQuota: 1 * MB, CycleDay: 17} // the smoke test's shape

	q := mustQuota(t, l, path, epoch)
	// Spend most of it in one burst, well inside flushInterval, and never Flush.
	q.Add(900*1000, epoch)

	crashed := mustQuota(t, l, path, epoch)
	if crashed.Used(epoch) == 0 {
		t.Fatal("a small quota was never checkpointed — a restart mints a fresh cycle, which is the whole feature failing")
	}
	if lost := Bytes(900*1000) - crashed.Used(epoch); lost > q.granularity() {
		t.Errorf("lost %s of a %s quota (granularity %s)", lost, l.MonthlyQuota, q.granularity())
	}
}

// TestExhaustionIsCheckpointedImmediately pins the transition that matters most: a
// node that spends its quota and is killed before its next scheduled checkpoint
// must NOT come back believing the cycle is fresh.
func TestExhaustionIsCheckpointedImmediately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	l := Limits{MonthlyQuota: 1 * MB, CycleDay: 17}

	q := mustQuota(t, l, path, epoch)
	q.Add(uint64(1*MB), epoch) // exactly exhausts it, in one call, no Flush
	if !q.Exhausted(epoch) {
		t.Fatal("setup: not exhausted")
	}

	// kill -9 right here. The restarted node must still be exhausted.
	crashed := mustQuota(t, l, path, epoch)
	if !crashed.Exhausted(epoch) {
		t.Errorf("a node killed the instant it exhausted came back with %s used — a crash loop would serve forever", crashed.Used(epoch))
	}
}

// TestGranularityScalesWithTheQuota pins the clamps, so neither a tiny cap nor a
// huge one degenerates.
func TestGranularityScalesWithTheQuota(t *testing.T) {
	cases := []struct {
		quota Bytes
		want  Bytes
	}{
		{1 * MB, minFlushGranularity},   // floored: 1MB/64 = 15.6KB, below the floor
		{400 * GB, maxFlushGranularity}, // capped: 400GB/64 = 6.25GB, above the cap
		{640 * MB, 10 * MB},             // in range: 640MB/64 = 10MB
	}
	for _, c := range cases {
		q := mustQuota(t, Limits{MonthlyQuota: c.quota, CycleDay: 17}, "", epoch)
		if got := q.granularity(); got != c.want {
			t.Errorf("granularity for a %s quota = %s, want %s", c.quota, got, c.want)
		}
	}
}

// TestQuotaRollsOverOnTheCycleBoundary pins that the reset happens, that it
// happens on the anchor, and that it is checkpointed eagerly so a crash right
// after a rollover cannot resurrect last cycle's usage and strand the node.
func TestQuotaRollsOverOnTheCycleBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	l := Limits{MonthlyQuota: 1000, CycleDay: 17}

	start, _ := time.Parse(time.RFC3339, "2026-07-20T12:00:00Z")
	q := mustQuota(t, l, path, start)
	q.Add(1000, start)
	if !q.Exhausted(start) {
		t.Fatal("must be exhausted before the boundary")
	}

	// Still in the same cycle a week later: the quota does NOT reset early.
	sameCycle, _ := time.Parse(time.RFC3339, "2026-08-16T12:00:00Z")
	if !q.Exhausted(sameCycle) {
		t.Error("quota reset before its anchor day — the node would overshoot its ISP cap")
	}

	// Past the anchor: fresh cycle.
	nextCycle, _ := time.Parse(time.RFC3339, "2026-08-17T00:00:01Z")
	if q.Exhausted(nextCycle) {
		t.Error("quota did not reset on its anchor day — the node would sit idle for a month")
	}
	if got := q.Used(nextCycle); got != 0 {
		t.Errorf("Used after rollover = %d, want 0", got)
	}

	// The rollover was checkpointed without a Flush, so a crash here does not
	// resurrect the spent cycle.
	crashed := mustQuota(t, l, path, nextCycle)
	if crashed.Exhausted(nextCycle) {
		t.Error("a crash right after rollover resurrected the previous cycle's usage")
	}
}

// TestBackwardsClockDoesNotResetTheQuota is the regression test for a bug that hit
// exactly the hardware this card targets.
//
// rollover used to reset on ANY change of cycle start, including a backwards one —
// and because it checkpoints eagerly, the reset was written over the real usage,
// destroying it more thoroughly than a crash would.
//
// This is not the adversarial-clock case the type doc discusses (a node lying for
// gain only cheats itself). It is ordinary NTP on ordinary hardware: a Raspberry Pi
// with no RTC boots with a stale time, so NewQuota computes the wrong cycle and
// discards the checkpoint; NTP then steps the clock forward across the anchor day,
// rollover fires, and the zeroed counter is persisted. Every reboot would mint a
// fresh month. A VM suspend/resume or a dual-boot RTC skew gets there the same way.
//
// A cycle may only ever advance.
func TestBackwardsClockDoesNotResetTheQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	l := Limits{MonthlyQuota: 1000, CycleDay: 17}

	t1, _ := time.Parse(time.RFC3339, "2026-07-20T12:00:00Z") // cycle started Jul 17
	q := mustQuota(t, l, path, t1)
	q.Add(1000, t1)
	if !q.Exhausted(t1) {
		t.Fatal("setup: not exhausted")
	}

	// The clock steps BACK across the anchor, into what looks like the previous cycle.
	t2, _ := time.Parse(time.RFC3339, "2026-07-10T12:00:00Z")
	if !q.Exhausted(t2) {
		t.Error("a backwards clock step reset a spent quota — the node would serve a second month's worth")
	}
	if got := q.Used(t2); got != 1000 {
		t.Errorf("Used = %d after a backwards step, want 1000", got)
	}

	// The clock is corrected forward again. Still spent.
	if !q.Exhausted(t1) {
		t.Error("quota still reset after the clock was corrected")
	}

	// And the excursion must not have destroyed the on-disk usage.
	restarted := mustQuota(t, l, path, t1)
	if !restarted.Exhausted(t1) {
		t.Errorf("a restart after a clock excursion came back with %d used — the reset was persisted over the real usage", restarted.Used(t1))
	}
}

// The BOOT half of the same excursion — and the half the comment above actually
// describes, but does not reach. TestBackwardsClockDoesNotResetTheQuota builds the
// Quota at the CORRECT time and steps back afterwards, so it only ever exercises
// rollover's direction guard. The Pi it describes never gets that far: its clock is
// already wrong when NewQuota runs, before NTP has landed, so the guard that has to
// hold is NewQuota's own. This starts the process cold on the stale clock.
func TestStaleClockAtBootDoesNotResetTheQuota(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	l := Limits{MonthlyQuota: 1000, CycleDay: 17}

	// A month's quota is spent and checkpointed.
	spent, _ := time.Parse(time.RFC3339, "2026-07-20T12:00:00Z") // cycle started Jul 17
	q := mustQuota(t, l, path, spent)
	q.Add(1000, spent)
	if err := q.Flush(spent); err != nil {
		t.Fatal(err)
	}
	if !q.Exhausted(spent) {
		t.Fatal("setup: not exhausted")
	}

	// The node reboots with no RTC, so the clock reads 1970 until NTP lands — and
	// NewQuota runs inside that window. The disk knows a cycle the clock has never
	// heard of, which means the clock is wrong, not the disk.
	stale, _ := time.Parse(time.RFC3339, "1970-01-01T00:00:00Z")
	booted := mustQuota(t, l, path, stale)
	if !booted.Exhausted(stale) {
		t.Errorf("a stale boot clock reset a spent quota: Used = %d, want 1000 — the node would serve a fresh month on every reboot", booted.Used(stale))
	}

	// NTP corrects the clock forward. The usage is still spent: the adopted cycle is
	// the current one, so rollover finds nothing to advance to.
	if !booted.Exhausted(spent) {
		t.Errorf("quota reset once NTP corrected the clock: Used = %d, want 1000", booted.Used(spent))
	}

	// And nothing wrote a reset over the real usage while the clock was wrong, which
	// is what makes this worse than a crash: a crash loses one granularity, this
	// loses the month.
	restarted := mustQuota(t, l, path, spent)
	if !restarted.Exhausted(spent) {
		t.Errorf("a restart after a stale boot came back with %d used: the reset was persisted over the real usage", restarted.Used(spent))
	}
}

// A checkpoint from a genuinely older cycle is still discarded — the fix above must
// not turn "trust the later cycle" into "never reset". This is the Before direction,
// and it is the one that keeps the quota a monthly quota.
//
// TestStaleCheckpointIsDiscarded: a checkpoint from a cycle that has already
// reset must not be carried forward into the new one.
func TestStaleCheckpointIsDiscarded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	l := Limits{MonthlyQuota: 1000, CycleDay: 17}

	old, _ := time.Parse(time.RFC3339, "2026-07-20T12:00:00Z")
	q := mustQuota(t, l, path, old)
	q.Add(1000, old)
	if err := q.Flush(old); err != nil {
		t.Fatal(err)
	}

	// Start up two months later: that checkpoint belongs to a cycle long gone.
	fresh, _ := time.Parse(time.RFC3339, "2026-09-20T12:00:00Z")
	q2 := mustQuota(t, l, path, fresh)

	// Asked through String FIRST, and that ordering is the whole point. Used and
	// Exhausted both call rollover, which would advance a wrongly-adopted old cycle
	// and hand back 0 anyway — so they cannot tell whether NewQuota discarded the
	// checkpoint or merely got rescued a moment later. String does not roll over, so
	// it reports what NewQuota actually decided. Without this line the Before branch
	// is untested: replacing NewQuota's guard with an unconditional adopt still
	// passes everything below.
	if got := q2.String(); !strings.Contains(got, "since 2026-09-17") {
		t.Errorf("NewQuota reports %q — it adopted the checkpoint's dead cycle instead of starting the current one; rollover would paper over this on the next call", got)
	}

	if got := q2.Used(fresh); got != 0 {
		t.Errorf("Used = %d, want 0: a stale checkpoint was carried into a new cycle", got)
	}
}

// TestCorruptCheckpointIsAnError pins that corrupting the state file cannot be
// used to reset a quota. Silently starting from zero on unparseable state would
// turn "truncate this file" into "grant me a fresh month", which is the failure
// mode persistence exists to close.
func TestCorruptCheckpointIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	l := Limits{MonthlyQuota: 1000, CycleDay: 17}
	if _, err := NewQuota(l, path, epoch); err == nil {
		t.Fatal("NewQuota accepted a corrupt checkpoint — corrupting the file would reset the quota")
	} else if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q should name the file so an operator can act on it", err)
	}
}

func TestMissingCheckpointIsFirstRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "dir", "quota.json")
	l := Limits{MonthlyQuota: 1000, CycleDay: 17}
	q, err := NewQuota(l, path, epoch)
	if err != nil {
		t.Fatalf("a missing checkpoint is a first run, not an error: %v", err)
	}
	q.Add(10, epoch)
	if err := q.Flush(epoch); err != nil {
		t.Fatalf("Flush must create the directory: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("checkpoint not written: %v", err)
	}
}

// A checkpoint that cannot be written must not take the node down: refusing to
// serve because a disk is full turns a bookkeeping problem into an outage. But it
// must be visible, because a node whose checkpoints fail is one whose quota resets
// on restart, and the operator has to hear that before the bill does.
//
// The fixture blocks only the WRITE, and does so the same way on every platform.
// An earlier version made the parent a FILE before NewQuota ran, which also broke
// the read: Linux reports ENOTDIR there, which is not os.IsNotExist, so NewQuota
// refused to start and the test never reached the write it exists to exercise.
// Windows maps the same open to ERROR_PATH_NOT_FOUND, which IS os.IsNotExist, so
// it passed — the fixture only worked on the platform whose errno hid it.
//
// So the parent is squatted AFTER the read, which is the ordering that keeps both
// halves platform-independent: NewQuota sees a missing directory (a plain ENOENT
// first run everywhere), and the checkpoint dies in os.MkdirAll, which reports
// ENOTDIR from its own code on every platform rather than from the OS.
//
// It used to squat path+".tmp" instead, which worked because the staged file had
// a name a test could predict. Issue #188 took that away on purpose: the staged
// name is now unique per write, so nothing outside the writer can name it. Losing
// this fixture's old shape is the point of the change, not a casualty of it.
func TestCheckpointFailureIsSurfacedButNotFatal(t *testing.T) {
	// The state file lives one level down, in a directory that does not exist yet.
	stateDir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(stateDir, "quota.json")

	l := Limits{MonthlyQuota: 1000, CycleDay: 17}
	q, err := NewQuota(l, path, epoch)
	if err != nil {
		t.Fatalf("a missing checkpoint is a first run, not an error: %v", err)
	}

	// Now put a FILE where the checkpoint needs a directory. os.MkdirAll stats it,
	// finds a non-directory and returns ENOTDIR itself, identically everywhere.
	if err := os.WriteFile(stateDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	q.Add(500, epoch)
	if err := q.Flush(epoch); err == nil {
		t.Fatal("Flush must report a checkpoint failure")
	}
	if q.Err() == nil {
		t.Error("Err() must surface the sticky checkpoint failure")
	}
	// Still enforcing in memory, which is the point: the process keeps its guarantee
	// for its own lifetime even with no disk.
	q.Add(500, epoch)
	if !q.Exhausted(epoch) {
		t.Error("in-memory enforcement must survive a checkpoint failure")
	}
}

// A checkpoint that exists but cannot be READ must refuse to start, and this is the
// deliberate half of the asymmetry above: a failed write happens with the spent total
// still in memory, so the process keeps its guarantee and only risks losing it on
// restart. A failed read happens with nothing in memory at all. Starting anyway means
// starting at used=0, which serves a whole fresh month against a cap the operator has
// already spent — silently, and again on every restart. Refusing is loud, one-shot,
// and names the file. Same threat as a corrupt checkpoint (see
// TestCorruptCheckpointIsAnError): state we cannot confirm. Only os.IsNotExist is a
// first run, because only a missing file actually says "nothing was spent".
func TestUnreadableCheckpointRefusesToStart(t *testing.T) {
	dir := t.TempDir()
	// A directory squatting on the state path: readable-as-an-entry, unreadable as a
	// file, on every platform — and, unlike a permission bit, it behaves the same for
	// root, which CI may well run as.
	path := filepath.Join(dir, "quota.json")
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}

	l := Limits{MonthlyQuota: 1000, CycleDay: 17}
	q, err := NewQuota(l, path, epoch)
	if err == nil {
		t.Fatal("an unreadable checkpoint must refuse to start, not silently reset the cycle")
	}
	if q != nil {
		t.Error("NewQuota must return a nil Quota alongside its error, so no caller can serve on it")
	}
}

// The nil *Quota is the "no declared quota" case and must be inert everywhere, so
// call sites need no branch (same idiom as accounting.Counter).
func TestNilQuotaIsInert(t *testing.T) {
	var q *Quota
	q.Add(1e9, epoch) // must not panic
	if q.Exhausted(epoch) {
		t.Error("nil *Quota must never be exhausted")
	}
	if q.Used(epoch) != 0 || q.Remaining(epoch) != 0 {
		t.Error("nil *Quota must report zeroes")
	}
	if err := q.Flush(epoch); err != nil {
		t.Errorf("nil *Quota Flush: %v", err)
	}
	if q.Err() != nil {
		t.Error("nil *Quota must have no error")
	}
	if got := q.String(); got != "unmetered" {
		t.Errorf("nil *Quota String() = %q, want %q", got, "unmetered")
	}
	src := strings.NewReader("hello")
	if got := q.MeterForwarded(src, func() time.Time { return epoch }); got != io.Reader(src) {
		t.Error("nil *Quota MeterForwarded must return the reader unchanged, not wrap it")
	}
}

// TestMeterStopsAtExhaustion pins the node-side backstop: the cap is enforced by
// the party that pays the bill, not by the coordinator's courtesy. A metered
// stream that would carry the node past its declared quota stops, cutting the
// session — see ErrQuotaExhausted for why cutting is the right call.
func TestMeterStopsAtExhaustion(t *testing.T) {
	l := Limits{MonthlyQuota: 1000, CycleDay: 17}
	q := mustQuota(t, l, "", epoch)
	now := func() time.Time { return epoch }

	// A stream far larger than the remaining quota.
	r := q.MeterForwarded(strings.NewReader(strings.Repeat("x", 100_000)), now)
	n, err := io.Copy(io.Discard, r)

	if !errors.Is(err, ErrQuotaExhausted) {
		t.Fatalf("copy error = %v, want ErrQuotaExhausted — the node served past its declared cap", err)
	}
	// The overshoot is bounded by what was in flight when the cap was crossed (one
	// io.Copy buffer), not unbounded.
	if n > 1000+32*1024 {
		t.Errorf("served %d bytes against a 1000-byte quota: overshoot is not bounded", n)
	}
	if !q.Exhausted(epoch) {
		t.Error("quota should be exhausted")
	}
}

// A forwarded byte is charged for BOTH of its crossings of the operator's link:
// it arrives and it leaves, and the ISP meters each. Pins LinkCrossings against
// the quota the operator actually declared — a byte counted once would let a
// declared cap spend twice itself. The quota here is deliberately far larger than
// the stream, so this measures the counting and nothing else.
func TestQuotaMeterChargesBothLinkCrossings(t *testing.T) {
	l := Limits{MonthlyQuota: 10_000, CycleDay: 17}
	q := mustQuota(t, l, "", epoch)
	r := q.MeterForwarded(strings.NewReader(strings.Repeat("x", 600)), func() time.Time { return epoch })

	buf := make([]byte, 256)
	total := 0
	for {
		n, err := r.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	if total != 600 {
		t.Fatalf("read %d bytes, want 600", total)
	}
	// 1200 is written out rather than computed as 600*LinkCrossings on purpose: an
	// expectation derived from the constant under test moves with it and can never
	// fail, which is the same "pins nothing" defect as a test that logs a number
	// instead of asserting it. This literal is the claim.
	if got := q.Used(epoch); got != 1200 {
		t.Errorf("600 bytes forwarded charged %d against the operator's cap, want 1200 — a forwarded byte arrives and leaves, and the ISP meters both", got)
	}
}

func TestQuotaIsConcurrencySafe(t *testing.T) {
	l := Limits{MonthlyQuota: 1_000_000, CycleDay: 17}
	q := mustQuota(t, l, filepath.Join(t.TempDir(), "q.json"), epoch)

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 1000; j++ {
				q.Add(10, epoch)
				_ = q.Exhausted(epoch)
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if got := q.Used(epoch); got != 80_000 {
		t.Errorf("Used = %d, want 80000 — a byte was lost or double-counted under concurrency", got)
	}
}

// Issue #188: the checkpoint used to stage under a FIXED name (path + ".tmp")
// and rename without flushing.
//
// The predictable-name half is asserted structurally rather than by racing: a
// file sitting at the old staged name is now untouched by a checkpoint. Under
// the old writer that file WAS the staging area — truncated, refilled and
// renamed away — which is exactly why the failure fixture above could use it.
func TestCheckpointDoesNotStageUnderThePredictableName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quota.json")
	squatter := path + ".tmp"
	if err := os.WriteFile(squatter, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}

	q := mustQuota(t, Limits{MonthlyQuota: 10 * MB, CycleDay: 17}, path, epoch)
	q.Add(uint64(1*MB), epoch)
	if err := q.Flush(epoch); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	b, err := os.ReadFile(squatter)
	if err != nil {
		t.Fatalf("the checkpoint consumed %s, so it is still staging under a name another writer can pick: %v", squatter, err)
	}
	if string(b) != "not ours" {
		t.Errorf("%s now holds %q; a checkpoint must stage under a name it created itself", squatter, b)
	}
}

// The checkpoint stays 0644 and is the one file in this repository written that
// wide on purpose. quotaState's doc is the reason — an operator debugging "why
// is my node not serving" has to be able to cat it — and issue #188's shared
// writer takes the mode as a parameter precisely so that folding seven writers
// into one did not quietly narrow this one to match the six secrets.
func TestCheckpointStaysOperatorReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows expresses file modes through ACLs; os.Chmod only toggles the read-only attribute")
	}
	path := filepath.Join(t.TempDir(), "quota.json")
	q := mustQuota(t, Limits{MonthlyQuota: 10 * MB, CycleDay: 17}, path, epoch)
	q.Add(uint64(1*MB), epoch)
	if err := q.Flush(epoch); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("checkpoint mode %v, want 0644 — the shared writer must not have flattened this to the 0600 the secret-bearing writers use", got)
	}
}

// The interleaving half. One process cannot race itself here — checkpoint's
// caller holds q.mu — so the case that reaches the file is TWO processes sharing
// a state path, which nothing in this package can prevent and which a fixed
// staged name turned into a mangled checkpoint rather than a lost update.
//
// A mangled checkpoint is the expensive outcome for this file specifically:
// NewQuota treats an unparseable one as a hard startup error, so the node
// refuses to start until somebody deletes the file, and deleting it is what
// forgets the usage the operator is being billed for.
func TestConcurrentCheckpointsNeverInstallAMixture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quota.json")

	// Two quotas at one path, with limits far enough apart that any generation
	// is unmistakably one writer's — and different enough in length that a
	// mixture is detectable by content as well as by a parse failure.
	limits := [2]Limits{
		{MonthlyQuota: 400 * GB, CycleDay: 17},
		{MonthlyQuota: 1 * MB, CycleDay: 3},
	}

	var writers, readers sync.WaitGroup
	stop := make(chan struct{})
	var reads atomic.Int64

	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(path)
			if err != nil || len(b) == 0 {
				continue
			}
			var st quotaState
			if err := json.Unmarshal(b, &st); err != nil {
				t.Errorf("a reader observed %d bytes of unparseable JSON: %v — two checkpoints interleaved into one staged file", len(b), err)
				return
			}
			switch {
			case st.Limit == uint64(limits[0].MonthlyQuota) && st.CycleDay == limits[0].CycleDay:
			case st.Limit == uint64(limits[1].MonthlyQuota) && st.CycleDay == limits[1].CycleDay:
			default:
				t.Errorf("a reader observed limit=%d cycleDay=%d, which is neither writer's checkpoint", st.Limit, st.CycleDay)
				return
			}
			reads.Add(1)
		}
	}()

	for i := range limits {
		writers.Add(1)
		go func(i int) {
			defer writers.Done()
			q, err := NewQuota(limits[i], path, epoch)
			if err != nil {
				t.Errorf("NewQuota: %v", err)
				return
			}
			for n := 0; n < 80; n++ {
				q.Add(1, epoch)
				if err := q.Flush(epoch); err != nil {
					t.Errorf("Flush: %v", err)
					return
				}
			}
		}(i)
	}
	writers.Wait()
	// The writers are done, so the file certainly exists. Do NOT stop the
	// reader until it has actually looked at least once: under a loaded machine
	// — `go test ./...` across every package at once — its goroutine can fail to
	// be scheduled for the whole few milliseconds the writers take, and a run
	// where it observed nothing is a green test that checked nothing. Bounded,
	// so a reader that returned early on a real failure cannot hang the test.
	for deadline := time.Now().Add(5 * time.Second); reads.Load() == 0 && time.Now().Before(deadline); {
		runtime.Gosched()
	}
	close(stop)
	readers.Wait()

	if reads.Load() == 0 {
		t.Error("no reader ever observed the checkpoint; this test proved nothing")
	}
}
