package accounting

import (
	"io"
	"testing"
	"time"
)

var satEpoch = time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)

// seqClock returns the given times in order, one per call, repeating the last forever.
// satWriter reads the clock exactly twice per Write (start, then end), so a two-element
// sequence drives one write deterministically.
func seqClock(times ...time.Time) func() time.Time {
	i := 0
	return func() time.Time {
		t := times[i]
		if i < len(times)-1 {
			i++
		}
		return t
	}
}

// TestCounterSaturationPartitionsIntervals: TakeSaturated reports the flag and clears it,
// so a saturation set in one interval never leaks into the next (the same partitioning
// Delta gives the byte count).
func TestCounterSaturationPartitionsIntervals(t *testing.T) {
	c := &Counter{}
	if c.TakeSaturated() {
		t.Fatal("a fresh counter must not report saturated")
	}
	c.saturated.Store(true) // a blocked write (satWriter) would set this
	if !c.TakeSaturated() {
		t.Fatal("TakeSaturated did not report a set flag")
	}
	if c.TakeSaturated() {
		t.Fatal("TakeSaturated did not clear the flag; saturation leaked across intervals")
	}
}

// TestSatWriterMarksBlockedWrite: a write whose duration reaches the threshold (tunnel
// backpressure) marks the interval saturated; a faster write does not. Uses an injected
// clock so the boundary is exact, not timing-dependent.
func TestSatWriterMarksBlockedWrite(t *testing.T) {
	const threshold = 100 * time.Millisecond

	// elapsed == threshold: the >= boundary must count as blocked.
	blocked := &Counter{}
	bw := &satWriter{w: io.Discard, c: blocked, threshold: threshold, clock: seqClock(satEpoch, satEpoch.Add(threshold))}
	if _, err := bw.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if !blocked.TakeSaturated() {
		t.Fatal("a write that blocked for the full threshold must mark the interval saturated")
	}

	// elapsed < threshold: an unblocked write leaves the interval unsaturated.
	fast := &Counter{}
	fw := &satWriter{w: io.Discard, c: fast, threshold: threshold, clock: seqClock(satEpoch, satEpoch.Add(threshold-time.Nanosecond))}
	if _, err := fw.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if fast.TakeSaturated() {
		t.Fatal("a write faster than the threshold must not mark saturated (it under-reports on purpose)")
	}
}

// TestWatchSaturationNilInert: a nil counter (accounting disabled) returns the writer
// unchanged and reports unsaturated, so a client with no accounting is byte-for-byte
// unaffected.
func TestWatchSaturationNilInert(t *testing.T) {
	var c *Counter
	if got := c.WatchSaturation(io.Discard, time.Second); got != io.Writer(io.Discard) {
		t.Fatal("nil WatchSaturation must return the writer unchanged")
	}
	if c.TakeSaturated() {
		t.Fatal("nil TakeSaturated must report unsaturated")
	}
}
