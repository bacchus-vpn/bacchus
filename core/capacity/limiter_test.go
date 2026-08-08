package capacity

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// TestNilLimiterIsInert: no declared cap = the inert nil *Limiter, which is every
// node in today's fleet. This is what keeps old #143 opt-in with zero behaviour change
// for anyone who does not use it.
func TestNilLimiterIsInert(t *testing.T) {
	if NewLimiter(0) != nil {
		t.Fatal("NewLimiter(0) must return the inert nil *Limiter")
	}
	var l *Limiter
	src := strings.NewReader("hello")
	if got := l.LimitReads(context.Background(), src); got != io.Reader(src) {
		t.Error("the nil *Limiter must return the reader unchanged, not wrap it")
	}
}

// TestLimiterPacesToTheDeclaredCap: the limiter shapes the average rate to the
// operator's declared cap. Timing-based, so the assertion is deliberately loose on
// the upper bound (CI machines stall) and tight on the lower bound (finishing too
// FAST is the failure that matters — it means the cap did not hold).
func TestLimiterPacesToTheDeclaredCap(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-based")
	}
	const cap = 8 * Mbit // 1 MB/s
	const payload = 512 * 1024
	// 512 KB at 1 MB/s should take ~0.5s. The bucket starts full, so the first
	// burstBytes (64 KB) are free: expect ~(512-64)/1024 = ~0.44s.
	wantMin := 350 * time.Millisecond

	l := NewLimiter(cap)
	r := l.LimitReads(context.Background(), strings.NewReader(strings.Repeat("x", payload)))

	start := time.Now()
	n, err := io.Copy(io.Discard, r)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if n != payload {
		t.Fatalf("copied %d bytes, want %d — the limiter dropped data", n, payload)
	}
	if elapsed < wantMin {
		t.Errorf("copied %d bytes in %v: faster than the %s cap allows (want >= %v). The cap did not hold.", n, elapsed, cap, wantMin)
	}
	t.Logf("%d bytes at a %s cap took %v", n, cap, elapsed)
}

// TestLimiterPassesOversizedReads pins the burst clamp. rate.Limiter can never
// satisfy a request larger than its bucket, so an unclamped oversized read would
// block forever rather than merely be slow — a deadlock, not a slowdown.
func TestLimiterPassesOversizedReads(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-based")
	}
	const cap = 100 * Mbit
	l := NewLimiter(cap)
	payload := 4 * burstBytes
	r := l.LimitReads(context.Background(), strings.NewReader(strings.Repeat("x", payload)))

	// A single Read with a buffer far larger than the burst.
	buf := make([]byte, payload)
	done := make(chan int, 1)
	go func() {
		n, _ := r.Read(buf)
		done <- n
	}()
	select {
	case n := <-done:
		if n == 0 {
			t.Fatal("oversized read returned 0 bytes")
		}
		if n > burstBytes {
			t.Errorf("read returned %d bytes, want it clamped to the %d burst", n, burstBytes)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an oversized read blocked forever — the burst clamp is missing")
	}
}

// TestLimiterUnblocksOnContextCancel: a session torn down while its reader is
// parked waiting for tokens must not hold the node open for the length of the wait.
func TestLimiterUnblocksOnContextCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-based")
	}
	// A very low cap: the wait after the first read would be minutes.
	l := NewLimiter(8 * Kbit)
	ctx, cancel := context.WithCancel(context.Background())
	r := l.LimitReads(ctx, strings.NewReader(strings.Repeat("x", 10*burstBytes)))

	// Drain the initial burst so the next read must wait.
	buf := make([]byte, burstBytes)
	_, _ = r.Read(buf)

	errc := make(chan error, 1)
	go func() {
		_, err := r.Read(buf)
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errc:
		if err == nil {
			t.Error("a cancelled read should report the cancellation so the copy unwinds")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancelling the context did not unblock a parked read")
	}
}

// The cap is AGGREGATE across a node's sessions (the operator caps what leaves
// their house, not what any one stranger gets), and sharing one bucket is the
// enforcement. Two concurrent streams through one Limiter must together be paced to
// the cap — not get the cap each.
func TestLimiterIsAggregateAcrossSessions(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-based")
	}
	const cap = 8 * Mbit // 1 MB/s aggregate
	const each = 256 * 1024
	l := NewLimiter(cap)

	start := time.Now()
	done := make(chan int64, 2)
	for i := 0; i < 2; i++ {
		go func() {
			r := l.LimitReads(context.Background(), strings.NewReader(strings.Repeat("x", each)))
			n, _ := io.Copy(io.Discard, r)
			done <- n
		}()
	}
	var total int64
	total += <-done
	total += <-done
	elapsed := time.Since(start)

	if total != 2*each {
		t.Fatalf("copied %d bytes, want %d", total, 2*each)
	}
	// 512 KB aggregate at 1 MB/s, less the free initial 64 KB burst: ~0.44s. If each
	// stream had its own bucket this would finish in roughly half the time.
	if wantMin := 350 * time.Millisecond; elapsed < wantMin {
		t.Errorf("two streams moved %d bytes in %v (want >= %v): the cap is per-session, not aggregate", total, elapsed, wantMin)
	}
	t.Logf("two concurrent streams, %d bytes total at a %s aggregate cap, took %v", total, cap, elapsed)
}
