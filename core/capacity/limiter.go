package capacity

import (
	"context"
	"fmt"
	"io"

	"golang.org/x/time/rate"
)

// burstBytes is the token bucket's burst, and also the largest chunk a limited
// Read will take at once.
//
// It has to be at least as large as the biggest single read the data path issues,
// or a read would ask for more tokens than the bucket can ever hold and block
// forever. io.Copy uses 32 KB buffers, so 64 KB clears that with room to spare
// while keeping the burst small enough that a low cap still feels like a low cap
// rather than a stutter of large gulps.
const burstBytes = 64 * 1024

// Limiter enforces a node's declared aggregate speed cap (issue #143) on the data
// path. One Limiter is shared by every session on the node, which is what makes
// the cap AGGREGATE — the operator is capping what leaves their house, not what
// any one stranger gets. Sharing the bucket is the enforcement.
//
// The nil *Limiter is valid and inert (LimitReads returns the reader unchanged),
// so a node with no declared cap passes nil and no call site needs a branch. Same
// idiom as accounting.Counter and Quota, for the same reason.
//
// # Why the node enforces this at all
//
// The coordinator already stops assigning work to a node that has hit its limits,
// so a local limiter can look redundant. It is not, and the distinction matters:
//
//   - The coordinator's stop-assigning is the USEFUL half. It keeps clients from
//     being matched to a node that will refuse them, so a limit surfaces as "this
//     node is not offered" rather than "your connection failed".
//   - This is the SOUND half. The coordinator learns of a node's state only on its
//     next 10s register; a pool has several coordinators (ADR-0020) expiring
//     independently; and a coordinator may be buggy, partitioned, or hostile
//     (ADR-0020, #60/#69 — the standing assumption is that it is not trusted with
//     anything that matters).
//
// The operator, not the coordinator, pays the overage bill. So the guarantee is
// enforced by the party that bears the cost. Same shape as the kill switch
// (ADR-0014): the party that suffers the failure enforces the invariant locally,
// and the remote hint is a courtesy.
type Limiter struct {
	l *rate.Limiter
}

// NewLimiter returns a Limiter for the declared cap, or nil (inert) when the cap
// is zero/unset — which is every node in today's datacenter fleet, and is what
// keeps #143 opt-in with no behaviour change for anyone who does not use it.
func NewLimiter(c Rate) *Limiter {
	if c == 0 {
		return nil
	}
	// Rate is bits/s (the unit an operator reads off their ISP contract); the bucket
	// meters bytes, because that is what a Read returns.
	bytesPerSec := float64(c) / 8
	return &Limiter{l: rate.NewLimiter(rate.Limit(bytesPerSec), burstBytes)}
}

// LimitReads wraps r so bytes read through it are paced to the declared cap.
//
// Pacing on read, rather than on write, matches accounting.Counter's convention
// and holds for the same reason: every call site in core copies with
// io.Copy(dst, src), so wrapping the source shapes each byte exactly once. It also
// applies backpressure in the right place — slowing the read stalls the sender
// through TCP's own window rather than buffering the overage in this process.
//
// ctx unblocks a pending wait at shutdown, so a session being torn down while its
// reader is parked waiting for tokens does not hold the node open for the length
// of that wait.
func (l *Limiter) LimitReads(ctx context.Context, r io.Reader) io.Reader {
	if l == nil {
		return r
	}
	return &limitReader{r: r, l: l.l, ctx: ctx}
}

// WaitN paces n bytes that were moved outside an io.Reader, blocking until the
// bucket allows them. It is LimitReads' counterpart for a datagram path, where
// there is no stream to wrap: core's UDP relay (ADR-0034) hand-rolls its own
// read/write loop over whole datagrams rather than copying a stream.
//
// n must not exceed burstBytes or the bucket could never satisfy it and this would
// block forever. That holds by construction for every caller today — core's
// maxUDPDatagram is 65535, one byte under the burst, because a UDP payload cannot
// be larger — so this returns an error rather than deadlocking if that ever stops
// being true.
//
// The nil *Limiter is inert, as everywhere else in this package.
func (l *Limiter) WaitN(ctx context.Context, n int) error {
	if l == nil || n <= 0 {
		return nil
	}
	if n > burstBytes {
		return fmt.Errorf("capacity: %d bytes exceeds the %d-byte burst; the bucket could never satisfy it", n, burstBytes)
	}
	return l.l.WaitN(ctx, n)
}

type limitReader struct {
	r   io.Reader
	l   *rate.Limiter
	ctx context.Context
}

func (lr *limitReader) Read(p []byte) (int, error) {
	// Clamp to the burst: WaitN can never satisfy a request larger than the bucket,
	// so an oversized read would block forever rather than be slow.
	if len(p) > burstBytes {
		p = p[:burstBytes]
	}
	n, err := lr.r.Read(p)
	if n > 0 {
		// Wait AFTER the read, since the token cost is not known until the bytes are
		// in hand. This lets one read's worth through ahead of its tokens and settles
		// up before the next, which paces the AVERAGE rate to the cap.
		//
		// Paced on the RAW read count — one crossing, not two — unlike the quota, which
		// charges both (capacity.LinkCrossings). The two are denominated differently on
		// purpose, because the operator means different things by them: -max-speed is
		// "what leaves my connection" (its own help says so), and the scarce direction on
		// a residential line is the uplink, so pacing egress at the declared rate is
		// exactly the ask. -monthly-quota is "what my ISP bills me", and an ISP bills
		// both directions. Same link, two questions.
		if werr := lr.l.WaitN(lr.ctx, n); werr != nil && err == nil {
			// Only ctx cancellation can land here (n <= burst by the clamp above). The
			// session is going away; report it as the read's error so the copy unwinds.
			err = werr
		}
	}
	return n, err
}
