//go:build linux

package tray

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestDecideFailsToNo is the ruling this package encodes: every way of not
// getting a clear yes answers no, and the client keeps its pre-#186 close
// behaviour rather than hiding a window into a machine that cannot show it
// again.
//
// Mutation check: change decide to `return ok` and the error cases go red.
func TestDecideFailsToNo(t *testing.T) {
	cases := []struct {
		name string
		ask  func(context.Context) (bool, error)
		want bool
	}{
		{
			"a host is registered",
			func(context.Context) (bool, error) { return true, nil },
			true,
		},
		{
			"the watcher is there and no host is attached",
			func(context.Context) (bool, error) { return false, nil },
			false,
		},
		{
			"no session bus at all",
			func(context.Context) (bool, error) { return false, errors.New("no session bus") },
			false,
		},
		{
			// The dangerous shape: an implementation that answered yes and
			// then failed. Nothing may reach the caller as a yes unless the
			// error is nil.
			"an error alongside a yes",
			func(context.Context) (bool, error) { return true, errors.New("bus went away mid-call") },
			false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decide(c.ask); got != c.want {
				t.Errorf("decide = %v, want %v", got, c.want)
			}
		})
	}
}

// TestDecideBoundsTheProbe covers the startup hazard: this runs before the
// first frame, so a bus that accepts a connection and never answers must not
// hold the window back indefinitely.
func TestDecideBoundsTheProbe(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		done <- decide(func(ctx context.Context) (bool, error) {
			<-ctx.Done()
			return false, ctx.Err()
		})
	}()
	select {
	case got := <-done:
		if got {
			t.Error("a probe that only ever timed out answered yes")
		}
	case <-time.After(ProbeTimeout + 5*time.Second):
		t.Fatal("decide did not return — the probe is unbounded and startup can hang on a wedged session bus")
	}
}

// TestDecidePassesADeadlineDown asserts the context reaching the probe actually
// carries ProbeTimeout, rather than the bound living somewhere the bus call
// cannot see.
func TestDecidePassesADeadlineDown(t *testing.T) {
	var (
		hadDeadline bool
		within      bool
	)
	decide(func(ctx context.Context) (bool, error) {
		var d time.Time
		d, hadDeadline = ctx.Deadline()
		within = time.Until(d) <= ProbeTimeout
		return false, nil
	})
	if !hadDeadline {
		t.Fatal("the probe was handed a context with no deadline")
	}
	if !within {
		t.Errorf("the deadline is further out than ProbeTimeout (%s)", ProbeTimeout)
	}
}

// TestAvailableDoesNotPanic is the smoke check for the real path. It asserts
// nothing about the answer — a CI container has no session bus and a
// developer's desktop may have any tray at all — only that asking is safe and
// bounded on whatever this is running on.
func TestAvailableDoesNotPanic(t *testing.T) {
	start := time.Now()
	_ = Available()
	if elapsed := time.Since(start); elapsed > ProbeTimeout+5*time.Second {
		t.Errorf("Available() took %s, well past ProbeTimeout", elapsed)
	}
}
