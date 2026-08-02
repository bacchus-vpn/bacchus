package core

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// engineWithSource builds the smallest Engine these tests need. dialServed
// reads nothing but cfg.ServedSource, so nothing else has to exist — and
// keeping it that way is the point of the hook being a plain function on
// Config rather than something reached through session state.
func engineWithSource(src func() string) *Engine {
	return &Engine{cfg: Config{ServedSource: src}}
}

// listenLoopback starts a listener that accepts and immediately closes, and
// returns its address.
func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln
}

// TestDialServedWithoutAHookIsAnOrdinaryDial pins the default path: every node
// that is not routing itself — all of cmd/node, and clients/fyne on a platform
// with no Enforcer — must dial exactly as it did before issue #109.
//
// Both "no hook at all" and "a hook that answers empty" are covered, because
// they arrive from different places: nil is a controller with no Enforcer, and
// "" is an Enforcer with no serving session up yet.
func TestDialServedWithoutAHookIsAnOrdinaryDial(t *testing.T) {
	ln := listenLoopback(t)

	for _, tc := range []struct {
		name string
		src  func() string
	}{
		{"nil hook", nil},
		{"hook answers empty", func() string { return "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := engineWithSource(tc.src)
			c, err := e.dialServed("tcp", ln.Addr().String(), 2*time.Second)
			if err != nil {
				t.Fatalf("dialServed: %v", err)
			}
			defer c.Close()
			if e.servedSource() != nil {
				t.Errorf("servedSource() = %v, want nil", e.servedSource())
			}
		})
	}
}

// altLoopback is a source address the kernel would NOT pick on its own for a
// connection to 127.0.0.1, which is the entire reason it is not 127.0.0.1.
//
// The whole of 127.0.0.0/8 is local on Linux, so this is bindable, but the
// route to 127.0.0.1 selects 127.0.0.1 as its source. That difference is what
// makes "the socket bound what it was told" observable at all: with 127.0.0.1
// on both ends, a dialServed that ignored its source entirely would produce an
// identical local address and the test would pass against a no-op.
const altLoopback = "127.0.0.2"

// TestDialServedBindsTheSourceItIsGiven is the client-side half of the
// carve-out: the socket has to actually carry the address, because that address
// is the only thing distinguishing other people's traffic from the operator's
// own once both are heading for the same destinations.
func TestDialServedBindsTheSourceItIsGiven(t *testing.T) {
	ln := listenLoopback(t)
	e := engineWithSource(func() string { return altLoopback })

	c, err := e.dialServed("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dialServed: %v", err)
	}
	defer c.Close()

	host, _, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", c.LocalAddr(), err)
	}
	if host != altLoopback {
		t.Errorf("served connection left from %s, want %s — an unbound served socket egresses through the tunnel under the upstream exit's address", host, altLoopback)
	}
}

// TestDialServedAsksPerDial pins the laziness that makes the hook work at all.
//
// clients/fyne builds core.Config and connects the engine BEFORE enforcement
// starts, so an address read once at construction would always be the empty one.
// It also has to keep being re-read: a session that ended must stop handing out
// an address whose carve-out went with it.
func TestDialServedAsksPerDial(t *testing.T) {
	ln := listenLoopback(t)
	var calls atomic.Int64
	e := engineWithSource(func() string {
		calls.Add(1)
		return "127.0.0.1"
	})

	for i := 0; i < 3; i++ {
		c, err := e.dialServed("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		c.Close()
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("ServedSource was asked %d time(s) across 3 dials, want 3: a cached answer outlives the session that produced it", got)
	}
}

// TestDialServedRefusesADestinationTheCarveOutCannotReach is the fail-closed
// case, and it is the one worth being explicit about because the friendlier
// behaviour is the dangerous one.
//
// A v6-only destination with a v4 carve-out cannot take the carve-out. Falling
// back to an unbound dial would put that connection into the tunnel — egressing
// at the upstream exit's address, under a disclosure that says otherwise — for
// the one destination class the carve-out does not cover, and silently. So the
// dial fails instead.
func TestDialServedRefusesADestinationTheCarveOutCannotReach(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	defer ln.Close()

	e := engineWithSource(func() string { return altLoopback })
	c, err := e.dialServed("tcp", ln.Addr().String(), 2*time.Second)
	if err == nil {
		c.Close()
		t.Fatal("dialServed reached an IPv6 destination from an IPv4 carve-out. That connection cannot have taken the carve-out, so it went through the tunnel")
	}
}

// TestDialServedUDPBindsAndRefusesTheSameWay covers the exit's UDP egress. The
// family check is explicit there rather than left to the standard library,
// because net.DialUDP takes an already-resolved address and binds the
// mismatched pair rather than filtering it.
func TestDialServedUDPBindsAndRefusesTheSameWay(t *testing.T) {
	v4, err := net.ResolveUDPAddr("udp", "127.0.0.1:9")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	e := engineWithSource(func() string { return altLoopback })

	c, err := e.dialServedUDP(v4)
	if err != nil {
		t.Fatalf("dialServedUDP: %v", err)
	}
	host, _, _ := net.SplitHostPort(c.LocalAddr().String())
	c.Close()
	if host != altLoopback {
		t.Errorf("served UDP socket bound %s, want %s", host, altLoopback)
	}

	v6, err := net.ResolveUDPAddr("udp", "[::1]:9")
	if err != nil {
		t.Fatalf("resolve v6: %v", err)
	}
	if c, err := e.dialServedUDP(v6); err == nil {
		c.Close()
		t.Error("dialServedUDP accepted a destination of a different family from the carve-out; that datagram would leave through the tunnel")
	} else if !strings.Contains(err.Error(), "same family") {
		t.Errorf("error = %q, want it to name the family mismatch", err)
	}
}
