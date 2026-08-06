package core

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// freeLoopbackAddr returns a loopback address with nothing listening on it —
// bound to learn a port, then released. A concrete address is the point: a test
// can hand it to a binder and afterwards ask the network whether anything is
// still there, which is the only way to see the leak issue #197 describes.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release the reserved port: %v", err)
	}
	return addr
}

// stillAccepting asks the network whether anything answers a TCP connect on
// addr. Nothing else can answer the question these tests need answered: a leaked
// listener is by definition one the engine has no record of, so there is no
// engine state to inspect for it.
func stillAccepting(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestStopBetweenListenAndRegistrationLeavesNothingListening is issue #197's
// window, written out in the order the binders execute it: net.Listen has
// returned a live socket, the engine has not been told about it yet, and Stop
// lands in between. Both serveReconnectSocks and bindPoolSocks spend a few
// instructions there on every connect, and connectAsync calls Stop the moment
// enforcement fails — which is the ordinary outcome of a first run on Windows
// unelevated or on Linux without bacchus-netd.
//
// Before the fix, Stop's snapshot of e.listeners could not see the listener and
// nothing ever closed it: the engine reported a clean shutdown while holding
// 127.0.0.1:1080 — the client's whole interface between the tunnel and the
// user's traffic, pinned deliberately (see clients/fyne/internal/appstate) — for
// the life of the process, so every later Connect failed to bind it.
//
// The assertion is a dial rather than addListener's return value on purpose.
// What a user pays for this defect is a held port, so a held port is what is
// checked; it also means this same test body demonstrates the defect on the
// build that had it, where addListener returned nothing at all.
func TestStopBetweenListenAndRegistrationLeavesNothingListening(t *testing.T) {
	e, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{RoleClient}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	e.Stop()

	// The registration Stop's snapshot could not have seen.
	e.addListener(ln)

	if stillAccepting(addr) {
		_ = ln.Close()
		t.Fatalf("%s is still accepting after Stop returned. A listener handed to the engine during shutdown was registered into a list nothing will ever read again, and nothing closed it — on the client that is the pinned SOCKS port, held until the process exits", addr)
	}
}

// TestSocksBindersRefuseOnceTheEngineHasStopped covers BOTH binders. Issue #197
// names this as the shape that gets half-fixed: serveReconnectSocks and
// bindPoolSocks have the same bug behind different locks, and a fix to one of
// them leaves the client leaking on whichever path it happens to take.
//
// A stopped engine is the deterministic tail of the same window — the binder
// arrives after the snapshot rather than a few instructions before it — and it
// pins the other half of the contract: the caller is told, so a connect that
// cannot get a SOCKS listener fails instead of reporting success with nothing
// behind it.
func TestSocksBindersRefuseOnceTheEngineHasStopped(t *testing.T) {
	for _, tc := range []struct {
		name string
		pool bool
		bind func(*Engine, string) error
	}{
		{"single transport", false, (*Engine).serveReconnectSocks},
		{"transport pool", true, (*Engine).bindPoolSocks},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{Coordinators: []string{testCoord}, Roles: []string{RoleClient}}
			if tc.pool {
				cfg.TransportPool = []string{"reality", "webrtc"}
			}
			e, err := New(cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			addr := freeLoopbackAddr(t)

			e.Stop()

			if err := tc.bind(e, addr); !errors.Is(err, errEngineStopped) {
				t.Fatalf("bind on a stopped engine: err = %v, want errEngineStopped — a nil here is a Connect that reports success with no engine behind the port it just bound", err)
			}
			if stillAccepting(addr) {
				t.Fatalf("%s is still accepting after a bind on a stopped engine: the listener was created and then abandoned", addr)
			}
		})
	}
}

// TestStartLeavesNoExitListenerBehindAStoppedEngine is the same window at the
// other two addListener call sites — Start's exit ingress and its relay onion
// ingress, which the card does not name. Both bind before anything is tracked by
// e.wg, so an embedder that stops the engine while Start is still running (a
// signal handler racing startup, on cmd/node) had exactly the client's leak with
// a serving port instead of a SOCKS one.
//
// Start after Stop is out of Start's documented contract, and it is used here
// because it lands that ordering deterministically rather than one run in thirty.
// The relay ingress site takes this same branch; it is not exercised separately
// because standing one up needs an exit key and a signed relay directory, none of
// which bears on the ordering under test.
func TestStartLeavesNoExitListenerBehindAStoppedEngine(t *testing.T) {
	addr := freeLoopbackAddr(t)
	e, err := New(Config{
		Coordinators: []string{testCoord},
		Roles:        []string{RoleExit},
		Advertise:    "127.0.0.1:9",
		ListenAddr:   addr,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	e.Stop()

	if err := e.Start(context.Background()); !errors.Is(err, errEngineStopped) {
		t.Fatalf("Start on a stopped engine: err = %v, want errEngineStopped", err)
	}
	if stillAccepting(addr) {
		t.Fatalf("%s is still accepting: Start bound the exit ingress into an engine that had already snapshotted its listeners, so nothing will ever close it", addr)
	}
}
