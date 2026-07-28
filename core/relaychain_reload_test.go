package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// Relay-directory hot-reload (issue #27): the engine re-reads
// Config.RelayDirectoryPath on an interval and swaps a freshly verified
// directory into e.relayDir — so a long-lived node picks up an operator's
// rotated snapshot (new hops, a renewed expiry) without a restart, the
// client-side mirror of cmd/coordinator's own reloadRevocationsLoop.
//
// core/crl_reload_test.go (issue #90) is the direct template: same four-test
// shape (picks up a change; keeps the previous directory on each distinct
// failure mode; the loop itself stops on Stop; Start wires it end to end),
// because the fail-safe posture it pins is the identical one this file's
// doc comment states as the single most important behavioural property in
// core/relaychain.go — a failed reload must not degrade a hop's forwarding
// allow-list to "nothing" or a client's hop selection to "no chaining."

// relayDirFixtureEntries returns a snapshot entry set that can build a
// depth-N chain (an exit, a pairable head, and N-2 additional relay-only
// hops) and no deeper one — so buildChain(N, cc) succeeds and
// buildChain(N+1, cc) fails, which is what TestReloadRelayDirPicksUpNewHop
// uses to observe a reload actually taking effect rather than just
// inspecting relayDir's fields directly. Every id is a fixed, distinct byte
// pattern rather than a freshly generated key, so which entries survived a
// reload is legible in a failure message. depth must be >= 2.
func relayDirFixtureEntries(depth int) []coldstart.Entry {
	entries := []coldstart.Entry{
		{Role: "exit", ID: hex.EncodeToString(bytes.Repeat([]byte{0x10}, 32)), Addr: "127.0.0.1:1", Country: "NL"},
		{Role: "exit", ID: hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)), Addr: "127.0.0.1:2", Country: "NL"}, // the chain head: exit-role, so the coordinator can pair a client to it
	}
	for i := 2; i < depth; i++ {
		entries = append(entries, coldstart.Entry{
			Role: "relay", ID: hex.EncodeToString(bytes.Repeat([]byte{byte(0x10 + i)}, 32)), Ingress: fmt.Sprintf("127.0.0.1:%d", i+1),
		})
	}
	return entries
}

// writeRelayDirFile signs entries under the shared test snapshot key and
// writes it to a fresh temp file, returning the path reloadRelayDir reads.
func writeRelayDirFile(t *testing.T, entries []coldstart.Entry) string {
	t.Helper()
	_, priv := testSnapKeys(t)
	signed := signTestSnapshot(t, priv, entries)
	path := filepath.Join(t.TempDir(), "relay-directory.bin")
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatalf("write relay directory file: %v", err)
	}
	return path
}

// newRelayReloadEngine builds a client-role engine (not started) whose
// RelayDirectoryPath points at path, which must already hold a directory
// valid right now — construction's own load is just as fail-loud as a first
// RelayDirectory always was, mirroring newCRLReloadEngine
// (core/crl_reload_test.go). No coordinator dial happens before Start, so
// this needs no real network I/O.
func newRelayReloadEngine(t *testing.T, hops int, path string) *Engine {
	t.Helper()
	signed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture directory: %v", err)
	}
	e, err := New(Config{
		Coordinators:       []string{testCoord},
		Roles:              []string{RoleClient},
		RelayHops:          hops,
		RelayDirectory:     signed,
		RelayDirectoryKey:  testSnapPub(t),
		RelayDirectoryPath: path,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { e.Stop(); e.Wait() })
	return e
}

// TestReloadRelayDirPicksUpNewHop is the #27 acceptance test: a chain depth
// that fails against the client's initially loaded directory succeeds once
// the operator rotates the file to one with enough hops and a reload runs —
// without restarting the client.
func TestReloadRelayDirPicksUpNewHop(t *testing.T) {
	now := time.Now()
	path := writeRelayDirFile(t, relayDirFixtureEntries(2)) // exit + head only: no depth-3 candidate yet
	e := newRelayReloadEngine(t, 3, path)

	if _, err := e.buildChain(3, "NL"); err == nil {
		t.Fatal("fixture premise is wrong: a depth-2 directory must not be able to build a depth-3 chain")
	}

	// The operator rotates the file to a bundle with a third hop.
	_, priv := testSnapKeys(t)
	rotated := signTestSnapshot(t, priv, relayDirFixtureEntries(3))
	if err := os.WriteFile(path, rotated, 0o600); err != nil {
		t.Fatalf("rewrite relay directory file: %v", err)
	}

	e.reloadRelayDir(now)

	if _, err := e.buildChain(3, "NL"); err != nil {
		t.Fatalf("after reload, buildChain(3, \"NL\") = %v, want success — the rotated directory was not picked up", err)
	}
}

// TestReloadRelayDirKeepsPreviousOnFailure covers the fail-safe half of
// #27: a reload that cannot read, cannot verify, or finds the file itself
// expired must not blind the node — the previously loaded directory keeps
// being enforced, and the reload must not crash or panic. This is the
// property core/relaychain.go's file doc calls "the single most important
// behavioural property in this file," now pinned for the reload path
// specifically rather than only for construction.
func TestReloadRelayDirKeepsPreviousOnFailure(t *testing.T) {
	now := time.Now()

	t.Run("file deleted", func(t *testing.T) {
		path := writeRelayDirFile(t, relayDirFixtureEntries(3))
		e := newRelayReloadEngine(t, 3, path)
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove relay directory file: %v", err)
		}
		e.reloadRelayDir(now) // must not panic
		if _, err := e.buildChain(3, "NL"); err != nil {
			t.Fatalf("a failed reload must keep enforcing the previous directory: buildChain(3, \"NL\") = %v, want success", err)
		}
	})

	t.Run("file corrupted", func(t *testing.T) {
		path := writeRelayDirFile(t, relayDirFixtureEntries(3))
		e := newRelayReloadEngine(t, 3, path)
		if err := os.WriteFile(path, []byte("not a signed snapshot at all"), 0o600); err != nil {
			t.Fatalf("corrupt relay directory file: %v", err)
		}
		e.reloadRelayDir(now)
		if _, err := e.buildChain(3, "NL"); err != nil {
			t.Fatalf("a failed reload must keep enforcing the previous directory: buildChain(3, \"NL\") = %v, want success", err)
		}
	})

	t.Run("file expired", func(t *testing.T) {
		path := writeRelayDirFile(t, relayDirFixtureEntries(3))
		e := newRelayReloadEngine(t, 3, path)
		_, priv := testSnapKeys(t)
		// Lapsed, and would otherwise still name every hop the depth-3 chain needs
		// — the only thing wrong with it is that it has expired, so a reload that
		// merely checked signature/shape and skipped the expiry check would pass
		// this case for the wrong reason.
		expired, err := coldstart.Sign(priv, coldstart.Snapshot{
			Version:   coldstart.SnapshotVersion,
			IssuedAt:  now.Add(-2 * time.Hour),
			ExpiresAt: now.Add(-time.Hour),
			Entries:   relayDirFixtureEntries(3),
		})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := os.WriteFile(path, expired, 0o600); err != nil {
			t.Fatalf("rewrite relay directory file: %v", err)
		}
		e.reloadRelayDir(now)
		if _, err := e.buildChain(3, "NL"); err != nil {
			t.Fatalf("an expired reload must keep enforcing the previous directory: buildChain(3, \"NL\") = %v, want success", err)
		}
	})
}

// TestReloadRelayDirLoopStopsOnEngineStop drives reloadRelayDirLoop directly
// (mirroring TestReloadCRLLoopStopsOnEngineStop and core/reaper_test.go's
// TestReaperDrainsHalfOpenSessions pattern): with a short interval it must
// tick and return promptly once e.stop closes, leaving no goroutine behind.
func TestReloadRelayDirLoopStopsOnEngineStop(t *testing.T) {
	path := writeRelayDirFile(t, relayDirFixtureEntries(2))
	e := newRelayReloadEngine(t, 2, path)
	// Shrink the interval on the *relayDirectory* the engine already holds —
	// there is no *Engine field for this (see relayDirectory.reloadInterval's
	// doc on why), so a test reaches it the same way production code would
	// after a first Load(), before starting the loop.
	if d := e.relayDir.Load(); d != nil {
		d.reloadInterval = 2 * time.Millisecond
	}

	e.wg.Add(1)
	go e.reloadRelayDirLoop()

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	time.Sleep(20 * time.Millisecond) // let a few ticks happen
	e.Stop()                          // idempotent; t.Cleanup's e.Stop() is a harmless no-op afterward

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reloadRelayDirLoop did not exit after Stop")
	}
}

// TestStartReloadsRelayDirOnInterval is the full end-to-end wiring proof: a
// real Start (no manual reloadRelayDir call) picks up a rotated directory
// through the actual ticker, for a genuinely running engine — mirroring
// TestStartReloadsCRLOnInterval.
func TestStartReloadsRelayDirOnInterval(t *testing.T) {
	path := writeRelayDirFile(t, relayDirFixtureEntries(2))
	signed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture directory: %v", err)
	}
	e, err := New(Config{
		Coordinators:       []string{testCoord},
		Roles:              []string{RoleClient},
		RelayHops:          3,
		RelayDirectory:     signed,
		RelayDirectoryKey:  testSnapPub(t),
		RelayDirectoryPath: path,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d := e.relayDir.Load(); d != nil {
		d.reloadInterval = 20 * time.Millisecond
	}
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { e.Stop(); e.Wait() }()

	if _, err := e.buildChain(3, "NL"); err == nil {
		t.Fatal("fixture premise is wrong: a depth-2 directory must not be able to build a depth-3 chain")
	}

	_, priv := testSnapKeys(t)
	rotated := signTestSnapshot(t, priv, relayDirFixtureEntries(3))
	if err := os.WriteFile(path, rotated, 0o600); err != nil {
		t.Fatalf("rewrite relay directory file: %v", err)
	}

	if !waitFor(2*time.Second, func() bool {
		_, err := e.buildChain(3, "NL")
		return err == nil
	}) {
		t.Fatal("Start's relay-directory reload loop never picked up the rotated directory")
	}
}
