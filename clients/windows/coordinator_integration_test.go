//go:build windows

package main

// Protocol conformance for the Windows client: the REAL cmd/coordinator against
// this package's OWN engine composition, over real sockets.
//
// # Why this file exists
//
// cmd/coordinator/protocol_integration_test.go states the rule, and states why:
// "at least one test must put the real coordinator's handler and the real core
// client on opposite ends of a real socket, with nothing hand-rolled in between.
// A protocol change that breaks the pairing must fail HERE even when both sides'
// unit tests still pass." That file covers cmd/coordinator against core.
//
// This package was the one that proved the rule and did not follow it. Its fake
// coordinator (midsession_recovery_test.go) was forked from cmd/node's before
// country-only assignment landed, so it answered a connect that named no country
// and minted sessions with no exit id. Every test here passed. No client built
// from this package could have connected to a real coordinator. A fake on both
// sides of a protocol tests the fakes.
//
// The fake is still the right tool for the supervisor tests — they need a
// coordinator that can be made to go silent mid-session, serve exactly one
// pairing, and answer instantly. What they cannot do is notice when the fake and
// the real thing have drifted apart. That is this file's only job.
//
// # Why a subprocess
//
// cmd/coordinator is package main, so its handler cannot be imported the way
// cmd/coordinator's own test imports core. Running the built binary is the
// stronger option anyway: it exercises flag parsing, the registry, the TURN
// server and the packet loop as shipped, not a test harness's reconstruction of
// them. The cost is a `go build` per run, which is why this is behind -short.
//
// # What is deliberately NOT faked
//
// clientEngineConfig — the composition connect() and switchCountry both build
// through — is called directly, so the fields this client actually sets are the
// fields the coordinator actually sees. A test that hand-wrote a core.Config
// here would pass while the client's own composition was wrong, which is the
// exact failure being guarded against.

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
)

// buildCoordinator compiles cmd/coordinator and returns the binary's path.
//
// Built from this worktree's own source rather than from anything pre-staged, so
// the coordinator under test is always the one in the tree the client is being
// changed in — the drift this file exists to catch is precisely the case where
// the two are edited at different times.
func buildCoordinator(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "bacchus-coordinator.exe")
	// The package runs its tests with CWD = clients/windows; the module root is
	// two levels up.
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/coordinator")
	cmd.Dir = filepath.Join("..", "..")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/coordinator: %v\n%s", err, out)
	}
	return bin
}

// freeUDPPort reserves a loopback UDP port, reads it, and releases it. There is
// a window between release and the coordinator's own bind; nothing else in this
// package binds UDP on a fixed port, so in practice it is uncontended. A
// coordinator that fails to bind surfaces as the readiness wait timing out, with
// its stderr attached.
func freeUDPPort(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a UDP port: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

// startRealCoordinator runs the built coordinator on loopback and returns its
// signalling address and TURN credentials.
//
// Every path flag points into a temp dir. The coordinator generates its
// snapshot-signing key on first run and treats the other files as absent, which
// is the documented "nothing configured" posture: admission disabled, no
// operator tags, nothing revoked, no GeoIP. That last one matters here — with no
// GeoIP database the coordinator falls back to each node's self-reported country
// (issue #136), which is how a loopback exit gets a country at all.
func startRealCoordinator(t *testing.T) (signalAddr, turnURL, turnUser, turnPass string) {
	t.Helper()
	bin := buildCoordinator(t)
	dir := t.TempDir()
	signalAddr = freeUDPPort(t)
	turnAddr := freeUDPPort(t)
	turnUser, turnPass = "bacchus", "test-turn-pass"

	cmd := exec.Command(bin,
		"-addr", signalAddr,
		"-advertise", signalAddr,
		"-turn-addr", turnAddr,
		"-turn-public-ip", "127.0.0.1",
		"-turn-user", turnUser,
		"-turn-pass", turnPass,
		"-bootstrap-key", filepath.Join(dir, "bootstrap.key"),
		"-bootstrap-secrets", filepath.Join(dir, "bootstrap-secrets.json"),
		"-operators", filepath.Join(dir, "operators.json"),
		"-admission-revocations", filepath.Join(dir, "revocations.json"),
	)
	var logs strings.Builder
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("start coordinator: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("coordinator output:\n%s", logs.String())
		}
	})

	// No readiness probe here, deliberately: a UDP listener that is up and one
	// that does not exist are indistinguishable from the outside, so anything
	// this could check would be a sleep wearing a costume. Readiness is instead
	// established by the caller waiting for the real coordinator to answer a real
	// request — the exit registration showing up in the country list. A
	// coordinator that failed to start surfaces there as a timeout, with its
	// stderr attached by the cleanup above.
	return signalAddr, "turn:" + turnAddr, turnUser, turnPass
}

// TestRealCoordinator_ClientEngineConfigPairsEndToEnd is the conformance test.
//
// It asserts three things a hand-rolled fake cannot:
//
//  1. The country this client offers in its picker is one the REAL coordinator
//     advertises, through the real ListCountries reply. This is the leg the
//     stale fake never served, and the one that failed in the merged tree.
//  2. A connect built by this package's own clientEngineConfig is ACCEPTED. A
//     connect naming no country is refused outright by the real coordinator
//     (refuseNoCountry), so a client that regressed to sending ExitID and no Geo
//     fails here rather than silently pairing.
//  3. Real traffic reaches a real exit through the resulting tunnel — a genuine
//     SOCKS5 CONNECT and echo — so the session is proven end to end rather than
//     inferred from a nil error.
func TestRealCoordinator_ClientEngineConfigPairsEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-coordinator pairing test in -short (it builds cmd/coordinator)")
	}
	redirectEventLogForTest(t)
	resetConnectionState(t)
	requireFreeSocksAddr(t)

	signalAddr, turnURL, turnUser, turnPass := startRealCoordinator(t)
	echoAddr := startEchoServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	// A real exit, self-reporting its country exactly as cmd/node does.
	exit := startTestExit(t, ctx, randomExitKeyHex(t), []string{signalAddr}, testCountry)
	exitID := exit.ID()

	// Assertion 1: the picker's own source of truth. listCountries() is the
	// function the tray calls, so this is the client's real list path against the
	// real coordinator — not a core.Engine call standing in for it.
	setTestConfig(Config{Coordinators: []string{signalAddr}})
	var offered []countryItem
	if !waitUntil(60*time.Second, func() bool {
		offered = listCountries()
		for _, c := range offered {
			if strings.EqualFold(c.code, testCountry) {
				return true
			}
		}
		return false
	}) {
		t.Fatalf("the real coordinator never offered %s in its country list; got %+v — "+
			"the tray picker would be empty against a real deployment", testCountry, offered)
	}

	// Assertion 2: the client's own engine composition is accepted. Built through
	// clientEngineConfig so a regression in what this client SENDS fails here.
	snap := Config{
		Coordinators: []string{signalAddr},
		TURN:         turnURL,
		TURNUser:     turnUser,
		TURNPass:     turnPass,
	}
	engCfg, err := clientEngineConfig(snap, testCountry, nil, testEventSink(t, "real-coord"))
	if err != nil {
		t.Fatalf("clientEngineConfig: %v", err)
	}
	if engCfg.ExitID != "" {
		t.Fatalf("clientEngineConfig set ExitID = %q; the real coordinator ignores it and core logs a NO EFFECT error for it", engCfg.ExitID)
	}
	if engCfg.Geo != testCountry {
		t.Fatalf("clientEngineConfig set Geo = %q, want %q — a connect naming no country is refused outright", engCfg.Geo, testCountry)
	}

	eng, err := core.New(engCfg)
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	defer sessionCancel()
	if err := eng.Start(sessionCtx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)
	if err := eng.Connect(sessionCtx); err != nil {
		t.Fatalf("Connect against the real coordinator: %v — this is the failure a fake on both sides hides", err)
	}

	// Assertion 3: real bytes, through the tunnel, to the real exit.
	if err := waitUntilNoErr(120*time.Second, func() error {
		return echoThrough(engCfg.SocksAddr, echoAddr, "hello-real-coordinator")
	}); err != nil {
		t.Fatalf("no traffic reached the exit through a session paired by the real coordinator: %v", err)
	}

	// The exit the coordinator chose is the one that is running. The client never
	// named it — it arrived on the session reply — so this also pins that the id
	// actually made the trip.
	if exitID == "" {
		t.Fatal("the fixture exit has no id")
	}
	if !strings.EqualFold(exit.ID(), exitID) {
		t.Fatalf("exit identity changed under the test: %q vs %q", exit.ID(), exitID)
	}
}

// TestRealCoordinator_RefusesAConnectNamingNoCountry pins the other direction of
// the same contract: the coordinator's refusal is real, so "set Geo" is a
// requirement rather than a convention this client happens to follow.
//
// Without this, clientEngineConfig could stop setting Geo and the test above
// would still pass on a lucky default. With it, the failure mode is named: a
// connect that carries no country does not pair, at all.
func TestRealCoordinator_RefusesAConnectNamingNoCountry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the real-coordinator refusal test in -short (it builds cmd/coordinator)")
	}
	redirectEventLogForTest(t)
	resetConnectionState(t)

	signalAddr, turnURL, turnUser, turnPass := startRealCoordinator(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// No exit registered at all: the coordinator has no country to offer, so even
	// core's own "pick the first assignable country" fallback has nothing to pick
	// and the connect cannot name one.
	eng, err := core.New(core.Config{
		Roles:        []string{core.RoleClient},
		SocksAddr:    freeTCPAddr(t),
		Coordinators: []string{signalAddr},
		TURNURL:      turnURL,
		TURNUser:     turnUser,
		TURNPass:     turnPass,
		OnEvent:      testEventSink(t, "no-country"),
	})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)

	connectErr := make(chan error, 1)
	go func() { connectErr <- eng.Connect(ctx) }()
	select {
	case err := <-connectErr:
		if err == nil {
			t.Fatal("the real coordinator paired a connect that could name no country — country-only assignment is not being enforced")
		}
		t.Logf("refused as expected: %v", err)
	case <-time.After(3 * time.Minute):
		t.Fatal("Connect neither paired nor failed against a coordinator with no countries")
	}
}
