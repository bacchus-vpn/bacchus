package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/policy"
	"github.com/bacchus-vpn/bacchus/core/version"
)

// The frozen conformance fixture lives with core/policy. These tests reuse it
// rather than minting a bundle, so what the coordinator enforces here is the same
// object the wire-format suite accepts, and the two cannot drift apart.
const fixtureBundle = "../../core/policy/testdata/vectors.json"

type fixture struct {
	Now     string          `json:"now"`
	RootPub string          `json:"root_pub"`
	Bundle  json.RawMessage `json:"bundle"`
	Seq     uint64          `json:"expect_seq"`
	MinVer  string          `json:"expect_min_serving_version"`
}

func readFixture(t *testing.T) fixture {
	t.Helper()
	b, err := os.ReadFile(fixtureBundle)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

// fixturePolicy verifies the frozen bundle and returns the resulting Policy, so a
// test can install exactly what the coordinator would have loaded.
func fixturePolicy(t *testing.T) policy.Policy {
	t.Helper()
	f := readFixture(t)
	root, err := base64.StdEncoding.DecodeString(f.RootPub)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	v, err := policy.NewVerifier(root, nil)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	bundle, err := policy.ParseBundle(f.Bundle)
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	now, err := time.Parse(time.RFC3339, f.Now)
	if err != nil {
		t.Fatalf("parse now: %v", err)
	}
	p, err := v.Verify(bundle, now, 0)
	if err != nil {
		t.Fatalf("verify fixture bundle: %v", err)
	}
	return p
}

// withPolicyState sets the package's policy globals for one test and restores them
// afterwards, so policy tests do not leak into the registry tests that share these
// globals.
func withPolicyState(t *testing.T, configured bool, held *policy.Policy) {
	t.Helper()
	policyState.mu.Lock()
	prevConfigured, prevHeld, prevOK := policyState.configured, policyState.held, policyState.ok
	policyState.configured = configured
	if held != nil {
		policyState.held, policyState.ok = *held, true
	} else {
		policyState.held, policyState.ok = policy.Policy{}, false
	}
	policyState.mu.Unlock()
	t.Cleanup(func() {
		policyState.mu.Lock()
		policyState.configured, policyState.held, policyState.ok = prevConfigured, prevHeld, prevOK
		policyState.mu.Unlock()
	})
}

// TestUnconfiguredPolicyIsTheStatusQuo pins that landing this changes nothing for a
// deployment that has not adopted signed policy. With no root configured the gate
// is inert and every surface behaves exactly as it did before.
func TestUnconfiguredPolicyIsTheStatusQuo(t *testing.T) {
	withPolicyState(t, false, nil)

	if !policyAllowsAssignment() {
		t.Error("with policy unconfigured, assignment must be allowed")
	}
	if policyEnabled() {
		t.Error("policyEnabled() = true with no root configured")
	}
}

// TestConfiguredButUnloadedPolicyFailsClosed is the direction that matters. A
// coordinator that has been told to enforce signed policy, and has none, assigns
// nothing — the same state as one whose policy went stale.
func TestConfiguredButUnloadedPolicyFailsClosed(t *testing.T) {
	withPolicyState(t, true, nil)

	if policyAllowsAssignment() {
		t.Fatal("a coordinator with policy configured but none loaded must NOT assign new work")
	}
}

func TestLoadedPolicyAllowsAssignment(t *testing.T) {
	p := fixturePolicy(t)
	withPolicyState(t, true, &p)

	if !policyAllowsAssignment() {
		t.Fatal("a coordinator holding a verified policy must assign work")
	}
}

// TestRegisterRefusedWhenPolicyIsUnenforceable is the serve-pool half of the
// drain: no new node enters the pool, and the refusal says why.
func TestRegisterRefusedWhenPolicyIsUnenforceable(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.2.0")
	resetRegistry(t)
	withPolicyState(t, true, nil)
	peer := fakePeer(t)

	handle(wire{Type: "register", Role: "exit", ID: "new-exit", Country: "rs", Addr: "1.2.3.4:20000", Release: "0.2.0"},
		peer.LocalAddr().(*net.UDPAddr))

	if reason := readReject(t, peer); !strings.Contains(reason, "no enforceable network policy") {
		t.Fatalf("reject reason should name the missing policy, got %q", reason)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, ok := exits["new-exit"]; ok {
		t.Fatal("a node must not enter the serve pool while policy is unenforceable")
	}
}

// TestRegisterAcceptedWhenPolicyIsHeld is the control for the test above: the same
// register succeeds once a policy is being enforced, so the refusal is attributable
// to the drain and not to something else about the message.
func TestRegisterAcceptedWhenPolicyIsHeld(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.2.0")
	resetRegistry(t)
	p := fixturePolicy(t)
	// The fixture's own fence is 0.2.0, which this node satisfies.
	withPolicyState(t, true, &p)
	peer := fakePeer(t)

	handle(wire{Type: "register", Role: "exit", ID: "new-exit", Country: "rs", Addr: "1.2.3.4:20000", Release: "0.2.0"},
		peer.LocalAddr().(*net.UDPAddr))

	expectSilence(t, peer)
	mu.Lock()
	defer mu.Unlock()
	if _, ok := exits["new-exit"]; !ok {
		t.Fatal("a node must enter the serve pool while a policy is enforced")
	}
}

// TestConnectRefusedWhenPolicyIsUnenforceable is the matchmaking half of the drain.
func TestConnectRefusedWhenPolicyIsUnenforceable(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.2.0")
	resetRegistry(t)
	withPolicyState(t, true, nil)
	peer := fakePeer(t)

	handle(wire{Type: "connect", Country: "rs", Nonce: "abc123"}, peer.LocalAddr().(*net.UDPAddr))

	if reason := readReject(t, peer); !strings.Contains(reason, "no enforceable network policy") {
		t.Fatalf("reject reason should name the missing policy, got %q", reason)
	}
}

// TestDrainLeavesEstablishedSessionsAlone pins the soft-drain shape. The stale
// policy stops NEW work; it must not tear down what is already running, which is
// what makes this need no teardown path and no timer.
func TestDrainLeavesEstablishedSessionsAlone(t *testing.T) {
	setPC(t)
	setPolicy(t, "0.0.0", "0.2.0")
	resetRegistry(t)

	// Register an exit while a policy is held, then let the policy lapse.
	p := fixturePolicy(t)
	withPolicyState(t, true, &p)
	peer := fakePeer(t)
	handle(wire{Type: "register", Role: "exit", ID: "live-exit", Country: "rs", Addr: "1.2.3.4:20000", Release: "0.2.0"},
		peer.LocalAddr().(*net.UDPAddr))
	expectSilence(t, peer)

	mu.Lock()
	_, registered := exits["live-exit"]
	mu.Unlock()
	if !registered {
		t.Fatal("setup: the exit should be registered")
	}

	// Policy goes stale.
	clearPolicy()

	mu.Lock()
	defer mu.Unlock()
	if _, ok := exits["live-exit"]; !ok {
		t.Error("a stale policy must not evict an already-registered node; the drain stops NEW work only")
	}
}

// TestPolicyServingFloorOverridesTheFlag is the precedence requirement, and it is
// checked in both directions: a loaded policy wins, and the flag applies until one
// is loaded.
//
// The point of asserting it here rather than trusting read order is that two
// sources of truth for one fence is what gets discovered during an incident.
func TestPolicyServingFloorOverridesTheFlag(t *testing.T) {
	setPolicy(t, "0.1.0", "0.2.0") // the -min-serving-version flag says 0.1.0

	// No policy loaded: the flag is the fence.
	withPolicyState(t, true, nil)
	if got, want := policyServingFloor(), mustVersion(t, "0.1.0"); got != want {
		t.Errorf("with no policy loaded, floor = %s, want the flag's %s", got, want)
	}

	// Policy loaded: its floor wins, and the fixture's is 0.2.0.
	p := fixturePolicy(t)
	withPolicyState(t, true, &p)
	if got, want := policyServingFloor(), mustVersion(t, p.ServeFloor.MinServingVersion); got != want {
		t.Errorf("with a policy loaded, floor = %s, want the policy's %s", got, want)
	}
	if p.ServeFloor.MinServingVersion == "0.1.0" {
		t.Fatal("fixture no longer distinguishes the two sources; this test proves nothing")
	}
}

// TestServingCheckUsesThePolicyFloor is the same precedence observed through the
// gate that actually fences a node, rather than through the helper.
func TestServingCheckUsesThePolicyFloor(t *testing.T) {
	setPolicy(t, "0.0.0", "0.2.0") // flag fence DISABLED
	p := fixturePolicy(t)          // policy fence 0.2.0
	withPolicyState(t, true, &p)

	// A node the flag would have admitted must now be fenced by the policy.
	reason, ok := servingCheck("0.1.0", "some-node", 0)
	if ok {
		t.Fatal("a node below the POLICY floor must be fenced even though the flag fence is disabled")
	}
	if !strings.Contains(reason, "0.2.0") {
		t.Errorf("the reason should name the policy floor, got %q", reason)
	}

	// And one at the policy floor serves.
	if _, ok := servingCheck("0.2.0", "some-node", 0); !ok {
		t.Error("a node at the policy floor must serve")
	}
}

func mustVersion(t *testing.T, s string) version.Version {
	t.Helper()
	v, err := version.Parse(s)
	if err != nil {
		t.Fatalf("parse version %q: %v", s, err)
	}
	return v
}

// TestPolicyBackoffIsCappedAndStartsAtTheRefreshCadence pins that a source which is
// down is not hammered, and — more importantly — that the backoff can never be the
// reason a coordinator failed closed: it is capped well below any realistic grace
// window, so a policy approaching its deadline keeps getting frequent chances.
func TestPolicyBackoffIsCappedAndStartsAtTheRefreshCadence(t *testing.T) {
	if got := policyBackoffFor(0); got != policyRefresh {
		t.Errorf("healthy interval = %s, want the refresh cadence %s", got, policyRefresh)
	}
	if got := policyBackoffFor(1); got <= policyRefresh {
		t.Errorf("interval after one failure = %s, want it to back off past %s", got, policyRefresh)
	}
	for _, n := range []int{5, 20, 1000} {
		if got := policyBackoffFor(n); got > policyBackoffMax {
			t.Errorf("interval after %d failures = %s, want it capped at %s", n, got, policyBackoffMax)
		}
	}
	if policyBackoffMax >= time.Hour {
		t.Errorf("backoff cap %s is too coarse: a policy nearing its deadline must keep getting frequent chances to refresh", policyBackoffMax)
	}
}

// TestNewPolicySourcePicksByScheme pins the source selection, which is the one
// piece of operator-facing magic here.
func TestNewPolicySourcePicksByScheme(t *testing.T) {
	if _, ok := newPolicySource("https://example.invalid/policy.json").(httpPolicySource); !ok {
		t.Error("an https URL should select the HTTP source")
	}
	if _, ok := newPolicySource("http://example.invalid/policy.json").(httpPolicySource); !ok {
		t.Error("an http URL should select the HTTP source")
	}
	if _, ok := newPolicySource("/var/lib/bacchus/policy.json").(filePolicySource); !ok {
		t.Error("a path should select the file source")
	}
	if _, ok := newPolicySource("policy.json").(filePolicySource); !ok {
		t.Error("a relative path should select the file source")
	}
}

// TestStartPolicyRejectsMisconfiguration pins that an operator error is fatal at
// startup rather than a coordinator that silently never enforces anything. A root
// with no source would fail closed forever, which is the most confusing possible
// outcome.
func TestStartPolicyRejectsMisconfiguration(t *testing.T) {
	f := readFixture(t)
	root, err := base64.StdEncoding.DecodeString(f.RootPub)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	rootHex := hex.EncodeToString(root)
	dir := t.TempDir()

	for _, tc := range []struct {
		name, root, source string
	}{
		{"root with no source", rootHex, ""},
		{"root that is not hex", "zzzz", "/tmp/x"},
		{"root of the wrong length", "aabbcc", "/tmp/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withPolicyState(t, false, nil)
			err := startPolicy(context.Background(), tc.root, tc.source, filepath.Join(dir, "state.json"))
			if err == nil {
				t.Fatal("startPolicy() accepted a misconfiguration, want a fatal error")
			}
		})
	}
}

// TestStartPolicyUnsetIsDisabled pins the opt-in: no root means the mechanism is
// off and startup succeeds.
func TestStartPolicyUnsetIsDisabled(t *testing.T) {
	withPolicyState(t, false, nil)
	if err := startPolicy(context.Background(), "", "", filepath.Join(t.TempDir(), "state.json")); err != nil {
		t.Fatalf("startPolicy() with no root = %v, want nil", err)
	}
	if policyEnabled() {
		t.Error("policy must be disabled when no root is configured")
	}
	if !policyAllowsAssignment() {
		t.Error("an unconfigured coordinator must keep assigning work")
	}
}

// TestRefreshLoadsVerifiesAndPersists exercises one full fetch-verify-install cycle
// against a file source holding the frozen bundle, and checks the sequence floor
// reached disk — the value that cannot be re-derived and whose loss would open a
// rollback window across the next restart.
func TestRefreshLoadsVerifiesAndPersists(t *testing.T) {
	f := readFixture(t)
	root, err := base64.StdEncoding.DecodeString(f.RootPub)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, f.Bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	statePath := filepath.Join(dir, "state.json")

	v, err := policy.NewVerifier(root, nil)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	cache := policy.NewCache(statePath)

	withPolicyState(t, true, nil)
	if policyAllowsAssignment() {
		t.Fatal("setup: should start failed closed")
	}

	// The frozen bundle is only live around its own instant, which is why the clock
	// is injected: this exercises the real success path rather than whatever the
	// calendar happens to allow today.
	now, err := time.Parse(time.RFC3339, f.Now)
	if err != nil {
		t.Fatalf("parse fixture now: %v", err)
	}

	var minSeq uint64
	if !refreshPolicyOnce(context.Background(), v, cache, filePolicySource{path: bundlePath}, &minSeq, now) {
		t.Fatal("refreshPolicyOnce() failed on the frozen bundle at its own instant")
	}
	if !policyAllowsAssignment() {
		t.Error("a verified policy must lift the drain")
	}
	if minSeq != f.Seq {
		t.Errorf("floor = %d, want %d", minSeq, f.Seq)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("verified policy was not persisted: %v", err)
	}

	// A restart: a fresh cache over the same file must re-verify the bytes and come
	// back with both the policy and the floor. This is the "restart does not begin
	// unpoliced" requirement, and it passes only because the BYTES were cached — a
	// parsed struct would have been trusted rather than re-checked.
	restored := policy.NewCache(statePath)
	gotSeq, gotPolicy, ok, err := restored.Load(v, now)
	if err != nil || !ok {
		t.Fatalf("restart Load() = (%v, ok=%v), want the cached policy re-verified", err, ok)
	}
	if gotPolicy.Seq != f.Seq || gotSeq != f.Seq {
		t.Errorf("restart restored seq %d (floor %d), want %d", gotPolicy.Seq, gotSeq, f.Seq)
	}

	// And a replayed older generation is refused at the persisted floor — the
	// rollback that a coordinator forgetting its floor on restart would have allowed.
	bundle, err := policy.ParseBundle(f.Bundle)
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	if _, err := v.Verify(bundle, now, f.Seq+1); err == nil {
		t.Error("a generation below the floor must be refused")
	}
}

// TestRefreshRefusesToReplaceAHeldPolicyWithGarbage is the anti-unload property: a
// hostile upstream must not be able to disarm a coordinator by serving something
// broken. What is held keeps being enforced until its own deadline passes.
func TestRefreshRefusesToReplaceAHeldPolicyWithGarbage(t *testing.T) {
	f := readFixture(t)
	root, err := base64.StdEncoding.DecodeString(f.RootPub)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"policy":"AAAA","cert":"AAAA"}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	v, err := policy.NewVerifier(root, nil)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	// Hold a policy whose deadline is far in the future, so the age-out does not fire
	// and the only thing that could unload it is the bad fetch.
	held := fixturePolicy(t)
	held.Expires = time.Now().Add(24 * time.Hour)
	held.Grace = 24 * time.Hour
	withPolicyState(t, true, &held)

	var minSeq uint64
	if ok := refreshPolicyOnce(context.Background(), v, policy.NewCache(filepath.Join(dir, "state.json")),
		filePolicySource{path: bundlePath}, &minSeq, time.Now()); ok {
		t.Fatal("a garbage bundle must not report success")
	}
	if !policyAllowsAssignment() {
		t.Error("a garbage bundle must NOT unload a held policy — a hostile upstream would otherwise disarm this coordinator by serving nonsense")
	}
	if got, ok := currentPolicy(); !ok || got.Seq != held.Seq {
		t.Error("the held policy should still be the one being enforced")
	}
}

// TestRefreshRefusesToReplaceAHeldPolicyWhenTheFetchFails is the same property for
// an unreachable source: a failed fetch is not a stale policy.
func TestRefreshRefusesToReplaceAHeldPolicyWhenTheFetchFails(t *testing.T) {
	f := readFixture(t)
	root, err := base64.StdEncoding.DecodeString(f.RootPub)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	v, err := policy.NewVerifier(root, nil)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	held := fixturePolicy(t)
	held.Expires = time.Now().Add(24 * time.Hour)
	held.Grace = 24 * time.Hour
	withPolicyState(t, true, &held)

	dir := t.TempDir()
	var minSeq uint64
	if ok := refreshPolicyOnce(context.Background(), v, policy.NewCache(filepath.Join(dir, "state.json")),
		filePolicySource{path: filepath.Join(dir, "does-not-exist.json")}, &minSeq, time.Now()); ok {
		t.Fatal("a failed fetch must not report success")
	}
	if !policyAllowsAssignment() {
		t.Error("a failed fetch is not a stale policy: what is held keeps being enforced until its own deadline")
	}
}

// TestRefreshAgesOutAHeldPolicyPastItsDeadline is the fail-closed transition, and
// it must happen even when the fetch fails — otherwise a source that simply stopped
// answering would leave this coordinator enforcing one generation forever, which is
// authoring policy by omission.
func TestRefreshAgesOutAHeldPolicyPastItsDeadline(t *testing.T) {
	f := readFixture(t)
	root, err := base64.StdEncoding.DecodeString(f.RootPub)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	v, err := policy.NewVerifier(root, nil)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}

	// Held, but already past exp + grace.
	held := fixturePolicy(t)
	held.Expires = time.Now().Add(-2 * time.Hour)
	held.Grace = time.Hour
	withPolicyState(t, true, &held)
	if !policyAllowsAssignment() {
		t.Fatal("setup: should start allowing assignment")
	}

	dir := t.TempDir()
	var minSeq uint64
	// Source deliberately unreachable: the age-out must not depend on a successful
	// fetch.
	refreshPolicyOnce(context.Background(), v, policy.NewCache(filepath.Join(dir, "state.json")),
		filePolicySource{path: filepath.Join(dir, "does-not-exist.json")}, &minSeq, time.Now())

	if policyAllowsAssignment() {
		t.Fatal("a policy past exp+grace must stop new assignments even when the fetch also failed")
	}
	if _, ok := currentPolicy(); ok {
		t.Error("a policy past its deadline must be released, not merely ignored")
	}
}

// TestGraceIsDistinguishableFromFresh pins that the coordinator can tell "enforcing
// normally" from "enforcing on borrowed time". The grace log line is the only
// warning an operator gets before a hard stop, so a build that could not tell the
// two apart would have nothing to log.
func TestGraceIsDistinguishableFromFresh(t *testing.T) {
	p := fixturePolicy(t)

	fresh := p.Issued.Add(time.Hour)
	if !p.Fresh(fresh) {
		t.Error("inside its window the policy must read as fresh")
	}
	onGrace := p.Expires.Add(time.Hour)
	if p.Fresh(onGrace) {
		t.Error("past expiry the policy must NOT read as fresh, or the grace warning never fires")
	}
	if !onGrace.Before(p.Deadline()) {
		t.Fatal("fixture grace is too short for this test to distinguish the states")
	}
}
