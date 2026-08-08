package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/revocation"
)

// The frozen conformance fixture lives with core/revocation. These tests reuse
// it rather than minting a bundle, so what the coordinator enforces here is the
// same object the wire-format suite accepts, and the two cannot drift apart —
// the same discipline cmd/coordinator/policy_test.go already applies to
// core/policy's fixture.
const revocationsFixtureBundle = "../../core/revocation/testdata/vectors.json"

type revocationsFixture struct {
	Now           string          `json:"now"`
	RootPub       string          `json:"root_pub"`
	Bundle        json.RawMessage `json:"bundle"`
	ExpectAsOf    string          `json:"expect_as_of"`
	ExpectRevoked []string        `json:"expect_revoked"`
}

func readRevocationsFixture(t *testing.T) revocationsFixture {
	t.Helper()
	b, err := os.ReadFile(revocationsFixtureBundle)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f revocationsFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

func (f revocationsFixture) rootPub(t *testing.T) []byte {
	t.Helper()
	root, err := base64.StdEncoding.DecodeString(f.RootPub)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	return root
}

func (f revocationsFixture) now(t *testing.T) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, f.Now)
	if err != nil {
		t.Fatalf("parse now: %v", err)
	}
	return now
}

func (f revocationsFixture) asOf(t *testing.T) time.Time {
	t.Helper()
	asOf, err := time.Parse(time.RFC3339, f.ExpectAsOf)
	if err != nil {
		t.Fatalf("parse expect_as_of: %v", err)
	}
	return asOf
}

// TestStartRevocationsUnsetIsDisabled pins the opt-in: no root means the
// mechanism is off and startup succeeds without touching any target.
func TestStartRevocationsUnsetIsDisabled(t *testing.T) {
	var target atomic.Pointer[admission.RevocationList]
	target.Store(admission.NewRevocationList())
	if err := startRevocations(context.Background(), "",
		revocationsNamespaceConfig{label: "device", source: "", state: filepath.Join(t.TempDir(), "state.json"), target: &target},
	); err != nil {
		t.Fatalf("startRevocations() with no root = %v, want nil", err)
	}
	// The pre-existing plain-file list must be untouched.
	if target.Load().Revoked("anything") {
		t.Error("an untouched RevocationList reported something revoked")
	}
}

// TestStartRevocationsRejectsMisconfiguration mirrors
// TestStartPolicyRejectsMisconfiguration: an operator error here is fatal at
// startup rather than a coordinator that silently never verifies anything.
func TestStartRevocationsRejectsMisconfiguration(t *testing.T) {
	f := readRevocationsFixture(t)
	rootHex := hex.EncodeToString(f.rootPub(t))
	dir := t.TempDir()
	var target atomic.Pointer[admission.RevocationList]
	target.Store(admission.NewRevocationList())

	for _, tc := range []struct {
		name, root, source string
	}{
		{"root with no source", rootHex, ""},
		{"root that is not hex", "zzzz", "/tmp/x"},
		{"root of the wrong length", "aabbcc", "/tmp/x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := startRevocations(context.Background(), tc.root,
				revocationsNamespaceConfig{label: "device", source: tc.source, state: filepath.Join(dir, "state.json"), target: &target},
			)
			if err == nil {
				t.Fatal("startRevocations() accepted a misconfiguration, want a fatal error")
			}
		})
	}
}

// TestStartRevocationsNamespaceSkipsADisabledGate pins that a nil target — the
// case setupAdmission/setupDeviceCred return when their own gate is off — is a
// warning and a no-op, never an error and never a panic. A root configured
// ahead of the corresponding credential gate is a legal, if unusual,
// deployment step.
func TestStartRevocationsNamespaceSkipsADisabledGate(t *testing.T) {
	f := readRevocationsFixture(t)
	v, err := revocation.NewVerifier(f.rootPub(t), nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	err = startRevocationsNamespace(context.Background(), revocationsNamespaceConfig{
		label: "device", source: "unused", state: filepath.Join(t.TempDir(), "state.json"), target: nil,
	}, v)
	if err != nil {
		t.Fatalf("startRevocationsNamespace() with a nil target = %v, want nil (skip, not fail)", err)
	}
}

// TestRevocationsRefreshInstallsIntoTheSamePointer is the property the whole
// card exists to prove: a successful verify installs into the identical
// atomic.Pointer[admission.RevocationList] the plain-file loop already writes
// to, not a parallel structure nothing reads.
func TestRevocationsRefreshInstallsIntoTheSamePointer(t *testing.T) {
	f := readRevocationsFixture(t)
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, f.Bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	v, err := revocation.NewVerifier(f.rootPub(t), nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	cache := revocation.NewCache(filepath.Join(dir, "state.json"))

	var target atomic.Pointer[admission.RevocationList]
	target.Store(admission.NewRevocationList())

	state := &revocationsLoopState{}
	if !refreshRevocationsOnce(context.Background(), "device", v, cache, filePolicySource{path: bundlePath}, state, f.now(t), &target) {
		t.Fatal("refreshRevocationsOnce() failed on the frozen bundle at its own instant")
	}

	rl := target.Load()
	for _, serial := range f.ExpectRevoked {
		if !rl.Revoked(serial) {
			t.Errorf("serial %q from the verified document is not in the installed RevocationList", serial)
		}
	}
	if rl.Revoked("not-in-the-fixture-at-all") {
		t.Error("a serial that was never revoked reports revoked")
	}
}

// TestRevocationsRefreshPersistsAndSurvivesARestart mirrors
// TestRefreshLoadsVerifiesAndPersists: the floor must reach disk, and a fresh
// Cache over the same file must restore it and refuse anything older.
func TestRevocationsRefreshPersistsAndSurvivesARestart(t *testing.T) {
	f := readRevocationsFixture(t)
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, f.Bundle, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	statePath := filepath.Join(dir, "state.json")

	v, err := revocation.NewVerifier(f.rootPub(t), nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	cache := revocation.NewCache(statePath)
	var target atomic.Pointer[admission.RevocationList]
	target.Store(admission.NewRevocationList())

	state := &revocationsLoopState{}
	if !refreshRevocationsOnce(context.Background(), "device", v, cache, filePolicySource{path: bundlePath}, state, f.now(t), &target) {
		t.Fatal("refreshRevocationsOnce() failed on the frozen bundle")
	}
	if !state.minAsOf.Equal(f.asOf(t)) {
		t.Errorf("floor = %s, want %s", state.minAsOf, f.asOf(t))
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("verified bundle was not persisted: %v", err)
	}

	restored := revocation.NewCache(statePath)
	gotFloor, gotDoc, ok, err := restored.Load(v, f.now(t))
	if err != nil || !ok {
		t.Fatalf("restart Load() = (%v, ok=%v), want the cached bundle re-verified", err, ok)
	}
	if !gotDoc.AsOf.Equal(f.asOf(t)) || !gotFloor.Equal(f.asOf(t)) {
		t.Errorf("restart restored as_of %s (floor %s), want %s", gotDoc.AsOf, gotFloor, f.asOf(t))
	}

	// A replayed older generation is refused at the persisted floor.
	bundle, err := revocation.ParseBundle(f.Bundle)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if _, err := v.Verify(bundle, f.now(t), f.asOf(t).Add(time.Nanosecond)); err == nil {
		t.Error("a generation strictly below the floor must be refused")
	}
}

// TestRevocationsRefreshRefusesToReplaceWhatIsHeldOnGarbage is the anti-unload
// property (ADR-0017 decision 4): a hostile or broken upstream must not be
// able to un-revoke a serial by serving something that fails to verify. What
// is installed keeps being enforced.
func TestRevocationsRefreshRefusesToReplaceWhatIsHeldOnGarbage(t *testing.T) {
	f := readRevocationsFixture(t)
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"revocations":"AAAA","cert":"AAAA"}`), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	v, err := revocation.NewVerifier(f.rootPub(t), nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	cache := revocation.NewCache(filepath.Join(dir, "state.json"))

	// Pre-install a list carrying a serial a garbage fetch must not remove.
	held := admission.NewRevocationList()
	held.Revoke("held-serial")
	var target atomic.Pointer[admission.RevocationList]
	target.Store(held)

	state := &revocationsLoopState{}
	if refreshRevocationsOnce(context.Background(), "device", v, cache, filePolicySource{path: bundlePath}, state, f.now(t), &target) {
		t.Fatal("a garbage bundle must not report success")
	}
	if !target.Load().Revoked("held-serial") {
		t.Error("a garbage fetch un-revoked a serial that was already installed — the exact failure ADR-0017 exists to close")
	}
}

// TestRevocationsRefreshRefusesToReplaceWhatIsHeldWhenFetchFails is the same
// property for an unreachable source.
func TestRevocationsRefreshRefusesToReplaceWhatIsHeldWhenFetchFails(t *testing.T) {
	f := readRevocationsFixture(t)
	dir := t.TempDir()

	v, err := revocation.NewVerifier(f.rootPub(t), nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	cache := revocation.NewCache(filepath.Join(dir, "state.json"))

	held := admission.NewRevocationList()
	held.Revoke("held-serial")
	var target atomic.Pointer[admission.RevocationList]
	target.Store(held)

	state := &revocationsLoopState{}
	if refreshRevocationsOnce(context.Background(), "device", v, cache, filePolicySource{path: filepath.Join(dir, "does-not-exist.json")}, state, f.now(t), &target) {
		t.Fatal("a failed fetch must not report success")
	}
	if !target.Load().Revoked("held-serial") {
		t.Error("a failed fetch un-revoked a serial that was already installed")
	}
}

// TestRevocationsBackoffIsCappedAndStartsAtTheRefreshCadence mirrors
// TestPolicyBackoffIsCappedAndStartsAtTheRefreshCadence.
func TestRevocationsBackoffIsCappedAndStartsAtTheRefreshCadence(t *testing.T) {
	if got := revocationsBackoffFor(0); got != revocationsRefresh {
		t.Errorf("healthy interval = %s, want the refresh cadence %s", got, revocationsRefresh)
	}
	if got := revocationsBackoffFor(1); got <= revocationsRefresh {
		t.Errorf("interval after one failure = %s, want it to back off past %s", got, revocationsRefresh)
	}
	for _, n := range []int{5, 20, 1000} {
		if got := revocationsBackoffFor(n); got > revocationsBackoffMax {
			t.Errorf("interval after %d failures = %s, want it capped at %s", n, got, revocationsBackoffMax)
		}
	}
}

// TestRevocationsRefreshIntervalMatchesADR0017sPropagationFigure is the
// arithmetic check behind the card's stop-and-return condition: ADR-0017
// decision 3 corrects the worst-case propagation figure to
// "revocation-sync's own interval [60s, unchanged] plus whatever interval the
// coordinator's fetch-and-verify loop uses" and recommends this loop mirror
// policyRefresh SPECIFICALLY because that is what makes the corrected figure
// ~70s. This test is the record that the arithmetic was checked rather than
// assumed: if revocationsRefresh ever drifts from policyRefresh, or if
// revocation-sync's own interval (a bacchus-payment fact this repository
// cannot import and does not re-derive) ever changes, this stops being true
// and is exactly the kind of drift the card's stop condition names.
func TestRevocationsRefreshIntervalMatchesADR0017sPropagationFigure(t *testing.T) {
	if revocationsRefresh != policyRefresh {
		t.Fatalf("revocationsRefresh = %s, want it to equal policyRefresh (%s) — ADR-0017 decision 3's ~70s figure is 60s (revocation-sync, unchanged) + THIS interval, and 10s is what makes that true", revocationsRefresh, policyRefresh)
	}
	const revocationSyncInterval = 60 * time.Second // ADR-0017 decision 3, restated in cmd/coordinator/revocations.go's package comment
	if got, want := revocationSyncInterval+revocationsRefresh, 70*time.Second; got != want {
		t.Fatalf("60s + revocationsRefresh = %s, want %s (ADR-0017 decision 3's corrected worst case)", got, want)
	}
}

// TestRevocationsAdditiveWithNoSourceConfigured is the "Done when" bar
// stated verbatim: a coordinator with no source flags configured behaves
// exactly as today. It exercises startRevocations end to end against two real
// (nil-safe) targets, one per namespace, the shape main() actually builds.
func TestRevocationsAdditiveWithNoSourceConfigured(t *testing.T) {
	var deviceTarget, admissionTarget atomic.Pointer[admission.RevocationList]
	preExisting := admission.NewRevocationList()
	preExisting.Revoke("from-the-plain-file")
	deviceTarget.Store(preExisting)
	admissionTarget.Store(admission.NewRevocationList())

	if err := startRevocations(context.Background(), "",
		revocationsNamespaceConfig{label: "device", target: &deviceTarget},
		revocationsNamespaceConfig{label: "admission", target: &admissionTarget},
	); err != nil {
		t.Fatalf("startRevocations() with no root = %v, want nil", err)
	}
	if !deviceTarget.Load().Revoked("from-the-plain-file") {
		t.Error("the pre-existing plain-file list was disturbed by an unconfigured mechanism")
	}
}
