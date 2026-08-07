package revocation_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/revocation"
)

// frozenBundle returns the positive fixture's raw bundle bytes, its root key,
// the instant it is live at, and the AsOf it carries. The cache tests reuse the
// frozen bundle rather than minting one, so what they persist and re-verify is
// the same object the conformance suite accepts.
func frozenBundle(t *testing.T) (raw []byte, rootPub []byte, now time.Time, asOf time.Time) {
	t.Helper()
	var pv posVectors
	readJSON(t, positiveVectors, &pv)
	return pv.Bundle, unb64(t, pv.RootPub), mustTime(t, pv.Now), mustTime(t, pv.ExpectAsOf)
}

func newCache(t *testing.T) (*revocation.Cache, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revocation-state.json")
	return revocation.NewCache(path), path
}

// TestCacheColdStartIsNotAnError pins that a missing state file is a cold start
// rather than a failure: a coordinator starting for the first time has no floor
// and no cached bundle, and that is the expected state, not a broken one.
func TestCacheColdStartIsNotAnError(t *testing.T) {
	_, rootPub, now, _ := frozenBundle(t)
	c, _ := newCache(t)
	v, err := revocation.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	minAsOf, d, ok, err := c.Load(v, now)
	if err != nil {
		t.Fatalf("Load() on a cold start = %v, want no error", err)
	}
	if ok {
		t.Errorf("Load() reported a cached document (as_of %s) on a cold start", d.AsOf)
	}
	if !minAsOf.IsZero() {
		t.Errorf("cold-start floor = %s, want the zero time", minAsOf)
	}
}

// TestCacheRoundTripReVerifies is the basic property: what was stored comes
// back, and it comes back because it VERIFIED again, not because it was
// trusted.
func TestCacheRoundTripReVerifies(t *testing.T) {
	raw, rootPub, now, asOf := frozenBundle(t)
	c, path := newCache(t)
	v, err := revocation.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, asOf); err != nil {
		t.Fatalf("Store: %v", err)
	}
	minAsOf, d, ok, err := c.Load(v, now)
	if err != nil || !ok {
		t.Fatalf("Load() = (%v, ok=%v), want a verified document", err, ok)
	}
	if !d.AsOf.Equal(asOf) {
		t.Errorf("cached AsOf = %s, want %s", d.AsOf, asOf)
	}
	if !minAsOf.Equal(asOf) {
		t.Errorf("floor = %s, want %s", minAsOf, asOf)
	}

	// The state file must not be world-readable: whoever can write it can lower
	// this coordinator's rollback floor.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("state file mode = %04o, want no group/other access", perm)
	}
}

// TestCacheStoresBytesNotAParsedStruct is the reason the cache holds the
// bundle verbatim. The bytes that verified must be the bytes re-verified;
// re-serializing a parsed form would put this enforcer's own marshaling
// between the signature and the check, and a signature is over bytes as
// received.
func TestCacheStoresBytesNotAParsedStruct(t *testing.T) {
	raw, _, _, asOf := frozenBundle(t)
	c, path := newCache(t)

	if err := c.Store(raw, asOf); err != nil {
		t.Fatalf("Store: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var f struct {
		Bundle json.RawMessage `json:"bundle"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	// The signed halves must survive byte-for-byte, which is what
	// re-verification depends on.
	stored, err := revocation.ParseBundle(f.Bundle)
	if err != nil {
		t.Fatalf("stored bundle no longer parses: %v", err)
	}
	orig, err := revocation.ParseBundle(raw)
	if err != nil {
		t.Fatalf("original bundle: %v", err)
	}
	if string(stored.Revocations) != string(orig.Revocations) || string(stored.Cert) != string(orig.Cert) {
		t.Error("cached bundle's signed bytes differ from what was stored")
	}
}

// TestCacheRefusesADelegationPastItsWindowButKeepsTheFloor is the case that
// makes the split return worth having.
//
// A revocations document carries no window of its own (doc.go) — the only
// window in this whole object is the DELEGATION's, so that is what a cache
// entry can age out of. A coordinator restarting after that has happened must
// come back holding NOTHING freshly restored — but it must NOT have forgotten
// how far the ratchet had turned, or a restart becomes the rollback. Loading
// reports no document AND a live floor.
func TestCacheRefusesADelegationPastItsWindowButKeepsTheFloor(t *testing.T) {
	raw, rootPub, now, asOf := frozenBundle(t)
	c, _ := newCache(t)
	v, err := revocation.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, asOf); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Well past the frozen delegation cert's own NotAfter (365 days out from the
	// fixture's `now`).
	late := now.Add(400 * 24 * time.Hour)
	minAsOf, _, ok, err := c.Load(v, late)
	if ok {
		t.Fatal("Load() returned a document under a delegation past its window")
	}
	if err == nil {
		t.Error("Load() past the delegation's window reported no error; an operator should see why the cache was refused")
	}
	if !minAsOf.Equal(asOf) {
		t.Errorf("floor after refusing a stale cache = %s, want %s — a restart must not forget the ratchet", minAsOf, asOf)
	}
}

// TestCacheReVerifiesAgainstTheCurrentRoot pins that the file is untrusted. A
// cache written under one root must not load under another, which is what
// makes "the file on disk is as untrusted as the network" true rather than
// aspirational.
func TestCacheReVerifiesAgainstTheCurrentRoot(t *testing.T) {
	raw, _, now, asOf := frozenBundle(t)
	c, _ := newCache(t)

	// A verifier holding some other root entirely.
	foreign := make([]byte, 32)
	for i := range foreign {
		foreign[i] = byte(i + 1)
	}
	v, err := revocation.NewVerifier(foreign, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, asOf); err != nil {
		t.Fatalf("Store: %v", err)
	}
	_, _, ok, err := c.Load(v, now)
	if ok {
		t.Fatal("Load() accepted a cached bundle that does not chain to the configured root")
	}
	if err == nil {
		t.Error("Load() reported no error for a bundle under a foreign root")
	}
}

// TestCacheReVerifiesAgainstARevokedDelegation covers the other way a cache
// entry goes bad while sitting on disk: the delegation that authorized it was
// revoked after it was written. Re-verification must notice, which it only
// does because the delegation is re-checked on every load rather than cached
// as "already valid".
func TestCacheReVerifiesAgainstARevokedDelegation(t *testing.T) {
	raw, rootPub, now, asOf := frozenBundle(t)
	var pv posVectors
	readJSON(t, positiveVectors, &pv)

	c, _ := newCache(t)
	if err := c.Store(raw, asOf); err != nil {
		t.Fatalf("Store: %v", err)
	}

	revoked := func(serial string) bool { return serial == pv.ExpectDelegationSerial }
	v, err := revocation.NewVerifier(rootPub, revoked)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	minAsOf, _, ok, err := c.Load(v, now)
	if ok {
		t.Fatal("Load() accepted a cached bundle whose delegation is revoked")
	}
	if err == nil {
		t.Error("Load() reported no error for a revoked delegation")
	}
	if !minAsOf.Equal(asOf) {
		t.Errorf("floor = %s, want %s", minAsOf, asOf)
	}
}

// TestCacheFloorOnlyRatchets is the rollback protection at the persistence
// layer. Storing an older generation must not lower the floor, because the
// floor is the only thing standing between a restart and a replayed older
// bundle.
func TestCacheFloorOnlyRatchets(t *testing.T) {
	raw, rootPub, now, asOf := frozenBundle(t)
	c, _ := newCache(t)
	v, err := revocation.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, asOf); err != nil {
		t.Fatalf("Store: %v", err)
	}
	// An attempt to record an older generation.
	if err := c.Store(raw, asOf.Add(-10*time.Hour)); err != nil {
		t.Fatalf("Store(older): %v", err)
	}
	minAsOf, _, _, err := c.Load(v, now)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !minAsOf.Equal(asOf) {
		t.Errorf("floor after storing an older as_of = %s, want it held at %s", minAsOf, asOf)
	}

	// And StoreFloor has the same ratchet.
	if err := c.StoreFloor(asOf.Add(-24 * time.Hour)); err != nil {
		t.Fatalf("StoreFloor: %v", err)
	}
	got, _, _, err := c.Load(v, now)
	if err != nil {
		t.Fatalf("Load after StoreFloor: %v", err)
	}
	if !got.Equal(asOf) {
		t.Errorf("floor after StoreFloor(older) = %s, want it held at %s", got, asOf)
	}
}

// TestCacheReAcceptingTheSameAsOfSucceeds pins the requirement that
// re-accepting the SAME generation works. An enforcer re-fetches the same
// document on every refresh, so a floor implemented as "strictly after" would
// refuse the bundle it is currently enforcing on the very next tick.
func TestCacheReAcceptingTheSameAsOfSucceeds(t *testing.T) {
	raw, rootPub, now, asOf := frozenBundle(t)
	c, _ := newCache(t)
	v, err := revocation.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, asOf); err != nil {
		t.Fatalf("Store: %v", err)
	}
	minAsOf, _, ok, err := c.Load(v, now)
	if err != nil || !ok {
		t.Fatalf("first Load = (%v, ok=%v)", err, ok)
	}
	// The refresh path: same bundle, at the floor it just set.
	bundle, err := revocation.ParseBundle(raw)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if _, err := v.Verify(bundle, now, minAsOf); err != nil {
		t.Fatalf("re-accepting the same as_of at its own floor = %v, want accept", err)
	}
}

// TestCacheStoreFloorPreservesTheBundle covers recording a floor without
// disturbing a cached bundle, so a coordinator that ratchets its floor does
// not blank its own restart cache as a side effect.
func TestCacheStoreFloorPreservesTheBundle(t *testing.T) {
	raw, rootPub, now, asOf := frozenBundle(t)
	c, _ := newCache(t)
	v, err := revocation.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, asOf); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := c.StoreFloor(asOf); err != nil {
		t.Fatalf("StoreFloor: %v", err)
	}
	_, d, ok, err := c.Load(v, now)
	if err != nil || !ok {
		t.Fatalf("Load after StoreFloor = (%v, ok=%v), want the bundle still cached", err, ok)
	}
	if !d.AsOf.Equal(asOf) {
		t.Errorf("AsOf = %s, want %s", d.AsOf, asOf)
	}
}

// TestCacheRejectsAGarbageFile covers an unreadable state file: it must be a
// loud error rather than a silent cold start, because silently forgetting the
// floor is how a rollback gets in.
func TestCacheRejectsAGarbageFile(t *testing.T) {
	_, rootPub, now, _ := frozenBundle(t)
	c, path := newCache(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	v, err := revocation.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	_, _, ok, err := c.Load(v, now)
	if ok {
		t.Fatal("Load() accepted a garbage state file")
	}
	if err == nil {
		t.Error("Load() on a garbage state file reported no error")
	}
}

// TestCacheStoreIsAtomic pins that a state file is never observed truncated.
// The floor is the one value that cannot be re-derived from signed data, so a
// partial write that lost it would be a silent rollback window.
func TestCacheStoreIsAtomic(t *testing.T) {
	raw, _, _, asOf := frozenBundle(t)
	c, path := newCache(t)

	if err := c.Store(raw, asOf); err != nil {
		t.Fatalf("Store: %v", err)
	}
	// No temp files left behind in the directory.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("stray file left in the state directory: %s", e.Name())
		}
	}
}
