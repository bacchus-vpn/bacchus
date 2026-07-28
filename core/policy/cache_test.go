package policy_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/policy"
)

// frozenBundle returns the positive fixture's raw bundle bytes, its root key, and
// the instant it is live at. The cache tests reuse the frozen bundle rather than
// minting one, so what they persist and re-verify is the same object the
// conformance suite accepts.
func frozenBundle(t *testing.T) (raw []byte, rootPub []byte, now time.Time, seq uint64) {
	t.Helper()
	var pv posVectors
	readJSON(t, positiveVectors, &pv)
	return pv.Bundle, unb64(t, pv.RootPub), mustTime(t, pv.Now), pv.ExpectSeq
}

func newCache(t *testing.T) (*policy.Cache, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy-state.json")
	return policy.NewCache(path), path
}

// TestCacheColdStartIsNotAnError pins that a missing state file is a cold start
// rather than a failure: a coordinator starting for the first time has no floor and
// no cached policy, and that is the expected state, not a broken one.
func TestCacheColdStartIsNotAnError(t *testing.T) {
	_, rootPub, now, _ := frozenBundle(t)
	c, _ := newCache(t)
	v, err := policy.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	minSeq, p, ok, err := c.Load(v, now)
	if err != nil {
		t.Fatalf("Load() on a cold start = %v, want no error", err)
	}
	if ok {
		t.Errorf("Load() reported a cached policy (seq %d) on a cold start", p.Seq)
	}
	if minSeq != 0 {
		t.Errorf("cold-start floor = %d, want 0", minSeq)
	}
}

// TestCacheRoundTripReVerifies is the basic property: what was stored comes back,
// and it comes back because it VERIFIED again, not because it was trusted.
func TestCacheRoundTripReVerifies(t *testing.T) {
	raw, rootPub, now, seq := frozenBundle(t)
	c, path := newCache(t)
	v, err := policy.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, seq); err != nil {
		t.Fatalf("Store: %v", err)
	}
	minSeq, p, ok, err := c.Load(v, now)
	if err != nil || !ok {
		t.Fatalf("Load() = (%v, ok=%v), want a verified policy", err, ok)
	}
	if p.Seq != seq {
		t.Errorf("cached Seq = %d, want %d", p.Seq, seq)
	}
	if minSeq != seq {
		t.Errorf("floor = %d, want %d", minSeq, seq)
	}

	// The state file must not be world-readable: whoever can write it can lower this
	// coordinator's rollback floor.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat state: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("state file mode = %04o, want no group/other access", perm)
	}
}

// TestCacheStoresBytesNotAParsedStruct is the reason the cache holds the bundle
// verbatim. The bytes that verified must be the bytes re-verified; re-serializing a
// parsed form would put this enforcer's own marshaling between the signature and
// the check, and a signature is over bytes as received.
func TestCacheStoresBytesNotAParsedStruct(t *testing.T) {
	raw, _, _, seq := frozenBundle(t)
	c, path := newCache(t)

	if err := c.Store(raw, seq); err != nil {
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
	// The signed halves must survive byte-for-byte, which is what re-verification
	// depends on.
	stored, err := policy.ParseBundle(f.Bundle)
	if err != nil {
		t.Fatalf("stored bundle no longer parses: %v", err)
	}
	orig, err := policy.ParseBundle(raw)
	if err != nil {
		t.Fatalf("original bundle: %v", err)
	}
	if string(stored.Doc) != string(orig.Doc) || string(stored.Cert) != string(orig.Cert) {
		t.Error("cached bundle's signed bytes differ from what was stored")
	}
}

// TestCacheRefusesAnExpiredEntryButKeepsTheFloor is the case that makes the split
// return worth having.
//
// A coordinator restarting after its held policy aged out is unpoliced and must
// fail closed — but it must NOT have forgotten how far the ratchet had turned, or a
// restart becomes the rollback. Loading reports no policy AND a live floor.
func TestCacheRefusesAnExpiredEntryButKeepsTheFloor(t *testing.T) {
	raw, rootPub, now, seq := frozenBundle(t)
	c, _ := newCache(t)
	v, err := policy.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, seq); err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Well past exp + grace.
	late := now.Add(400 * 24 * time.Hour)
	minSeq, _, ok, err := c.Load(v, late)
	if ok {
		t.Fatal("Load() returned a policy that is past its deadline")
	}
	if err == nil {
		t.Error("Load() past the deadline reported no error; an operator should see why the cache was refused")
	}
	if minSeq != seq {
		t.Errorf("floor after refusing a stale cache = %d, want %d — a restart must not forget the ratchet", minSeq, seq)
	}
}

// TestCacheReVerifiesAgainstTheCurrentRoot pins that the file is untrusted. A cache
// written under one root must not load under another, which is what makes "the file
// on disk is as untrusted as the network" true rather than aspirational.
func TestCacheReVerifiesAgainstTheCurrentRoot(t *testing.T) {
	raw, _, now, seq := frozenBundle(t)
	c, _ := newCache(t)

	// A verifier holding some other root entirely.
	foreign := make([]byte, 32)
	for i := range foreign {
		foreign[i] = byte(i + 1)
	}
	v, err := policy.NewVerifier(foreign, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, seq); err != nil {
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

// TestCacheReVerifiesAgainstARevokedDelegation covers the other way a cache entry
// goes bad while sitting on disk: the delegation that authorized it was revoked
// after it was written. Re-verification must notice, which it only does because the
// delegation is re-checked on every load rather than cached as "already valid".
func TestCacheReVerifiesAgainstARevokedDelegation(t *testing.T) {
	raw, rootPub, now, seq := frozenBundle(t)
	var pv posVectors
	readJSON(t, positiveVectors, &pv)

	c, _ := newCache(t)
	if err := c.Store(raw, seq); err != nil {
		t.Fatalf("Store: %v", err)
	}

	revoked := func(serial string) bool { return serial == pv.ExpectDelegationSerial }
	v, err := policy.NewVerifier(rootPub, revoked)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	minSeq, _, ok, err := c.Load(v, now)
	if ok {
		t.Fatal("Load() accepted a cached bundle whose delegation is revoked")
	}
	if err == nil {
		t.Error("Load() reported no error for a revoked delegation")
	}
	if minSeq != seq {
		t.Errorf("floor = %d, want %d", minSeq, seq)
	}
}

// TestCacheFloorOnlyRatchets is the rollback protection at the persistence layer.
// Storing an older generation must not lower the floor, because the floor is the
// only thing standing between a restart and a replayed older policy.
func TestCacheFloorOnlyRatchets(t *testing.T) {
	raw, rootPub, now, seq := frozenBundle(t)
	c, _ := newCache(t)
	v, err := policy.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, seq); err != nil {
		t.Fatalf("Store: %v", err)
	}
	// An attempt to record a lower generation.
	if err := c.Store(raw, seq-10); err != nil {
		t.Fatalf("Store(lower): %v", err)
	}
	minSeq, _, _, err := c.Load(v, now)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if minSeq != seq {
		t.Errorf("floor after storing a lower seq = %d, want it held at %d", minSeq, seq)
	}

	// And StoreFloor has the same ratchet.
	if err := c.StoreFloor(1); err != nil {
		t.Fatalf("StoreFloor: %v", err)
	}
	got, _, _, err := c.Load(v, now)
	if err != nil {
		t.Fatalf("Load after StoreFloor: %v", err)
	}
	if got != seq {
		t.Errorf("floor after StoreFloor(1) = %d, want it held at %d", got, seq)
	}
}

// TestCacheReAcceptingTheSameSeqSucceeds pins the requirement that re-accepting the
// SAME generation works. An enforcer re-fetches the same document on every refresh,
// so a floor implemented as "strictly greater" would refuse the policy it is
// currently enforcing on the very next tick.
func TestCacheReAcceptingTheSameSeqSucceeds(t *testing.T) {
	raw, rootPub, now, seq := frozenBundle(t)
	c, _ := newCache(t)
	v, err := policy.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, seq); err != nil {
		t.Fatalf("Store: %v", err)
	}
	minSeq, _, ok, err := c.Load(v, now)
	if err != nil || !ok {
		t.Fatalf("first Load = (%v, ok=%v)", err, ok)
	}
	// The refresh path: same bundle, at the floor it just set.
	bundle, err := policy.ParseBundle(raw)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	if _, err := v.Verify(bundle, now, minSeq); err != nil {
		t.Fatalf("re-accepting the same seq at its own floor = %v, want accept", err)
	}
}

// TestCacheStoreFloorPreservesTheBundle covers recording a floor without disturbing
// a cached bundle, so a coordinator that ratchets its floor does not blank its own
// restart cache as a side effect.
func TestCacheStoreFloorPreservesTheBundle(t *testing.T) {
	raw, rootPub, now, seq := frozenBundle(t)
	c, _ := newCache(t)
	v, err := policy.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}

	if err := c.Store(raw, seq); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := c.StoreFloor(seq); err != nil {
		t.Fatalf("StoreFloor: %v", err)
	}
	_, p, ok, err := c.Load(v, now)
	if err != nil || !ok {
		t.Fatalf("Load after StoreFloor = (%v, ok=%v), want the bundle still cached", err, ok)
	}
	if p.Seq != seq {
		t.Errorf("Seq = %d, want %d", p.Seq, seq)
	}
}

// TestCacheRejectsAGarbageFile covers an unreadable state file: it must be a loud
// error rather than a silent cold start, because silently forgetting the floor is
// how a rollback gets in.
func TestCacheRejectsAGarbageFile(t *testing.T) {
	_, rootPub, now, _ := frozenBundle(t)
	c, path := newCache(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	v, err := policy.NewVerifier(rootPub, nil)
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

// TestCacheStoreIsAtomic pins that a state file is never observed truncated. The
// floor is the one value that cannot be re-derived from signed data, so a partial
// write that lost it would be a silent rollback window.
func TestCacheStoreIsAtomic(t *testing.T) {
	raw, _, _, seq := frozenBundle(t)
	c, path := newCache(t)

	if err := c.Store(raw, seq); err != nil {
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
