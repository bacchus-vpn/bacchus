package revocation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// cacheVersion is the on-disk state file's own format version, independent of
// the document's. A file written by a future coordinator is refused rather than
// misread — but see Load, which treats that as "no usable cache" rather than a
// fatal error, because the rollback floor must survive formats it cannot parse
// only as far as it can actually be read.
const cacheVersion = 1

// cacheFile is the on-disk shape, mirroring core/policy.cacheFile with AsOf in
// place of Seq — the two floors play the identical role, just typed
// differently (see doc.go's "Rollback, not a plain-file replacement" section).
type cacheFile struct {
	Version int `json:"version"`

	// MinAsOf is the newest as_of this enforcer has ever accepted for this
	// namespace. It is the rollback floor, and persisting it is the entire
	// reason this file exists: an enforcer that kept the floor only in memory
	// could be rolled back by anyone able to make it restart, using a
	// genuinely signed, correctly delegated bundle from an older generation.
	//
	// It is recorded independently of Bundle and survives a Bundle this
	// process no longer holds. A cache whose bundle was never stored (or
	// cleared) must still not forget how far the ratchet had turned.
	MinAsOf time.Time `json:"min_as_of"`

	// Bundle is the last VERIFIED bundle, verbatim as fetched, so a restart
	// does not begin holding nothing. Absent when nothing has ever been
	// accepted for this namespace.
	Bundle json.RawMessage `json:"bundle,omitempty"`
}

// Cache is an enforcer's persistent state for ONE namespace (device or
// admission — see cmd/coordinator/revocations.go, which holds two): the
// rollback floor it must never forget, and the last verified bundle so a
// restart does not start holding nothing.
//
// # The file is untrusted
//
// Everything read back is re-verified. The bundle is re-checked against the
// root and the current clock exactly as if it had arrived over the network,
// because a file on disk is as untrusted as the network — more so, in that it
// persists.
//
// The one thing that cannot be re-derived is MinAsOf: it is this enforcer's own
// record of how far the ratchet has turned, and nothing in the signed data can
// confirm it. Write access to this file is therefore equivalent to the ability
// to roll this coordinator back to an older, validly-signed generation, which is
// why it is written 0600 and belongs beside the coordinator's other secrets
// rather than in a world-writable spool — the identical property
// core/policy.Cache documents, and the identical deployment responsibility.
type Cache struct{ path string }

// NewCache returns a Cache backed by the state file at path. The file is
// created on the first successful Store; a missing file is a cold start, not an
// error.
func NewCache(path string) *Cache { return &Cache{path: path} }

// Path returns the state file's location, for logging.
func (c *Cache) Path() string { return c.path }

// Load reads the persisted state and re-verifies the cached bundle.
//
// It returns the rollback floor, and the document if — and only if — the
// cached bundle still verifies at now. The two are returned independently on
// purpose:
//
//   - A cache whose bundle no longer verifies (a root rotated, a delegation
//     revoked or expired since it was written) yields (floor, zero Doc,
//     false). The caller then has nothing freshly restored, but it has NOT
//     forgotten its floor, so a replayed older generation is still refused.
//   - A missing or unreadable file yields (zero time, zero Doc, false) with no
//     error. A cold start is not a failure.
//
// err is non-nil only for a file that exists and cannot be understood at all,
// which an operator should see; even then the floor returned is the best value
// recoverable, never a silently-zeroed one.
func (c *Cache) Load(v *Verifier, now time.Time) (minAsOf time.Time, d Doc, ok bool, err error) {
	b, readErr := os.ReadFile(c.path)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			return time.Time{}, Doc{}, false, nil
		}
		return time.Time{}, Doc{}, false, fmt.Errorf("revocation: read cache %s: %w", c.path, readErr)
	}
	var f cacheFile
	if jsonErr := json.Unmarshal(b, &f); jsonErr != nil {
		return time.Time{}, Doc{}, false, fmt.Errorf("revocation: parse cache %s: %w", c.path, jsonErr)
	}
	if f.Version != cacheVersion {
		return f.MinAsOf, Doc{}, false, fmt.Errorf("revocation: cache %s: unsupported state version %d", c.path, f.Version)
	}
	if len(f.Bundle) == 0 {
		// A floor recorded with no bundle: legitimate if nothing has verified yet,
		// or after StoreFloor was used on its own.
		return f.MinAsOf, Doc{}, false, nil
	}
	bundle, parseErr := ParseBundle(f.Bundle)
	if parseErr != nil {
		return f.MinAsOf, Doc{}, false, fmt.Errorf("revocation: cache %s: %w", c.path, parseErr)
	}
	// Re-verified against the CURRENT clock and the CURRENT root, at the floor
	// the same file records — so a cache file edited to carry an older
	// generation is refused by the same rollback check the network path uses.
	loaded, verifyErr := v.Verify(bundle, now, f.MinAsOf)
	if verifyErr != nil {
		return f.MinAsOf, Doc{}, false, fmt.Errorf("revocation: cache %s: %w", c.path, verifyErr)
	}
	return f.MinAsOf, loaded, true, nil
}

// Store records a newly verified bundle and raises the rollback floor to its
// as_of.
//
// The floor only ever RATCHETS: asOf is compared against what is already on
// disk and the later one wins. Re-storing the same generation — which happens
// on every healthy refresh tick, since the enforcer re-fetches the same
// document — is a no-op on the floor rather than an error.
//
// raw is the bundle exactly as fetched. It is written verbatim so the bytes
// that verified are the bytes re-verified on the next load; re-serializing a
// parsed form would put this enforcer's own marshaling between the signature
// and the check.
//
// The write is atomic (temp file, then rename) so a crash mid-write cannot
// leave a truncated state file, which would otherwise lose the floor.
func (c *Cache) Store(raw []byte, asOf time.Time) error {
	prev, _ := c.peek()
	if asOf.Before(prev) {
		asOf = prev
	}
	f := cacheFile{Version: cacheVersion, MinAsOf: asOf, Bundle: append(json.RawMessage(nil), raw...)}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("revocation: marshal cache: %w", err)
	}
	return c.writeAtomic(b)
}

// StoreFloor raises the rollback floor without recording a bundle. It is how an
// enforcer remembers a generation it verified but chose not to cache, and it
// preserves any bundle already on disk.
func (c *Cache) StoreFloor(asOf time.Time) error {
	prev, f := c.peek()
	if asOf.Before(prev) {
		asOf = prev
	}
	f.Version, f.MinAsOf = cacheVersion, asOf
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("revocation: marshal cache: %w", err)
	}
	return c.writeAtomic(b)
}

// peek reads the current state file for its floor, tolerating every failure: a
// missing, unreadable or unparseable file simply reports a zero floor. Callers
// use it only to avoid LOWERING the floor, so failing to read one can never
// raise it.
func (c *Cache) peek() (time.Time, cacheFile) {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return time.Time{}, cacheFile{}
	}
	var f cacheFile
	if err := json.Unmarshal(b, &f); err != nil {
		return time.Time{}, cacheFile{}
	}
	if f.Version != cacheVersion {
		return f.MinAsOf, cacheFile{}
	}
	return f.MinAsOf, f
}

// writeAtomic writes b to c.path via a temporary file in the same directory and
// a rename, so a reader never observes a partial state file. Byte-for-byte the
// same discipline as core/policy.Cache.writeAtomic, core/admission.RevocationList.SaveFile
// and every other atomic writer in this repository.
func (c *Cache) writeAtomic(b []byte) error {
	dir := filepath.Dir(c.path)
	tmp, err := os.CreateTemp(dir, ".revocation-state-*")
	if err != nil {
		return fmt.Errorf("revocation: create temp state in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once the rename has succeeded
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("revocation: chmod temp state: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("revocation: write temp state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("revocation: sync temp state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("revocation: close temp state: %w", err)
	}
	if err := os.Rename(name, c.path); err != nil {
		return fmt.Errorf("revocation: install state %s: %w", c.path, err)
	}
	return nil
}
