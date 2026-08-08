package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bacchus-vpn/bacchus/core/atomicfile"
)

// cacheVersion is the on-disk state file's own format version, independent of the
// policy document's. A file written by a future coordinator is refused rather than
// misread — but see Load, which treats that as "no usable cache" rather than a
// fatal error, because the sequence floor must survive formats it cannot parse
// only as far as it can actually be read.
const cacheVersion = 1

// cacheFile is the on-disk shape.
//
// The bundle is stored as the raw fetched JSON, not as a parsed Policy. Caching
// the PARSED struct would mean trusting a local file to have been verified at some
// point in the past by some earlier build, which is exactly the assumption an
// attacker with write access wants a verifier to make. The bytes are re-verified on
// every load, against the current clock and the current root, so a cache entry that
// has since expired or whose delegation has since been revoked is refused on the
// way back in.
type cacheFile struct {
	Version int `json:"version"`

	// MinSeq is the highest policy sequence this enforcer has ever accepted. It is
	// the rollback floor, and persisting it is the entire reason this file exists:
	// an enforcer that kept the floor only in memory could be rolled back by anyone
	// able to make it restart, using a genuinely signed, correctly delegated,
	// unexpired document from an older generation.
	//
	// It is recorded independently of Bundle and survives a Bundle that no longer
	// verifies. A cache whose bundle has expired must still not forget how far the
	// ratchet had turned.
	MinSeq uint64 `json:"min_seq"`

	// Bundle is the last VERIFIED bundle, verbatim as fetched, so a restart does not
	// begin unpoliced. Absent when nothing has been accepted yet.
	Bundle json.RawMessage `json:"bundle,omitempty"`
}

// Cache is an enforcer's persistent policy state: the rollback floor it must never
// forget, and the last verified bundle so a restart does not start unpoliced.
//
// # The file is untrusted
//
// Everything read back is re-verified. The bundle is re-checked against the root
// and the current clock exactly as if it had arrived over the network, because a
// file on disk is as untrusted as the network — more so, in that it persists.
//
// The one thing that cannot be re-derived is MinSeq: it is this enforcer's own
// record of how far the ratchet has turned, and nothing in the signed data can
// confirm it. Write access to this file is therefore equivalent to the ability to
// roll this coordinator back one generation, which is why it is written 0600 and
// belongs beside the coordinator's other secrets rather than in a world-writable
// spool. That is a deployment property, recorded in docs/adr/0043, not something
// this code can enforce.
type Cache struct{ path string }

// NewCache returns a Cache backed by the state file at path. The file is created
// on the first successful Store; a missing file is a cold start, not an error.
func NewCache(path string) *Cache { return &Cache{path: path} }

// Path returns the state file's location, for logging.
func (c *Cache) Path() string { return c.path }

// Load reads the persisted state and re-verifies the cached bundle.
//
// It returns the rollback floor, and the policy if — and only if — the cached
// bundle still verifies at now. The two are returned independently on purpose:
//
//   - A cache whose bundle has expired, or whose delegation has been revoked since
//     it was written, yields (floor, zero Policy, false). The coordinator is then
//     unpoliced and must fail closed, but it has NOT forgotten its floor, so a
//     replayed older generation is still refused.
//   - A missing or unreadable file yields (0, zero Policy, false) with no error.
//     A cold start is not a failure.
//
// err is non-nil only for a file that exists and cannot be understood at all,
// which an operator should see; even then the floor returned is the best value
// recoverable, never a silent zero.
func (c *Cache) Load(v *Verifier, now time.Time) (minSeq uint64, p Policy, ok bool, err error) {
	b, readErr := os.ReadFile(c.path)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			return 0, Policy{}, false, nil
		}
		return 0, Policy{}, false, fmt.Errorf("policy: read cache %s: %w", c.path, readErr)
	}
	var f cacheFile
	if jsonErr := json.Unmarshal(b, &f); jsonErr != nil {
		return 0, Policy{}, false, fmt.Errorf("policy: parse cache %s: %w", c.path, jsonErr)
	}
	if f.Version != cacheVersion {
		return f.MinSeq, Policy{}, false, fmt.Errorf("policy: cache %s: unsupported state version %d", c.path, f.Version)
	}
	if len(f.Bundle) == 0 {
		// A floor recorded with no bundle: legitimate after the held policy aged out.
		return f.MinSeq, Policy{}, false, nil
	}
	bundle, parseErr := ParseBundle(f.Bundle)
	if parseErr != nil {
		return f.MinSeq, Policy{}, false, fmt.Errorf("policy: cache %s: %w", c.path, parseErr)
	}
	// Re-verified against the CURRENT clock and the CURRENT root, at the floor the
	// same file records — so a cache file edited to carry an older generation is
	// refused by the same rollback check the network path uses.
	loaded, verifyErr := v.Verify(bundle, now, f.MinSeq)
	if verifyErr != nil {
		return f.MinSeq, Policy{}, false, fmt.Errorf("policy: cache %s: %w", c.path, verifyErr)
	}
	return f.MinSeq, loaded, true, nil
}

// Store records a newly verified bundle and raises the rollback floor to its
// sequence.
//
// The floor only ever RATCHETS: seq is compared against what is already on disk and
// the higher wins. Re-storing the same generation — which happens on every refresh,
// since the enforcer re-fetches the same document — is a no-op on the floor rather
// than an error.
//
// raw is the bundle exactly as fetched. It is written verbatim so the bytes that
// verified are the bytes re-verified on the next load; re-serializing a parsed form
// would put this enforcer's own marshaling between the signature and the check.
//
// The write is atomic (a complete file renamed over the target) so a crash
// mid-write cannot leave a truncated state file, which would otherwise lose the
// floor. Whether the RENAME itself is made durable depends on whether this write
// raises the floor — see writeAtomic.
func (c *Cache) Store(raw []byte, seq uint64) error {
	prev, _ := c.peek()
	raises := seq > prev
	if seq < prev {
		seq = prev
	}
	f := cacheFile{Version: cacheVersion, MinSeq: seq, Bundle: append(json.RawMessage(nil), raw...)}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("policy: marshal cache: %w", err)
	}
	return c.writeAtomic(b, raises)
}

// StoreFloor raises the rollback floor without recording a bundle. It is how an
// enforcer remembers a generation it verified but chose not to cache, and it
// preserves any bundle already on disk.
func (c *Cache) StoreFloor(seq uint64) error {
	prev, f := c.peek()
	raises := seq > prev
	if seq < prev {
		seq = prev
	}
	f.Version, f.MinSeq = cacheVersion, seq
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("policy: marshal cache: %w", err)
	}
	return c.writeAtomic(b, raises)
}

// peek reads the current state file for its floor, tolerating every failure: a
// missing, unreadable or unparseable file simply reports a zero floor. Callers use
// it only to avoid LOWERING the floor, so failing to read one can never raise it.
func (c *Cache) peek() (uint64, cacheFile) {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return 0, cacheFile{}
	}
	var f cacheFile
	if err := json.Unmarshal(b, &f); err != nil {
		return 0, cacheFile{}
	}
	if f.Version != cacheVersion {
		return f.MinSeq, cacheFile{}
	}
	return f.MinSeq, f
}

// writeAtomic installs b at c.path through core/atomicfile: a complete file is
// staged in the same directory, flushed and renamed over the target, so a reader
// never observes a partial state file. 0600, because write access to this file
// is write access to this coordinator's rollback floor.
//
// # Why raising the floor is written durably and re-recording it is not
//
// A file's own flush makes the BYTES durable. It says nothing about the
// directory entry, so a power loss immediately after the rename can come back
// holding the previous file. Issue #188 ruled that boundary per WRITE rather
// than per file, and this is the caller the distinction was invented for.
//
// cmd/coordinator calls Store on EVERY successful refresh — policyRefresh is 10
// seconds — and almost all of those re-record a floor that has not moved. Losing
// one of those renames costs nothing: the file reverts to a state this
// coordinator was legitimately in ten seconds ago, floor and bundle together,
// and the next refresh re-records it. Paying a directory fsync 8,640 times a day
// to protect a write that repairs itself is not a trade worth making.
//
// A write that RAISES the floor is the opposite. That one is not re-emitted: it
// records that this enforcer has seen a generation, and nothing regenerates that
// knowledge except another honest fetch of the same document. Lose it, and an
// attacker who controls the fetch can serve the previous generation — genuinely
// signed, correctly delegated, unexpired — and the ratchet has forgotten why it
// should refuse. So a floor raise takes the directory fsync, and it is cheap
// exactly because it is rare: once per published generation, not once per
// refresh.
func (c *Cache) writeAtomic(b []byte, raisesFloor bool) error {
	install := atomicfile.Write
	if raisesFloor {
		install = atomicfile.WriteDurable
	}
	if err := install(c.path, b, 0o600); err != nil {
		return fmt.Errorf("policy: persist state: %w", err)
	}
	return nil
}
