package coldstart

import (
	"fmt"
	"os"
	"path/filepath"
)

// writeFileAtomic installs b at path by staging a complete file under
// ".<name>.tmp*" in path's OWN directory, flushing it, and renaming it over the
// target. The live file is never opened for writing, so there is no moment at
// which path holds a partial file (issue #178).
//
// It is the same shape core/admission.RevocationList.SaveFile took for issue
// #168 and core/policy.Cache.writeAtomic has carried since ADR-0043, and it is
// here rather than shared with either of them for a reason given at the bottom.
//
// # Why this package needs it
//
// The secrets file is written by cmd/coldstart-issue, which is
// READ-MODIFY-WRITE: it loads every secret already issued, adds one, and writes
// the whole file back. That inverts the usual stakes of a torn write. Losing an
// update would cost the one secret being added; losing the FILE costs every
// bootstrap secret ever issued, and those are not reconstructible — each is a
// random secret ID and HMAC key that exists in exactly two places, this file and
// a bacchus1: invite that already travelled out of band to a real person
// (docs/design/bootstrap-protocol.md §5). Destroying the server's copy does not
// invalidate those invites in any orderly way; it silently makes every one of
// them unauthenticatable, with no record of what was issued.
//
// The read side is the OPPOSITE polarity from #168's and is the reason this is a
// data-loss card rather than a security one: cmd/coordinator seeds an empty
// store before reloadSecretsLoop's first pass, so an unparseable secrets file
// means nobody can bootstrap. That is fail-closed and noisy, not an admission
// bypass. All of the danger here is on the write side.
//
// And the window is not proportional to the risk. os.WriteFile, which both
// callers used to be, opens the live file with O_TRUNC and refills it; the
// exposure is between the truncate and the bytes landing, and it does not shrink
// as the file grows. A secrets file that gains an entry per issued invite spends
// the same absolute time destroyed-and-not-yet-rewritten on its thousandth write
// as on its first.
//
// # The two mechanics that are load-bearing rather than tidy
//
//   - The temporary file is created IN THE TARGET'S DIRECTORY. os.Rename is
//     atomic only within one filesystem, and a rename across one degrades to
//     copy-then-delete — exactly the half-written file this exists to prevent.
//   - The bytes are flushed BEFORE the rename. A rename that becomes visible
//     ahead of the data it points at is a file the next reader sees as empty,
//     and for the secrets file that reads as "no user may bootstrap".
//
// # Three consequences of replacing the file instead of rewriting it
//
// Named because each is a real change from os.WriteFile rather than an
// implementation detail:
//
//   - The result is mode 0600 every time. os.WriteFile applied its perm only
//     when creating, so an existing file kept whatever mode it had. That only
//     ever narrows, and both files this writes are secret-bearing.
//   - A path that is a SYMLINK is replaced rather than written through.
//   - A writer killed mid-save leaves its staged file behind, which os.WriteFile
//     never did. They are named ".<target>.tmp*" so they sort beside the file
//     they were staged for, are hidden from a plain ls, and can never be
//     mistaken for the file itself.
//
// # What it deliberately does not do
//
// It does not fsync the DIRECTORY, so a machine that loses power immediately
// after the rename can come back holding the previous file. That is a different
// property — whether the rename is durable, not whether the bytes are whole —
// and its failure restores a complete older file rather than a torn one. Every
// atomic writer in this repository stops at the same line (core/policy/cache.go,
// core/admission/verify.go, core/capacity/quota.go, core/devicestore/store.go,
// core/selection/store.go, cmd/bacchus-netd/dns.go); moving it is a repo-wide
// change rather than this function's.
//
// It does not create parent directories, which keeps both callers behaving
// exactly as their os.WriteFile did: a missing secrets/ directory is still an
// error rather than something a mint quietly conjures.
//
// It does not serialise two writers. Atomicity is a promise to a READER — every
// read lands on a whole file — and it says nothing about two read-modify-write
// issuers racing, where the loser's secret is dropped from a file that is
// perfectly well-formed. That is cmd/coldstart-issue's lock, not this.
//
// # Why package-local
//
// This is the third copy of the shape in the repository and the argument for
// folding all of them into one helper is real, but it is not this card's to
// make: the two existing copies are correct, guarded by their own tests, and
// live in packages this lane does not own, so consolidating means editing
// passing code in three places to no behavioural end. A helper shared by the two
// writers IN THIS PACKAGE is the granularity that pays for itself here. Issue
// #188 holds the repo-wide question.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("stage in %s: %w", dir, err)
	}
	staged := tmp.Name()
	// Removed on every path that does not rename it away, so a failure leaves
	// the live file untouched AND nothing beside it for the next operator to
	// wonder about. A no-op once the rename has succeeded.
	defer func() { _ = os.Remove(staged) }()
	if err := writeStaged(tmp, b); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", staged, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", staged, err)
	}
	if err := os.Rename(staged, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// writeStaged fills a staged file and flushes it to stable storage, so
// everything that can fail has failed before anything is renamed over the file
// somebody else is reading.
func writeStaged(f *os.File, b []byte) error {
	// 0600 explicitly rather than whatever os.CreateTemp's mode survived the
	// umask. This replaces files the previous os.WriteFile named 0600, and the
	// secrets file is staged in the coordinator's secrets directory beside its
	// signing keys.
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}
