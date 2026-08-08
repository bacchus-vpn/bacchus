package update

import (
	"fmt"
	"io/fs"

	"github.com/bacchus-vpn/bacchus/core/atomicfile"
)

// This file used to hold this package's own copy of the atomic-write shape —
// temp file in the SAME directory as the target, chmod, write, Sync, close,
// rename — written here because the wave that built the release channel could
// not edit the packages the consolidation was landing in. It was the tenth copy,
// created in the same wave that folded the other nine into core/atomicfile.
//
// All three functions below are now that package, and everything they promise is
// documented there. They are kept as named functions rather than inlined at the
// call sites so this package's callers keep their "update: " error prefix, which
// ADR-0066 §2 keeps at the caller rather than absorbing into the writer.
//
// # The two write forms, and why this package needs both
//
// ADR-0066 §5 decides the directory-fsync boundary per WRITE and not per file:
// take it when the write records something nothing will re-emit, skip it when a
// later ordinary write re-establishes the same state. This package's writes fall
// on both sides of that line, which is the same shape core/policy has and the
// reason the rule is stated per write at all. writeAtomic is the skipping form
// and writeAtomicDurable the taking one; each names at its own doc which of this
// package's writes it is for, and every call site says which one it took.
//
// # What this package still does NOT route through core/atomicfile, and why
//
// Stage's download (apply.go) stages, flushes and renames an artifact by exactly
// the same discipline, and it is deliberately not this. core/atomicfile.Write
// takes the complete contents as a []byte; a release artifact is tens of
// megabytes arriving from a network source, streamed through io.Copy into the
// staging file under a size limit taken from the signed manifest, and re-read
// from disk afterwards to hash the bytes AS WRITTEN. Buffering it to hand a
// slice to a helper would defeat both the limit and the re-read, and
// core/atomicfile has no streaming form to offer instead. That is a shape
// difference rather than a duplicated one.

// writeAtomic installs b at path with mode mode, replacing whatever is there
// rather than rewriting it: a complete file is staged in path's OWN directory,
// flushed, and renamed over the target, so a reader never observes a partial
// file. Same directory, not merely the same filesystem, so the final rename(2)
// cannot cross a mount boundary.
//
// The bytes are made durable and the RENAME is not — ADR-0066 §5's skipping
// side. It is the form for the writes in this package that a later ordinary
// write re-establishes:
//
//   - State.write RE-RECORDING a floor that has not moved, which is what almost
//     every check does. The next check writes the same MinSeq again, so a lost
//     rename costs one generation of a file this peer was legitimately holding a
//     moment ago and repairs itself unprompted. That is core/policy's argument
//     unchanged, down to the field name it is about.
//   - ClearPending. A lost rename restores a Pending record naming a staged file
//     Apply has already renamed onto the target, so the next check re-verifies a
//     path that is gone, forgets it and re-downloads — a wasted download, not a
//     wrong decision. AppliedRelease is informational by its own doc: what
//     decides whether an update is needed is the running build's version.
func writeAtomic(path string, b []byte, mode fs.FileMode) error {
	if err := atomicfile.Write(path, b, mode); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	return nil
}

// writeAtomicDurable is writeAtomic plus the directory fsync: the bytes are
// durable AND the rename that installed them is, so a machine that loses power
// the instant after this returns comes back holding the new file rather than
// possibly the old one.
//
// It is ADR-0066 §5's taking side, and issue #229 is the card that applied the
// rule to this package's two writes that qualify:
//
//   - A floor RAISE (State.RaiseFloor and SetPending when the seq moves).
//     MinSeq is the only value in this package that cannot be re-derived from
//     signed data — nothing re-emits "this peer has seen generation N" except
//     another honest fetch of the same manifest. Lose the raise and a peer can
//     be walked back onto a burned release by anyone who controls the source,
//     using a genuinely signed, correctly delegated, unexpired manifest from an
//     older generation, which is the attack ADR-0052 §7 named the floor for. It
//     is cheap exactly because it is rare: once per published release, not once
//     per check.
//   - The confirmation MARKER (writeMarker). Nothing re-emits a marker: it is
//     written once per apply, before anything moves, and it is the only record
//     that an apply is on probation. Lose it and the demotion never happens —
//     ADR-0052 §7's worst-of-three failure, where a crash loop is at a glance
//     indistinguishable from a healthy restart. Apply does syncDir the same
//     directory a few operations later on the path that SUCCEEDS, so the window
//     is between the marker and that sync; the window on the path that fails,
//     and the whole of CheckStartup's claim write, are not covered by it at all.
//
// A SyncDir failure is REPORTED even though the file itself is already installed
// — core/atomicfile.WriteDurable's own posture, and the opposite of syncDir
// below. The difference is what the caller can still do about it: syncDir's
// callers run AFTER a rename that has already published a binary, where
// unwinding a successful publish would be worse than the lost fsync. Both of the
// writes above run BEFORE anything moves, so reporting costs one skipped update
// and leaves the decision with the caller.
func writeAtomicDurable(path string, b []byte, mode fs.FileMode) error {
	if err := atomicfile.WriteDurable(path, b, mode); err != nil {
		return fmt.Errorf("update: %w", err)
	}
	return nil
}

// syncDir fsyncs a directory so a rename into it survives a power loss. Renaming
// is atomic with respect to a concurrent reader whether or not this runs; what it
// buys is that the new directory entry is durable, which for a binary published by
// rename is the difference between a crash losing the update and a crash losing
// the binary.
//
// A failure is reported but is never fatal to a caller that has already renamed:
// the rename happened, and some filesystems simply will not answer this. The
// callers in apply.go discard it rather than unwinding a successful publish.
// writeAtomicDurable above takes the opposite posture for the reason its doc
// gives — it runs before anything has been published, so a caller still has a
// choice.
//
// Windows is the reason this delegates rather than calling Sync on a directory
// handle itself. FlushFileBuffers requires a handle with GENERIC_WRITE and
// os.Open asks for none, so the direct form returned ERROR_ACCESS_DENIED on
// every Windows call, which the callers were silently discarding.
// core/atomicfile is where that platform difference is expressed once, as a
// documented no-op — see dirsync_windows.go for what is and is not established
// about the alternatives, and issue #228 for the gap the no-op leaves.
func syncDir(dir string) error {
	return atomicfile.SyncDir(dir)
}
