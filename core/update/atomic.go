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
// Both functions below are now that package, and everything they promise is
// documented there. They are kept as named functions rather than inlined at the
// call sites so this package's callers keep their "update: " error prefix, which
// ADR-0066 §2 keeps at the caller rather than absorbing into the writer.
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
// It takes core/atomicfile.Write and not WriteDurable, which is the state of
// this package rather than a ruling about it. ADR-0066 §5 decides that boundary
// per WRITE — take the directory fsync when the write records something nothing
// will re-emit — and this one function serves two callers whose answers under
// that rule differ from each other (state.go's floor is re-recorded on every
// check, its RAISE is not, and the confirmation marker is not re-emitted at all).
// Splitting it is a change at those call sites, which are outside the files this
// change owns; issue #215's closing notes carry the analysis so it is one edit
// rather than a re-derivation. Nothing here is made less durable than it was:
// this package has never fsynced a directory from this path.
func writeAtomic(path string, b []byte, mode fs.FileMode) error {
	if err := atomicfile.Write(path, b, mode); err != nil {
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
//
// Windows is the reason this delegates rather than calling Sync on a directory
// handle itself. Opening a directory as a file and flushing it is not a thing
// there — FlushFileBuffers wants a handle opened for writing and a directory
// handle is never one — so the direct form returned ERROR_ACCESS_DENIED on every
// Windows call, which the callers were silently discarding. core/atomicfile is
// where that platform difference is expressed once, as a documented no-op.
func syncDir(dir string) error {
	return atomicfile.SyncDir(dir)
}
