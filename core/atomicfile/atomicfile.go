// Package atomicfile installs a file by REPLACING it rather than rewriting it:
// a complete copy is staged beside the target, flushed, and renamed over it, so
// no reader ever observes a partial file and no crash can leave one behind.
//
// It exists because this repository had written the same twenty lines ten times
// — core/policy, core/admission, core/coldstart, core/revocation,
// core/devicestore, core/capacity, core/selection, core/update,
// cmd/bacchus-netd and clients/fyne's appstate — and three of those ten were
// subtly wrong in the same two ways (see "The two defects", below). ADR-0066
// records the decision to fold them into one, and answers the argument against
// it; the count was nine when that record landed and ten by the time issue #215
// reached the last of them, because core/update's arrived in the same wave the
// consolidation did.
//
// # What os.WriteFile does instead, and why it is not enough
//
// os.WriteFile opens the LIVE file with O_TRUNC and refills it. Between the
// truncate and the last byte the file on disk is empty or short, a concurrent
// reader can read it in that state, and a writer that dies in the window leaves
// it that way permanently. The exposure does not shrink as the file grows: a
// file that gains an entry per operation spends the same absolute time
// destroyed-and-not-yet-rewritten on its thousandth write as on its first.
//
// The two failures are not symmetric, and the second is the dangerous one. A
// concurrent READ that lands in the window is usually fail-safe — the callers
// here keep their previous in-memory copy when a parse fails, so the next
// reload repairs it. A RESTART afterwards is not: there is nothing in memory to
// keep, and every one of these files means something specific when it is
// missing or unparseable ("nothing is revoked", "no user may bootstrap", "this
// enforcer has accepted no policy"). A torn write therefore plants a DELAYED
// failure that detonates at the next restart, hours or weeks later, with
// nothing left connecting it to the write that caused it.
//
// # The three mechanics that are load-bearing rather than tidy
//
//   - The staged file is created IN THE TARGET'S OWN DIRECTORY. os.Rename is
//     atomic only within one filesystem, and a rename across one degrades to
//     copy-then-delete — exactly the half-written file this exists to prevent.
//   - The staged file's name is UNIQUE (os.CreateTemp), not "<target>.tmp".
//     Two savers sharing one staged name interleave their bytes into it and the
//     rename installs the mixture: a file that is whole in the sense that it was
//     renamed and mangled in the sense that no writer wrote it. A unique name
//     makes that unrepresentable rather than unlikely.
//   - The bytes are FLUSHED BEFORE the rename. A rename that becomes visible
//     ahead of the data it points at is a file the next reader sees as empty,
//     which is the one state every caller here reads as a statement rather than
//     as an error.
//
// # Three consequences of replacing the file instead of rewriting it
//
// Named because each is a real change from os.WriteFile rather than an
// implementation detail:
//
//   - The result carries perm EVERY time. os.WriteFile applied its perm only
//     when creating, so an existing file kept whatever mode it had.
//   - A path that is a SYMLINK is replaced rather than written through.
//   - A writer killed mid-save leaves its staged file behind, which os.WriteFile
//     never did. Staged files are named ".<target>.tmp*" so they sort beside the
//     file they were staged for, are hidden from a plain ls, and can never be
//     mistaken for the file itself. A save that COMPLETES cleans up after
//     itself on every path, including its failure paths.
//
// # What it deliberately does not do
//
// It does not create parent directories. Three of the callers do want that and
// three deliberately do not, they disagree about the mode (0700 and 0755), and
// a missing directory is a real error for a tool that should not quietly
// conjure one. So the callers that want it keep their own os.MkdirAll line,
// where the mode is visible at the site that chose it.
//
// It does not serialise two writers. Atomicity is a promise to a READER — every
// read lands on a whole file — and it says nothing about two read-modify-write
// callers racing, where the loser's change is dropped from a file that is
// perfectly well-formed. That is the caller's lock.
//
// It does not wrap errors with a package prefix. Every error names the
// operation and the path; callers add their own prefix as they already do.
//
// # The two defects this replaces
//
// core/devicestore, core/capacity and core/selection each staged to a FIXED
// name and renamed without flushing. Both halves are fixed by using this:
// os.CreateTemp for the name, Sync before the rename. cmd/bacchus-netd's
// resolv.conf writer was a fourth variant that skipped only the flush — its
// mode ordering, which looked like the odd one out, was the one this package
// adopted (see Write).
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write installs b at path with mode perm, by staging a complete file under
// ".<name>.tmp*" in path's own directory, flushing it, and renaming it over the
// target. The live file is never opened for writing, so there is no moment at
// which path holds a partial file.
//
// The signature is os.WriteFile's on purpose. It is meant to be the substitution
// a caller reaches for without thinking about it, and every difference between
// the two is in the package doc rather than in the call.
//
// # Why perm is applied AFTER the bytes and before the flush
//
// This is the one ordering the nine copies disagreed about, and the odd one out
// was right. os.CreateTemp creates its file 0600 whatever the umask, so:
//
//   - Applying perm BEFORE the write is safe only while perm is no wider than
//     0600. cmd/bacchus-netd writes /etc/resolv.conf 0644 — a file that MUST be
//     world-readable — and applying that first would let every local user read
//     a half-written resolv.conf.
//   - Applying it AFTER the write is safe for both directions. The bytes land
//     while the staged file is still owner-only, the mode is set once the file
//     is complete, and nothing but this process can open it under either mode
//     because the name it will be read under does not exist yet.
//
// It is applied before Sync rather than after so the mode change is flushed
// along with the data, not left as a metadata update racing the rename.
//
// Write makes the file's DATA durable. It does not make the RENAME durable —
// see WriteDurable, and ADR-0066 for which callers need which.
func Write(path string, b []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("stage in %s: %w", dir, err)
	}
	staged := f.Name()
	// Removed on every path that does not rename it away, so a failure leaves
	// the live file untouched AND nothing beside it for the next operator to
	// wonder about. A no-op once the rename has succeeded.
	defer func() { _ = os.Remove(staged) }()
	if err := fill(f, b, perm); err != nil {
		f.Close()
		return fmt.Errorf("write %s: %w", staged, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", staged, err)
	}
	if err := os.Rename(staged, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// WriteDurable is Write plus SyncDir: the bytes are durable AND the rename that
// installed them is, so a machine that loses power the instant after this
// returns comes back holding the new file rather than possibly the old one.
//
// It is NOT the default, and the choice between the two is a real one that
// ADR-0066 rules per caller rather than once. The short form: use Write when a
// later write re-establishes the same state (a checkpoint, a cache, a floor
// re-persisted on every refresh — losing one rename costs one generation and
// the next ordinary write repairs it, so paying an extra fsync on every write
// buys a self-healing failure). Use WriteDurable when the file is the
// accumulated record of decisions somebody made and NOTHING will write it again
// until the next decision — a revocation list, a secrets ledger — because there
// the lost rename is silent, unrepaired, and means the operator was told an
// action took effect when it did not.
//
// ON WINDOWS THIS IS EXACTLY Write. SyncDir is a documented no-op there, so a
// caller reaching for this name on that platform gets the bytes flushed and the
// rename not, which is the guarantee it was reaching past. It is said here as
// well as at SyncDir because this is the name callers pick, and callers on that
// platform now exist: clients/fyne's coldstart directory cache and core/update's
// floor raise and confirmation marker both reach this from the desktop client.
// See dirsync_windows.go for what Windows does and does not document about it,
// and issue #228 for the gap.
func WriteDurable(path string, b []byte, perm os.FileMode) error {
	if err := Write(path, b, perm); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(path))
}

// SyncDir flushes dir's own entries, which is what makes a rename (or a create)
// in it survive a power loss. A file's own Sync does not do this: it makes the
// DATA durable, and leaves the directory entry naming it as a metadata update
// the filesystem may commit whenever it likes.
//
// Exported separately from WriteDurable because the create case needs it too
// and cannot go through Write: the three ed25519 seed writers (issue #189) use
// O_EXCL on the real path precisely so that two processes cannot both believe
// they generated the key, which a stage-and-rename cannot express. Their
// polarity is also worse than a replacing writer's — losing a rename restores a
// complete older file, but losing a first-run CREATE leaves no file at all, and
// all three of those regenerate silently on the next start after having already
// distributed the public half. ADR-0066 §6 records that, and issue #215 called
// it at all three: cmd/coordinator's bootstrap key, cmd/admission-issue's
// admission root, and core/devicestore's on-device keypair all call this once
// the seed is flushed and closed, and all three report a failure rather than
// swallowing it — the key file is on disk either way, so the next run reads it
// instead of minting a second.
//
// On Windows this is a documented no-op, so those three get Write's guarantees
// there and not WriteDurable's. dirsync_windows.go holds what Windows documents
// instead — briefly, that flushing the FILE's handle is the only lever Windows
// gives an application, that the seed writers already pull it, and that whether
// it reaches the entry in the file's PARENT directory is the one step Microsoft
// does not state. Issue #228 is the gap; issue #238 is the power-loss run that
// can close it.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open %s: %w", dir, err)
	}
	defer d.Close()
	if err := syncDirHandle(d); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}

// fill writes the staged file's contents, sets its mode and flushes it, so
// everything that can fail has failed before anything is renamed over the file
// somebody else is reading.
func fill(f *os.File, b []byte, perm os.FileMode) error {
	if _, err := f.Write(b); err != nil {
		return err
	}
	// After the bytes and before the flush — see Write's doc for why that
	// ordering is the one that is safe for a widening perm as well as a
	// narrowing one.
	if err := f.Chmod(perm); err != nil {
		return err
	}
	return f.Sync()
}
