package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ExecMode is the mode a published binary is given. 0755: readable and executable
// by anyone, writable only by the owner. The node's unit runs as root and writes
// into /usr/local/bin, which is already something it can do (ADR-0052 §4), so the
// update path adds no capability the process did not have.
const ExecMode fs.FileMode = 0o755

// Staging, previous and marker suffixes, all beside the target because the final
// publish is a rename(2) and a rename cannot cross a mount boundary.
const (
	// stagedSuffix names a downloaded, fully verified artifact that has not been
	// published. It is re-verified before it is ever renamed in — a file that sat on
	// disk across a restart is as untrusted as the network, more so in that it
	// persists (core/policy.Cache says the same about its own state file).
	stagedSuffix = ".staged"
	// prevSuffix names the binary that was running before the last apply. It is KEPT,
	// not deleted: it is the only thing a demotion has to rename back (ADR-0052 §7).
	prevSuffix = ".prev"
	// pendingSuffix names the confirmation marker. Its presence at startup means a
	// previous boot applied an update and never reached a serving state.
	pendingSuffix = ".pending"
)

// ErrDemoted reports that a startup check found an unconfirmed marker, renamed the
// previous binary back over the target, and that this process is now running bytes
// that are no longer at the path its supervisor will execute next.
//
// A caller that sees it must EXIT rather than continue. Under Restart=always the
// supervisor then re-execs the restored binary; a process that carried on would be
// the new release still running while the path claims the old one, which is the
// worst of both.
var ErrDemoted = errors.New("update: demoted to the previous binary after an unconfirmed start")

// ErrNoPending reports that there was nothing staged to apply. It is an ordinary
// answer, not a failure.
var ErrNoPending = errors.New("update: nothing staged")

// StagedPath is where an artifact for target is staged: beside the target, named
// by the artifact's digest and nothing else.
//
// The digest in the name is not decoration. It means a staging file cannot be
// confused for one belonging to a different artifact, it means two concurrent
// stages of different artifacts cannot collide, and — since Artifact.Name is hex
// of a digest — it means no signed string ever reaches a path component.
func StagedPath(target string, a Artifact) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+"-"+a.Name()+stagedSuffix)
}

// PreviousPath and MarkerPath are the two files an apply leaves beside the target.
func PreviousPath(target string) string { return target + prevSuffix }
func MarkerPath(target string) string   { return target + pendingSuffix }

// Stage downloads a from src into the directory holding target, verifies the
// COMPLETE file against the manifest, and returns the path of the staging file.
//
// Nothing about the target is touched. On any failure — a source that will not
// answer, a short read, a wrong digest, a full disk — the staging file is removed
// and the running binary and its path are exactly as they were. That is the card's
// exit condition, and it is a property of this function's structure rather than of
// a cleanup that has to be remembered: the only operation in this package that
// publishes anything is Apply's rename, and Stage never calls it.
//
// The hash is taken over the file AS WRITTEN, by re-reading it, not over the
// stream as it arrives. Hashing the stream would prove the bytes were correct on
// the way past and prove nothing about the bytes on the disk; a truncated write, a
// full filesystem or a lying kernel would all pass. This is the one place where
// paying for a second pass over 20 MB is obviously worth it.
func Stage(ctx context.Context, src Source, a Artifact, target string) (string, error) {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".bacchus-update-*")
	if err != nil {
		return "", fmt.Errorf("update: create staging file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	// Removed on every path that does not reach the final rename below. A staging
	// file is never left behind for a later run to reason about.
	defer func() { _ = os.Remove(tmpName) }()

	rc, err := src.Artifact(ctx, a)
	if err != nil {
		tmp.Close()
		return "", fmt.Errorf("update: fetch artifact: %w", err)
	}
	// One byte past the declared size: a source serving more than the signed manifest
	// promised is stopped by the read rather than by a hash taken after an unbounded
	// download has already filled the disk.
	n, copyErr := io.Copy(tmp, io.LimitReader(rc, a.Size+1))
	closeErr := rc.Close()
	if copyErr != nil {
		tmp.Close()
		return "", fmt.Errorf("update: download artifact: %w", copyErr)
	}
	if closeErr != nil {
		tmp.Close()
		return "", fmt.Errorf("update: close artifact source: %w", closeErr)
	}
	if n != a.Size {
		tmp.Close()
		return "", fmt.Errorf("%w: source served %d bytes, manifest says %d", ErrSizeMismatch, n, a.Size)
	}
	if err := tmp.Chmod(ExecMode); err != nil {
		tmp.Close()
		return "", fmt.Errorf("update: chmod staging file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", fmt.Errorf("update: sync staging file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("update: close staging file: %w", err)
	}

	if err := verifyFile(tmpName, a); err != nil {
		return "", err
	}

	staged := StagedPath(target, a)
	if err := os.Rename(tmpName, staged); err != nil {
		return "", fmt.Errorf("update: name staging file: %w", err)
	}
	// Not fatal, and not everywhere possible: the staging file is verified and
	// named, and the worst a lost directory entry costs is a re-download.
	_ = syncDir(dir)
	return staged, nil
}

// verifyFile re-opens path and checks its complete contents against a.
func verifyFile(path string, a Artifact) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("update: reopen staged artifact: %w", err)
	}
	defer f.Close()
	if _, err := VerifyArtifact(a, f); err != nil {
		return err
	}
	return nil
}

// Apply publishes a staged artifact at target, keeping what was there.
//
// The sequence, and why each step is the one it is (ADR-0052 §3):
//
//  1. Re-verify the staged file against the manifest row. It may have been written
//     minutes or a reboot ago, and a file on disk is untrusted.
//  2. Write the confirmation marker, BEFORE anything moves. A crash between here
//     and step 4 leaves a marker with the old binary still in place, and the
//     startup check treats that correctly: it finds no previous binary to restore
//     and clears the marker.
//  3. Rename the current binary to target.prev. Not delete — this is the only copy
//     a demotion has to go back to.
//  4. Rename the staged file onto target.
//
// NOTHING WORKS AROUND ETXTBSY, BECAUSE NOTHING EVER WRITES TO THE RUNNING PATH.
// rename(2) replaces a directory entry; the running process keeps the inode it was
// started from and runs unharmed until it exits. The same order is what makes this
// work on Windows, for a different reason: a running .exe may be RENAMED but may
// not be replaced or deleted, so moving it aside first is not an optimisation
// there — it is the only order that can work at all.
//
// If step 4 fails the previous binary is renamed back and the error names both
// failures. There is no window in which the target path does not exist and no
// state in which it holds unverified bytes.
func Apply(target, staged string, a Artifact, release string) error {
	if err := verifyFile(staged, a); err != nil {
		return err
	}
	marker := Marker{Release: release, Previous: PreviousPath(target), Artifact: a.Name()}
	if err := writeMarker(MarkerPath(target), marker); err != nil {
		return err
	}

	prev := PreviousPath(target)
	movedAside := false
	if _, err := os.Stat(target); err == nil {
		if err := os.Rename(target, prev); err != nil {
			_ = os.Remove(MarkerPath(target))
			return fmt.Errorf("update: move the current binary aside: %w", err)
		}
		movedAside = true
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(MarkerPath(target))
		return fmt.Errorf("update: stat %s: %w", target, err)
	}

	if err := os.Rename(staged, target); err != nil {
		if movedAside {
			if rerr := os.Rename(prev, target); rerr != nil {
				// Both halves, because the second is the one that matters to whoever has
				// to fix it by hand and the first is why it happened.
				return fmt.Errorf("update: publish %s: %w; AND restoring the previous binary from %s failed: %v", target, err, prev, rerr)
			}
		}
		_ = os.Remove(MarkerPath(target))
		return fmt.Errorf("update: publish %s: %w", target, err)
	}
	_ = syncDir(filepath.Dir(target))
	return nil
}

// Confirm clears the marker for the release THIS PROCESS started. A process calls
// it once it has reached a state that proves the new binary works — for a node,
// serving; for the client, a completed start.
//
// "Reached a serving state" is deliberately the caller's judgement and not this
// package's. What counts as working differs per binary, and a definition invented
// here would be wrong for at least one of them.
//
// It is idempotent and a missing marker is not an error: an ordinary start with no
// pending update calls this and finds nothing.
//
// A marker that has NOT started is left alone, and that is the whole reason this is
// not a bare Remove. The process that calls Confirm is normally the process that
// applied the release, and it applies while running the OLD binary — it keeps the
// inode it was started from, and the handover happens at the next restart. Its own
// probation timer therefore fires against a marker belonging to a release that has
// not run yet, and clearing it would delete the new release's only protection
// before the new release had been tried once. Confirming what this process's start
// proved is the exact claim a caller is entitled to make.
func Confirm(target string) error {
	m, ok, err := readMarker(MarkerPath(target))
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	if !m.Started {
		return nil
	}
	return clearMarker(target)
}

// clearMarker removes the marker unconditionally. Confirm is the exported,
// conditional form; this is what the startup check uses once it has decided.
func clearMarker(target string) error {
	if err := os.Remove(MarkerPath(target)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("update: clear confirmation marker: %w", err)
	}
	return nil
}

// CheckStartup runs the demotion watchdog. Every binary that can update itself
// calls it as early in main as it can, whether or not updating is configured — it
// is a stat of one path when there is nothing to do.
//
// Four outcomes:
//
//   - No marker: nil. The ordinary start.
//   - A marker and NO previous binary: the marker is cleared and nil is returned.
//     This is the crash-between-marker-and-rename case, where nothing was ever
//     published.
//   - A marker that has not started: it is recorded as started and nil is
//     returned. THIS START IS THE APPLIED RELEASE'S TRIAL.
//   - A marker that HAS started: the previous start of this release did not
//     confirm. The previous binary is renamed back over the target, the marker is
//     cleared, and ErrDemoted is returned. The caller must exit; the supervisor
//     re-execs the restored binary.
//
// # Why the first start is a trial rather than a demotion
//
// The marker is written by the APPLY, and an apply runs in the old binary — the
// running process keeps the inode it was started from, so the new release does not
// execute until the next restart. "A start that finds a marker" is therefore
// satisfied by the new release's own first start, which is the start it has to be
// given. A watchdog that demoted there would roll back every release that works,
// on the first restart after it was applied, forever: the node would apply, be
// demoted, apply again on the next check, and never move.
//
// So a marker is a PROBATION with two states rather than a trap with one. The
// first start claims it; a start that finds it already claimed is the second start
// of a release whose first start never got far enough to call Confirm, and that is
// exactly the crash loop this exists for. Under RestartSec=2 the cost of the extra
// state is one two-second cycle before the demotion; the cost of not having it is
// that the release channel cannot deliver a release.
//
// # What this catches, and what it does not
//
// It catches "the update applied and the new binary starts but never gets far
// enough to work". Under Restart=always that is otherwise a crash loop which at a
// glance is indistinguishable from a healthy restart, which is why ADR-0052 §7
// calls it the worst of the three failures.
//
// It does NOT catch a binary that cannot execute at all — a corrupt file that
// verified against a manifest signed over corrupt bytes, a missing loader, the
// wrong architecture. Nothing in this process can, because this process never
// starts, so the marker is never read and never claimed. That is deploy/'s to
// handle, and the unclaimed marker is precisely the signal it acts on:
// deploy/bacchus-update-rollback.sh, wired to the units by OnFailure=, performs
// the same rename from the same place when systemd gives up restarting. The two
// cannot fight, because each acts on a marker state the other never leaves behind
// (ADR-0069, correcting ADR-0065 §6).
//
// It also does not catch "applied, started, and cannot serve" — #114's shape,
// where a node registers, heartbeats and is assigned work while silently dropping
// every session. The marker cannot: the process is up and confirms itself. ADR-0052
// §7 declined to invent a health signal for that and ADR-0065 does not either.
func CheckStartup(target string) error {
	m, ok, err := readMarker(MarkerPath(target))
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	prev := PreviousPath(target)
	if _, statErr := os.Stat(prev); statErr != nil {
		// Nothing to go back to: either the apply never got past the marker, or a
		// previous demotion already consumed it. Clearing the marker is the only
		// correct move — leaving it would demote a healthy binary on the next start
		// with nothing to demote it TO.
		if err := clearMarker(target); err != nil {
			return err
		}
		return nil
	}
	if !m.Started {
		// The applied release's first start. Claim the marker before returning, so
		// that a process which dies one instruction later is still recorded as having
		// had its turn. A marker that cannot be claimed — a read-only directory — is
		// reported rather than assumed either way: the caller logs it and continues,
		// which leaves this release running unprotected rather than demoting a build
		// that may be perfectly good.
		m.Started = true
		if err := writeMarker(MarkerPath(target), m); err != nil {
			return err
		}
		return nil
	}
	if err := os.Rename(prev, target); err != nil {
		return fmt.Errorf("update: demote to %s: %w", prev, err)
	}
	_ = syncDir(filepath.Dir(target))
	if err := clearMarker(target); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s did not confirm release %s", ErrDemoted, filepath.Base(target), m.Release)
}
