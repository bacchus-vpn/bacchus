package update_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/update"
)

// The state file and the confirmation marker are this package's two ordinary
// file writes, and until issue #215 they went through a hand-rolled copy of the
// atomic-write shape with no test of its own. What the copy promised, and what
// core/atomicfile now promises in its place, is asserted here at THIS package's
// seam rather than only at the helper's: a caller reading these files must never
// land on a partial one, and a save must not litter the directory it writes in.
//
// It is worth having at this level because the two files mean something specific
// when they are unreadable. A torn state file loses MinSeq, which is the one
// value in this package that cannot be re-derived from signed data — lose it and
// a peer can be walked back onto a burned release. A torn marker is read as
// PRESENT with a zero body, which demotes.

// TestTheStateFileIsReplacedRatherThanRewritten is the whole difference between
// this and os.WriteFile. os.WriteFile keeps the file and refills its contents, so
// there is an interval in which the file exists and is short; staging and
// renaming replaces it, so the file at that path is wholly the old one or wholly
// the new one and never a state in between.
func TestTheStateFileIsReplacedRatherThanRewritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-state.json")
	s := update.NewState(path)

	if err := s.RaiseFloor(3); err != nil {
		t.Fatalf("RaiseFloor: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Resolve this stat's identity NOW, while the file it describes is still the
	// one at that path: on Windows os.SameFile opens each operand's path when it
	// is CALLED, so a before/after comparison across a rename would otherwise
	// compare the new file with itself and report a match on a replaced file.
	_ = os.SameFile(before, before)

	if err := s.RaiseFloor(4); err != nil {
		t.Fatalf("RaiseFloor: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("the state write rewrote the live file in place rather than replacing it: a process killed between the truncate and the bytes landing leaves this peer with no rollback floor, and the next start reads what it left")
	}

	minSeq, pending, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if minSeq != 4 || pending != nil {
		t.Fatalf("Load after two raises = (%d, %v), want (4, nil)", minSeq, pending)
	}
}

// TestAStateWriteLeavesNothingStagedBehind: staging is the cost of atomicity,
// and a temporary file left beside the state file on every check would be a new
// mess of its own — beside a BINARY, in a directory an operator reads to see what
// this peer is running. Only a write that is killed may leave one.
func TestAStateWriteLeavesNothingStagedBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-state.json")
	s := update.NewState(path)

	for _, seq := range []uint64{1, 2, 2, 5} {
		if err := s.RaiseFloor(seq); err != nil {
			t.Fatalf("RaiseFloor(%d): %v", seq, err)
		}
	}
	if err := s.ClearPending("0.2.0"); err != nil {
		t.Fatalf("ClearPending: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("a state write left %q beside the state file", e.Name())
		}
	}
}

// TestTheStateFileIsOwnerOnly pins 0600, which the move onto core/atomicfile
// turned from a chmod inside this package into an argument passed to a shared
// writer. The mode is a PARAMETER of that writer precisely so a later tidy-up
// cannot flatten the set (ADR-0066 §3), and this is what makes flattening this
// one fail rather than pass quietly.
//
// State.Path's own doc gives the reason: write access to this file is the
// ability to roll this peer back one generation. The mode is also carried on
// every write rather than only at creation, so a file that was somehow created
// wider is narrowed by the next ordinary write instead of staying wide.
func TestTheStateFileIsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not the access control on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "update-state.json")

	if err := os.WriteFile(path, []byte(`{"version":1,"min_seq":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s := update.NewState(path)
	if err := s.RaiseFloor(2); err != nil {
		t.Fatalf("RaiseFloor: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file mode = %v, want 0600 — write access to it is the ability to roll this peer back one generation", perm)
	}
}

// TestAFailedStateWriteLeavesTheOldStateInPlace: the failure this package must
// not have is a state file that is neither the old one nor the new one. A
// staging failure is reported, the live file is untouched, and the floor it
// carries is still readable.
func TestAFailedStateWriteLeavesTheOldStateInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "update-state.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	s := update.NewState(path)
	if err := s.RaiseFloor(7); err != nil {
		t.Fatalf("RaiseFloor: %v", err)
	}
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Nowhere to stage: the directory the target lives in is gone, so the write
	// fails before it can touch anything. Rename the directory rather than
	// removing it, so the old contents are still there to compare against.
	if err := os.Rename(filepath.Dir(path), filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	err = s.RaiseFloor(8)
	if err == nil {
		t.Fatal("a state write with nowhere to stage reported success")
	}
	// The error names this package and the directory it could not stage in —
	// the prefix is the caller's job, the path is core/atomicfile's.
	if !strings.HasPrefix(err.Error(), "update: ") {
		t.Errorf("a state-write failure lost this package's prefix: %v", err)
	}
	if !strings.Contains(err.Error(), filepath.Dir(path)) {
		t.Errorf("a state-write failure did not name the directory it failed in: %v", err)
	}

	if err := os.Rename(filepath.Join(dir, "moved"), filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the state file did not survive a failed write: %v", err)
	}
	if string(after) != string(good) {
		t.Errorf("a failed write changed the state file:\n before: %s\n after:  %s", good, after)
	}
	minSeq, _, err := s.Load()
	if err != nil || minSeq != 7 {
		t.Errorf("floor after a failed write = (%d, %v), want (7, nil)", minSeq, err)
	}
}

// The rest of this file is issue #229: ADR-0066 §5's per-write durability rule
// applied to this package's three writers. Two of them record something nothing
// re-emits — a floor RAISE and the confirmation marker — and take the directory
// fsync; the others re-record state a later ordinary write re-establishes and do
// not.
//
// What the fsync buys is a property of a POWER LOSS and cannot be observed from
// inside a process. core/atomicfile's TestWriteDurableInstallsTheFile and
// core/revocation's split test both say that about themselves and assert the
// shape instead. There is one thing a process CAN observe, and it is enough to
// catch the failure that matters here — a raise that silently drops onto the
// non-durable path — because the durable form opens the directory and the other
// one never touches it. See unreadableDir.

// unreadableDir makes dir searchable and writable but not readable, which is the
// one difference between core/atomicfile.Write and WriteDurable that is visible
// from inside a process.
//
// Staging a file, renaming it and reading it back need write and search on the
// directory (0300 has both). Opening the DIRECTORY ITSELF to fsync it needs read
// (0300 has none). So under this fixture a write that takes the directory fsync
// reports a failure and a write that skips it succeeds, and a test can assert
// which of the two a given call made.
//
// Skipped rather than failed wherever the premise does not hold, because a pass
// obtained for an unrelated reason is worse than no coverage: root bypasses the
// permission entirely, Windows has no directory fsync to fail (issue #228), and
// a filesystem that does not enforce directory modes would silently turn this
// into a test of nothing.
func unreadableDir(t *testing.T, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("core/atomicfile.SyncDir is a documented no-op on Windows (issue #228), so there is no directory open to fail")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which bypasses the directory permission this fixture is built on")
	}
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	// Restored before t.TempDir's own cleanup, which needs to list the directory.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if f, err := os.Open(dir); err == nil {
		f.Close()
		t.Skip("this filesystem does not enforce directory read permission, so a directory fsync cannot be made to fail here")
	}
}

// TestOnlyAFloorRaiseTakesTheDirectoryFsync is the assertion that a raise which
// is lost does not pass silently. All four state writes are driven under
// unreadableDir, and the two that ADR-0066 §5 puts on either side of the line are
// distinguished by whether they consulted the directory at all.
//
// The stake is asymmetric and that is the whole reason for the split. MinSeq is
// the only value in this package that cannot be re-derived from signed data:
// lose a raise and a peer can be walked back onto a burned release by anyone who
// controls the source, using a genuinely signed, correctly delegated, unexpired
// manifest from an older generation — ADR-0052 §7's attack. Lose a re-record and
// the next check writes the same number again.
func TestOnlyAFloorRaiseTakesTheDirectoryFsync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-state.json")
	s := update.NewState(path)
	if err := s.RaiseFloor(4); err != nil {
		t.Fatalf("RaiseFloor(4): %v", err)
	}

	unreadableDir(t, dir)

	// The steady state: every check re-records the floor it already holds.
	if err := s.RaiseFloor(4); err != nil {
		t.Errorf("re-recording an unmoved floor took the directory fsync: %v", err)
	}
	// Below the floor: ignored rather than rejected, and still not a raise.
	if err := s.RaiseFloor(3); err != nil {
		t.Errorf("a seq below the floor took the directory fsync: %v", err)
	}
	// Pending at the floor the check already raised, which is the ordinary order
	// in Updater.Check — RaiseFloor paid for the raise, so this write does not.
	if err := s.SetPending(update.Pending{Release: "0.4.0", Seq: 4, Staged: "unused"}); err != nil {
		t.Errorf("recording a pending artifact at an unmoved floor took the directory fsync: %v", err)
	}
	if err := s.ClearPending("0.4.0"); err != nil {
		t.Errorf("ClearPending took the directory fsync: %v", err)
	}

	// And the two that move the ratchet.
	err := s.RaiseFloor(5)
	if err == nil {
		t.Fatal("a floor RAISE did not consult the directory it renamed into: a lost raise is not re-emitted by anything, and it walks this peer back onto a burned release (ADR-0052 §7)")
	}
	if !strings.HasPrefix(err.Error(), "update: ") {
		t.Errorf("a durable state write lost this package's prefix: %v", err)
	}
	if !strings.Contains(err.Error(), dir) {
		t.Errorf("a durable state write did not name the directory it could not flush: %v", err)
	}
	if err := s.SetPending(update.Pending{Release: "0.6.0", Seq: 6, Staged: "unused"}); err == nil {
		t.Error("SetPending raised the floor without consulting the directory")
	}

	// The floor is on disk either way: core/atomicfile installs the file and then
	// reports that it could not establish the rename's durability, so what the
	// error means is "this may not survive a power loss", never "this was not
	// written".
	minSeq, _, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if minSeq != 6 {
		t.Errorf("floor after two raises reported as failures = %d, want 6 — the writes themselves succeeded", minSeq)
	}
}

// TestAFloorRaiseInstallsTheSameStateAsAReRecord: the two paths differ in
// durability and in nothing else. A raise must not be a different file format, a
// different mode, or a writer that leaves debris where the other does not —
// those are the ways a split like this goes wrong silently, since the fsync
// itself is invisible from here.
func TestAFloorRaiseInstallsTheSameStateAsAReRecord(t *testing.T) {
	raisedPath := filepath.Join(t.TempDir(), "update-state.json")
	raised := update.NewState(raisedPath)
	if err := raised.RaiseFloor(9); err != nil {
		t.Fatalf("RaiseFloor (raise): %v", err)
	}

	rerecordedPath := filepath.Join(t.TempDir(), "update-state.json")
	rerecorded := update.NewState(rerecordedPath)
	if err := rerecorded.RaiseFloor(9); err != nil {
		t.Fatalf("RaiseFloor (seed): %v", err)
	}
	if err := rerecorded.RaiseFloor(9); err != nil {
		t.Fatalf("RaiseFloor (re-record): %v", err)
	}

	a, b := readFile(t, raisedPath), readFile(t, rerecordedPath)
	if !bytes.Equal(a, b) {
		t.Errorf("a floor raise and a re-record wrote different files:\n raise:     %s\n re-record: %s", a, b)
	}
	for _, p := range []string{raisedPath, rerecordedPath} {
		entries, err := os.ReadDir(filepath.Dir(p))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != filepath.Base(p) {
				t.Errorf("a state write left %q beside %s", e.Name(), filepath.Base(p))
			}
		}
		if runtime.GOOS != "windows" {
			fi, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if perm := fi.Mode().Perm(); perm != 0o600 {
				t.Errorf("state file mode = %v, want 0600 — the durable path must not be the one that widens it", perm)
			}
		}
	}
}

// TestTheConfirmationMarkerIsWrittenDurably: nothing re-emits a marker. It is
// written once per apply, before anything moves, and it is the only record that
// the release about to be published is on probation — so losing its rename is a
// demotion that never happens, which ADR-0052 §7 calls the worst of the three
// release failures because a crash loop is at a glance indistinguishable from a
// healthy restart.
//
// Apply does syncDir the same directory a few operations later on the path that
// SUCCEEDS, which is what makes this one marginal rather than obvious. It does
// not cover the path that fails, and it does not cover CheckStartup's claim write
// at all.
func TestTheConfirmationMarkerIsWrittenDurably(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	staged, err := update.Stage(context.Background(), serveSource{blob: releaseBytes}, a, target)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}

	unreadableDir(t, filepath.Dir(target))

	if err := update.Apply(target, staged, a, "0.5.0"); err == nil {
		t.Fatal("Apply published a release whose confirmation marker's directory entry could not be flushed: the marker is the only thing a demotion has to find")
	}
	// Nothing was published, which is the correct polarity: a release applied
	// without a durable marker is one nothing can demote.
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("a failed marker write still published a release: target holds %q", got)
	}
	if _, err := os.Stat(update.PreviousPath(target)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed apply moved the running binary aside: %v", err)
	}
	// And it left no marker behind. An unstarted marker with no previous binary
	// beside it is what deploy/bacchus-update-rollback.sh acts on, and an apply
	// that published nothing must not leave one for it to find.
	if _, err := os.Stat(update.MarkerPath(target)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed apply left a confirmation marker behind: %v", err)
	}
}
