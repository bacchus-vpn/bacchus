package update_test

import (
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
