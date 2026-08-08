package update_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/update"
)

// The running binary and the release that replaces it. Distinguishable by content,
// because every assertion below is on BYTES rather than on an error value: the
// card's exit condition is that a refused release leaves the running binary in
// place, and an error return is not evidence of that.
var (
	runningBytes = []byte("#!/bin/false\nI AM THE RUNNING BINARY\n")
	releaseBytes = []byte("#!/bin/false\nI AM THE NEW RELEASE\n")
)

// installed writes runningBytes to a target path inside a fresh directory and
// returns the path.
func installed(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "bacchus-node")
	if err := os.WriteFile(target, runningBytes, 0o755); err != nil {
		t.Fatalf("install: %v", err)
	}
	return target
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// assertUntouched is the assertion the card asks for, and it is deliberately made
// of bytes: the target still holds exactly the running binary, and no staging file
// was left behind in its directory for anything to find later.
func assertUntouched(t *testing.T, target string) {
	t.Helper()
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("the running binary was modified: target now holds %q", got)
	}
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == filepath.Base(target) {
			continue
		}
		t.Fatalf("a refused update left %q beside the target", e.Name())
	}
}

// serveSource is a Source that hands back exactly the bytes it was given, however
// wrong they are. Every negative case below is a hostile or broken source, and
// this is what makes one.
type serveSource struct {
	manifest []byte
	blob     []byte
	err      error
}

func (s serveSource) String() string { return "test" }
func (s serveSource) Manifest(context.Context) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.manifest, nil
}
func (s serveSource) Artifact(context.Context, update.Artifact) (io.ReadCloser, error) {
	if s.err != nil {
		return nil, s.err
	}
	return io.NopCloser(bytes.NewReader(s.blob)), nil
}

func TestStageAndApplyReplaceTheTarget(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)

	staged, err := update.Stage(context.Background(), serveSource{blob: releaseBytes}, a, target)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	// Staging alone changes nothing about the target.
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("Stage modified the target")
	}
	if got := readFile(t, staged); !bytes.Equal(got, releaseBytes) {
		t.Fatalf("the staged file does not hold the release")
	}

	if err := update.Apply(target, staged, a, "0.5.0"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
		t.Fatalf("after Apply the target holds %q", got)
	}
	// The previous binary is KEPT. It is the only thing a demotion has to go back to.
	if got := readFile(t, update.PreviousPath(target)); !bytes.Equal(got, runningBytes) {
		t.Fatalf("the previous binary was not kept: %q", got)
	}
	if _, err := os.Stat(update.MarkerPath(target)); err != nil {
		t.Fatalf("Apply left no confirmation marker: %v", err)
	}
}

// The heart of it: the running process keeps the inode it was started from. This
// is what "nothing works around ETXTBSY, because nothing ever writes to the
// running path" means, and it is asserted through an open descriptor rather than
// described.
func TestApplyNeverWritesThroughTheRunningInode(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)

	// The descriptor a running process would hold on its own executable.
	running, err := os.Open(target)
	if err != nil {
		t.Fatalf("open the running binary: %v", err)
	}
	defer running.Close()

	staged, err := update.Stage(context.Background(), serveSource{blob: releaseBytes}, a, target)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := update.Apply(target, staged, a, "0.5.0"); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// The path now holds the new release...
	if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
		t.Fatalf("the target was not replaced")
	}
	// ...and the bytes the already-open descriptor sees are still the old ones. A
	// design that wrote in place would fail here (and on a real running binary would
	// have failed with ETXTBSY before it got the chance).
	if _, err := running.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	stillRunning, err := io.ReadAll(running)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stillRunning, runningBytes) {
		t.Fatalf("the running inode changed under the process: %q", stillRunning)
	}
}

func TestACorruptedArtifactLeavesTheRunningBinaryInPlace(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)

	corrupt := append([]byte(nil), releaseBytes...)
	corrupt[len(corrupt)/2] ^= 0x40 // same length, different bytes

	_, err := update.Stage(context.Background(), serveSource{blob: corrupt}, a, target)
	if !errors.Is(err, update.ErrHashMismatch) {
		t.Fatalf("Stage on corrupted bytes = %v, want ErrHashMismatch", err)
	}
	assertUntouched(t, target)
}

func TestATruncatedArtifactLeavesTheRunningBinaryInPlace(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)

	_, err := update.Stage(context.Background(), serveSource{blob: releaseBytes[:len(releaseBytes)-3]}, a, target)
	if !errors.Is(err, update.ErrSizeMismatch) {
		t.Fatalf("Stage on a short read = %v, want ErrSizeMismatch", err)
	}
	assertUntouched(t, target)
}

// A source that keeps sending is stopped by the declared size, not by a hash taken
// after it has filled the disk.
func TestAnOversizedArtifactIsRefusedByTheDeclaredSize(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)

	tooMuch := append(append([]byte(nil), releaseBytes...), bytes.Repeat([]byte("x"), 4096)...)
	_, err := update.Stage(context.Background(), serveSource{blob: tooMuch}, a, target)
	if !errors.Is(err, update.ErrSizeMismatch) {
		t.Fatalf("Stage on an oversized artifact = %v, want ErrSizeMismatch", err)
	}
	assertUntouched(t, target)
}

func TestAnUnreachableSourceLeavesTheRunningBinaryInPlace(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	_, err := update.Stage(context.Background(), serveSource{err: errors.New("no route")}, a, target)
	if err == nil {
		t.Fatal("Stage succeeded against a source that will not answer")
	}
	assertUntouched(t, target)
}

// Apply re-verifies the staged file, because the file may have sat on disk across
// a restart in a directory this code does not own.
func TestApplyRefusesAStagedFileThatNoLongerVerifies(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	staged, err := update.Stage(context.Background(), serveSource{blob: releaseBytes}, a, target)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	// Somebody with write access to the directory edits the staged file after it was
	// verified.
	if err := os.WriteFile(staged, []byte("cuckoo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := update.Apply(target, staged, a, "0.5.0"); !errors.Is(err, update.ErrSizeMismatch) {
		t.Fatalf("Apply on a tampered staging file = %v, want a verification refusal", err)
	}
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("the running binary was replaced by unverified bytes: %q", got)
	}
	if _, err := os.Stat(update.MarkerPath(target)); err == nil {
		t.Fatal("a refused Apply left a confirmation marker")
	}
}

// The failure path in the middle of Apply: the move-aside fails, so nothing is
// published and the marker is cleaned up.
func TestApplyCleansUpWhenTheCurrentBinaryCannotBeMovedAside(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	staged, err := update.Stage(context.Background(), serveSource{blob: releaseBytes}, a, target)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	// A non-empty directory at target.prev: rename(2) will not replace one.
	prev := update.PreviousPath(target)
	if err := os.Mkdir(prev, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prev, "occupied"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := update.Apply(target, staged, a, "0.5.0"); err == nil {
		t.Fatal("Apply succeeded with the previous path occupied")
	}
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("the running binary was replaced despite the failure: %q", got)
	}
	if _, err := os.Stat(update.MarkerPath(target)); err == nil {
		t.Fatal("a failed Apply left a confirmation marker, which would demote a healthy binary on the next start")
	}
}

func TestCheckStartupDemotesAnUnconfirmedStart(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	staged, err := update.Stage(context.Background(), serveSource{blob: releaseBytes}, a, target)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := update.Apply(target, staged, a, "0.5.0"); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// The new binary's FIRST start. It claims the marker and is left to run: the
	// apply happened in the old binary, so this is the release's only opportunity
	// to prove itself, and demoting here would roll back every release that works.
	if err := update.CheckStartup(target); err != nil {
		t.Fatalf("CheckStartup on the applied release's first start = %v, want nil", err)
	}
	if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
		t.Fatalf("the first start demoted the release it was supposed to try: %q", got)
	}

	// It starts and never confirms — it crashed, or never reached a serving state.
	// The NEXT start finds the marker already claimed.
	err = update.CheckStartup(target)
	if !errors.Is(err, update.ErrDemoted) {
		t.Fatalf("CheckStartup after an unconfirmed start = %v, want ErrDemoted", err)
	}
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("the demotion did not restore the previous binary: %q", got)
	}
	if _, err := os.Stat(update.MarkerPath(target)); err == nil {
		t.Fatal("the demotion left the marker behind, so the restored binary would demote itself next")
	}
	// And the start after that is ordinary: there is nothing left to demote to.
	if err := update.CheckStartup(target); err != nil {
		t.Fatalf("CheckStartup after a demotion = %v, want nil", err)
	}
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("a second CheckStartup changed the target: %q", got)
	}
}

func TestCheckStartupIsSilentAfterAConfirmedStart(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	staged, err := update.Stage(context.Background(), serveSource{blob: releaseBytes}, a, target)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := update.Apply(target, staged, a, "0.5.0"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// The whole life of a good release: applied, started once, and confirmed by
	// that start. Every restart afterwards is ordinary.
	if err := update.CheckStartup(target); err != nil {
		t.Fatalf("CheckStartup on the first start = %v, want nil", err)
	}
	if err := update.Confirm(target); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	for i := range 3 {
		if err := update.CheckStartup(target); err != nil {
			t.Fatalf("CheckStartup %d start(s) after a confirmed release = %v, want nil", i+1, err)
		}
		if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
			t.Fatalf("a confirmed release was demoted anyway: %q", got)
		}
	}
}

// The defect this shape exists to close, stated as the sequence that produced it.
//
// The marker is written by the apply, and the apply runs in the OLD binary: a
// running process keeps the inode it was started from, so the new release does not
// execute until the next restart. A watchdog that demoted on merely FINDING a
// marker therefore demoted the new release on its own first start — every time,
// including for a release that works — and a node would apply, be demoted, apply
// again on its next check, and never move off the release it was on.
//
// Asserted on bytes and across the full cycle, because "CheckStartup returned nil"
// is not evidence that the release survived.
func TestAWorkingReleaseSurvivesTheRestartThatHandsOverToIt(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	staged, err := update.Stage(context.Background(), serveSource{blob: releaseBytes}, a, target)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := update.Apply(target, staged, a, "0.5.0"); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// The applying process is still running the old binary. Its own probation timer
	// fires here — one minute after ITS start, which has nothing to do with the
	// release it just applied — and must not clear a marker the new release has not
	// had the chance to claim.
	if err := update.Confirm(target); err != nil {
		t.Fatalf("Confirm from the applying process: %v", err)
	}
	if _, err := os.Stat(update.MarkerPath(target)); err != nil {
		t.Fatalf("the applying process cleared the new release's marker: %v — the release would then "+
			"run with no demotion protection at all, which is the opposite of what the marker is for", err)
	}

	// The handover. The supervisor re-execs the target, which is now the release.
	if err := update.CheckStartup(target); err != nil {
		t.Fatalf("the release's first start = %v, want nil", err)
	}
	if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
		t.Fatalf("the release was demoted by the very start that was meant to try it: %q", got)
	}

	// It reaches a serving state and confirms. Now the marker is gone and the
	// previous binary is dead weight rather than a pending rollback.
	if err := update.Confirm(target); err != nil {
		t.Fatalf("Confirm after the release's own start: %v", err)
	}
	if _, err := os.Stat(update.MarkerPath(target)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the marker survived a confirmed start: %v", err)
	}
	if err := update.CheckStartup(target); err != nil {
		t.Fatalf("an ordinary restart afterwards = %v, want nil", err)
	}
	if got := readFile(t, target); !bytes.Equal(got, releaseBytes) {
		t.Fatalf("an ordinary restart demoted a confirmed release: %q", got)
	}
}

// The marker states which of the two watchdogs owns the case, and it is a fact on
// disk rather than an inference: a supervisor-side check has no way to ask a
// process that never started what it did.
//
//   - started=false — no process of this release has reached main. Either the
//     handover has not happened yet, or the binary cannot execute at all, which is
//     the case only something outside the process can reach (#222).
//   - started=true — a process reached main. A crash loop puts it through
//     CheckStartup again and the demotion happens in-process.
func TestTheMarkerRecordsWhetherTheReleaseEverStarted(t *testing.T) {
	target := installed(t)
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	staged, err := update.Stage(context.Background(), serveSource{blob: releaseBytes}, a, target)
	if err != nil {
		t.Fatalf("Stage: %v", err)
	}
	if err := update.Apply(target, staged, a, "0.5.0"); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	m := readMarker(t, target)
	if m.Started {
		t.Fatal("a freshly applied release is recorded as started, so nothing outside the process " +
			"could tell a binary that will not execute from one that ran and crashed")
	}
	if m.Release != "0.5.0" {
		t.Fatalf("marker release = %q, want 0.5.0 — the supervisor-side rollback logs it", m.Release)
	}

	if err := update.CheckStartup(target); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if !readMarker(t, target).Started {
		t.Fatal("a start that reached CheckStartup did not claim the marker, so a crash loop would " +
			"never be demoted and the supervisor-side check would act on a case it does not own")
	}
}

// readMarker reads the on-disk marker beside target. The supervisor-side rollback
// reads the same file with the same field names, from shell, so the encoding is
// part of the contract rather than an implementation detail.
func readMarker(t *testing.T, target string) update.Marker {
	t.Helper()
	b, err := os.ReadFile(update.MarkerPath(target))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	var m update.Marker
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse marker %q: %v", b, err)
	}
	return m
}

// A crash between the marker and the rename leaves a marker with nothing to go
// back to. Clearing it is the only correct move: leaving it would demote a healthy
// binary on the next start, with nothing to demote it to.
func TestCheckStartupClearsAMarkerWithNoPreviousBinary(t *testing.T) {
	target := installed(t)
	if err := os.WriteFile(update.MarkerPath(target), []byte(`{"release":"9.9.9"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := update.CheckStartup(target); err != nil {
		t.Fatalf("CheckStartup = %v, want nil", err)
	}
	if _, err := os.Stat(update.MarkerPath(target)); err == nil {
		t.Fatal("the marker was left behind")
	}
	if got := readFile(t, target); !bytes.Equal(got, runningBytes) {
		t.Fatalf("the target changed: %q", got)
	}
}

func TestCheckStartupOnAFreshInstallDoesNothing(t *testing.T) {
	target := installed(t)
	if err := update.CheckStartup(target); err != nil {
		t.Fatalf("CheckStartup with no marker = %v, want nil", err)
	}
	assertUntouched(t, target)
}

// The staged file's name is content-addressed, so two artifacts cannot collide and
// no signed string reaches a path component.
func TestStagedPathIsContentAddressed(t *testing.T) {
	a := artifactOf("linux", "amd64", update.RoleNode, releaseBytes)
	p := update.StagedPath("/usr/local/bin/bacchus-node", a)
	if filepath.Dir(p) != "/usr/local/bin" {
		t.Fatalf("the staging file is not beside the target: %s", p)
	}
	if !strings.Contains(filepath.Base(p), a.Name()) {
		t.Fatalf("the staging file is not named by the digest: %s", p)
	}
	b := artifactOf("linux", "amd64", update.RoleNode, runningBytes)
	if update.StagedPath("/usr/local/bin/bacchus-node", b) == p {
		t.Fatal("two different artifacts stage to the same path")
	}
}
