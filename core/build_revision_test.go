package core

import (
	"context"
	"runtime/debug"
	"testing"
	"time"
)

// A node's build revision on the register wire (issue #182, ADR-0063): before
// this, the coordinator could name its OWN revision (coordBuild, issue #114)
// and nothing about a node's, so pairing the two still meant reading a node's
// binary by hand (go version -m). This is core's sending half.
//
// MUTATION: return release unchanged from renderBuildRevision — red on the
// first two subtests below.
// MUTATION: drop the vcs.modified arm — red on "dirty".
// MUTATION: drop the `revision == ""` branch and return the bare (truncated)
// revision — red on the "unstamped" subtest, which is the case every worktree
// and every `go test` build is in, and which must report empty rather than
// look stamped.
func TestRenderBuildRevision(t *testing.T) {
	rev := debug.BuildSetting{Key: "vcs.revision", Value: "b2f75452973be9c296887220cb8829930a88099d"}
	clean := debug.BuildSetting{Key: "vcs.modified", Value: "false"}
	dirty := debug.BuildSetting{Key: "vcs.modified", Value: "true"}

	t.Run("stamped", func(t *testing.T) {
		got := renderBuildRevision([]debug.BuildSetting{rev, clean})
		if got != "b2f75452973b" {
			t.Fatalf("got %q, want the revision truncated to 12 hex characters", got)
		}
	})

	t.Run("stamped with uncommitted changes", func(t *testing.T) {
		got := renderBuildRevision([]debug.BuildSetting{rev, dirty})
		if got != "b2f75452973b-dirty" {
			t.Fatalf("got %q, want the truncated revision plus a -dirty suffix", got)
		}
	})

	t.Run("unstamped", func(t *testing.T) {
		got := renderBuildRevision([]debug.BuildSetting{{Key: "-compiler", Value: "gc"}})
		if got != "" {
			t.Fatalf("got %q, want empty for a build with no VCS data — this must not look stamped", got)
		}
	})

	t.Run("a short revision is not padded or truncated", func(t *testing.T) {
		short := debug.BuildSetting{Key: "vcs.revision", Value: "abc123"}
		if got := renderBuildRevision([]debug.BuildSetting{short, clean}); got != "abc123" {
			t.Fatalf("got %q, want the short revision verbatim", got)
		}
	})
}

// TestRegisterCarriesTheNodesBuildRevision is the end-to-end proof: whatever
// nodeBuildRevision computes for THIS test binary reaches the wire, verbatim,
// beside Release — mirroring core/capacity_wire_test.go's
// TestRegisterCarriesDeclaredLimits shape (fakeCoordinator + readRegister).
//
// This binary is built by `go test` from a git WORKTREE, which — per
// nodeBuildRevision's own doc — carries no VCS data, so this also stands as
// the end-to-end proof that the empty case reaches the wire as an omitted
// field rather than blocking registration.
func TestRegisterCarriesTheNodesBuildRevision(t *testing.T) {
	coord := fakeCoordinator(t)
	eng, err := New(Config{
		Coordinators: []string{coord.LocalAddr().String()},
		Roles:        []string{"relay"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer eng.Stop()

	m := readRegister(t, coord, 3*time.Second)
	want := nodeBuildRevision()
	if m.Build != want {
		t.Errorf("register Build = %q, want %q (nodeBuildRevision's own answer for this binary)", m.Build, want)
	}
	if want != "" {
		t.Logf("this build carries VCS data (%q) — the empty-build path is exercised by the unit tests instead", want)
	}
}
