// The release stamp, read back out of a real bacchus-node rather than out of a
// test binary that happens to link core/version.
//
// This is cmd/bacchus-netd/version_linux_test.go's check, applied to the second
// of the three fleet binaries (issue #263). The chain it completes is the one
// issue #223 broke and ADR-0065's second correction records: core/version's own
// TestStampMatchesTheVersionFile proves the symbol path resolves,
// TestEveryStampedBuildLinksTheVersionPackage proves this command references the
// package at all, and neither proves the last hop — that the number a build path
// passed comes out of THIS binary, in a form an operator can read. A `-X` that
// lands in a var nothing prints is a stamp nobody can see.
//
// So the test builds the command the way every build path builds it, runs it, and
// compares. Nothing here parses source or trusts a flag.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildNode builds cmd/node with a given -ldflags into a directory of the
// caller's choosing and returns the binary's path.
//
// Shared with oneshot_probation_test.go, which needs a real binary for a
// different reason: this file asks what the binary SAYS, that one asks what it
// does to the file beside it.
func buildNode(t *testing.T, dir, ldflags string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH, so this build-and-run check cannot run: %v", err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	bin := filepath.Join(dir, "bacchus-node")

	args := []string{"build"}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", bin, "./cmd/node")
	build := exec.Command("go", args...)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building cmd/node: %v\n%s", err, out)
	}
	return bin
}

// versionFlagPrintsTheStamp builds cmd/node with a given -ldflags and returns what
// `-version` writes to stdout.
//
// -version is answered before the demotion watchdog, before any coordinator is
// dialled and before any port is opened, which is what makes this runnable as an
// ordinary hermetic test — and is also the property an operator needs: asking an
// installed node what it is must not require a reachable coordinator and must not
// start a connect attempt.
func versionFlagPrintsTheStamp(t *testing.T, ldflags string) string {
	t.Helper()
	bin := buildNode(t, t.TempDir(), ldflags)

	var stdout, stderr strings.Builder
	run := exec.Command(bin, "-version")
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("%s -version: %v\nstderr:\n%s", bin, err, stderr.String())
	}
	return strings.TrimSpace(stdout.String())
}

// A build stamped the way deploy/install.sh, docs/RUNNING.md, deploy/bacchus-pin.sh
// and both workflows stamp it says that release when it is asked.
//
// The failure this catches is the one that produces no error anywhere: a `-X`
// whose symbol the linker cannot resolve is dropped with a zero exit, so the only
// evidence that a stamp landed is the value coming back out.
func TestNodeVersionFlagReportsTheStampedRelease(t *testing.T) {
	raw, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatalf("reading the VERSION file: %v", err)
	}
	want := strings.TrimSpace(string(raw))

	got := versionFlagPrintsTheStamp(t,
		"-X github.com/bacchus-vpn/bacchus/core/version.current="+want)
	if got != want {
		t.Fatalf("bacchus-node -version printed %q, want %q from the VERSION file. The stamp did not "+
			"reach this binary: -ldflags -X naming a symbol the linker has no reference to is ignored "+
			"SILENTLY, with a zero exit, which is why this is read back out of a built binary rather "+
			"than asserted from the flag (issues #223, #263)", got, want)
	}
}

// An UNSTAMPED build answers 0.0.0 and does not refuse, because a bare `go build`
// must keep working (issue #128). The two cases are tested together on purpose: a
// -version that printed something plausible either way would pass the test above
// while telling an operator nothing.
//
// It is also the limit issue #263 asked to have recorded where it is inherited
// rather than discovered later: 0.0.0 is what a DRY release run stamps too, so
// executing any of the three binaries cannot settle a dry run. The byte-level read
// in core/update.TestReleaseArtifactsCarryTheStamp is what does that, and this
// flag strengthens its calibration rather than replacing it.
func TestNodeVersionFlagOnAnUnstampedBuildSaysNoRelease(t *testing.T) {
	if got := versionFlagPrintsTheStamp(t, ""); got != "0.0.0" {
		t.Fatalf("an unstamped bacchus-node printed %q, want 0.0.0 — the honest answer from a binary "+
			"nobody told which release it is", got)
	}
}
