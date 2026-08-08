//go:build linux

// The release stamp, read back out of a real bacchus-netd rather than out of a
// test binary that happens to link core/version.
//
// This is the end of the chain issue #223 broke. core/version's own
// TestStampMatchesTheVersionFile proves the symbol path resolves;
// TestEveryStampedBuildLinksTheVersionPackage proves this command references the
// package at all. Neither proves the last hop — that the number a build path
// passed comes out of THIS binary, in a form an operator can read. A `-X` that
// lands in a var nothing prints is a stamp nobody can see, which is the same
// blindness in a different place.
//
// So the test builds the command the way every build path builds it, runs it,
// and compares. Nothing here parses source or trusts a flag.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// versionFlagPrintsTheStamp builds cmd/bacchus-netd with a given -ldflags and
// returns what `-version` writes to stdout.
//
// -version is answered before the CAP_NET_ADMIN check and before anything binds,
// which is what makes this runnable as an ordinary unprivileged test — and is
// also the property an operator needs: asking an installed helper what it is
// must not require root and must not activate the socket unit.
func versionFlagPrintsTheStamp(t *testing.T, ldflags string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH, so this build-and-run check cannot run: %v", err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "bacchus-netd")

	args := []string{"build"}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", bin, "./cmd/bacchus-netd")
	build := exec.Command("go", args...)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building cmd/bacchus-netd: %v\n%s", err, out)
	}

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
// whose symbol the linker cannot resolve is dropped with a zero exit, so the
// only evidence that a stamp landed is the value coming back out.
func TestVersionFlagReportsTheStampedRelease(t *testing.T) {
	raw, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatalf("reading the VERSION file: %v", err)
	}
	want := strings.TrimSpace(string(raw))

	got := versionFlagPrintsTheStamp(t,
		"-X github.com/bacchus-vpn/bacchus/core/version.current="+want)
	if got != want {
		t.Fatalf("bacchus-netd -version printed %q, want %q from the VERSION file. The stamp did not "+
			"reach this binary: -ldflags -X naming a symbol the linker has no reference to is ignored "+
			"SILENTLY, with a zero exit, which is why this is read back out of a built binary rather "+
			"than asserted from the flag (issue #223)", got, want)
	}
}

// An UNSTAMPED build answers 0.0.0 and does not refuse, because a bare `go build`
// must keep working (issue #128). The two cases are tested together on purpose:
// a -version that printed something plausible either way would pass the test
// above while telling an operator nothing, which is precisely the state
// core/version's empty default exists to end.
func TestVersionFlagOnAnUnstampedBuildSaysNoRelease(t *testing.T) {
	if got := versionFlagPrintsTheStamp(t, ""); got != "0.0.0" {
		t.Fatalf("an unstamped bacchus-netd printed %q, want 0.0.0 — the honest answer from a binary "+
			"nobody told which release it is", got)
	}
}
