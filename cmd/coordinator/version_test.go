// The release stamp, read back out of a real bacchus-coordinator rather than out
// of a test binary that happens to link core/version.
//
// cmd/bacchus-netd/version_linux_test.go's check applied to the third fleet
// binary (issue #263), and the last hop of the chain issue #223 broke:
// core/version's TestStampMatchesTheVersionFile proves the symbol path resolves,
// TestEveryStampedBuildLinksTheVersionPackage proves this command references the
// package at all, and only running the binary proves the number comes back out in
// a form an operator can read.
//
// It matters more here than for the other two. Asking a coordinator what it is
// used to mean starting it, and starting a coordinator means binding a public UDP
// port — so on a live box the question could not be asked at all without changing
// what the box was doing. -version is answered before the listener, before the
// TURN credentials are checked and before -print-bootstrap-pubkey, which
// GENERATES a signing key when none is there.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// coordinatorVersionOutput builds cmd/coordinator with a given -ldflags, runs it
// with -version and no other flag at all, and returns stdout.
//
// "No other flag" is part of the assertion rather than a convenience: the
// coordinator refuses to start without -turn-public-ip and -turn-pass, so a
// -version answered after that check would be unanswerable on any box whose
// operator does not already have the credentials to hand. This run passing at all
// is the evidence that it is answered before them.
func coordinatorVersionOutput(t *testing.T, ldflags string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH, so this build-and-run check cannot run: %v", err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bacchus-coordinator")

	args := []string{"build"}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", bin, "./cmd/coordinator")
	build := exec.Command("go", args...)
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building cmd/coordinator: %v\n%s", err, out)
	}

	var stdout, stderr strings.Builder
	run := exec.Command(bin, "-version")
	// The working directory is the temp dir so that a run which wrongly reached
	// the bootstrap-key loader would leave its evidence here rather than in the
	// repository. Nine coordinator flags default to a relative secrets/ path.
	run.Dir = dir
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("%s -version: %v\nstderr:\n%s", bin, err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets")); err == nil {
		t.Fatalf("-version created a secrets/ directory. It must read no configuration and generate " +
			"no key: -print-bootstrap-pubkey MINTS a snapshot-signing key when none is there, and a " +
			"-version that reached it would change the box it was asked about (issue #263)")
	}
	return strings.TrimSpace(stdout.String())
}

// A build stamped the way deploy/install.sh, docs/RUNNING.md, deploy/bacchus-pin.sh
// and both workflows stamp it says that release when it is asked.
//
// The failure this catches produces no error anywhere: a `-X` whose symbol the
// linker cannot resolve is dropped with a zero exit, so the only evidence that a
// stamp landed is the value coming back out.
func TestCoordinatorVersionFlagReportsTheStampedRelease(t *testing.T) {
	raw, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatalf("reading the VERSION file: %v", err)
	}
	want := strings.TrimSpace(string(raw))

	got := coordinatorVersionOutput(t,
		"-X github.com/bacchus-vpn/bacchus/core/version.current="+want)
	if got != want {
		t.Fatalf("bacchus-coordinator -version printed %q, want %q from the VERSION file. The stamp "+
			"did not reach this binary: -ldflags -X naming a symbol the linker has no reference to is "+
			"ignored SILENTLY, with a zero exit, which is why this is read back out of a built binary "+
			"rather than asserted from the flag (issues #223, #263)", got, want)
	}
}

// An UNSTAMPED build answers 0.0.0 and does not refuse, because a bare `go build`
// must keep working (issue #128). Tested beside the case above on purpose: a
// -version printing something plausible either way would pass that test while
// telling an operator nothing.
func TestCoordinatorVersionFlagOnAnUnstampedBuildSaysNoRelease(t *testing.T) {
	if got := coordinatorVersionOutput(t, ""); got != "0.0.0" {
		t.Fatalf("an unstamped bacchus-coordinator printed %q, want 0.0.0 — the honest answer from a "+
			"binary nobody told which release it is", got)
	}
}
