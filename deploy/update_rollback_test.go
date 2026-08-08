// Coverage for deploy/bacchus-update-rollback.sh and its wiring (issue #222,
// ADR-0069), in the form deploy/asn_drift_check_test.go established here: a Go
// test that RUNS the shell rather than reading it.
//
// Two things make it worth more than a careful reading of the script.
//
// The marker it reads is written by core/update, in Go, with encoding/json — and
// read here in shell, with grep. Two encodings of one contract are exactly the
// pair that drifts silently, so these tests never hand-write a marker: every one
// of them is produced by calling the real update.Apply, and the assertions are on
// the bytes at the target path afterwards. If the field name, the type or the JSON
// shape changes on the Go side, this goes red.
//
// And the property that actually matters is a NEGATIVE one — that the two
// watchdogs do not fight. A supervisor-side rollback that fires in the case the
// in-process check already owns would undo a demotion the process had just
// performed, or roll back a release that was running perfectly, and nothing about
// reading the two mechanisms side by side proves it does not. So the case
// core/update owns is set up here for real, by running CheckStartup, and the
// script is then asserted to change nothing at all.
package deploy

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/update"
)

const rollbackRelPath = "deploy/bacchus-update-rollback.sh"

// The two builds, distinguishable by content because every assertion below is on
// bytes: "the script exited 0" is not evidence that the right binary is in place.
var (
	rollbackPrevBytes    = []byte("#!/bin/false\nI AM THE PREVIOUS BINARY, AND I WORK\n")
	rollbackReleaseBytes = []byte("#!/bin/false\nI AM THE RELEASE THAT CANNOT EXECUTE\n")
)

// box is a machine: a target binary, a fake systemctl that answers for one unit,
// and a log of what that systemctl was asked to do.
type box struct {
	t      *testing.T
	dir    string // holds bin/ and the systemctl log
	target string
	unit   string
}

func newBox(t *testing.T) *box {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	b := &box{t: t, dir: dir, target: filepath.Join(bin, "bacchus-node"), unit: "bacchus-exit.service"}
	if err := os.WriteFile(b.target, rollbackPrevBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	b.fakeSystemctl()
	return b
}

// fakeSystemctl writes the one external command the script depends on. It answers
// `show -p ExecStart --value` in systemd's real rendering — "{ path=… ; argv[]=… ;
// … }", copied from a live `systemctl show` rather than invented — and appends
// everything else to a log the assertions read.
func (b *box) fakeSystemctl() {
	b.t.Helper()
	script := "#!/bin/sh\n" +
		"log=" + filepath.Join(b.dir, "systemctl.log") + "\n" +
		"case \"$*\" in\n" +
		"  *ExecStart*) printf '{ path=" + b.target + " ; argv[]=" + b.target + " -role exit ; ignore_errors=no ; start_time=[n/a] ; pid=0 ; code=exited ; status=203 }\\n' ;;\n" +
		"  *) printf '%s\\n' \"$*\" >>\"$log\" ;;\n" +
		"esac\n"
	path := filepath.Join(b.dir, "bin", "systemctl")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		b.t.Fatal(err)
	}
}

// applyRelease publishes rollbackReleaseBytes over the target using the REAL
// apply, so the marker and the kept previous binary are the ones a node would
// have. Nothing here writes a marker by hand.
func (b *box) applyRelease(release string) {
	b.t.Helper()
	staged := b.target + ".staged-by-test"
	if err := os.WriteFile(staged, rollbackReleaseBytes, 0o755); err != nil {
		b.t.Fatal(err)
	}
	sum := sha256.Sum256(rollbackReleaseBytes)
	a := update.Artifact{
		OS: "linux", Arch: "amd64", Role: update.RoleNode,
		Size: int64(len(rollbackReleaseBytes)), SHA256: sum[:],
	}
	if err := update.Apply(b.target, staged, a, release); err != nil {
		b.t.Fatalf("update.Apply: %v", err)
	}
}

// rollback runs the real script with the fake systemctl first on PATH.
func (b *box) rollback() (string, int) {
	b.t.Helper()
	cmd := exec.Command("sh", filepath.Join(repoRoot(b.t), rollbackRelPath), b.unit)
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(b.dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if !asExitError(err, &ee) {
			b.t.Fatalf("running %s: %v\n%s", rollbackRelPath, err, out)
		}
		code = ee.ExitCode()
	}
	return string(out), code
}

func (b *box) targetBytes() []byte {
	b.t.Helper()
	got, err := os.ReadFile(b.target)
	if err != nil {
		b.t.Fatalf("read target: %v", err)
	}
	return got
}

func (b *box) systemctlLog() string {
	got, err := os.ReadFile(filepath.Join(b.dir, "systemctl.log"))
	if err != nil {
		return ""
	}
	return string(got)
}

func (b *box) markerExists() bool {
	_, err := os.Stat(update.MarkerPath(b.target))
	return err == nil
}

// The case this exists for: a release was applied, no process of it ever ran, and
// the unit is failing. The previous binary goes back and the unit is started.
func TestRollbackRestoresAReleaseThatNeverStarted(t *testing.T) {
	b := newBox(t)
	b.applyRelease("0.5.0")
	if string(b.targetBytes()) != string(rollbackReleaseBytes) {
		t.Fatal("the test setup did not publish the release")
	}

	out, code := b.rollback()
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if got := string(b.targetBytes()); got != string(rollbackPrevBytes) {
		t.Fatalf("the target was not rolled back; it holds %q", got)
	}
	if b.markerExists() {
		t.Fatal("the marker survived the rollback, so the restored binary would be rolled back again")
	}
	if _, err := os.Stat(update.PreviousPath(b.target)); err == nil {
		t.Fatal("the previous binary is still at .prev as well as at the target — it was copied, not renamed")
	}
	log := b.systemctlLog()
	for _, want := range []string{"reset-failed", "start"} {
		if !strings.Contains(log, want) {
			t.Fatalf("the unit was not %s after the rollback; systemctl saw:\n%s", want, log)
		}
	}
	if !strings.Contains(log, "--no-block") {
		t.Errorf("the start was not --no-block. A oneshot triggered by OnFailure= that blocks on a start "+
			"job of the unit that triggered it is a deadlock on the machine that most needs this to work; "+
			"systemctl saw:\n%s", log)
	}
	if !strings.Contains(out, "0.5.0") {
		t.Errorf("the rollback did not name the release it undid, which is the one thing the journal "+
			"line has to carry:\n%s", out)
	}
}

// OnFailure= fires on EVERY failed start under Restart=always — measured on
// systemd 259, where a unit configured to give up after three attempts triggered
// its handler four times — so this script runs repeatedly by design and not by
// accident. A second run must be a no-op and must NOT swap the release back in.
func TestRollbackIsIdempotent(t *testing.T) {
	b := newBox(t)
	b.applyRelease("0.5.0")
	if _, code := b.rollback(); code != 0 {
		t.Fatalf("first run exited %d", code)
	}
	if err := os.Remove(filepath.Join(b.dir, "systemctl.log")); err != nil {
		t.Fatal(err)
	}

	for i := range 3 {
		out, code := b.rollback()
		if code != 0 {
			t.Fatalf("run %d exited %d\n%s", i+2, code, out)
		}
		if got := string(b.targetBytes()); got != string(rollbackPrevBytes) {
			t.Fatalf("run %d changed the target to %q — a repeat run swapped the broken release back", i+2, got)
		}
	}
	if log := b.systemctlLog(); log != "" {
		t.Fatalf("a repeat run restarted the unit with nothing to roll back, which turns a unit that is "+
			"failing for some other reason into a restart loop; systemctl saw:\n%s", log)
	}
}

// The negative property: the case core/update already owns is set up for real,
// and the script must change nothing. A release that reached main once is a crash
// loop, and the in-process check demotes it on its next start.
func TestRollbackLeavesTheInProcessWatchdogsCaseAlone(t *testing.T) {
	b := newBox(t)
	b.applyRelease("0.5.0")

	// The release starts. This is exactly what a node's main does first.
	if err := update.CheckStartup(b.target); err != nil {
		t.Fatalf("CheckStartup on the release's first start: %v", err)
	}

	out, code := b.rollback()
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if got := string(b.targetBytes()); got != string(rollbackReleaseBytes) {
		t.Fatalf("the script rolled back a release that HAD started, which is the in-process check's "+
			"case: target now holds %q", got)
	}
	if !b.markerExists() {
		t.Fatal("the script cleared a marker it does not own, so the in-process check would no longer " +
			"demote this release on its next start and the crash loop would be permanent")
	}
	if log := b.systemctlLog(); log != "" {
		t.Fatalf("the script restarted the unit in a case it does not own; systemctl saw:\n%s", log)
	}

	// And the in-process check still does its job afterwards: the second start
	// demotes, which is what the script must not have interfered with.
	if err := update.CheckStartup(b.target); err == nil {
		t.Fatal("the in-process check no longer demotes after the script ran beside it")
	}
	if got := string(b.targetBytes()); got != string(rollbackPrevBytes) {
		t.Fatalf("after the in-process demotion the target holds %q", got)
	}
}

// A unit fails for a hundred reasons that are not an update. Every one of them
// reaches this script, and every one of them must leave the machine alone.
func TestRollbackDoesNothingWhenNoReleaseIsPending(t *testing.T) {
	b := newBox(t)
	out, code := b.rollback()
	if code != 0 {
		t.Fatalf("exit %d, want 0 — an ordinary unit failure is not this script's business\n%s", code, out)
	}
	if got := string(b.targetBytes()); got != string(rollbackPrevBytes) {
		t.Fatalf("the target changed with no release pending: %q", got)
	}
	if log := b.systemctlLog(); log != "" {
		t.Fatalf("the unit was restarted with nothing to roll back, which would turn any failure into a "+
			"restart loop; systemctl saw:\n%s", log)
	}
}

// A marker with no previous binary beside it cannot be acted on: the rollback is a
// rename and the file to rename is gone. It fails loudly rather than quietly
// leaving a machine that will never come back.
func TestRollbackFailsLoudlyWithNothingToRestore(t *testing.T) {
	b := newBox(t)
	b.applyRelease("0.5.0")
	if err := os.Remove(update.PreviousPath(b.target)); err != nil {
		t.Fatal(err)
	}

	out, code := b.rollback()
	if code == 0 {
		t.Fatalf("exit 0 with nothing to restore; the operator has to replace a binary by hand and "+
			"nothing said so\n%s", out)
	}
	if got := string(b.targetBytes()); got != string(rollbackReleaseBytes) {
		t.Fatalf("a failed rollback changed the target anyway: %q", got)
	}
	if !b.markerExists() {
		t.Error("the marker was cleared by a rollback that did not happen, destroying the only record " +
			"that a release was applied and never ran")
	}
	if !strings.Contains(out, "by hand") {
		t.Errorf("the failure does not say what the operator has to do:\n%s", out)
	}
}

// The unit name is the only argument, and a run without one must not guess.
func TestRollbackRefusesWithoutAUnit(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("sh", filepath.Join(root, rollbackRelPath))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("the script accepted no arguments:\n%s", out)
	}
}

// A script nothing invokes is the failure this whole mechanism could have. The
// wiring is asserted from the shipped files: both units that carry Restart=always
// name the handler, and the installer places the handler and its template unit.
func TestTheUnitsThatRestartForeverNameTheRollbackHandler(t *testing.T) {
	root := repoRoot(t)
	for _, unit := range []string{"bacchus-exit.service", "bacchus-coordinator.service"} {
		body := string(readFile(t, filepath.Join(root, "deploy", unit)))
		if !strings.Contains(body, "Restart=always") {
			t.Fatalf("%s no longer restarts forever; this test's premise, and the mechanism's, has changed", unit)
		}
		if !strings.Contains(body, "OnFailure=bacchus-update-rollback@%n.service") {
			t.Errorf("%s carries Restart=always and does not name the rollback handler, so a release that "+
				"will not start at all loops there forever with nothing outside the process able to see it "+
				"(issue #222)", unit)
		}
	}

	installer := string(readFile(t, filepath.Join(root, "deploy", "install.sh")))
	for _, want := range []string{
		"bacchus-update-rollback.sh",
		"bacchus-update-rollback@.service",
	} {
		if !strings.Contains(installer, want) {
			t.Errorf("deploy/install.sh does not install %s, so every unit it installs names an "+
				"OnFailure= handler that is not on the box", want)
		}
	}
}
