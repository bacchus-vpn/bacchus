// Coverage for deploy/bacchus-pin.sh and deploy/bacchus-fleet-check.sh (issue #205,
// ADR-0064), in the form deploy/asn_drift_check_test.go established for this
// repository: a Go test that RUNS a shell build artifact rather than reading it.
//
// It matters more here than there. This lane cannot reach the boxes, so nothing about
// these scripts will ever be rehearsed on hardware before an operator runs them against
// a live fleet — and the properties that make the procedure worth having are exactly the
// ones a careful reading cannot confirm: that a failed transfer replaces nothing
// anywhere, that the coordinator restarts LAST, that no `.service` file is ever copied,
// and that an unstamped binary is refused before it leaves the building.
//
// So the fleet is simulated rather than mocked. `ssh` and `scp` are replaced by scripts
// that rewrite the remote path into a per-host directory and then really run the
// command, so `sha256sum`, `mv` and `rm` execute for real against real files; only
// `systemctl` and `go` are stubs, and both log what they were asked to do. What is being
// asserted is therefore the script's own control flow, not a second description of it.
package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	pinRelPath        = "deploy/bacchus-pin.sh"
	fleetCheckRelPath = "deploy/bacchus-fleet-check.sh"
	adrRelPath        = "docs/adr/0064-pinning-the-testbed-to-a-commit.md"

	// The fake fleet. Documentation hostnames throughout (RFC 2606's .invalid, which
	// resolves nowhere), the same rule deploy/testbed.env.example itself follows.
	coordTarget = "admin@coordinator.example.invalid"
	exitTarget  = "admin@exit-a.example.invalid"
	relayTarget = "admin@relay-b.example.invalid"

	fakeHead = "2f4f77887c679eaaf41046d27f5fd25dad15ea11"
)

// -------------------------------------------------------------------------
// the fake fleet
// -------------------------------------------------------------------------

type fleet struct {
	dir  string // holds bin/, root/, and the logs
	repo string // a real git checkout the script builds "from"
	cfg  string // the host list
	t    *testing.T
}

func (f *fleet) log(name string) string {
	b, err := os.ReadFile(filepath.Join(f.dir, name))
	if err != nil {
		return ""
	}
	return string(b)
}

// remoteFile is the path a file on `target` really lives at inside the fake fleet.
func (f *fleet) remoteFile(target, name string) string {
	return filepath.Join(f.dir, "root", target, "usr/local/bin", name)
}

func write(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("WriteFile %s: %v", path, err)
	}
}

// newFleet builds a temporary world: a real one-commit git checkout to build from, a
// per-host directory tree, and fake ssh/scp/go/systemctl/journalctl.
func newFleet(t *testing.T) *fleet {
	t.Helper()
	dir := t.TempDir()
	f := &fleet{dir: dir, t: t}

	// A real checkout: the script's first refusal is "this is a git worktree", and the
	// only honest way to get past it is a directory with a real .git in it.
	f.repo = filepath.Join(dir, "checkout")
	write(t, filepath.Join(f.repo, "VERSION"), "0.1.0\n", 0o644)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = f.repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, b)
		}
	}
	git("init", "-q")
	git("add", "-A")
	git("commit", "-q", "-m", "x")
	head := strings.TrimSpace(run(t, f.repo, "git", "rev-parse", "HEAD"))
	write(t, filepath.Join(dir, "HEAD"), head, 0o644)

	for _, target := range []string{coordTarget, exitTarget, relayTarget} {
		// Each box starts with a previous binary in place. That is what a failed
		// transfer has to leave untouched.
		name := "bacchus-node"
		if target == coordTarget {
			name = "bacchus-coordinator"
		}
		write(t, f.remoteFile(target, name), "PREVIOUS BINARY\n", 0o755)
	}

	bin := filepath.Join(dir, "bin")
	// ssh: rewrite /usr/local/bin into this host's tree, then really run the command.
	write(t, filepath.Join(bin, "ssh"), `#!/bin/sh
target="$1"; shift
printf '%s\t%s\n' "$target" "$*" >> "$FLEET/ssh.log"
if [ -f "$FLEET/fail-ssh-$target" ]; then exit 255; fi
root="$FLEET/root/$target/usr/local/bin"
mkdir -p "$root"
cmd=$(printf '%s' "$*" | sed "s|/usr/local/bin|$root|g")
PATH="$FLEET/bin:$PATH" FLEET="$FLEET" TARGET="$target" sh -c "$cmd"
`, 0o755)
	// scp: the same rewrite, then a real copy.
	write(t, filepath.Join(bin, "scp"), `#!/bin/sh
src="$1"; dst="$2"
printf '%s\t%s\n' "$src" "$dst" >> "$FLEET/scp.log"
target="${dst%%:*}"; path="${dst#*:}"
if [ -f "$FLEET/fail-scp-$target" ]; then
  echo "scp: connection closed" >&2
  exit 1
fi
root="$FLEET/root/$target/usr/local/bin"
mkdir -p "$root"
real=$(printf '%s' "$path" | sed "s|/usr/local/bin|$root|")
cp "$src" "$real"
if [ -f "$FLEET/corrupt-$target" ]; then printf 'x' >> "$real"; fi
`, 0o755)
	write(t, filepath.Join(bin, "systemctl"), `#!/bin/sh
printf '%s\t%s\n' "$TARGET" "$*" >> "$FLEET/systemctl.log"
case "$1" in
show) cat "$FLEET/unit-show" 2>/dev/null || true ;;
esac
`, 0o755)
	write(t, filepath.Join(bin, "journalctl"), `#!/bin/sh
cat "$FLEET/journal" 2>/dev/null || true
`, 0o755)
	// go: builds a deterministic stub and answers the two metadata questions the
	// script asks about it. Every answer is a file the test can rewrite, which is how
	// the stamp-verification failures below are provoked.
	write(t, filepath.Join(bin, "go"), `#!/bin/sh
case "$1 $2" in
"version -m")
  cat "$FLEET/go-version-m"
  exit 0
  ;;
"tool nm")
  if [ -f "$FLEET/no-str-symbol" ]; then
    echo "  ec4a80 D github.com/bacchus-vpn/bacchus/core/version.current"
  else
    echo "  ec4a80 D github.com/bacchus-vpn/bacchus/core/version.current"
    echo "  897b68 R github.com/bacchus-vpn/bacchus/core/version.current.str"
  fi
  exit 0
  ;;
esac
out=""
pkg=""
prev=""
for a in "$@"; do
  case "$prev" in -o) out="$a" ;; esac
  case "$a" in ./cmd/*) pkg="$a" ;; esac
  prev="$a"
done
# A runnable stub: the pin script executes the one it builds for cmd/coordinator-probe.
{ echo '#!/bin/sh'
  echo "# BUILT $pkg"
  echo 'echo "CURRENT (probe stub)"'
  echo 'if [ -f "$FLEET/fail-probe" ]; then exit 1; fi'
} > "$out"
chmod 0755 "$out"
printf 'build\t%s\n' "$*" >> "$FLEET/go.log"
exit 0
`, 0o755)

	write(t, filepath.Join(dir, "go-version-m"), `stub: go1.26.4
	build	-ldflags="-X github.com/bacchus-vpn/bacchus/core/version.current=0.1.0"
	build	CGO_ENABLED=0
	build	vcs=git
	build	vcs.revision=`+head+`
	build	vcs.modified=false
`, 0o644)

	f.cfg = filepath.Join(dir, "testbed.env")
	write(t, f.cfg, "COORDINATOR_TARGET="+coordTarget+"\n"+
		"COORDINATOR_UNIT=bacchus-coordinator\n"+
		"COORDINATOR_SIGNALING=coordinator.example.invalid:8080\n"+
		"NODE_TARGETS=\""+exitTarget+"=bacchus-exit "+relayTarget+"=bacchus-relay\"\n"+
		"BIN_DIR=/usr/local/bin\n", 0o644)

	return f
}

func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, b)
	}
	return string(b)
}

func (f *fleet) head() string {
	b, _ := os.ReadFile(filepath.Join(f.dir, "HEAD"))
	return strings.TrimSpace(string(b))
}

// pin runs the real script against the fake fleet and returns its output and exit code.
func (f *fleet) pin(extra ...string) (string, int) {
	f.t.Helper()
	root := repoRoot(f.t)
	args := append([]string{filepath.Join(root, pinRelPath), "--config", f.cfg, "--repo", f.repo}, extra...)
	cmd := exec.Command("sh", args...)
	cmd.Env = append(os.Environ(),
		"FLEET="+f.dir,
		"BACCHUS_SSH="+filepath.Join(f.dir, "bin", "ssh"),
		"BACCHUS_SCP="+filepath.Join(f.dir, "bin", "scp"),
		"BACCHUS_GO="+filepath.Join(f.dir, "bin", "go"),
		"BACCHUS_PIN_SETTLE=0",
	)
	b, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if err != nil {
		if !asExitError(err, &ee) {
			f.t.Fatalf("running %s: %v\n%s", pinRelPath, err, b)
		}
		code = ee.ExitCode()
	}
	return string(b), code
}

func asExitError(err error, out **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*out = ee
	}
	return ok
}

func (f *fleet) remote(target, name string) string {
	b, err := os.ReadFile(f.remoteFile(target, name))
	if err != nil {
		return ""
	}
	return string(b)
}

// -------------------------------------------------------------------------
// the properties
// -------------------------------------------------------------------------

// The happy path, and the four things it has to get right at once.
func TestPin_DeploysEveryBoxFromOneBuild(t *testing.T) {
	f := newFleet(t)
	out, code := f.pin("--no-verify")
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}

	// 1. Every box holds the new binary.
	for _, c := range []struct{ target, name string }{
		{coordTarget, "bacchus-coordinator"},
		{exitTarget, "bacchus-node"},
		{relayTarget, "bacchus-node"},
	} {
		if got := f.remote(c.target, c.name); !strings.Contains(got, "BUILT ") {
			t.Errorf("%s still holds %q", c.target, got)
		}
		// 2. And no temporary file survives it.
		if f.remote(c.target, c.name+".bacchus-pin.new") != "" {
			t.Errorf("%s: the staging file was left behind", c.target)
		}
	}

	// 3. One build, not one per box: two `go build` invocations for two binaries,
	//    and the node's is copied to both node boxes.
	if n := strings.Count(f.log("go.log"), "build\t"); n != 2 {
		t.Errorf("%d go build invocations, want 2 (one per binary, shared across boxes):\n%s", n, f.log("go.log"))
	}

	// 4. Nothing that is not a binary is ever copied — a .service file least of all.
	if strings.Contains(f.log("scp.log"), ".service") {
		t.Errorf("a unit file was copied; the coordinator's real unit carries hand-added flags\n%s", f.log("scp.log"))
	}
}

// The ordering the whole node-revision check rests on. Restart the coordinator first
// and no node prints a `registered:` line, because each is back inside the 35s registry
// TTL — so the journal keeps answering with values from before the deploy.
func TestPin_CoordinatorRestartsLast(t *testing.T) {
	f := newFleet(t)
	if _, code := f.pin("--no-verify"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSpace(f.log("systemctl.log")), "\n")
	lastNode, coordStart := -1, -1
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, coordTarget+"\tstart"):
			coordStart = i
		case !strings.HasPrefix(l, coordTarget+"\t") && strings.Contains(l, "\tstart "):
			if i > lastNode {
				lastNode = i
			}
		}
	}
	if coordStart < 0 || lastNode < 0 {
		t.Fatalf("could not find both a node start and the coordinator start:\n%s", f.log("systemctl.log"))
	}
	if coordStart < lastNode {
		t.Errorf("the coordinator restarted before the last node — the fleet check then reads pre-deploy values:\n%s", f.log("systemctl.log"))
	}
}

// A failed transfer must leave the fleet entirely on its previous build. Half-updated
// is the state issue #114 was opened about; entirely-previous is a state that works.
func TestPin_FailedTransferReplacesNothingAnywhere(t *testing.T) {
	f := newFleet(t)
	write(t, filepath.Join(f.dir, "fail-scp-"+relayTarget), "", 0o644)

	out, code := f.pin("--no-verify")
	if code == 0 {
		t.Fatalf("exit 0 despite a failed transfer\n%s", out)
	}
	for _, c := range []struct{ target, name string }{
		{coordTarget, "bacchus-coordinator"},
		{exitTarget, "bacchus-node"},
		{relayTarget, "bacchus-node"},
	} {
		if got := f.remote(c.target, c.name); got != "PREVIOUS BINARY\n" {
			t.Errorf("%s: live binary is %q — a failed transfer replaced something", c.target, got)
		}
		if f.remote(c.target, c.name+".bacchus-pin.new") != "" {
			t.Errorf("%s: a staging file was left behind after the failure", c.target)
		}
	}
	if strings.Contains(f.log("systemctl.log"), "stop") {
		t.Errorf("a unit was stopped even though staging failed:\n%s", f.log("systemctl.log"))
	}
	if !strings.Contains(out, "still entirely on its previous build") {
		t.Errorf("the failure does not tell the operator what state the fleet is in:\n%s", out)
	}
}

// A transfer that arrives corrupted is caught on the box, before anything is replaced.
// This is the check that makes "scp exited 0" stop being the definition of deployed.
func TestPin_CorruptTransferIsCaughtBeforeAnythingIsReplaced(t *testing.T) {
	f := newFleet(t)
	write(t, filepath.Join(f.dir, "corrupt-"+exitTarget), "", 0o644)

	out, code := f.pin("--no-verify")
	if code == 0 {
		t.Fatalf("exit 0 despite a corrupted transfer\n%s", out)
	}
	if !strings.Contains(out, "digests") {
		t.Errorf("the digest mismatch is not reported:\n%s", out)
	}
	if got := f.remote(coordTarget, "bacchus-coordinator"); got != "PREVIOUS BINARY\n" {
		t.Errorf("the coordinator was replaced anyway: %q", got)
	}
}

// A build whose release stamp did not land must never leave the building: on the box it
// reports 0.0.0, which the version fence cannot rank and the skew warning cannot compare.
func TestPin_RefusesAnUnstampedBuild(t *testing.T) {
	f := newFleet(t)
	write(t, filepath.Join(f.dir, "go-version-m"), "stub: go1.26.4\n\tbuild\tCGO_ENABLED=0\n\tbuild\tvcs.revision="+f.head()+"\n\tbuild\tvcs.modified=false\n", 0o644)

	out, code := f.pin("--no-verify")
	if code == 0 {
		t.Fatalf("exit 0 for an unstamped build\n%s", out)
	}
	if !strings.Contains(out, "WITHOUT the release stamp") {
		t.Errorf("the refusal does not name the cause:\n%s", out)
	}
	if f.log("scp.log") != "" {
		t.Errorf("something was copied before the stamp was verified:\n%s", f.log("scp.log"))
	}
}

// `-X` naming a symbol that does not exist is silently ignored by the linker: the flag
// is recorded, the build succeeds, and the binary reports 0.0.0 anyway. `go version -m`
// cannot see that; the missing `.str` symbol can.
func TestPin_RefusesAStampThatDidNotLand(t *testing.T) {
	f := newFleet(t)
	write(t, filepath.Join(f.dir, "no-str-symbol"), "", 0o644)

	out, code := f.pin("--no-verify")
	if code == 0 {
		t.Fatalf("exit 0 for a stamp the linker ignored\n%s", out)
	}
	if !strings.Contains(out, "did not APPLY it") {
		t.Errorf("the refusal does not distinguish a recorded stamp from an applied one:\n%s", out)
	}
}

// A build from a tree that does not match the commit being pinned is not a pin.
func TestPin_RefusesAMismatchedRevision(t *testing.T) {
	f := newFleet(t)
	write(t, filepath.Join(f.dir, "go-version-m"), "stub: go1.26.4\n"+
		"\tbuild\t-ldflags=\"-X github.com/bacchus-vpn/bacchus/core/version.current=0.1.0\"\n"+
		"\tbuild\tvcs.revision="+fakeHead+"\n\tbuild\tvcs.modified=false\n", 0o644)

	out, code := f.pin("--no-verify")
	if code == 0 || !strings.Contains(out, "does not carry vcs.revision") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// --commit is an assertion, not an instruction: the script never moves HEAD. A script
// that checked the commit out for you could turn a half-finished rebase into a
// deployment, and would do it at the moment the operator was least expecting a write.
func TestPin_RefusesWhenHEADIsNotTheNamedCommit(t *testing.T) {
	f := newFleet(t)

	// A commit that really exists in this repository and is not the one checked out.
	write(t, filepath.Join(f.repo, "other"), "x\n", 0o644)
	run(t, f.repo, "git", "add", "-A")
	run(t, f.repo, "git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "other")
	other := strings.TrimSpace(run(t, f.repo, "git", "rev-parse", "HEAD"))
	run(t, f.repo, "git", "reset", "-q", "--hard", "HEAD~1")

	out, code := f.pin("--no-verify", "--commit", other)
	if code != 2 {
		t.Fatalf("exit %d, want 2\n%s", code, out)
	}
	if !strings.Contains(out, "never moves HEAD") {
		t.Errorf("the refusal does not say who is expected to check the commit out:\n%s", out)
	}
	if f.log("go.log") != "" {
		t.Error("it built something before checking the commit")
	}

	// A commit that is not in this repository at all is a different mistake and gets a
	// different sentence.
	out, code = f.pin("--no-verify", "--commit", fakeHead)
	if code != 2 || !strings.Contains(out, "is not a commit in") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// A dirty tree is not a named commit, so there is nothing to pin the fleet to.
func TestPin_RefusesADirtyTree(t *testing.T) {
	f := newFleet(t)
	write(t, filepath.Join(f.repo, "VERSION"), "9.9.9\n", 0o644)
	out, code := f.pin("--no-verify")
	if code != 2 || !strings.Contains(out, "uncommitted changes") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// The refusal an agent or an operator working in this repository hits first, and the one
// with the least obvious cause: a git worktree records no VCS data, so every binary
// built in one reports build=unknown and the fleet check has nothing to compare.
func TestPin_RefusesAWorktreeCheckout(t *testing.T) {
	f := newFleet(t)
	fakeWorktree := filepath.Join(f.dir, "worktree")
	write(t, filepath.Join(fakeWorktree, ".git"), "gitdir: /elsewhere\n", 0o644)

	root := repoRoot(t)
	cmd := exec.Command("sh", filepath.Join(root, pinRelPath), "--config", f.cfg, "--repo", fakeWorktree, "--no-verify")
	cmd.Env = append(os.Environ(), "FLEET="+f.dir)
	b, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("exit 0 for a worktree\n%s", b)
	}
	if !strings.Contains(string(b), "git worktree") || !strings.Contains(string(b), "build=unknown") {
		t.Errorf("the refusal does not explain what a worktree costs:\n%s", b)
	}
}

// The end-to-end result, including both checks. A journal in which every node reports
// the pinned revision, and a probe that exits 0, is the only combination that passes.
func TestPin_VerifiesByReadingTheJournalAndProbing(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	write(t, filepath.Join(f.dir, "journal"), journalFor(head[:12], head[:12], head[:12]), 0o644)
	write(t, filepath.Join(f.dir, "unit-show"),
		"ExecStart={ path=/usr/local/bin/bacchus-coordinator ; argv[]=/usr/local/bin/bacchus-coordinator -advertise 192.0.2.1:8080 }\nWorkingDirectory=\n", 0o644)

	out, code := f.pin()
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "the fleet is pinned to") {
		t.Errorf("the fleet check did not run or did not pass:\n%s", out)
	}
	if !strings.Contains(out, "CURRENT") {
		t.Errorf("the capability probe did not report on the deployment:\n%s", out)
	}
}

// One stale node is the whole point. The binaries are on the boxes either way; what
// must not happen is the script reporting success.
func TestPin_VerificationFailsOnAStaleNode(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	write(t, filepath.Join(f.dir, "journal"), journalFor(head[:12], head[:12], "a868e6e3c447"), 0o644)

	out, code := f.pin()
	if code != 3 {
		t.Fatalf("exit %d, want 3\n%s", code, out)
	}
	if !strings.Contains(out, "MISMATCH") {
		t.Errorf("the stale node is not named:\n%s", out)
	}
	if !strings.Contains(out, "assumes the pin held") {
		t.Errorf("the operator is not told what the failure means for the boxes:\n%s", out)
	}
}

// A journal in which every node is on the pinned commit is not the whole answer: the
// coordinator may be on the right binary and not serving what that binary carries — a
// flag, a firewall, a unit that failed to come back. The probe is a second, independent
// question, and its failure has to fail the run.
func TestPin_VerificationFailsWhenTheProbeDoes(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	write(t, filepath.Join(f.dir, "journal"), journalFor(head[:12], head[:12], head[:12]), 0o644)
	write(t, filepath.Join(f.dir, "fail-probe"), "", 0o644)

	out, code := f.pin()
	if code != 3 {
		t.Fatalf("exit %d, want 3 — a clean journal must not carry a failed probe\n%s", code, out)
	}
	if !strings.Contains(out, "the fleet is pinned to") {
		t.Errorf("the journal check should still have passed:\n%s", out)
	}
}

// The live mis-set on the box today: the unit has WorkingDirectory unset, so a relative
// path in ExecStart resolves under /, and a revocation file that is not there does not
// fail — it means nothing is revoked.
func TestPin_WarnsAboutRelativePathsUnderAnEmptyWorkingDirectory(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	write(t, filepath.Join(f.dir, "journal"), journalFor(head[:12], head[:12], head[:12]), 0o644)
	write(t, filepath.Join(f.dir, "unit-show"),
		"ExecStart={ argv[]=/usr/local/bin/bacchus-coordinator -device-revocations secrets/device-revocations.json }\nWorkingDirectory=\n", 0o644)

	out, _ := f.pin()
	if !strings.Contains(out, "secrets/device-revocations.json") || !strings.Contains(out, "nothing is revoked") {
		t.Errorf("the relative-path warning did not fire:\n%s", out)
	}
}

// journalFor renders a coordinator journal in which the coordinator started at coord and
// two nodes then registered at the given revisions.
func journalFor(coord, exitRev, relayRev string) string {
	return "Aug 08 11:00:00 box bacchus-coordinator[9]: exit registered: n7 -> 192.0.2.10:20000 country=NL (observed IP) release=0.1.0 build=deadbeefdead\n" +
		"Aug 08 12:00:00 box bacchus-coordinator[9]: version fence DISABLED (-min-serving-version 0.0.0) — any node version may serve (issue #36); coordinator release 0.1.0 (revision " + coord + ")\n" +
		"Aug 08 12:00:03 box bacchus-coordinator[9]: exit registered: n7 -> 192.0.2.10:20000 country=NL (observed IP) release=0.1.0 build=" + exitRev + "\n" +
		"Aug 08 12:00:04 box bacchus-coordinator[9]: relay registered: n9 (192.0.2.20:41234) country=DE (node hint, unresolved IP) release=0.1.0 build=" + relayRev + "\n"
}

// -------------------------------------------------------------------------
// bacchus-fleet-check.sh on its own
// -------------------------------------------------------------------------

func fleetCheck(t *testing.T, journal string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(repoRoot(t), fleetCheckRelPath)}, args...)...)
	cmd.Stdin = strings.NewReader(journal)
	b, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if err != nil {
		if !asExitError(err, &ee) {
			t.Fatalf("running %s: %v\n%s", fleetCheckRelPath, err, b)
		}
		code = ee.ExitCode()
	}
	return string(b), code
}

// The property that makes this check trustworthy rather than merely convenient:
// registrations from BEFORE the coordinator restarted are not evidence about what is
// running now, and they look exactly as convincing.
func TestFleetCheck_IgnoresRegistrationsFromBeforeTheRestart(t *testing.T) {
	j := "exit registered: n7 -> 192.0.2.10:20000 release=0.1.0 build=aaaaaaaaaaaa\n" +
		"coordinator release 0.1.0 (revision bbbbbbbbbbbb)\n" +
		"exit registered: n7 -> 192.0.2.10:20000 release=0.1.0 build=bbbbbbbbbbbb\n"
	out, code := fleetCheck(t, j, "bbbbbbbbbbbb")
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if strings.Contains(out, "aaaaaaaaaaaa") {
		t.Errorf("a pre-restart registration reached the verdict:\n%s", out)
	}
}

// A journal window with no coordinator start in it cannot answer the question at all,
// and must say so rather than reporting on whatever it happens to contain.
func TestFleetCheck_RefusesAWindowWithNoCoordinatorStart(t *testing.T) {
	j := "exit registered: n7 -> 192.0.2.10:20000 release=0.1.0 build=bbbbbbbbbbbb\n"
	out, code := fleetCheck(t, j, "bbbbbbbbbbbb")
	if code != 3 {
		t.Fatalf("exit %d, want 3\n%s", code, out)
	}
	if !strings.Contains(out, "Widen the window") {
		t.Errorf("the refusal is not actionable:\n%s", out)
	}
}

// The rolling-restart trap in its purest form: the coordinator restarted and no node has
// registered since, so there is nothing to read. That is a distinct finding from drift.
func TestFleetCheck_ReportsNoRegistrationsSeparately(t *testing.T) {
	out, code := fleetCheck(t, "coordinator release 0.1.0 (revision bbbbbbbbbbbb)\n", "bbbbbbbbbbbb")
	if code != 4 {
		t.Fatalf("exit %d, want 4\n%s", code, out)
	}
	if !strings.Contains(out, "NO node has registered since") {
		t.Errorf("%s", out)
	}
}

// A 40-character sha and the 12 characters the wire carries are the same commit. Both
// must be accepted, or the check fails against a correct deployment — and `git rev-parse
// --short` produces a THIRD length, which is why the comparison truncates rather than
// compares as strings.
func TestFleetCheck_AcceptsAnyRevisionLength(t *testing.T) {
	j := "coordinator release 0.1.0 (revision 2f4f77887c67)\n" +
		"exit registered: n7 -> 192.0.2.10:20000 release=0.1.0 build=2f4f77887c67\n"
	for _, rev := range []string{fakeHead, "2f4f77887c67", "2F4F77887C67", "2f4f778"} {
		if out, code := fleetCheck(t, j, rev); code != 0 {
			t.Errorf("%s: exit %d\n%s", rev, code, out)
		}
	}
}

func TestFleetCheck_UnknownAndDirtyAreFailures(t *testing.T) {
	t.Run("node built without VCS data", func(t *testing.T) {
		j := "coordinator release 0.1.0 (revision 2f4f77887c67)\n" +
			"exit registered: n7 -> 192.0.2.10:20000 release=0.1.0 build=unknown\n"
		out, code := fleetCheck(t, j, "2f4f77887c67")
		if code != 1 || !strings.Contains(out, "UNRECORDED") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("node built dirty", func(t *testing.T) {
		j := "coordinator release 0.1.0 (revision 2f4f77887c67)\n" +
			"exit registered: n7 -> 192.0.2.10:20000 release=0.1.0 build=2f4f77887c67-dirty\n"
		out, code := fleetCheck(t, j, "2f4f77887c67")
		if code != 1 || !strings.Contains(out, "DIRTY") {
			t.Fatalf("a -dirty suffix truncates to a MATCHING 12 characters, so this is exactly the "+
				"case a naive comparison passes: exit %d\n%s", code, out)
		}
	})
	t.Run("coordinator built dirty", func(t *testing.T) {
		// The coordinator renders its own dirty flag differently from a node's wire
		// value — ", uncommitted changes" against "-dirty" — so one pattern silently
		// reports the other as clean.
		j := "coordinator release 0.1.0 (revision 2f4f77887c67, uncommitted changes)\n" +
			"exit registered: n7 -> 192.0.2.10:20000 release=0.1.0 build=2f4f77887c67\n"
		out, code := fleetCheck(t, j, "2f4f77887c67")
		if code != 1 || !strings.Contains(out, "DIRTY") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
	t.Run("coordinator with no revision recorded", func(t *testing.T) {
		j := "coordinator release 0.1.0 (no build revision recorded — see coordBuild)\n" +
			"exit registered: n7 -> 192.0.2.10:20000 release=0.1.0 build=2f4f77887c67\n"
		out, code := fleetCheck(t, j, "2f4f77887c67")
		if code != 1 || !strings.Contains(out, "UNRECORDED") {
			t.Fatalf("exit %d\n%s", code, out)
		}
	})
}

func TestFleetCheck_RefusesAnUnusableRevisionArgument(t *testing.T) {
	for _, arg := range []string{"", "abc123", "zzzzzzzz", "2f4f778 extra"} {
		if out, code := fleetCheck(t, "", arg); code != 2 {
			t.Errorf("%q: exit %d, want 2\n%s", arg, code, out)
		}
	}
}

// -------------------------------------------------------------------------
// the invariant this repository cannot lose
// -------------------------------------------------------------------------

// Deployment documentation is the artifact in this repository most likely to carry a
// real address into a public one, and a procedure is written by pasting from a session
// where the real values were right there. Nothing here can prove a given address is not
// the owner's, so this asserts the rule that makes the question answerable instead:
// every IPv4 literal and every registrable hostname in these files is documentation-only.
//
// It scans the deployment artifacts rather than the whole tree, because it is the rule
// for THESE files: prose elsewhere legitimately names upstreams (core/asn's feed) and
// third-party STUN servers.
func TestDeployArtifactsNameNoRealHost(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{pinRelPath, fleetCheckRelPath, "deploy/testbed.env.example", adrRelPath} {
		body := string(readFile(t, filepath.Join(root, rel)))

		for _, ip := range ipv4Literal.FindAllString(body, -1) {
			if !documentationIPv4(ip) {
				t.Errorf("%s: %s is an IPv4 literal outside the documentation ranges.\n"+
					"Use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24 (RFC 5737).", rel, ip)
			}
		}
		for _, h := range registrableHost.FindAllString(body, -1) {
			if !documentationHost(h) {
				t.Errorf("%s: %q is a registrable hostname.\n"+
					"Use example.invalid (RFC 2606) or a <placeholder>.", rel, h)
			}
		}
	}
}

var (
	// A bare dotted quad. Deliberately not anchored on word boundaries beyond \b, so a
	// host:port and an address inside a sentence both match.
	ipv4Literal = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	// A name under a public TLD somebody could actually register. The TLD list is the
	// point: it keeps `vcs.revision`, `bacchus-pin.new` and `version.current.str` out
	// while catching anything that resolves.
	registrableHost = regexp.MustCompile(`\b[a-z0-9][a-z0-9.-]*\.(com|net|org|io|dev|co|me|app|cloud|xyz|info|ru|de|nl|fr|uk|us|eu|ch|se|is)\b`)
)

func documentationIPv4(ip string) bool {
	for _, ok := range []string{"192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.1", "0.0.0.0", "255.255.255.255"} {
		if strings.HasPrefix(ip, ok) {
			return true
		}
	}
	return false
}

func documentationHost(h string) bool {
	switch {
	case h == "example.com" || strings.HasSuffix(h, ".example.com"):
		return true
	case strings.HasPrefix(h, "github.com/bacchus-vpn/"), h == "github.com":
		return true
	case strings.Contains(h, "iptoasn.com"):
		return true
	}
	return false
}
