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
	"fmt"
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

	// The two node ids the fake fleet's boxes register as. Hex, because a real one
	// always is — an exit's IS its X25519 public key and a relay's is 6 random bytes
	// (core/engine.go, randID) — and because deploy/bacchus-node-id.sh keys on that
	// to keep `exit TCP server on …` and core/pool.go's line about somebody ELSE's
	// exit out of the answer.
	exitNodeID  = "a7c0ffee1234"
	relayNodeID = "a9beefcafe01"
)

const (
	nodeIDRelPath     = "deploy/bacchus-node-id.sh"
	unitCheckRelPath  = "deploy/bacchus-unit-check.sh"
	exitUnitRelPath   = "deploy/bacchus-exit.service"
	coordUnitRelPath  = "deploy/bacchus-coordinator.service"
	rollbackOnFailure = "OnFailure=bacchus-update-rollback@%n.service"
)

// nodeJournal renders what a node box's OWN journal holds after a start: the lines
// core.Engine.Start emits through e.emit, which reaches log.Println because cmd/node
// sets no Config.OnEvent. Rendered here for the fake fleet; the shape is held against
// the real binary by TestTheNodeStartupLineCarriesTheIdThisScriptReads.
func nodeJournal(role, id string) string {
	b := "Aug 08 12:00:00 box bacchus-node[7]: transport webrtc, dtls fingerprint: firefox\n"
	if role == "exit" {
		b += "Aug 08 12:00:00 box bacchus-node[7]: exit " + id + " (NL) advertising 192.0.2.10:20000 + direct WebRTC\n"
		b += "Aug 08 12:00:00 box bacchus-node[7]: exit TCP server on 192.0.2.10:20000\n"
		return b
	}
	return b + "Aug 08 12:00:00 box bacchus-node[7]: relay " + id + " online\n"
}

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
	// systemctl: `show` answers from $FLEET/unit-show, `cat` from
	// $FLEET/unit-cat-$TARGET — per host, because the unit comparison (issue #234)
	// asks every box and the interesting fixtures differ per box.
	write(t, filepath.Join(bin, "systemctl"), `#!/bin/sh
printf '%s\t%s\n' "$TARGET" "$*" >> "$FLEET/systemctl.log"
case "$1" in
show) cat "$FLEET/unit-show" 2>/dev/null || true ;;
cat) cat "$FLEET/unit-cat-$TARGET" 2>/dev/null || true ;;
esac
`, 0o755)
	// journalctl: a NODE box answers from $FLEET/journal-$TARGET (and
	// $FLEET/journal-$TARGET.2 on the second read of that box, after the containment
	// restart), because a node's own journal is where it states its id (issue #232).
	// The COORDINATOR's journal is the Nth read from $FLEET/journal.N when that file
	// exists and $FLEET/journal otherwise: one pin run reads it twice — the fleet
	// check, and the re-check after it restarts a node that did not come back (issue
	// #225) — and a fixed answer could not tell a restart that worked from one that
	// changed nothing.
	//
	// The two counters are separate. Interleaving node reads into the coordinator's
	// sequence would make journal.2 arrive on whichever ssh happened to be third.
	write(t, filepath.Join(bin, "journalctl"), `#!/bin/sh
if [ -f "$FLEET/journal-$TARGET" ]; then
  c="$FLEET/node-reads-$TARGET"
  n=$(cat "$c" 2>/dev/null || echo 0)
  n=$((n + 1))
  echo "$n" > "$c"
  if [ -f "$FLEET/journal-$TARGET.$n" ]; then cat "$FLEET/journal-$TARGET.$n"; else cat "$FLEET/journal-$TARGET"; fi
  exit 0
fi
case "$*" in
*bacchus-coordinator*) ;;
*) exit 0 ;;   # a node box with no fixture answers nothing, rather than eating a coordinator read
esac
n=$(cat "$FLEET/journal.reads" 2>/dev/null || echo 0)
n=$((n + 1))
echo "$n" > "$FLEET/journal.reads"
if [ -f "$FLEET/journal.$n" ]; then cat "$FLEET/journal.$n"; else cat "$FLEET/journal" 2>/dev/null || true; fi
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
"test -count=1")
  # core/version's own stamp read-back, which the pin script runs before building.
  if [ -f "$FLEET/stamp-does-not-resolve" ]; then
    echo "--- FAIL: TestStampMatchesTheVersionFile" >&2
    exit 1
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

	// The fake fleet starts out correctly deployed, so a test that wants a gap creates
	// one rather than every test inheriting one. Each node box states its own id in
	// its own journal (issue #232), and each box whose unit this repository ships runs
	// exactly what is shipped (issue #234).
	write(t, filepath.Join(dir, "journal-"+exitTarget), nodeJournal("exit", exitNodeID), 0o644)
	write(t, filepath.Join(dir, "journal-"+relayTarget), nodeJournal("relay", relayNodeID), 0o644)
	root := repoRoot(t)
	write(t, filepath.Join(dir, "unit-cat-"+coordTarget),
		"# /etc/systemd/system/bacchus-coordinator.service\n"+string(readFile(t, filepath.Join(root, coordUnitRelPath))), 0o644)
	write(t, filepath.Join(dir, "unit-cat-"+exitTarget),
		"# /etc/systemd/system/bacchus-exit.service\n"+string(readFile(t, filepath.Join(root, exitUnitRelPath))), 0o644)

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

// `-X` naming a symbol that does not resolve is silently ignored by the linker: the
// flag is recorded, the build succeeds, and the binary reports 0.0.0 anyway. No reading
// of the built binary's metadata can see that, so the check is core/version's own
// read-back — and it has to run BEFORE anything is built, or the refusal arrives after
// the work.
func TestPin_RefusesAStampThatDoesNotResolve(t *testing.T) {
	f := newFleet(t)
	write(t, filepath.Join(f.dir, "stamp-does-not-resolve"), "", 0o644)

	out, code := f.pin("--no-verify")
	if code == 0 {
		t.Fatalf("exit 0 for a stamp the linker ignored\n%s", out)
	}
	if !strings.Contains(out, "IGNORED SILENTLY") {
		t.Errorf("the refusal does not distinguish a recorded stamp from a resolved one:\n%s", out)
	}
	if f.log("go.log") != "" {
		t.Errorf("it built binaries before establishing that the stamp resolves:\n%s", f.log("go.log"))
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

// The live mis-set on the box today, and the one the warning could not see
// (issue #226).
//
// Every path written into the real unit's ExecStart is ABSOLUTE. `WorkingDirectory=`
// is empty all the same, and cmd/coordinator's nine relative-default flags — both
// revocation lists among them — are not in ExecStart at all, because a flag left at its
// default never is. So the old condition (empty WorkingDirectory AND a relative path in
// ExecStart) stayed silent on exactly the deployment it was written for, and this input
// was a clean pass.
//
// MUTATION: put the `[ -n "$rel" ]` guard back around the warning — this goes red and
// TestPin_VerifiesByReadingTheJournalAndProbing keeps passing, which is how the case
// stayed invisible.
func TestPin_WarnsOnAnEmptyWorkingDirectoryEvenWhenExecStartIsAllAbsolute(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	write(t, filepath.Join(f.dir, "journal"), journalFor(head[:12], head[:12], head[:12]), 0o644)
	write(t, filepath.Join(f.dir, "unit-show"),
		"ExecStart={ path=/usr/local/bin/bacchus-coordinator ; argv[]=/usr/local/bin/bacchus-coordinator "+
			"-advertise 192.0.2.1:8080 -operators /etc/bacchus/operators.json }\nWorkingDirectory=\n", 0o644)

	out, code := f.pin()
	if code != 0 {
		t.Fatalf("exit %d — the warning is a warning, not a failure\n%s", code, out)
	}
	if !strings.Contains(out, "no WorkingDirectory=") {
		t.Errorf("an empty WorkingDirectory drew no warning, because nothing in ExecStart was relative:\n%s", out)
	}
	if !strings.Contains(out, "NOTHING IS REVOKED") {
		t.Errorf("the warning does not say what a path resolving nowhere costs:\n%s", out)
	}
	// It must not claim ExecStart names relative paths, because it does not.
	if strings.Contains(out, "ExecStart also spells out relative paths") {
		t.Errorf("the warning reports relative paths in an ExecStart that has none:\n%s", out)
	}
}

// A unit that DOES name a relative path still gets it listed — the extra detail was
// worth having, and issue #226 removed only its role as the gate.
func TestPin_WarnsAboutRelativePathsUnderAnEmptyWorkingDirectory(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	write(t, filepath.Join(f.dir, "journal"), journalFor(head[:12], head[:12], head[:12]), 0o644)
	write(t, filepath.Join(f.dir, "unit-show"),
		"ExecStart={ argv[]=/usr/local/bin/bacchus-coordinator -device-revocations secrets/device-revocations.json }\nWorkingDirectory=\n", 0o644)

	out, _ := f.pin()
	if !strings.Contains(out, "NOTHING IS REVOKED") {
		t.Errorf("the warning did not fire:\n%s", out)
	}
	if !strings.Contains(out, "ExecStart also spells out relative paths") ||
		!strings.Contains(out, "secrets/device-revocations.json") {
		t.Errorf("the relative path in ExecStart is no longer listed:\n%s", out)
	}
}

// -------------------------------------------------------------------------
// a node that did not come back (issues #224, #225)
// -------------------------------------------------------------------------

// The containment wave ruling R4 asked for, and only now that the check can see
// the condition at all: a node that did not re-register is restarted ONCE and the
// journal is read again.
//
// The cause is one this script creates. The coordinator restarts last — which is
// what makes `build=` fresh, and is not negotiable — so every node is brought up
// against the outgoing coordinator and then has it removed a second later, and a
// node in that state never rebuilds the link (issue #225: 100 minutes observed,
// fixed by a restart in under a second).
//
// MUTATION: drop the `-eq 4` guard so any failure restarts — TestPin_DoesNotRestart
// OnDrift goes red, which is the pair this one has to be read with.
func TestPin_RestartsANodeThatDidNotReRegister(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	rev := head[:12]
	// Two boxes are deployed (NODE_TARGETS) and only one registers.
	write(t, filepath.Join(f.dir, "journal"), journalOf(rev, registration{"exit", exitNodeID, rev}), 0o644)
	// After the restart, both do.
	write(t, filepath.Join(f.dir, "journal.2"), journalOf(rev,
		registration{"exit", exitNodeID, rev}, registration{"relay", relayNodeID, rev}), 0o644)

	out, code := f.pin()
	if code != 0 {
		t.Fatalf("exit %d, want 0 — the restart brought the missing node back\n%s", code, out)
	}
	if !strings.Contains(out, "1 of 2 expected node(s) did NOT register") {
		t.Errorf("the absent node was not reported as its own finding:\n%s", out)
	}
	// And it is NAMED, which is the whole of issue #232: the count said one of two,
	// the roll call says which one.
	if !strings.Contains(out, relayTarget+" (bacchus-relay) registers as "+relayNodeID) {
		t.Errorf("the absent box was not named:\n%s", out)
	}
	// Every node unit, because which one is missing cannot be known from a journal
	// that names node ids while the host list names ssh targets.
	for _, want := range []string{exitTarget + "\trestart bacchus-exit", relayTarget + "\trestart bacchus-relay"} {
		if !strings.Contains(f.log("systemctl.log"), want) {
			t.Errorf("no %q in:\n%s", want, f.log("systemctl.log"))
		}
	}
	// The coordinator is never restarted here: that would empty the registry again
	// and the re-read would have nothing to find.
	if strings.Contains(f.log("systemctl.log"), coordTarget+"\trestart") {
		t.Errorf("the coordinator was restarted as part of the containment:\n%s", f.log("systemctl.log"))
	}
	if !strings.Contains(out, "issue #225") {
		t.Errorf("the run does not say the restart was a containment for a known bug:\n%s", out)
	}
}

// Drift is never restarted away. A box on the wrong binary is on the wrong binary
// afterwards too, and the restart would destroy the evidence.
func TestPin_DoesNotRestartOnDrift(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	write(t, filepath.Join(f.dir, "journal"), journalFor(head[:12], head[:12], "a868e6e3c447"), 0o644)

	out, code := f.pin()
	if code != 3 {
		t.Fatalf("exit %d, want 3\n%s", code, out)
	}
	if strings.Contains(f.log("systemctl.log"), "restart") {
		t.Errorf("a unit was restarted to answer a wrong-build finding:\n%s", f.log("systemctl.log"))
	}
}

// The escape hatch, for the person who wants to look at the stranded process
// rather than have it swept up: the restart is what makes #225 undiagnosable.
func TestPin_NoRestartAbsentLeavesTheStrandedNodeAlone(t *testing.T) {
	f := newFleet(t)
	rev := f.head()[:12]
	write(t, filepath.Join(f.dir, "journal"), journalOf(rev, registration{"exit", exitNodeID, rev}), 0o644)

	out, code := f.pin("--no-restart-absent")
	if code != 3 {
		t.Fatalf("exit %d, want 3 — an absent node is still a failed verification\n%s", code, out)
	}
	if strings.Contains(f.log("systemctl.log"), "restart") {
		t.Errorf("--no-restart-absent restarted something anyway:\n%s", f.log("systemctl.log"))
	}
	// The point of keeping the stranded process is diagnosing it, so the run has to
	// say which box to go and look at (issue #232, issue #225).
	if !strings.Contains(out, relayTarget) {
		t.Errorf("the stranded box was not named, so the flag preserves a process nobody can find:\n%s", out)
	}
}

// -------------------------------------------------------------------------
// the roll call (issue #232)
// -------------------------------------------------------------------------

// THE case issue #232 was opened for, and the one a count cannot answer at all.
//
// A volunteer client serves as a relay or an exit (ADR-0053) and registers exactly
// like a deployed node without being in anybody's host list. So the journal here
// carries TWO ids for a two-box NODE_TARGETS and --expect 2 is satisfied — the fleet
// check says `2 of 2` and `the fleet is pinned`, correctly, from what it can see —
// while one of the two DEPLOYED boxes never registered and a stranger's box is
// standing in for it.
//
// Only comparing identities catches that, and only the pin can, because only the pin
// has the host list.
//
// MUTATION: drop `|| [ "$roll_absent" -gt 0 ]` from either place it appears in
// bacchus-pin.sh — the `absent` condition (the containment never fires for a box the
// count cannot see) or the `rc` condition (the run exits 0 with the box named and the
// verdict green). Each is half of the false pass, and this covers both.
func TestPin_AVolunteerCannotStandInForADeployedBox(t *testing.T) {
	f := newFleet(t)
	rev := f.head()[:12]
	// Two ids, matching --expect 2 — but one of them is nobody's box. The relay is
	// still absent after the containment restart, so the verdict has to hold.
	write(t, filepath.Join(f.dir, "journal"), journalOf(rev,
		registration{"exit", exitNodeID, rev},
		registration{"relay", "beef00volunteer", rev}), 0o644)

	out, code := f.pin()
	if code != 3 {
		t.Fatalf("exit %d, want 3 — a volunteer held the count up while a deployed box was absent\n%s", code, out)
	}
	// The count really did pass. That is not a bug in the check; it is its limit.
	if !strings.Contains(out, "2 of 2 expected node(s) registered") {
		t.Errorf("the fleet check no longer reports what it can see:\n%s", out)
	}
	if strings.Contains(out, "did NOT register in this window") {
		t.Errorf("the check reported an absence it cannot see, which would make this test prove nothing:\n%s", out)
	}
	if !strings.Contains(out, "ROLL CALL") || !strings.Contains(out, relayTarget) {
		t.Errorf("the deployed box that did not register was not named:\n%s", out)
	}
	if !strings.Contains(out, "belong to no box in NODE_TARGETS") {
		t.Errorf("the extra registration is not explained as a volunteer:\n%s", out)
	}
	// The containment fires on the roll call's finding too, not only on the count's.
	for _, want := range []string{exitTarget + "\trestart bacchus-exit", relayTarget + "\trestart bacchus-relay"} {
		if !strings.Contains(f.log("systemctl.log"), want) {
			t.Errorf("no %q — the containment never ran for an absence only the roll call saw:\n%s", want, f.log("systemctl.log"))
		}
	}
}

// A box whose own id cannot be read falls back to the count, and says so. Silence
// here would be the worst outcome: a roll call that quietly drops a box it could not
// ask reports a complete fleet from an incomplete question.
func TestPin_SaysSoWhenABoxCannotStateItsId(t *testing.T) {
	f := newFleet(t)
	rev := f.head()[:12]
	// The relay box answers nothing at all — an older binary, or a window that does
	// not reach its last start.
	write(t, filepath.Join(f.dir, "journal-"+relayTarget), "-- No entries --\n", 0o644)
	write(t, filepath.Join(f.dir, "journal"), journalOf(rev,
		registration{"exit", exitNodeID, rev},
		registration{"relay", relayNodeID, rev}), 0o644)

	out, code := f.pin()
	if code != 0 {
		t.Fatalf("exit %d, want 0 — both boxes registered; one of them just could not be asked\n%s", code, out)
	}
	if !strings.Contains(out, "no node id in its journal") || !strings.Contains(out, relayTarget) {
		t.Errorf("the box that could not be asked is not named:\n%s", out)
	}
	if !strings.Contains(out, "fall back to the") {
		t.Errorf("the run does not say what it lost by not being able to ask:\n%s", out)
	}
}

// A journal that could not be READ is not evidence that anybody is absent, and this is
// the way a roll call gets that wrong: the ids file is empty in both cases. An ssh that
// failed, or a window that does not reach the coordinator's restart, would then name
// every deployed box and restart the entire fleet to answer a fetch that did not
// happen — the loudest possible response to the least informative input.
//
// MUTATION: drop the `case "$1" in 0|1|4)` guard from roll_call — this goes red with
// both boxes named and both units restarted.
func TestPin_AnUnreadableJournalIsNotEvidenceOfAbsence(t *testing.T) {
	f := newFleet(t)
	// A window with no `coordinator release` line in it: the check exits 3 and says
	// so, and it has counted nothing.
	write(t, filepath.Join(f.dir, "journal"),
		"Aug 08 12:00:03 box bacchus-coordinator[9]: exit registered: "+exitNodeID+" -> 192.0.2.10:20000 release=0.1.0 build=deadbeefdead\n", 0o644)

	out, code := f.pin()
	if code != 3 {
		t.Fatalf("exit %d, want 3 — the window cannot answer the question\n%s", code, out)
	}
	if !strings.Contains(out, "Widen the window") {
		t.Fatalf("the check did not report the case this test is about:\n%s", out)
	}
	if strings.Contains(out, "ROLL CALL") {
		t.Errorf("an unread journal was reported as boxes being absent:\n%s", out)
	}
	if strings.Contains(f.log("systemctl.log"), "restart") {
		t.Errorf("the fleet was restarted to answer a journal that could not be read:\n%s", f.log("systemctl.log"))
	}
}

// The map is re-read after the containment restart, not carried across it. A relay
// without -relay-ingress takes a FRESH RANDOM id at every start (core/engine.go,
// randID), so the ids read before a restart name processes that no longer exist —
// and a roll call comparing them would report a box that came back perfectly as
// absent, on every run that restarted anything.
//
// MUTATION: delete the second `read_node_ids` in the containment block — the run
// exits 3 with the relay named as absent, which is a false failure.
func TestPin_ReReadsNodeIdsAfterTheContainmentRestart(t *testing.T) {
	f := newFleet(t)
	rev := f.head()[:12]
	const relayAfterRestart = "a9000011112222"

	write(t, filepath.Join(f.dir, "journal"), journalOf(rev, registration{"exit", exitNodeID, rev}), 0o644)
	// The relay comes back under a DIFFERENT id, as a real one does.
	write(t, filepath.Join(f.dir, "journal.2"), journalOf(rev,
		registration{"exit", exitNodeID, rev}, registration{"relay", relayAfterRestart, rev}), 0o644)
	write(t, filepath.Join(f.dir, "journal-"+relayTarget+".2"), nodeJournal("relay", relayAfterRestart), 0o644)

	out, code := f.pin()
	if code != 0 {
		t.Fatalf("exit %d, want 0 — the relay came back under a fresh id, which is what a relay does\n%s", code, out)
	}
	if !strings.Contains(out, relayAfterRestart) {
		t.Errorf("the second roll call still used the id from before the restart:\n%s", out)
	}
}

// -------------------------------------------------------------------------
// the units: compared, never copied (issue #234)
// -------------------------------------------------------------------------

// The failure issue #234 IS. Issue #222 added `OnFailure=` to both server units,
// merging it put it on no box — bacchus-pin.sh never copies a .service file, and must
// not — and every pin run afterwards reported a pinned fleet, because nothing compared
// the two either. It is issue #205's finding in a different place: the repository holds
// a mechanism the fleet does not have, and nothing reports the difference.
//
// It is a report and not a failure: the binaries genuinely are pinned, units are
// configuration this script deliberately does not manage, and a check that failed every
// run until three units were hand-edited would be switched off or answered with the copy
// flag that must not exist.
//
// MUTATION: delete the `compare_unit` loop from bacchus-pin.sh — this goes red and
// every other test in this file keeps passing, which is exactly how a merged mechanism
// sat on no box for a whole wave.
func TestPin_ReportsALiveUnitMissingADirectiveItsTemplateShips(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	write(t, filepath.Join(f.dir, "journal"), journalFor(head[:12], head[:12], head[:12]), 0o644)

	// The live exit unit as it is on the boxes today: the shipped one, minus the
	// handler wiring, plus a flag somebody added by hand.
	shipped := string(readFile(t, filepath.Join(repoRoot(t), exitUnitRelPath)))
	live := strings.ReplaceAll(shipped, rollbackOnFailure, "")
	live = strings.ReplaceAll(live, "-exit-key ${EXIT_KEY}", "-exit-key ${EXIT_KEY} -admission-cred /etc/bacchus/node.cred")
	write(t, filepath.Join(f.dir, "unit-cat-"+exitTarget), "# /etc/systemd/system/bacchus-exit.service\n"+live, 0o644)

	out, code := f.pin()
	if code != 0 {
		t.Fatalf("exit %d, want 0 — the binaries are pinned; the unit gap is reported, not fatal\n%s", code, out)
	}
	if !strings.Contains(out, "MISSING from the live unit") || !strings.Contains(out, rollbackOnFailure) {
		t.Errorf("the directive the box does not have was not reported:\n%s", out)
	}
	if !strings.Contains(out, exitTarget) {
		t.Errorf("the report does not say which box is missing it:\n%s", out)
	}
	// The hand-added flag is the reason units are never copied, so it must be shown
	// as a difference and never as something to fix.
	if !strings.Contains(out, "-admission-cred /etc/bacchus/node.cred") {
		t.Errorf("the hand-added flag is not shown, which is the half that explains the no-copy rule:\n%s", out)
	}
	// And still nothing was copied.
	if strings.Contains(f.log("scp.log"), ".service") {
		t.Errorf("a unit file was copied to answer the gap:\n%s", f.log("scp.log"))
	}
}

// The other half of the same run: a box whose unit matches the shipped one draws no
// warning, so the report above means something when it appears.
func TestPin_SaysNothingWhenTheLiveUnitMatches(t *testing.T) {
	f := newFleet(t)
	head := f.head()
	write(t, filepath.Join(f.dir, "journal"), journalFor(head[:12], head[:12], head[:12]), 0o644)

	out, code := f.pin()
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if strings.Contains(out, "MISSING from the live unit") {
		t.Errorf("a unit identical to the shipped one was reported as missing something:\n%s", out)
	}
	if !strings.Contains(out, "carry the same directives") {
		t.Errorf("the comparison did not run, so its silence proves nothing:\n%s", out)
	}
	// A node unit this repository ships no template for is stated rather than skipped
	// silently — bacchus-relay is exactly that case today.
	if !strings.Contains(out, "nothing ships as deploy/bacchus-relay.service") {
		t.Errorf("a unit with no shipped template was passed over without a word:\n%s", out)
	}
}

// registration is one `<role> registered:` line in a rendered journal.
type registration struct{ role, id, rev string }

// journalOf renders a coordinator journal: a startup line at coord, then one
// registration line per entry. Roles and ids are given separately because the
// difference between them is the whole of issue #224 — two roles on one id is one
// box, and it used to count as two.
func journalOf(coord string, regs ...registration) string {
	b := "Aug 08 12:00:00 box bacchus-coordinator[9]: version fence DISABLED (-min-serving-version 0.0.0) — " +
		"any node version may serve (issue #36); coordinator release 0.1.0 (revision " + coord + ")\n"
	for i, r := range regs {
		switch r.role {
		case "exit":
			b += fmt.Sprintf("Aug 08 12:00:%02d box bacchus-coordinator[9]: exit registered: %s -> 192.0.2.10:20000 "+
				"country=NL (observed IP) release=0.1.0 build=%s\n", i+1, r.id, r.rev)
		default:
			b += fmt.Sprintf("Aug 08 12:00:%02d box bacchus-coordinator[9]: relay registered: %s (192.0.2.20:41234) "+
				"country=DE (node hint, unresolved IP) release=0.1.0 build=%s\n", i+1, r.id, r.rev)
		}
	}
	return b
}

// journalFor renders a coordinator journal in which the coordinator started at coord and
// two nodes then registered at the given revisions.
func journalFor(coord, exitRev, relayRev string) string {
	return "Aug 08 11:00:00 box bacchus-coordinator[9]: exit registered: " + exitNodeID + " -> 192.0.2.10:20000 country=NL (observed IP) release=0.1.0 build=deadbeefdead\n" +
		"Aug 08 12:00:00 box bacchus-coordinator[9]: version fence DISABLED (-min-serving-version 0.0.0) — any node version may serve (issue #36); coordinator release 0.1.0 (revision " + coord + ")\n" +
		"Aug 08 12:00:03 box bacchus-coordinator[9]: exit registered: " + exitNodeID + " -> 192.0.2.10:20000 country=NL (observed IP) release=0.1.0 build=" + exitRev + "\n" +
		"Aug 08 12:00:04 box bacchus-coordinator[9]: relay registered: " + relayNodeID + " (192.0.2.20:41234) country=DE (node hint, unresolved IP) release=0.1.0 build=" + relayRev + "\n"
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

// One box serving two roles is ONE node. It prints two `registered:` lines
// carrying one node id — `-role exit,relay` and `-volunteer-relay
// -volunteer-exit` both do — and keying the table on `role id` counted it twice.
//
// That is how the first real pin run printed `3 node(s) registered` and `the fleet
// is pinned` from three rows carrying two ids, with one of three boxes dead.
//
// MUTATION: key on `p[1] " " p[3]` again (role plus id, as before issue #224) —
// this reports 3 of 3 and passes, which is exactly the false pass that was shipped.
func TestFleetCheck_CountsADualRoleNodeOnce(t *testing.T) {
	j := journalOf("2f4f77887c67",
		registration{"exit", "aaa", "2f4f77887c67"},
		registration{"relay", "aaa", "2f4f77887c67"},
		registration{"exit", "bbb", "2f4f77887c67"})

	out, code := fleetCheck(t, j, "--expect", "3", "2f4f77887c67")
	if code != 4 {
		t.Fatalf("exit %d, want 4 — three rows carrying two ids is TWO nodes, and a third box is missing\n%s", code, out)
	}
	if !strings.Contains(out, "2 of 3 expected node(s) registered") {
		t.Errorf("the summary does not say how many of how many:\n%s", out)
	}
	if !strings.Contains(out, "exit,relay aaa") {
		t.Errorf("the dual-role box is not shown as one row naming both roles:\n%s", out)
	}
	if n := strings.Count(out, "aaa"); n != 1 {
		t.Errorf("the dual-role box appears %d times, want 1:\n%s", n, out)
	}
}

// Absence is its own finding, and the messages must not be interchangeable: a box
// on the wrong build is serving traffic wrongly (issue #114), a box that never
// registered is not serving at all and may simply be off. Both non-zero, both
// different.
func TestFleetCheck_ReportsAnAbsentNodeSeparatelyFromDrift(t *testing.T) {
	j := journalOf("2f4f77887c67",
		registration{"exit", "aaa", "2f4f77887c67"},
		registration{"relay", "bbb", "2f4f77887c67"})

	out, code := fleetCheck(t, j, "--expect", "3", "2f4f77887c67")
	if code != 4 {
		t.Fatalf("exit %d, want 4\n%s", code, out)
	}
	if !strings.Contains(out, "did NOT register in this window") {
		t.Errorf("the absent node is not named as a finding:\n%s", out)
	}
	if strings.Contains(out, "NOT on one commit") {
		t.Errorf("an absent node is being reported as drift:\n%s", out)
	}
	// It must not invent a name for the box, and it must say why it cannot.
	if !strings.Contains(out, "journal names node ids and your host list names ssh targets") {
		t.Errorf("the message does not say why the missing box cannot be named:\n%s", out)
	}
	// And it must name the cause a deploy actually creates.
	if !strings.Contains(out, "#225") {
		t.Errorf("the message does not point at the failure the deploy order guarantees:\n%s", out)
	}
}

// Both findings at once. Both are printed, and the exit code is drift's: a box
// serving the wrong binary is the stronger instruction — distrust every result
// from this fleet — while an absent box is one that is not answering at all.
func TestFleetCheck_DriftOutranksAbsenceInTheExitCode(t *testing.T) {
	j := journalOf("2f4f77887c67",
		registration{"exit", "aaa", "2f4f77887c67"},
		registration{"relay", "bbb", "a868e6e3c447"})

	out, code := fleetCheck(t, j, "--expect", "3", "2f4f77887c67")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "NOT on one commit") || !strings.Contains(out, "did NOT register in this window") {
		t.Errorf("both findings must be reported even though one exit code is returned:\n%s", out)
	}
}

// MORE ids than expected is not a failure. A volunteer client serves as a relay or
// an exit (ADR-0053) and registers exactly like a deployed node without being in
// any host list — so the count is a FLOOR, and the output says so rather than
// letting a reader take it for a roll call.
func TestFleetCheck_MoreNodesThanExpectedIsNotAFailure(t *testing.T) {
	j := journalOf("2f4f77887c67",
		registration{"exit", "aaa", "2f4f77887c67"},
		registration{"relay", "bbb", "2f4f77887c67"},
		registration{"relay", "volunteer", "2f4f77887c67"})

	out, code := fleetCheck(t, j, "--expect", "2", "2f4f77887c67")
	if code != 0 {
		t.Fatalf("exit %d, want 0 — a volunteer is not a failed pin\n%s", code, out)
	}
	if !strings.Contains(out, "volunteer") {
		t.Errorf("nothing explains why there are more nodes than the host list has:\n%s", out)
	}
}

// --expect takes a count and never a host list, and the refusal says why: this
// script prints no hostname, which is what makes its output the half of a pin run
// that is safe to paste into a public issue. bacchus-pin.sh's own output names
// every ssh target on every line.
func TestFleetCheck_RefusesAHostListAsTheExpectedCount(t *testing.T) {
	for _, arg := range []string{"exit-a=bacchus-exit relay-b=bacchus-relay", "three", "-1", ""} {
		out, code := fleetCheck(t, "", "--expect", arg, "2f4f77887c67")
		if code != 2 {
			t.Errorf("--expect %q: exit %d, want 2\n%s", arg, code, out)
		}
	}
	if out, code := fleetCheck(t, "", "--expect"); code != 2 || !strings.Contains(out, "needs a value") {
		t.Errorf("a bare --expect: exit %d\n%s", code, out)
	}
}

// Without --expect the check is what it was: no floor above zero. It must say that
// out loud rather than printing a bare count that reads like a roll call — the
// sentence that made the first real run's `3 node(s) registered` convincing.
func TestFleetCheck_SaysSoWhenItHasNoFloor(t *testing.T) {
	j := journalOf("2f4f77887c67", registration{"exit", "aaa", "2f4f77887c67"})

	out, code := fleetCheck(t, j, "2f4f77887c67")
	if code != 0 {
		t.Fatalf("exit %d, want 0 — without --expect there is nothing to compare\n%s", code, out)
	}
	if !strings.Contains(out, "No --expect given") {
		t.Errorf("the absence of a floor is not stated:\n%s", out)
	}
}

func TestFleetCheck_RefusesAnUnusableRevisionArgument(t *testing.T) {
	for _, arg := range []string{"", "abc123", "zzzzzzzz", "2f4f778 extra"} {
		if out, code := fleetCheck(t, "", arg); code != 2 {
			t.Errorf("%q: exit %d, want 2\n%s", arg, code, out)
		}
	}
}

// --ids-to is the side channel the roll call is built on (issue #232). Two properties:
// it names every id this window counted, and it does not change stdout — the check's
// output is the pasteable half of a pin run and gaining a machine-readable section
// would be the easiest way to lose that without noticing.
func TestFleetCheck_WritesTheIdsItCountedWithoutChangingItsOutput(t *testing.T) {
	j := journalOf("2f4f77887c67",
		registration{"exit", "aaa", "2f4f77887c67"},
		registration{"relay", "aaa", "2f4f77887c67"},
		registration{"relay", "bbb", "2f4f77887c67"})

	plain, code := fleetCheck(t, j, "--expect", "2", "2f4f77887c67")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, plain)
	}

	ids := filepath.Join(t.TempDir(), "ids")
	withIDs, code := fleetCheck(t, j, "--expect", "2", "--ids-to", ids, "2f4f77887c67")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, withIDs)
	}
	if withIDs != plain {
		t.Errorf("--ids-to changed what is printed:\n--- without ---\n%s\n--- with ---\n%s", plain, withIDs)
	}

	got := strings.Fields(string(readFile(t, ids)))
	// A dual-role box is ONE id here too, or the pin would look for a box that does
	// not exist.
	if len(got) != 2 || got[0] != "aaa" || got[1] != "bbb" {
		t.Errorf("ids file holds %q, want [aaa bbb]", got)
	}
}

// A run that finds nothing must leave an EMPTY file rather than the previous run's
// ids. The pin reads this file twice — once before its containment restart and once
// after — and a stale read names the wrong box, which is worse than naming none.
func TestFleetCheck_TruncatesTheIdsFileEvenWhenItFindsNothing(t *testing.T) {
	ids := filepath.Join(t.TempDir(), "ids")
	if out, code := fleetCheck(t, journalOf("2f4f77887c67",
		registration{"exit", "aaa", "2f4f77887c67"}), "--ids-to", ids, "2f4f77887c67"); code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	// A window with no coordinator start at all: exit 3, and nothing to report.
	if out, code := fleetCheck(t, "exit registered: aaa release=0.1.0 build=2f4f77887c67\n",
		"--ids-to", ids, "2f4f77887c67"); code != 3 {
		t.Fatalf("exit %d, want 3\n%s", code, out)
	}
	if got := strings.TrimSpace(string(readFile(t, ids))); got != "" {
		t.Errorf("the ids file still holds %q from the previous run", got)
	}
}

// -------------------------------------------------------------------------
// bacchus-node-id.sh: the other half of the pairing (issue #232)
// -------------------------------------------------------------------------

func nodeID(t *testing.T, journal string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(repoRoot(t), nodeIDRelPath)}, args...)...)
	cmd.Stdin = strings.NewReader(journal)
	b, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if err != nil {
		if !asExitError(err, &ee) {
			t.Fatalf("running %s: %v\n%s", nodeIDRelPath, err, b)
		}
		code = ee.ExitCode()
	}
	return string(b), code
}

func TestNodeID_ReadsBothStartupShapes(t *testing.T) {
	t.Run("exit", func(t *testing.T) {
		out, code := nodeID(t, nodeJournal("exit", exitNodeID))
		if code != 0 || strings.TrimSpace(out) != exitNodeID {
			t.Fatalf("exit %d, got %q", code, out)
		}
	})
	t.Run("relay", func(t *testing.T) {
		out, code := nodeID(t, nodeJournal("relay", relayNodeID))
		if code != 0 || strings.TrimSpace(out) != relayNodeID {
			t.Fatalf("exit %d, got %q", code, out)
		}
	})
	t.Run("one box, both roles, one id", func(t *testing.T) {
		out, code := nodeID(t, nodeJournal("exit", exitNodeID)+nodeJournal("relay", exitNodeID))
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, out)
		}
		if n := len(strings.Fields(out)); n != 1 {
			t.Errorf("printed %d values for one process, want 1:\n%s", n, out)
		}
	})
}

// A window can hold more than one START, because the pin restarts a node that did not
// come back and reads this again. The last one is the process that is running; the one
// before it is a relay identity that no longer exists.
func TestNodeID_TakesTheLastStartInTheWindow(t *testing.T) {
	j := nodeJournal("relay", "a900000000aa") + nodeJournal("relay", relayNodeID)
	out, code := nodeID(t, j)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.TrimSpace(out) != relayNodeID {
		t.Errorf("got %q, want the id from the LAST start (%s)", strings.TrimSpace(out), relayNodeID)
	}
}

// The line shapes are matched WHOLE, and this is why. core/pool.go prints
// `exit <id> in <country> did not carry traffic` about an exit this node was ASSIGNED
// — somebody else's id — and it appears on a volunteer box, which runs a client and an
// exit at once, AFTER the startup lines. A loose `exit <hex>` pattern would take the
// last one of those and report a stranger's node id as this box's identity, which is
// worse than reporting none: the roll call would then name a box that is running fine.
//
// MUTATION: relax the patterns to /exit [0-9a-f]+/ and /relay [0-9a-f]+/ — this goes
// red on the first and third cases and every other test here keeps passing.
func TestNodeID_IgnoresLinesThatAreNotTheStartupLine(t *testing.T) {
	j := nodeJournal("exit", exitNodeID) +
		"Aug 08 12:01:00 box bacchus-node[7]: exit deadbeefcafe in NL did not carry traffic — asking for another\n" +
		"Aug 08 12:01:01 box bacchus-node[7]: exit TCP server on 192.0.2.10:20000\n" +
		"Aug 08 12:01:02 box bacchus-node[7]: relay abcdef012345 assigned session s1\n"
	out, code := nodeID(t, j)
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.TrimSpace(out) != exitNodeID {
		t.Errorf("got %q — a line that is not a startup line reached the answer", strings.TrimSpace(out))
	}
}

// Nothing to report is its own exit code, and it says which of the three causes to
// look at. Reporting an empty id as success would put an empty string into the roll
// call, where it matches nothing and names every box as absent.
func TestNodeID_ReportsAWindowWithNoStartupLine(t *testing.T) {
	out, code := nodeID(t, "Aug 08 12:00:00 box bacchus-node[7]: exit TCP server on 192.0.2.10:20000\n")
	if code != 4 {
		t.Fatalf("exit %d, want 4\n%s", code, out)
	}
	if !strings.Contains(out, "widen journalctl --since") {
		t.Errorf("the message is not actionable:\n%s", out)
	}
	if strings.Contains(out, "192.0.2.10") {
		t.Errorf("it echoed the input it could not parse; this output is captured into a variable:\n%s", out)
	}
}

// -------------------------------------------------------------------------
// bacchus-unit-check.sh (issue #234)
// -------------------------------------------------------------------------

func unitCheck(t *testing.T, template, live string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", filepath.Join(repoRoot(t), unitCheckRelPath), template)
	cmd.Stdin = strings.NewReader(live)
	b, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if err != nil {
		if !asExitError(err, &ee) {
			t.Fatalf("running %s: %v\n%s", unitCheckRelPath, err, b)
		}
		code = ee.ExitCode()
	}
	return string(b), code
}

// The shipped units compared against themselves, which is what a correctly installed
// box looks like. Both templates, because the coordinator's ExecStart uses `\` line
// continuations and a comparison that did not join them would report a unit as
// differing from itself — a check that cries wolf on every run is a check nobody reads.
func TestUnitCheck_AUnitMatchesItself(t *testing.T) {
	root := repoRoot(t)
	for _, rel := range []string{exitUnitRelPath, coordUnitRelPath} {
		body := string(readFile(t, filepath.Join(root, rel)))
		out, code := unitCheck(t, filepath.Join(root, rel), "# /etc/systemd/system/x.service\n"+body)
		if code != 0 {
			t.Errorf("%s: exit %d, want 0\n%s", rel, code, out)
		}
		if !strings.Contains(out, "carry the same directives") {
			t.Errorf("%s: %s", rel, out)
		}
	}
}

func TestUnitCheck_ReportsTheThreeKindsOfDifference(t *testing.T) {
	root := repoRoot(t)
	shipped := string(readFile(t, filepath.Join(root, exitUnitRelPath)))
	live := strings.ReplaceAll(shipped, rollbackOnFailure, "")
	live = strings.ReplaceAll(live, "Restart=always", "Restart=always\nStartLimitBurst=5")
	live = strings.ReplaceAll(live, "RestartSec=2", "RestartSec=9")

	out, code := unitCheck(t, filepath.Join(root, exitUnitRelPath), live)
	if code != 5 {
		t.Fatalf("exit %d, want 5\n%s", code, out)
	}
	// Missing is the finding; the other two are context, and conflating them is how a
	// hand-added flag reads as something to fix.
	if !strings.Contains(out, "MISSING from the live unit") || !strings.Contains(out, rollbackOnFailure) {
		t.Errorf("the missing directive is not the headline:\n%s", out)
	}
	if !strings.Contains(out, "only on the box") || !strings.Contains(out, "StartLimitBurst=5") {
		t.Errorf("a directive only the box has is not reported:\n%s", out)
	}
	if !strings.Contains(out, "RestartSec=") || !strings.Contains(out, "live: 9") {
		t.Errorf("a directive whose VALUE differs is not reported with both values:\n%s", out)
	}
	// And it says what to do without ever offering to do it.
	if !strings.Contains(out, "BY HAND") || !strings.Contains(out, "daemon-reload") {
		t.Errorf("the remedy is not stated:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "scp ") || strings.Contains(out, "install -D -m 0644 deploy/bacchus-exit.service") {
		t.Errorf("it suggested copying the unit, which is the one thing this must never do:\n%s", out)
	}
}

// Comments, blank lines, ordering and the `# /path` header systemctl cat prints are
// not configuration. A textual diff of these two would be pages of noise, and noise
// is how a report stops being read.
func TestUnitCheck_IgnoresCommentsBlankLinesAndOrdering(t *testing.T) {
	root := repoRoot(t)
	tmpl := filepath.Join(t.TempDir(), "x.service")
	write(t, tmpl, "[Unit]\nDescription=x\nOnFailure=h.service\n\n[Service]\nExecStart=/bin/x\nRestart=always\n", 0o644)
	_ = root

	live := "# /etc/systemd/system/x.service\n; an operator's note\n[Service]\n\nRestart=always\nExecStart=/bin/x\n\n[Unit]\n# another note\nOnFailure=h.service\nDescription=x\n"
	out, code := unitCheck(t, tmpl, live)
	if code != 0 {
		t.Fatalf("exit %d, want 0 — nothing here is a difference in configuration\n%s", code, out)
	}
}

// A unit that is not on the box at all prints nothing, and that is a finding rather
// than a pass: `systemctl cat` is silent for a unit that does not exist.
func TestUnitCheck_RefusesAnEmptyLiveUnit(t *testing.T) {
	out, code := unitCheck(t, filepath.Join(repoRoot(t), exitUnitRelPath), "")
	if code != 3 {
		t.Fatalf("exit %d, want 3\n%s", code, out)
	}
	if !strings.Contains(out, "does not exist on that box") {
		t.Errorf("the empty answer is not explained:\n%s", out)
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
	for _, rel := range []string{pinRelPath, fleetCheckRelPath, nodeIDRelPath, unitCheckRelPath, "deploy/testbed.env.example", adrRelPath} {
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
