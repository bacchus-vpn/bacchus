// Coverage for the scheduled IP-to-AS drift check (issue #150, ADR-0044's fourth
// amendment §5 and the amendment that closes it).
//
// deploy/bacchus-asn-drift-check.sh and .github/workflows/asn-table-drift.yml are
// both non-Go build artifacts, in the same sense deploy/windows/i18n_test.go and
// clients/fyne/manifest_test.go already establish for this repository: a Go test
// that reads and, where the artifact is executable, actually RUNS the thing being
// asserted about, rather than trusting either its own narration or a human rehearsal
// that only happens once. That precedent is followed here in a stronger form than
// either of those two files needed - the script is a fetch-and-compare tool with real
// failure modes, so this exercises it end to end against a local fixture server
// instead of only parsing its text.
//
// WHAT IS DELIBERATELY NOT ASSERTED: that the schedule actually fires on GitHub's
// infrastructure (nothing here can observe that), and that the REAL upstream feed and
// the REAL 700,000-row committed table behave a particular way today - both would tie
// this suite's result to the live internet and to the calendar, which is exactly the
// property ADR-0044's fourth amendment §3 already argues does not belong in ordinary
// pull request coverage. Every behavioural test below builds its own tiny "upstream"
// and "committed" fixtures instead, the same choice core/asn/embedded_test.go's own
// header explains for the real 700,000-row table: a failure here should name rows a
// reader can check by eye.
package deploy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	scriptRelPath   = "deploy/bacchus-asn-drift-check.sh"
	workflowRelPath = ".github/workflows/asn-table-drift.yml"
)

// baseFeed is a minimal upstream range feed: one row per family plus one IPv6 row,
// each already an aligned block so asn-stage emits it unchanged. Documentation
// addresses (RFC 5737 / RFC 3849) and documentation ASNs (RFC 5398), matching the
// rule cmd/asn-stage/main_test.go and core/asn/testdata already use - the transform
// does not care what the numbers mean, so there is no reason to use real ones here
// either.
const baseFeed = "" +
	"192.0.2.0\t192.0.2.255\t64496\tZZ\tdoc-a\n" +
	"198.51.100.0\t198.51.100.255\t64497\tZZ\tdoc-b\n" +
	"2001:db8::\t2001:db8::ffff\t64498\tZZ\tdoc-c\n"

// driftedFeed is baseFeed plus one more routed range, standing in for upstream
// having moved since the committed table was staged.
const driftedFeed = baseFeed + "203.0.113.0\t203.0.113.255\t64499\tZZ\tdoc-d\n"

// -------------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------------

// repoRoot finds the repository root from this package's directory (one level up)
// and confirms it, rather than assuming it - the same reasoning release.yml's own
// VERSION check gives: a gate that opens when its input disappears is not a gate,
// and a test that silently ran the wrong script would be worse than one that fails
// to find it.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	root := filepath.Dir(wd)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("computed repository root %s has no go.mod (%v) - this test assumes it runs from the deploy package directly under the repository root", root, err)
	}
	return root
}

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	return b
}

// stageFixture runs the real cmd/asn-stage tool over feed and returns the path of
// the staged, gzipped table it produces. This is the SAME transform
// bacchus-asn-drift-check.sh itself runs; it is used here only so tests can work
// against a small, known "committed" fixture instead of having to reproduce the
// real 700,000-row table byte for byte.
func stageFixture(t *testing.T, root, feed string) string {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "upstream.tsv")
	if err := os.WriteFile(in, []byte(feed), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	out := filepath.Join(dir, "table.tsv.gz")
	cmd := exec.Command("go", "run", "./cmd/asn-stage", "-in", in, "-out", out, "-gzip")
	cmd.Dir = root
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go run ./cmd/asn-stage: %v\n%s", err, b)
	}
	return out
}

// serveBytes starts an httptest server that returns b for every request, and
// registers its own cleanup. The response is precomputed by the caller and closed
// over as a plain []byte - never a *testing.T call - because the handler runs on a
// goroutine the testing package does not consider safe for T.Fatal/T.Error.
func serveBytes(t *testing.T, b []byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/feed.tsv.gz"
}

type checkResult struct {
	exitCode int
	stderr   string
}

// runDriftCheck runs the real script against root (the repository root, so its own
// "am I being run from the repository root" precondition holds) with extraEnv laid
// over the test process's own environment.
func runDriftCheck(t *testing.T, root string, extraEnv ...string) checkResult {
	t.Helper()
	cmd := exec.Command("sh", scriptRelPath)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := checkResult{stderr: stdout.String() + stderr.String()}
	if err == nil {
		return res
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("running %s: %v (not a plain exit status)\noutput:\n%s", scriptRelPath, err, res.stderr)
	}
	res.exitCode = exitErr.ExitCode()
	return res
}

// -------------------------------------------------------------------------
// deploy/bacchus-asn-drift-check.sh - behavioural coverage
// -------------------------------------------------------------------------

// TestDriftCheckPassesWhenUpstreamMatchesCommitted is the "done when" bullet's first
// half: a run that fetches, stages and compares, and finds nothing wrong, exits 0 and
// says so rather than staying silent.
func TestDriftCheckPassesWhenUpstreamMatchesCommitted(t *testing.T) {
	root := repoRoot(t)
	committed := stageFixture(t, root, baseFeed)
	before := readFile(t, committed)

	url := serveBytes(t, gzipBytes(t, baseFeed))
	res := runDriftCheck(t, root,
		"BACCHUS_ASN_FEED_URL="+url,
		"BACCHUS_ASN_TABLE_PATH="+committed,
		"BACCHUS_ASN_MIN_ROWS=1",
	)

	if res.exitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (no drift)\noutput:\n%s", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "no drift") {
		t.Errorf("output does not report no drift:\n%s", res.stderr)
	}
	if after := readFile(t, committed); !bytes.Equal(before, after) {
		t.Errorf("the committed fixture changed even on the no-drift path")
	}
}

// TestDriftCheckFailsLoudlyOnDrift is the ruled behaviour itself (issue #150,
// ADR-0044 §5, option C): a real difference between upstream and the committed
// table is not swallowed, and the message names what to do about it - the fix is a
// human regenerating and committing, and this message is the only place that
// instruction reaches them (this card's own "done when" bullet).
func TestDriftCheckFailsLoudlyOnDrift(t *testing.T) {
	root := repoRoot(t)
	committed := stageFixture(t, root, baseFeed)
	before := readFile(t, committed)

	url := serveBytes(t, gzipBytes(t, driftedFeed))
	res := runDriftCheck(t, root,
		"BACCHUS_ASN_FEED_URL="+url,
		"BACCHUS_ASN_TABLE_PATH="+committed,
		"BACCHUS_ASN_MIN_ROWS=1",
	)

	if res.exitCode != 2 {
		t.Fatalf("exit code = %d, want 2 (drift detected)\noutput:\n%s", res.exitCode, res.stderr)
	}
	for _, want := range []string{
		"DRIFT",
		"core/asn/embedded.go",
		"go run ./cmd/asn-stage",
		"iptoasn.com",
		"was NOT modified",
	} {
		if !strings.Contains(res.stderr, want) {
			t.Errorf("output does not mention %q, so an operator reading it would not know what to do:\n%s", want, res.stderr)
		}
	}
	if after := readFile(t, committed); !bytes.Equal(before, after) {
		t.Errorf("the committed fixture changed after drift was detected - it must only ever be read, never written")
	}
}

// TestDriftCheckFailsOnUnreachableUpstream is the OTHER half of the "done when"
// bullet: a bad download must not be confused with a stale table. Exit code 1 (not
// 2) is the machine-readable half of that distinction; the message is the
// human-readable half.
func TestDriftCheckFailsOnUnreachableUpstream(t *testing.T) {
	root := repoRoot(t)
	committed := stageFixture(t, root, baseFeed)
	before := readFile(t, committed)

	// A server that is already closed: connection refused is immediate, so this
	// stays fast rather than waiting out a timeout.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	badURL := srv.URL + "/feed.tsv.gz"
	srv.Close()

	res := runDriftCheck(t, root,
		"BACCHUS_ASN_FEED_URL="+badURL,
		"BACCHUS_ASN_TABLE_PATH="+committed,
	)

	if res.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1 (inconclusive)\noutput:\n%s", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "download") {
		t.Errorf("output does not name the download as the failure:\n%s", res.stderr)
	}
	if !strings.Contains(res.stderr, "was never opened for writing") {
		t.Errorf("output does not reassure that the committed table was untouched:\n%s", res.stderr)
	}
	if after := readFile(t, committed); !bytes.Equal(before, after) {
		t.Errorf("the committed fixture changed after a failed download - this is exactly the half-succeeding failure this check exists to prevent")
	}
}

// TestDriftCheckFailsOnCorruptDownload covers a transfer that completed but is not
// gzip at all - the integrity check bacchus-geoip-refresh.sh's own header explains
// (gzip's CRC32 and length trailer turn a truncated or corrupted transfer loud).
func TestDriftCheckFailsOnCorruptDownload(t *testing.T) {
	root := repoRoot(t)
	committed := stageFixture(t, root, baseFeed)
	before := readFile(t, committed)

	url := serveBytes(t, []byte("not a gzip file at all"))
	res := runDriftCheck(t, root,
		"BACCHUS_ASN_FEED_URL="+url,
		"BACCHUS_ASN_TABLE_PATH="+committed,
	)

	if res.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1 (inconclusive)\noutput:\n%s", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "decompress") {
		t.Errorf("output does not name decompression as the failure:\n%s", res.stderr)
	}
	if after := readFile(t, committed); !bytes.Equal(before, after) {
		t.Errorf("the committed fixture changed after a corrupt download")
	}
}

// TestDriftCheckFailsOnSuspiciouslySmallDownload covers a transfer that decompresses
// cleanly but is far too small to be a real release - the same row-count floor
// bacchus-geoip-refresh.sh applies to its own two families, carried over here
// (BACCHUS_ASN_MIN_ROWS is overridden so a tiny fixture can trip it without needing
// a real, hundred-thousand-row feed).
func TestDriftCheckFailsOnSuspiciouslySmallDownload(t *testing.T) {
	root := repoRoot(t)
	committed := stageFixture(t, root, baseFeed)
	before := readFile(t, committed)

	url := serveBytes(t, gzipBytes(t, "192.0.2.0\t192.0.2.1\t64496\tZZ\tdoc\n"))
	res := runDriftCheck(t, root,
		"BACCHUS_ASN_FEED_URL="+url,
		"BACCHUS_ASN_TABLE_PATH="+committed,
		"BACCHUS_ASN_MIN_ROWS=5",
	)

	if res.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1 (inconclusive)\noutput:\n%s", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "rows") {
		t.Errorf("output does not mention the row floor:\n%s", res.stderr)
	}
	if after := readFile(t, committed); !bytes.Equal(before, after) {
		t.Errorf("the committed fixture changed after a suspiciously small download")
	}
}

// TestDriftCheckFailsWhenTheDownloadDoesNotParse covers the THIRD failure shape,
// distinct from the two above: the download and its integrity check both succeed,
// but cmd/asn-stage itself refuses the content. Bundling this into "bad download"
// would misdirect whoever reads it - the network was fine; either upstream changed
// shape or the tool needs updating for it - so the script's own message says so.
func TestDriftCheckFailsWhenTheDownloadDoesNotParse(t *testing.T) {
	root := repoRoot(t)
	committed := stageFixture(t, root, baseFeed)
	before := readFile(t, committed)

	feed := "not-an-address\t192.0.2.5\t64496\tZZ\tdoc\n" +
		"192.0.2.6\t192.0.2.7\t64497\tZZ\tdoc\n"
	url := serveBytes(t, gzipBytes(t, feed))
	res := runDriftCheck(t, root,
		"BACCHUS_ASN_FEED_URL="+url,
		"BACCHUS_ASN_TABLE_PATH="+committed,
		"BACCHUS_ASN_MIN_ROWS=1",
	)

	if res.exitCode != 1 {
		t.Fatalf("exit code = %d, want 1 (inconclusive)\noutput:\n%s", res.exitCode, res.stderr)
	}
	if !strings.Contains(res.stderr, "asn-stage") {
		t.Errorf("output does not name asn-stage as the failure:\n%s", res.stderr)
	}
	if after := readFile(t, committed); !bytes.Equal(before, after) {
		t.Errorf("the committed fixture changed after a transform failure")
	}
}

// TestDriftCheckLogsTheCommittedTableAge exercises the DEFAULT BACCHUS_ASN_TABLE_PATH
// - every other test above overrides it to keep fixtures small, so this is the one
// place the real core/asn/embedded.go this repository ships is actually read. The
// exit code is deliberately not asserted: against the real, 700,000-row committed
// table this reports drift on any fixture small enough to hand-write, and that is
// not what this test is about.
func TestDriftCheckLogsTheCommittedTableAge(t *testing.T) {
	root := repoRoot(t)
	url := serveBytes(t, gzipBytes(t, baseFeed))
	res := runDriftCheck(t, root,
		"BACCHUS_ASN_FEED_URL="+url,
		"BACCHUS_ASN_MIN_ROWS=1",
	)
	if !strings.Contains(res.stderr, "retrieved") || !strings.Contains(res.stderr, "day") {
		t.Errorf("output does not log the committed table's retrieval age:\n%s", res.stderr)
	}
}

// TestDriftCheckRejectsUnexpectedArguments needs no network at all, and pins the
// usage contract: this script takes no positional arguments, only environment
// overrides.
func TestDriftCheckRejectsUnexpectedArguments(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("sh", scriptRelPath, "unexpected")
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("exit = %v, want exit code 2 for a usage error", err)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Errorf("output does not print usage:\n%s", stderr.String())
	}
}

// -------------------------------------------------------------------------
// .github/workflows/asn-table-drift.yml
// -------------------------------------------------------------------------

func loadWorkflow(t *testing.T, root string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, workflowRelPath))
	if err != nil {
		// Not a skip: a gate that opens when its input disappears is not a gate,
		// the same rule core/asn.TestReleaseWorkflowGatesTheTable already applies
		// to release.yml.
		t.Fatalf("cannot read %s: %v\n\nThis test asserts the scheduled drift-check workflow exists and is wired correctly; without the file there is nothing to assert and reporting green would be reporting over nothing.", workflowRelPath, err)
	}
	return string(b)
}

// nonCommentLines drops every line whose trimmed text starts with '#', so an
// assertion below cannot be satisfied by a comment EXPLAINING the property rather
// than the property itself. core/asn/embedded_test.go's workflowRuns documents the
// same trap being hit for real in this repository once already.
func nonCommentLines(src string) string {
	var out []string
	for _, ln := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// hasYAMLLine reports whether src has a non-comment line that, once trimmed of
// whitespace and one leading "- " list marker, STARTS WITH want. Anchoring the
// match to the start of the line rather than searching anywhere in it is the
// point: a plain strings.Contains(src, "schedule:") is also satisfied by
// "disabled_schedule:", which a mutation test written against an earlier draft of
// this suite caught for real - the same trap core/asn/embedded_test.go's
// workflowSetsEnv was written for, and the same fix.
func hasYAMLLine(src, want string) bool {
	for _, ln := range strings.Split(src, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "#") {
			continue
		}
		ln = strings.TrimPrefix(ln, "- ")
		if strings.HasPrefix(ln, want) {
			return true
		}
	}
	return false
}

// TestScheduledWorkflowRunsOnATimerAndCanBeRehearsed pins the two triggers this
// workflow needs and nothing more: schedule (so nobody has to remember to run it -
// the whole point of #150) and workflow_dispatch (so it can be exercised once before
// the schedule's first real Monday - see the workflow's own "WHY NO pull_request
// TRIGGER" for why that trigger is deliberately absent rather than forgotten).
func TestScheduledWorkflowRunsOnATimerAndCanBeRehearsed(t *testing.T) {
	src := loadWorkflow(t, repoRoot(t))
	if !hasYAMLLine(src, "schedule:") || !hasYAMLLine(src, "cron:") {
		t.Errorf("%s has no schedule:/cron: trigger, so nothing runs it without a human remembering to - exactly the failure #150 exists to remove", workflowRelPath)
	}
	if !hasYAMLLine(src, "workflow_dispatch:") {
		t.Errorf("%s has no workflow_dispatch: trigger. A schedule-only workflow cannot be rehearsed by any run on a branch, so its first execution would be the first real scheduled one", workflowRelPath)
	}
}

// TestScheduledWorkflowRunsTheDriftCheckScript guards against the workflow
// mentioning the script (in a comment, in its name) without ever invoking it. The
// script's path is a distinctive enough string on its own that the superstring
// trap hasYAMLLine exists for is not a live concern here, but nonCommentLines is
// still used so a mention in a comment cannot satisfy this on its own.
func TestScheduledWorkflowRunsTheDriftCheckScript(t *testing.T) {
	src := nonCommentLines(loadWorkflow(t, repoRoot(t)))
	if !strings.Contains(src, scriptRelPath) {
		t.Errorf("%s never runs %s outside of a comment", workflowRelPath, scriptRelPath)
	}
}

// TestScheduledWorkflowPinsTheToolchain guards the reason given in the workflow's
// own header for go-version-file over stable: this job's whole output is a
// byte-for-byte comparison, and cmd/asn-stage's determinism is a promise about one
// toolchain.
func TestScheduledWorkflowPinsTheToolchain(t *testing.T) {
	src := loadWorkflow(t, repoRoot(t))
	if !hasYAMLLine(src, "go-version-file: go.mod") {
		t.Errorf("%s does not pin go-version-file: go.mod. This job compares gzip bytes for equality; letting the toolchain float to whatever setup-go resolves 'stable' to on the day risks a false drift report that has nothing to do with upstream", workflowRelPath)
	}
}

// TestScheduledWorkflowNeverRequestsRepositoryWrite is the mechanical half of
// ADR-0044 §5's ruling (option C over A and B): this workflow must never be able to
// write to the repository, so the two permission scopes either option would need
// must never appear in it. Checked against the RAW file, not just non-comment
// lines, because the workflow's own header explains the refusal in prose without
// ever spelling out either scope literally - so this assertion has no reason to
// tolerate the scope appearing anywhere at all, comment or not.
func TestScheduledWorkflowNeverRequestsRepositoryWrite(t *testing.T) {
	raw := loadWorkflow(t, repoRoot(t))
	for _, denied := range []string{"contents: write", "pull-requests: write"} {
		if strings.Contains(raw, denied) {
			t.Errorf("%s contains %q. ADR-0044's fourth amendment §5 ruled option C specifically to keep a repository-write credential away from this job (ADR-0052 §6: a build machine that can push is a build machine that can be made to sign, or vice versa) - granting %q here re-opens exactly the door that ruling closed", workflowRelPath, denied, denied)
		}
	}
	if !hasYAMLLine(raw, "contents: read") {
		t.Errorf("%s does not declare permissions: contents: read. Without an explicit block the effective permissions are a repository or organization setting rather than something this file states for itself", workflowRelPath)
	}
}
