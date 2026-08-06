package asn

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// The embedded table (issue #55) is deliberately tested THINLY.
//
// ADR-0044's amendment says why: committing the real table is the product, pointing
// the tests at it is not. Every behavioural test for parsing, disjointness, pooling
// and the diversity ladder runs against the synthetic fixture in testdata, where a
// failure names four rows a reader can check by eye. A 700,000-row table in that
// path would make the same failures unreadable.
//
// So what is checked here is only what the fixture CANNOT check: that the bytes
// committed to this repository are real, loadable, and behave like a routing table.
// Nothing here asserts a specific AS for a specific address — that would pin the
// test to an allocation upstream is free to change, and would fail on a refresh that
// was entirely correct.

// TestEmbeddedTableLoads is the build-fault detector. The embedded bytes cannot
// change between build and run, so a table that does not load is a committed-file
// fault, and this is the thing that catches it before a release carries it — see
// core/relaychain.go's embeddedAS, which degrades rather than refusing at runtime
// precisely because this test is what fails instead.
func TestEmbeddedTableLoads(t *testing.T) {
	tab, err := Embedded()
	if err != nil {
		t.Fatalf("the committed table did not load: %v", err)
	}
	v4, v6 := tab.Len()
	if v4+v6 != tab.Rows {
		t.Errorf("rows %d != v4 %d + v6 %d", tab.Rows, v4, v6)
	}
	// Floors, not exact counts: the table is refreshed per release and the numbers
	// move every time. These are low enough that only a truncated, stubbed or
	// wrong-family table trips them, and Load has already enforced the properties
	// that actually matter (disjoint, sorted, no AS0).
	if v4 < 100_000 {
		t.Errorf("IPv4 spans = %d, far below a real routing table; is the committed table truncated?", v4)
	}
	if v6 < 10_000 {
		t.Errorf("IPv6 spans = %d, far below a real routing table; was it staged with -family v4?", v6)
	}
}

// TestEmbeddedTableResolvesGlobalAddresses proves the committed bytes are a routing
// table and not merely a well-formed file: they place addresses that are globally
// routed, they place both families, and they place two of them in DIFFERENT
// autonomous systems — which is the only property the diversity control consumes.
//
// The addresses are long-lived public anycast resolvers, chosen because their
// allocations are about as stable as the routing system offers. The assertions are
// still only "resolved" and "distinct", never a particular AS number, so a refresh
// that renumbers one of them keeps passing.
func TestEmbeddedTableResolvesGlobalAddresses(t *testing.T) {
	tab, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	for _, s := range []string{
		"1.1.1.1", "8.8.8.8",
		"2606:4700:4700::1111", "2001:4860:4860::8888",
		"::ffff:8.8.8.8", // a v4-mapped v6, what a dual-stack socket hands back
	} {
		if _, ok := tab.LookupAS(netip.MustParseAddr(s)); !ok {
			t.Errorf("LookupAS(%s) = unknown, want a resolved AS", s)
		}
	}

	a, ok1 := tab.LookupAS(netip.MustParseAddr("1.1.1.1"))
	b, ok2 := tab.LookupAS(netip.MustParseAddr("8.8.8.8"))
	if ok1 && ok2 && a == b {
		t.Errorf("two independently operated networks both resolved to %s; the table cannot distinguish anything", a)
	}
}

// TestEmbeddedTableReturnsUnknownForUnroutableSpace is the other half, and it is the
// one the staging transform can actually get wrong.
//
// asn-stage drops the upstream's `AS0 / Not routed` markers so unrouted space becomes
// a GAP. If it merged across a gap instead, an address nobody announces would inherit
// a neighbour's AS — the exact failure ADR-0044 §6 named — and it would show up here,
// because documentation and private space is unrouted by construction.
func TestEmbeddedTableReturnsUnknownForUnroutableSpace(t *testing.T) {
	tab, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	for _, s := range []string{
		"192.0.2.1", "198.51.100.1", "203.0.113.1", // RFC 5737 documentation
		"2001:db8::1",                           // RFC 3849 documentation
		"10.0.0.1", "172.16.0.1", "192.168.1.1", // RFC 1918
		"127.0.0.1", "::1", // loopback
		"169.254.1.1", // link-local
		"224.0.0.1",   // multicast
	} {
		if as, ok := tab.LookupAS(netip.MustParseAddr(s)); ok {
			t.Errorf("LookupAS(%s) = %s, want unknown — no AS announces this space", s, as)
		}
	}
}

// tableMaxAge is how stale the committed table may get before CI says so.
//
// 90 days, which is both core/geoip's staleness threshold and the quarterly cadence
// ADR-0044 §6 measured: at ~1.3% drift per month the error is near 3.6% at this point,
// which §6 treats as the acceptable operating range for an embedded table. A project
// shipping quarterly never sees this fire; one that has not shipped in a quarter is
// exactly the case where somebody should be told.
const tableMaxAge = 90 * 24 * time.Hour

// tableReleaseMaxAge is the tighter bar a RELEASE has to clear, and it exists because
// tableMaxAge measures the wrong end of the table's life (issue #66).
//
// 90 days is a budget on how wrong the table may be *in the hands of somebody running
// it*. That budget is spent on both sides of a release: the age of the table when the
// artifact is built, plus however long the person who installed it keeps running that
// build. Against tableMaxAge alone the whole of it can be spent before the artifact
// leaves the building — a release cut on day 89 hands a user a table that is already at
// the limit on the day they install it, and every day after that is over.
//
// So the release bar is where that split gets chosen, and 30 days is the choice: ship a
// table at most a month old and roughly 60 days of the budget are still on the user's
// side when they install. It is not a round number picked for looking careful — it is
// the unit ADR-0044 §6's own churn table is written in, whose one-month row is the
// 1.30% figure the whole cadence argument rests on.
//
// The cost of a tighter bar, named rather than waved past: every refresh commits a
// wholly new ~3.14 MB blob that git cannot delta (ADR-0044's second amendment §7). At 30
// days a hotfix cut within a month of a feature release inherits no refresh at all; at a
// week, every one of them would, and the repository would grow by a table per patch.
const tableReleaseMaxAge = 30 * 24 * time.Hour

// releaseTableEnv is what makes the release bar above load-bearing. Exactly one thing
// sets it: the verify-table job in .github/workflows/release.yml.
//
// Same shape and the same reason as core/version's BACCHUS_REQUIRE_STAMP and the CI
// server job's BACCHUS_NETD_REQUIRE_NS — an assertion that is inert by default and made
// mandatory by the one job that needs it. The release bar cannot simply apply
// everywhere: at 30 days it would block every unrelated pull request one month after a
// refresh instead of one quarter, and tableMaxAge's generosity is half of why that
// pressure is affordable. It also cannot be a warning, for the reason
// TestEmbeddedTableIsFresh gives about failing rather than logging.
const releaseTableEnv = "BACCHUS_ASN_RELEASE_TABLE"

// TestEmbeddedTableIsFresh is the forcing function behind "refreshed per release".
//
// Before this existed the refresh was written down in two places and enforced by
// neither, which made it folklore: nothing in the repository could even tell you the
// table was old, because the retrieval date lived only in TABLE.md prose and the gzip
// header's mtime is deliberately zeroed for determinism.
//
// It FAILS rather than logs. A t.Log on a passing test is invisible without -v, so a
// warning here would be indistinguishable from no check at all. The cost of failing is
// real and worth naming: once the table goes stale this blocks unrelated work until
// somebody refreshes it. That is the intended pressure — the threshold is generous
// enough that hitting it means the table genuinely is out of the range ADR-0044
// costed, and the message says exactly what to run.
//
// It carries BOTH bars rather than living beside a second test, and that is deliberate
// (issue #66). They are two thresholds on one quantity — the age of the committed
// table — so computing that age twice, in two tests, would be two places to keep in
// step for no gain. It also removes a whole class of quiet failure: a release job
// pointing `go test -run` at a second test that had been renamed or deleted would exit
// 0 and report a gate over nothing, which is the same silent no-op the release stamp
// was bitten by. There is one assertion here and deleting it is a loud act.
func TestEmbeddedTableIsFresh(t *testing.T) {
	retrieved, err := time.Parse(time.DateOnly, TableRetrieved)
	if err != nil {
		t.Fatalf("TableRetrieved = %q, which is not a YYYY-MM-DD date: %v", TableRetrieved, err)
	}
	if retrieved.After(time.Now()) {
		t.Fatalf("TableRetrieved = %s is in the future; was it typed rather than taken from the refresh?", TableRetrieved)
	}
	age := time.Since(retrieved)
	// Logged unconditionally so a release run is answerable from its own output: the
	// verify-table job runs this package with -v for exactly this line, and a run that
	// passes should still say what it passed on.
	t.Logf("the committed IP→AS table was retrieved %s, %d days ago; build floor %d days, release bar %d days",
		TableRetrieved, int(age.Hours()/24),
		int(tableMaxAge.Hours()/24), int(tableReleaseMaxAge.Hours()/24))

	if age > tableMaxAge {
		t.Errorf(`the committed IP→AS table was retrieved %s, %d days ago (limit %d).

At ~1.3%% drift per month it is now roughly %.1f%% wrong, which is outside the range
ADR-0044 costed for an embedded table. Refresh it:

    curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz
    go run ./cmd/asn-stage -in ip2asn-combined.tsv.gz -out core/asn/table.tsv.gz -gzip

then set TableRetrieved in core/asn/embedded.go to today and update the hashes and row
counts in core/asn/TABLE.md.`,
			TableRetrieved, int(age.Hours()/24), int(tableMaxAge.Hours()/24),
			1.3*age.Hours()/24/30)
	}

	// The release bar, checked after the floor rather than instead of it: they are two
	// thresholds on one quantity and a release run that trips both should say so.
	if os.Getenv(releaseTableEnv) == "" {
		return
	}
	if age > tableReleaseMaxAge {
		t.Errorf(`this is a release run (%s is set) and the committed IP→AS table was
retrieved %s, %d days ago. A release may ship one at most %d days old.

The table is still inside the %d-day floor that applies to any build, so nothing is
wrong with the tree — what is wrong is shipping it. ADR-0044 embedded this table in the
client binary, which means these bytes are what every user of this release resolves
relay hops against until they install another one, and cutting now would spend %d days
of a 90-day accuracy budget before the artifact reaches anybody. Refresh it:

    curl -O https://iptoasn.com/data/ip2asn-combined.tsv.gz
    go run ./cmd/asn-stage -in ip2asn-combined.tsv.gz -out core/asn/table.tsv.gz -gzip

then set TableRetrieved in core/asn/embedded.go to today, update the hashes and row
counts in core/asn/TABLE.md, and tag the commit that carries all of it.`,
			releaseTableEnv, TableRetrieved, int(age.Hours()/24),
			int(tableReleaseMaxAge.Hours()/24), int(tableMaxAge.Hours()/24),
			int(age.Hours()/24))
	}
}

// TestReleaseWorkflowGatesTheTable asserts that the release workflow actually carries
// the bar above, and carries it as a PRECONDITION rather than as a bystander beside the
// build.
//
// That distinction is the whole of issue #66 and it is not hypothetical. Between #55
// and #66 TestEmbeddedTableIsFresh ran only in ci.yml, and on a tag push GitHub starts
// ci.yml and release.yml from the same event with nothing ordering them — `needs:` is
// intra-workflow and `workflow_run` is a different tool for a different problem. A
// check that cannot stop the thing it is checking gates nothing, so the freshness test
// could go red beside a bundle that had already been built and a draft release that
// already existed.
//
// Two edits would quietly undo the fix and neither is a compile error:
//
//   - the workflow stops setting BACCHUS_ASN_RELEASE_TABLE, and every release run
//     silently applies the 90-day floor in place of the 30-day bar;
//   - the gate job stays in the file but windows-bundle stops needing it, at which
//     point it is a parallel check beside a build again — the original defect,
//     restored, and green.
//
// So the assertion lives here, in the package that owns the table, where ci.yml runs it
// on every ordinary pull request. The workflow that does gate merges is what guards the
// workflow that gates releases.
func TestReleaseWorkflowGatesTheTable(t *testing.T) {
	const path = "../../.github/workflows/release.yml"
	b, err := os.ReadFile(path)
	if err != nil {
		// Not a skip. A gate that opens when its input disappears is not a gate, which
		// is release.yml's own stated rule about a missing VERSION file.
		t.Fatalf("cannot read %s: %v\n\nThis test asserts the release workflow gates the shipped IP→AS table; without the file there is nothing to assert and reporting green would be reporting over nothing.", path, err)
	}
	src := string(b)

	gate := workflowJob(t, src, "verify-table")
	if !workflowSetsEnv(gate, releaseTableEnv) {
		t.Errorf(`the verify-table job in %s no longer sets %s.

Without it the release run applies tableMaxAge (%d days) instead of tableReleaseMaxAge
(%d days), so a release can ship a table up to two months older than intended and every
job in the workflow still reports green.`,
			path, releaseTableEnv, int(tableMaxAge.Hours()/24), int(tableReleaseMaxAge.Hours()/24))
	}

	bundle := workflowJob(t, src, "windows-bundle")
	needs, ok := workflowNeeds(bundle)
	switch {
	case !ok:
		t.Errorf(`the windows-bundle job in %s has no needs:.

It must name verify-table, or the gate runs in parallel with the build it is supposed to
prevent — which is the defect issue #66 was filed on, restored.`, path)
	case !strings.Contains(needs, "verify-table"):
		t.Errorf(`the windows-bundle job in %s needs %q, which does not include verify-table.

A job that does not gate the build gates nothing: the bundle would be compiled, the
artifact uploaded and on a tag push the draft release created, all while the table check
was still running beside it.`, path, needs)
	}
}

// TestReleaseWorkflowChecksTagAncestry is the other half of the same belt, for
// the other gate in the same job (issue #172).
//
// #151 added a step to verify-version that refuses a tag on a commit main does
// not contain, and the argument the whole release rests on runs through it:
// release.yml re-asserts only what expires with the calendar — the age of the
// shipped table — because every other assertion here is a function of the tree,
// and ci.yml's run on the pull request that merged those bytes is durable
// evidence about them. That is sound exactly to the extent that the tagged
// commit went through a pull request. A tag on a branch head or a local commit
// went through none, so no such run exists, and the tree being shipped has been
// tested by nothing at all.
//
// THE ASYMMETRY IS WHY THIS TEST EXISTS. Half of that step self-defends:
// removing fetch-depth: 0 makes it fail loudly, with a message naming
// fetch-depth: 0 as the fix, which was deliberate. DELETING THE STEP OUTRIGHT is
// the silent edit — releases keep working, nothing goes red, and the provenance
// guarantee is gone with no signal anywhere. Same shape as
// TestReleaseWorkflowGatesTheTable above and the same reason for living in Go
// rather than in a workflow: ci.yml gates merges, so the workflow that gates
// merges is what guards the workflow that gates releases.
//
// This package rather than a new one because the machinery is already here.
// core/asn does not own release.yml's tag rules, and it is a slightly odd
// address for them — but a second copy of workflowJob somewhere tidier is a
// second thing to keep in step with the file's layout, and the alternative of
// moving all of it is a change to a passing test that guards a shipped
// guarantee. If a third caller ever appears, that is the moment to move the
// three helpers into their own package and not before.
//
// fetch-depth is asserted here even though the step defends itself against its
// removal, because that defence fires DURING A RELEASE — the one moment nothing
// should be discovered — and this fires on every pull request. It costs one line
// and moves the discovery months earlier.
func TestReleaseWorkflowChecksTagAncestry(t *testing.T) {
	const path = "../../.github/workflows/release.yml"
	b, err := os.ReadFile(path)
	if err != nil {
		// Not a skip, for the reason the test above gives: a gate that opens when
		// its input disappears is not a gate.
		t.Fatalf("cannot read %s: %v\n\nThis test asserts the release workflow still refuses a tag on a commit main does not contain; without the file there is nothing to assert and reporting green would be reporting over nothing.", path, err)
	}
	src := string(b)

	gate := workflowJob(t, src, "verify-version")

	// The refusal itself, named by the one thing only it does: comparing the
	// TAGGED commit against main. The job runs merge-base twice more as a
	// self-test of merge-base itself, both against main's own parent, so a bare
	// search for "merge-base --is-ancestor" would survive deleting exactly the
	// assertion that matters.
	if !workflowRuns(gate, `merge-base --is-ancestor "$sha"`) {
		t.Errorf(`the verify-version job in %s no longer compares the tagged commit against main.

This is #151's step, and losing it is silent: releases keep building, every job
in the workflow stays green, and a tag pushed onto a branch head or a local
commit will build a bundle and draft a release from a tree ci.yml never saw. The
release-time argument for re-running ONE test rather than the suite depends on
the tagged commit having gone through a pull request, and this step is the only
thing that makes that so.

If the shell variable was renamed rather than the step deleted, rename it here
too — this test is what notices when the check goes away.`, path)
	}

	// What it is compared AGAINST. A step that still runs merge-base but against
	// the tag's own branch, or against HEAD, answers a question nobody asked and
	// passes for every tag. The full ref rather than the bare "origin/main" is
	// the workflow's own choice, and it is the one comparison in that file where
	// resolving to something else would be silent.
	if !workflowRuns(gate, "refs/remotes/origin/main") {
		t.Errorf(`the verify-version job in %s no longer names refs/remotes/origin/main.

The ancestry check is only a gate if main is what it checks against: a release is
cut from main or it is not cut (#151). A comparison against anything else — the
tag's own branch, HEAD — is satisfied by every tag and refuses nothing.`, path)
	}

	// The checkout that makes the answer meaningful. Asserted as a KEY, not as a
	// substring: this job's error text contains the string "fetch-depth: 0" in a
	// non-comment echo line, so a loose search is satisfied by the message that
	// tells you it is missing. Same trap workflowSetsEnv below was written for.
	if !workflowHasKey(gate, "fetch-depth: 0") {
		t.Errorf(`the verify-version job in %s no longer sets fetch-depth: 0 on its checkout.

actions/checkout defaults to depth 1 and on a tag push fetches only the tagged
commit — no branches, so no origin/main. The step catches that and fails with a
message naming this fix, so nothing ships wrongly; but it catches it during a
RELEASE, which is the one moment to discover nothing. This assertion catches it
on the pull request that removed it.`, path)
	}

	// And that the gate is a PRECONDITION rather than a bystander. The table gate
	// above learned this the hard way (issue #66): a check that runs beside the
	// build cannot stop it, and windows-bundle is where a bundle is compiled, an
	// artifact uploaded, and on a tag push a draft release created.
	bundle := workflowJob(t, src, "windows-bundle")
	needs, ok := workflowNeeds(bundle)
	switch {
	case !ok:
		t.Errorf(`the windows-bundle job in %s has no needs:.

It must name verify-version, or the ancestry check runs in parallel with the
build it is meant to prevent.`, path)
	case !strings.Contains(needs, "verify-version"):
		t.Errorf(`the windows-bundle job in %s needs %q, which does not include verify-version.

A check that finishes after the artifacts exist gates nothing: the bundle would
be compiled, the artifact uploaded and on a tag push the draft release created,
all while the question of whether the tag is even on main was still being
answered beside it.`, path, needs)
	}
}

// TestReleaseWorkflowPublishNeedsTheGatedBuild asserts the THIRD link of the
// chain the two tests above assert the first two of (issue #172's leftover,
// filed as issue #180 and deliberately out of that card's scope at the time).
//
// verify-table carries the shipped table's release bar and verify-version
// carries the tag's ancestry; windows-bundle needs both, which is what those two
// tests pin. Neither of them is the job that mints anything. `publish` is — it
// downloads the artifact, writes the notes and runs `gh release create` with the
// only `contents: write` permission in the file — and it is gated only because
// it needs windows-bundle, transitively, with nothing asserting that.
//
// It is its own test rather than a fifth assertion inside the ancestry one
// BECAUSE THE LINK BELONGS TO BOTH GATES. Buried in either, its failure message
// would arrive under a heading about the other one's subject, and deleting that
// test for an unrelated reason would take this with it.
//
// WHAT THE REALISTIC EDIT LOOKS LIKE, since the obvious one is self-defeating:
// dropping `needs:` outright would break publish immediately, because it
// downloads windows-bundle's artifact and reads `needs.windows-bundle.outputs`.
// The edit that stays green is publish coming to need a DIFFERENT bundle job. A
// 1.0 that ships Windows and Linux grows a second one, and `needs: linux-bundle`
// — or a second publish job beside this one — supplies artifacts perfectly well
// while carrying none of the gates. That is the shape this is here for; the
// no-needs branch below is asserted anyway because it costs one line and is what
// a restructure looks like from here.
//
// A third caller of workflowJob does not trip the note in
// TestReleaseWorkflowChecksTagAncestry about moving the three helpers into their
// own package. That note is about a second COPY of them appearing somewhere
// tidier — the same file and the same package is the case it argues for.
func TestReleaseWorkflowPublishNeedsTheGatedBuild(t *testing.T) {
	const path = "../../.github/workflows/release.yml"
	b, err := os.ReadFile(path)
	if err != nil {
		// Not a skip, for the reason the two tests above give: a gate that
		// opens when its input disappears is not a gate.
		t.Fatalf("cannot read %s: %v\n\nThis test asserts the job that creates a release still waits for the gated build; without the file there is nothing to assert and reporting green would be reporting over nothing.", path, err)
	}

	publish := workflowJob(t, string(b), "publish")
	needs, ok := workflowNeeds(publish)
	switch {
	case !ok:
		t.Errorf(`the publish job in %s has no needs:.

publish holds the only contents: write permission in this file and its if: fires
on any tag push, so with nothing to wait for it starts beside verify-version,
verify-table and the build itself.`, path)
	case !strings.Contains(needs, "windows-bundle"):
		t.Errorf(`the publish job in %s needs %q, which does not include windows-bundle.

windows-bundle is what carries both gates — it needs verify-version and
verify-table — so publish is gated on the tag being on main and on the age of the
shipped IP→AS table only for as long as it needs windows-bundle. A publish job
that waits for some other bundle instead gets its artifacts and none of the
gates, and a draft release can be created beside a red one.`, path, needs)
	}
}

// workflowRuns reports whether a job actually RUNS something containing want, as
// opposed to mentioning it in a comment.
//
// These workflow files carry more prose than YAML — verify-version's two steps
// are wrapped in about seventy lines of comment explaining why each exists — so
// a plain substring search over a job is satisfied by the explanation of a step
// that has been deleted. workflowSetsEnv's doc records the same trap being hit
// for real.
func workflowRuns(job, want string) bool {
	for _, ln := range strings.Split(job, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.Contains(ln, want) {
			return true
		}
	}
	return false
}

// workflowHasKey reports whether a job carries a line that is EXACTLY key once
// trimmed — for settings whose text also appears inside the error messages that
// talk about them, where workflowRuns' substring match would find the message
// rather than the setting.
func workflowHasKey(job, key string) bool {
	for _, ln := range strings.Split(job, "\n") {
		if strings.TrimSpace(ln) == key {
			return true
		}
	}
	return false
}

// workflowJob returns the lines of one top-level job from a workflow file.
//
// Textual rather than parsed: a YAML library is a dependency this module does not carry
// and would not otherwise want, and the two properties being asserted are both single
// lines. A job header is the only thing in these files at exactly two spaces of
// indentation, so the scan is "from this job's header to the next one".
func workflowJob(t *testing.T, src, name string) string {
	t.Helper()
	lines := strings.Split(src, "\n")
	start := -1
	for i, ln := range lines {
		if ln == "  "+name+":" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		// Deliberately not naming one subject. This has three callers now and
		// only one of them is about the shipped table; a message that names the
		// table would misdirect whoever removed the publish or verify-version
		// job, which is the more likely edit.
		t.Fatalf("no %q job in .github/workflows/release.yml.\n\nIf it was renamed, rename it here too — the tests in this file are what notice when the release stops being gated.", name)
	}
	for i := start; i < len(lines); i++ {
		if isJobHeader(lines[i]) {
			return strings.Join(lines[start:i], "\n")
		}
	}
	return strings.Join(lines[start:], "\n")
}

// isJobHeader reports whether a line is a top-level job key: two spaces, a name, a
// colon, nothing else.
func isJobHeader(ln string) bool {
	if !strings.HasPrefix(ln, "  ") || strings.HasPrefix(ln, "   ") {
		return false
	}
	name, ok := strings.CutSuffix(strings.TrimPrefix(ln, "  "), ":")
	if !ok || name == "" {
		return false
	}
	for _, r := range name {
		if !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// workflowSetsEnv reports whether a job actually SETS an environment variable, as
// opposed to merely mentioning it.
//
// The distinction is not pedantry: this job's steps carry a long comment naming the
// variable and explaining what it does, and a plain substring search over the job was
// satisfied by that comment — so deleting the `env:` entry left the check green while
// every release run silently fell back to the 90-day floor. Comment lines are dropped
// and the name has to appear as a key.
func workflowSetsEnv(job, name string) bool {
	for _, ln := range strings.Split(job, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.HasPrefix(ln, name+":") {
			return true
		}
	}
	return false
}

// workflowNeeds returns the value of a job's needs: key, if it has one.
func workflowNeeds(job string) (string, bool) {
	for _, ln := range strings.Split(job, "\n") {
		if v, ok := strings.CutPrefix(ln, "    needs:"); ok {
			return strings.TrimSpace(v), true
		}
	}
	return "", false
}

// TestEmbeddedIsParsedOnce pins the sync.OnceValues contract, which is load-bearing
// rather than decorative: core/relaychain.go's directory RELOADS on an interval
// (reloadRelayDirLoop), and every reload asks for this table. Were it parsed per
// call, a long-running client would spend ~190 ms and ~28 MB again on every reload,
// forever, for a result that cannot have changed.
func TestEmbeddedIsParsedOnce(t *testing.T) {
	a, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded: %v", err)
	}
	b, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded (second call): %v", err)
	}
	if a != b {
		t.Error("Embedded returned a different *Table on the second call; it is re-parsing the whole table per caller")
	}
}
