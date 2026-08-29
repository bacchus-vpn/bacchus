// Coverage for deploy/bacchus-gate-check.sh and the configuration it exists to make
// checkable, deploy/coordinator-gates.env.example (issues #249, #247, ADR-0072).
//
// Two halves, and the second is the one that matters.
//
// The first drives the script with synthetic journals, because the interesting states
// are combinations a real binary is awkward to be put into on demand: a window with no
// coordinator start in it, a signed-revocations root that is set and feeding neither
// namespace, a required gate the journal cannot answer.
//
// The second never hand-writes a log line. The contract this script reads is a LOG
// LINE, written in Go and parsed in shell — the pair ADR-0069 §4 names as the one that
// drifts silently, and the same reason deploy/node_startup_line_test.go builds cmd/node
// rather than describing it. So TestTheShippedGatesConfigurationTurnsTheGatesOn builds
// cmd/coordinator, runs it with the flag set coordinator-gates.env.example actually
// ships, and feeds the bytes the real binary produced through the real script.
//
// That closes the loop issue #249 opened. The card's own complaint is that the gates
// were "a flag set rediscovered from -h each time", and a documented flag set is only
// worth more than prose if something runs it: a renamed flag, a re-scoped one, or a
// default that changed direction turns this file red instead of turning a deployment
// quietly open.
package deploy

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	gateCheckRelPath = "deploy/bacchus-gate-check.sh"
	gatesEnvRelPath  = "deploy/coordinator-gates.env.example"
	gatesADRRelPath  = "docs/adr/0072-the-deployment-states-its-own-gates.md"
)

func gateCheck(t *testing.T, journal string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(repoRoot(t), gateCheckRelPath)}, args...)...)
	cmd.Stdin = strings.NewReader(journal)
	b, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if err != nil {
		if !asExitError(err, &ee) {
			t.Fatalf("running %s: %v\n%s", gateCheckRelPath, err, b)
		}
		code = ee.ExitCode()
	}
	return string(b), code
}

// The startup line the window is keyed on, in the shape cmd/coordinator prints it —
// the same line deploy/bacchus-fleet-check.sh keys on, which is why the two can read
// one journal.
const coordStart = "Aug 09 10:00:00 box bacchus-coordinator[9]: version fence DISABLED " +
	"(-min-serving-version 0.0.0) — any node version may serve (issue #36); " +
	"coordinator release 0.1.0 (revision 6396fc7abcde)\n"

// gatesOffJournal is the live testbed coordinator as issue #249 found it: the bootstrap
// pair, the policy set and -geoip, and not one credential gate.
func gatesOffJournal() string {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	return coordStart +
		p + "paths: working directory /\n" +
		p + "paths: -admission-revocations         /secrets/admission-revocations.json [relative \"secrets/admission-revocations.json\"; ABSENT — NOTHING IS REVOKED in the admission namespace]\n" +
		p + "paths: -device-revocations            /secrets/device-revocations.json [relative \"secrets/device-revocations.json\"; ABSENT — NOTHING IS REVOKED in the device namespace]\n" +
		p + "paths: -device-revocations-state      /secrets/device-revocations-state.json [relative \"secrets/device-revocations-state.json\"; ABSENT — a cold start]\n" +
		p + "paths: WARNING: 9 path(s) above are RELATIVE and this process's working directory is /, so they resolve under the root directory\n" +
		p + "WARNING: admission DISABLED (neither -admission-pubkey nor -admission-authority set) — any client or node can join this network (issue #42)\n" +
		p + "device-credential gate DISABLED (-device-root-pubkey not set) — connects are gated by admission alone; no entitlement is checked (issue #50)\n" +
		p + "signed revocations DISABLED (-revocations-root-pubkey unset) — -device-revocations and -admission-revocations remain the only source for both lists (issue #199, ADR-0017)\n" +
		p + "signed policy ENABLED — enforcing signed floors from <source>, state in /etc/bacchus/policy-state.json (issue #39, ADR-0043)\n" +
		p + "tier limits NOT ENFORCED: signed policy is configured but admission is not, so no connect carries the (trust, plan) pair the policy's tiers table is indexed by\n"
}

// The whole of issue #249 in one assertion: a fleet in this state is refusing nothing,
// and until this check existed nothing anywhere said so.
func TestGateCheck_ReportsTheLiveTestbedPostureAsOff(t *testing.T) {
	out, code := gateCheck(t, gatesOffJournal())
	if code != 0 {
		t.Fatalf("exit %d, want 0 — a report with nothing required judges nothing\n%s", code, out)
	}
	for _, want := range []string{
		"admission           OFF",
		"device              OFF",
		"revocation-lists    EMPTY",
		"signed-revocations  OFF",
		"policy              on",
		"account-service     UNKNOWN",
		"NOTHING IS REVOKED",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not carry %q:\n%s", want, out)
		}
	}
	// #247's condition, read from the coordinator's own resolved-paths block rather
	// than from the unit.
	if !strings.Contains(out, "working directory  /") || !strings.Contains(out, "issue #247") {
		t.Errorf("an empty working directory is not reported:\n%s", out)
	}
}

// Declaring a gate is what turns a report into a verdict. This is the case that stops
// #167, #173 and #209 from returning a false pass.
func TestGateCheck_ADeclaredGateThatIsOffFailsTheRun(t *testing.T) {
	out, code := gateCheck(t, gatesOffJournal(), "--require", "admission,device,revocation-lists")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	for _, want := range []string{
		"admission is DECLARED ON and is OFF",
		"device is DECLARED ON and is OFF",
		"revocation-lists is DECLARED ON and is EMPTY",
		"do not\n  run #167, #173 or #209",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

// #248's finding, applied to this script first: a gate that could not be READ is not a
// gate that is on, and it must not exit 0.
//
// The standing instance used to be -account-service on every build, because
// cmd/coordinator announced nothing about it. Issue #260 gave it a line, so the case
// this now covers is a coordinator OLDER than that line — which is not hypothetical:
// merging deploys nothing, so a box runs a wave behind until it is re-pinned, and the
// window a stale box writes cannot answer this row no matter how wide it is opened.
func TestGateCheck_AGateItCannotReadIsNotAPass(t *testing.T) {
	out, code := gateCheck(t, gatesOffJournal(), "--require", "account-service")
	if code != 4 {
		t.Fatalf("exit %d, want 4 — an unreadable gate must not read as ok\n%s", code, out)
	}
	if !strings.Contains(out, "NOT a gate that is on") || !strings.Contains(out, "issue #260") {
		t.Errorf("the reason is not stated:\n%s", out)
	}
	if !strings.Contains(out, "predates issue #260") {
		t.Errorf("the row does not say a stale binary is why, so an operator is told to widen a"+
			" window that will never carry the line:\n%s", out)
	}
}

// -------------------------------------------------------------------------
// -account-service, read from the journal (issues #193, #260, #275)
// -------------------------------------------------------------------------
//
// The row #261 exists to settle. Both spellings cmd/coordinator prints begin
// `account service: ` and diverge on the next word, and the two states are not
// interchangeable: one says a client learns an address from this deployment, the other
// says every client stays on the address in its own config file. A reader that matched
// the shared prefix and not the distinction would report the second as the first.
//
// The strings below are hand-written on purpose, unlike
// TestTheShippedGatesConfigurationTurnsTheGatesOn, which runs the real binary. Both are
// needed: that one proves this script reads what cmd/coordinator actually emits, and
// these prove what it does with the shapes a real coordinator will not produce on
// demand — a stale binary that emits nothing, and a future spelling neither side has
// written yet.

const (
	acctPublished = `account service: 2 address(es) published in the signed directory as role "account" (issue #193)`
	acctNone      = "account service: NONE published (-account-service unset) — every client stays on its own configuration (issue #193)"
)

func TestGateCheck_ReadsAPublishedAccountServiceAsOn(t *testing.T) {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	out, code := gateCheck(t, coordStart+p+acctPublished+"\n", "--require", "account-service")
	if code != 0 {
		t.Fatalf("exit %d, want 0 — a published address is the gate being on\n%s", code, out)
	}
	if !strings.Contains(out, "account-service     on") {
		t.Errorf("a published address is not reported as on:\n%s", out)
	}
	// The count is what makes the row worth reading: one address here narrows a
	// client that was configured with two (ADR-0061), so "on" alone is not the
	// whole answer.
	if !strings.Contains(out, "2 address(es) published") {
		t.Errorf("the report does not carry how many addresses were published:\n%s", out)
	}
}

// The case a prefix-only match gets wrong. NONE published is a coordinator that said
// something definite — every client stays on its own configuration — and it is not the
// gate being on. Declaring it must FAIL the run (exit 1), not pass it and not exit 4.
func TestGateCheck_ReadsNONEPublishedAsOffAndNotAsOn(t *testing.T) {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	out, code := gateCheck(t, coordStart+p+acctNone+"\n", "--require", "account-service")
	if code != 1 {
		t.Fatalf("exit %d, want 1 — NONE published is a stated OFF, not an on and not an unread\n%s", code, out)
	}
	if !strings.Contains(out, "account-service     OFF") {
		t.Errorf("NONE published is not reported as OFF:\n%s", out)
	}
	if !strings.Contains(out, "account-service is DECLARED ON and is OFF") {
		t.Errorf("declaring a gate that publishes nothing does not fail the run:\n%s", out)
	}
	// Without --require it is a report and nothing is judged, like every other row.
	if _, code := gateCheck(t, coordStart+p+acctNone+"\n"); code != 0 {
		t.Errorf("exit %d with nothing required, want 0", code)
	}
}

// A shape neither side has written yet. The Go/shell pair here is the one ADR-0069 §4
// names as drifting silently, so the third outcome is deliberate: an `account service:`
// line this script cannot parse stays UNKNOWN rather than falling into the on branch.
// Reporting an unparsed line as "enforcing" to the person reading #261 is the one
// answer worse than admitting the row cannot be read (#248).
func TestGateCheck_AnUnrecognizedAccountServiceLineIsNotOn(t *testing.T) {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	j := coordStart + p + "account service: something a later release prints\n"
	out, code := gateCheck(t, j, "--require", "account-service")
	if code != 4 {
		t.Fatalf("exit %d, want 4 — a line nobody parsed is not a gate that is on\n%s", code, out)
	}
	if !strings.Contains(out, "account-service     UNKNOWN") || !strings.Contains(out, "drifted apart") {
		t.Errorf("the drift is not reported:\n%s", out)
	}
}

// The same window rule every other row obeys. A publication announced by the
// coordinator that is gone is not evidence about the one that is running.
func TestGateCheck_AccountServiceDoesNotSurviveARestart(t *testing.T) {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	out, code := gateCheck(t, coordStart+p+acctPublished+"\n"+coordStart, "--require", "account-service")
	if code != 4 {
		t.Fatalf("exit %d, want 4 — the publication belongs to a coordinator that is gone\n%s", code, out)
	}
	if strings.Contains(out, "account-service     on") {
		t.Errorf("a publication from before the restart survived it:\n%s", out)
	}
}

// The same window rule bacchus-fleet-check.sh enforces, for the same reason: a posture
// read from before the last restart describes a coordinator that is not running.
func TestGateCheck_RefusesAWindowWithNoCoordinatorStart(t *testing.T) {
	j := "Aug 09 10:00:00 box bacchus-coordinator[9]: WARNING: admission DISABLED (neither -admission-pubkey nor -admission-authority set)\n"
	out, code := gateCheck(t, j)
	if code != 3 {
		t.Fatalf("exit %d, want 3\n%s", code, out)
	}
	if !strings.Contains(out, "Widen the") {
		t.Errorf("the message is not actionable:\n%s", out)
	}
}

// A gate turned on before the restart and off after it must read OFF. The reset is what
// makes that true, and it is easy to lose.
func TestGateCheck_IgnoresAPostureFromBeforeTheRestart(t *testing.T) {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	j := coordStart + p + "admission ENABLED — anchors: client,relay,exit=aabbccdd…\n" +
		coordStart + p + "WARNING: admission DISABLED (neither -admission-pubkey nor -admission-authority set)\n"
	out, code := gateCheck(t, j, "--require", "admission")
	if code != 1 {
		t.Fatalf("exit %d, want 1 — the earlier ENABLED belongs to a coordinator that is gone\n%s", code, out)
	}
}

// The same rule for everything that is set by a line and never by its absence: a
// `paths:` block, the working-directory warning, the tier notice. Each is a latch, and a
// latch that survives a restart reports the previous coordinator's configuration under
// the current one's name — which is the exact failure the window rule exists to prevent,
// arriving through the back door.
func TestGateCheck_ClearsEveryLatchAtARestart(t *testing.T) {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	stale := p + "paths: working directory /\n" +
		p + "paths: -device-revocations /secrets/device-revocations.json [relative \"secrets/device-revocations.json\"; ABSENT — NOTHING IS REVOKED in the device namespace]\n" +
		p + "paths: WARNING: 9 path(s) above are RELATIVE and this process's working directory is /\n" +
		p + "tier limits NOT ENFORCED: signed policy is configured but admission is not\n"
	fresh := p + "paths: working directory /etc/bacchus\n" +
		p + "paths: -device-revocations /etc/bacchus/device-revocations.json [present]\n" +
		p + "paths: -admission-revocations /etc/bacchus/admission-revocations.json [present]\n" +
		p + "admission ENABLED — anchors: client,relay,exit=aabbccdd…\n"

	out, code := gateCheck(t, coordStart+stale+coordStart+fresh, "--require", "admission,revocation-lists")
	if code != 0 {
		t.Fatalf("exit %d, want 0 — the run before the restart is not evidence about this one\n%s", code, out)
	}
	for _, gone := range []string{"NOTHING IS REVOKED", "the working directory is /", "tier limits"} {
		if strings.Contains(out, gone) {
			t.Errorf("a finding from before the restart survived it (%q):\n%s", gone, out)
		}
	}
	if !strings.Contains(out, "working directory  /etc/bacchus") {
		t.Errorf("the current working directory is not reported:\n%s", out)
	}
}

// A root that is set and feeding neither namespace is the configuration that looks done
// and is not: the flag is in ExecStart, the startup line says the mechanism is
// configured, and no verifier would ever consult either list.
func TestGateCheck_SignedRevocationsFedByNeitherNamespaceIsNotOn(t *testing.T) {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	j := coordStart +
		p + "signed revocations(device): -revocations-root-pubkey is set, but the device gate is not configured — there is no verifier that would ever consult this list (issue #199)\n" +
		p + "signed revocations(admission): -revocations-root-pubkey is set, but the admission gate is not configured — there is no verifier that would ever consult this list (issue #199)\n"
	out, code := gateCheck(t, j, "--require", "signed-revocations")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "NEITHER namespace is fed") {
		t.Errorf("the reason is not stated:\n%s", out)
	}
}

func TestGateCheck_OneNamespaceFedIsPartialAndNotOn(t *testing.T) {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	j := coordStart +
		p + "signed revocations(admission) ENABLED — fetching from <source> every 10s, state in /etc/bacchus/admission-revocations-state.json\n" +
		p + "signed revocations(device): -revocations-root-pubkey is set, but the device gate is not configured\n"
	out, code := gateCheck(t, j, "--require", "signed-revocations")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "PARTIAL") {
		t.Errorf("a half-fed mechanism is not reported as such:\n%s", out)
	}
}

// The device gate's audience is this coordinator as clients dial it — the one
// host-shaped value in the lines this reads. Like bacchus-fleet-check.sh's output, what
// this prints has to stay pasteable into a public issue.
func TestGateCheck_NeverEchoesTheAudience(t *testing.T) {
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "
	j := coordStart + p + "device-credential gate ENABLED — every connect must present a credential chaining to the configured offline root, bound to audience \"coordinator.example.invalid:8080\" (issue #50)\n"
	out, code := gateCheck(t, j)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if strings.Contains(out, "coordinator.example.invalid") {
		t.Errorf("it echoed the audience, which names a host:\n%s", out)
	}
	if !strings.Contains(out, "device              on") {
		t.Errorf("the gate is not reported as on:\n%s", out)
	}
}

func TestGateCheck_RefusesAGateItDoesNotKnow(t *testing.T) {
	out, code := gateCheck(t, gatesOffJournal(), "--require", "admision")
	if code != 2 {
		t.Fatalf("exit %d, want 2 on a typo — a silently ignored requirement is a requirement nobody has\n%s", code, out)
	}
}

// -------------------------------------------------------------------------
// the shipped configuration, run
// -------------------------------------------------------------------------

// gatesRecipes returns every commented `#BACCHUS_COORDINATOR_GATES=` line in the
// shipped example, in file order, with the surrounding quotes stripped.
//
// The recipes are commented because the file ships GATES OFF — that is what every
// deployment runs today and what an operator must be able to install without changing
// behaviour. Reading them from the comments is therefore not a shortcut around the
// file's real content; it IS the file's real content, and a recipe that stopped working
// would otherwise sit there being copied.
func gatesRecipes(t *testing.T) []string {
	t.Helper()
	body := string(readFile(t, filepath.Join(repoRoot(t), gatesEnvRelPath)))
	var out []string
	for _, line := range strings.Split(body, "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "#BACCHUS_COORDINATOR_GATES=")
		if !ok {
			continue
		}
		out = append(out, strings.Trim(strings.TrimSpace(v), `"`))
	}
	if len(out) == 0 {
		t.Fatalf("%s carries no #BACCHUS_COORDINATOR_GATES= recipe, so nothing in it is tested", gatesEnvRelPath)
	}
	return out
}

// The active line has to be EMPTY. It is the whole reason the unit can carry
// `$BACCHUS_COORDINATOR_GATES` on every box, including the ones nobody has configured:
// systemd splits an unquoted `$VAR` into zero or more arguments, so empty adds nothing.
func TestTheShippedGatesFileTurnsNothingOn(t *testing.T) {
	body := string(readFile(t, filepath.Join(repoRoot(t), gatesEnvRelPath)))
	active := 0
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, "BACCHUS_COORDINATOR_GATES=") {
			continue
		}
		active++
		if strings.TrimSpace(strings.TrimPrefix(line, "BACCHUS_COORDINATOR_GATES=")) != "" {
			t.Errorf("the active line turns a gate on: %q. deploy/install.sh places this file on"+
				" every coordinator, so it must change no behaviour.", line)
		}
	}
	if active != 1 {
		t.Errorf("found %d active BACCHUS_COORDINATOR_GATES= lines, want exactly 1 — systemd's"+
			" env-file parser takes the last, so two is a configuration nobody can read", active)
	}
	// The unit has to actually expand it, and as $VAR rather than ${VAR}: ${VAR} is
	// always exactly one argument, so an empty one would be a flag value of "".
	unit := string(readFile(t, filepath.Join(repoRoot(t), coordUnitRelPath)))
	if !strings.Contains(unit, "$BACCHUS_COORDINATOR_GATES") {
		t.Error("the coordinator unit does not expand $BACCHUS_COORDINATOR_GATES, so this file reaches nothing")
	}
	if strings.Contains(unit, "${BACCHUS_COORDINATOR_GATES}") {
		t.Error("the unit expands ${BACCHUS_COORDINATOR_GATES}, which is ALWAYS exactly one argument:" +
			" an empty value becomes an empty argv entry rather than no flags at all")
	}
	if !strings.Contains(unit, "EnvironmentFile=-/etc/bacchus/coordinator-gates.env") {
		t.Error("the unit does not source the gates file with a leading `-`, so a box without one fails to start")
	}
}

// testMaterial fills the example's placeholders with usable values. Every key is
// generated per run: this repository is public, and a fixed key in it is a key somebody
// eventually stages.
func testMaterial(t *testing.T, dir string) map[string]string {
	t.Helper()
	key := func() string {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(pub)
	}
	// A source may be an http(s) URL or a filesystem path. A path that is not there
	// is deliberately not a startup failure — the cache may still hold a usable
	// bundle and the refresh loop keeps trying — so an absent one exercises the
	// configuration without needing a signing ceremony to have happened.
	return map[string]string{
		"<OPERATOR_ADMISSION_PUBKEY>":                   key(),
		"<ACCOUNT_SERVICE_ADMISSION_PUBKEY>":            key(),
		"<DEVICE_ROOT_PUBKEY>":                          key(),
		"<REVOCATIONS_ROOT_PUBKEY>":                     key(),
		"<ACCOUNT_HOST>":                                "198.51.100.20",
		"<ACCOUNT_PORT>":                                "8443",
		"<DEVICE_REVOCATIONS_SOURCE>":                   filepath.Join(dir, "device-bundle.json"),
		"<ADMISSION_REVOCATIONS_SOURCE>":                filepath.Join(dir, "admission-bundle.json"),
		"/etc/bacchus/admission-revocations.json":       filepath.Join(dir, "admission-revocations.json"),
		"/etc/bacchus/device-revocations.json":          filepath.Join(dir, "device-revocations.json"),
		"/etc/bacchus/device-revocations-state.json":    filepath.Join(dir, "device-revocations-state.json"),
		"/etc/bacchus/admission-revocations-state.json": filepath.Join(dir, "admission-revocations-state.json"),
	}
}

// runCoordinatorBriefly starts the real binary, waits until it has said what it is going
// to say about its configuration, and kills it. It binds loopback with port 0 so two of
// these can run at once and neither can reach anything.
func runCoordinatorBriefly(t *testing.T, bin string, gateArgs []string, dir string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	args := append([]string{
		"-addr", "127.0.0.1:0",
		"-turn-addr", "127.0.0.1:0",
		"-turn-public-ip", "198.51.100.1",
		"-turn-pass", "not-a-real-password",
		// The device gate refuses to start without an audience, and -advertise is
		// where the live unit's comes from.
		"-advertise", "127.0.0.1:8080",
		"-bootstrap-key", filepath.Join(dir, "bootstrap.key"),
		"-bootstrap-secrets", filepath.Join(dir, "bootstrap-secrets.json"),
	}, gateArgs...)

	logPath := filepath.Join(dir, "coordinator.log")
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the coordinator: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// The listening line is the last thing main() prints before the packet loop, so
	// everything this reads is already in the file by then.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(logPath)
		if err == nil && strings.Contains(string(b), "listening on") {
			return string(b)
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, _ := os.ReadFile(logPath)
	t.Fatalf("the coordinator did not reach its listen line within the deadline. It printed:\n%s", b)
	return ""
}

// The load-bearing test of this whole lane: the configuration deploy/ documents is run
// through the binary it configures, and the check reads the result.
//
// It asserts three separate things that all have to hold at once, and each has failed in
// this project before in some other form: that every flag named in the example still
// exists and still takes that shape (a renamed flag would be a fatal parse error), that
// each documented step turns on exactly the gates it claims and not others, and that
// bacchus-gate-check.sh reads the real binary's own words rather than a description of
// them that has drifted.
func TestTheShippedGatesConfigurationTurnsTheGatesOn(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs cmd/coordinator")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}

	root := repoRoot(t)
	bin := filepath.Join(t.TempDir(), "bacchus-coordinator")
	build := exec.Command("go", "build", "-o", bin, "./cmd/coordinator")
	build.Dir = root
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building cmd/coordinator: %v\n%s", err, b)
	}

	// What each documented step is expected to produce. The steps are cumulative, so
	// the row for step N states the whole posture and not the delta.
	want := []struct {
		name    string
		require string
		lines   []string
	}{{
		// account-service is OFF here rather than unread, and that is the half of
		// issue #275 a hand-written fixture cannot prove: step 1 names no
		// -account-service, and the coordinator says so out loud.
		name:    "step 1 — admission and two revocation lists",
		require: "admission,revocation-lists",
		lines:   []string{"admission           on", "device              OFF", "revocation-lists    on", "account-service     OFF"},
	}, {
		name:    "step 2 — the device gate and the account service",
		require: "admission,device,revocation-lists,account-service",
		lines:   []string{"admission           on", "device              on", "revocation-lists    on", "account-service     on"},
	}, {
		name:    "step 3 — signed revocation bundles",
		require: "admission,device,revocation-lists,signed-revocations,account-service",
		lines:   []string{"signed-revocations  on", "account-service     on"},
	}}

	recipes := gatesRecipes(t)
	if len(recipes) != len(want) {
		t.Fatalf("%s ships %d recipes and this test knows %d. A new step needs a row here,"+
			" or it is documented and never run.", gatesEnvRelPath, len(recipes), len(want))
	}

	for i, recipe := range recipes {
		t.Run(want[i].name, func(t *testing.T) {
			dir := t.TempDir()
			// Both revocation FILES have to exist. An absent one is not an error —
			// it is an empty list, which is #247's whole point and the reason the
			// check reports the two separately from the flags.
			for _, n := range []string{"admission-revocations.json", "device-revocations.json"} {
				write(t, filepath.Join(dir, n), "[]\n", 0o600)
			}

			args := recipe
			for from, to := range testMaterial(t, dir) {
				args = strings.ReplaceAll(args, from, to)
			}
			if strings.ContainsAny(args, "<>") {
				t.Fatalf("a placeholder in %s has no fill in this test, so the recipe was never run: %s",
					gatesEnvRelPath, args)
			}

			journal := runCoordinatorBriefly(t, bin, strings.Fields(args), dir)
			out, code := gateCheck(t, journal, "--require", want[i].require)
			if code != 0 {
				t.Fatalf("the shipped recipe does not enforce what it claims (exit %d)\n%s\n"+
					"--- the coordinator said ---\n%s", code, out, journal)
			}
			for _, line := range want[i].lines {
				if !strings.Contains(out, line) {
					t.Errorf("missing %q\n%s\n--- the coordinator said ---\n%s", line, out, journal)
				}
			}
			// Whatever else changes, the working-directory warning must not fire:
			// every path in the shipped recipe is absolute, which is the half of
			// #247 that does not depend on the unit being edited.
			if strings.Contains(out, "the working directory is / and relative paths remain") {
				t.Errorf("a recipe left a gate flag on a relative path:\n%s", out)
			}
		})
	}
}

// -------------------------------------------------------------------------
// --label: one window, one pool member (issue #250, ADR-0074)
// -------------------------------------------------------------------------
//
// A gate is only as ON as the weakest member — every gate fails open, a client rotates
// freely, and there is no replication between coordinators — so this runs once per
// member and produces one report per member. Two unlabelled reports cannot be told
// apart, which is how per-member reading turns back into one undifferentiated answer.

func TestGateCheck_LabelsWhichMemberAWindowCameFrom(t *testing.T) {
	out, code := gateCheck(t, gatesOffJournal(), "--label", "2")
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "coordinator 2: bacchus-gate-check: what this coordinator said") {
		t.Errorf("the report header does not carry the label:\n%s", out)
	}

	out, code = gateCheck(t, gatesOffJournal(), "--label", "2", "--require", "admission")
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "coordinator 2: bacchus-gate-check: admission is DECLARED ON and is OFF") {
		t.Errorf("the finding does not say which member it is about:\n%s", out)
	}
}

// Without a label every line is byte-identical to what a single-coordinator deployment
// printed before, so an already-pasted report stays readable.
func TestGateCheck_AnUnlabelledReportIsUnchanged(t *testing.T) {
	out, _ := gateCheck(t, gatesOffJournal())
	if strings.Contains(out, "coordinator 1") {
		t.Errorf("an unlabelled report grew a label:\n%s", out)
	}
}

// The one property this script has is that it prints no hostname, and a free-text label
// is where one would get in.
func TestGateCheck_RefusesALabelThatLooksLikeAHost(t *testing.T) {
	for _, label := range []string{"coordinator.example.invalid", "admin@box", "192.0.2.1:8080", "a/b"} {
		out, code := gateCheck(t, gatesOffJournal(), "--label", label)
		if code != 2 {
			t.Errorf("--label %q: exit %d, want 2\n%s", label, code, out)
		}
		if !strings.Contains(out, "looks like a host") {
			t.Errorf("--label %q: the refusal does not say why:\n%s", label, out)
		}
	}
}
