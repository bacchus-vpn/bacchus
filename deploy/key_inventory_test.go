// Coverage for deploy/bacchus-key-inventory.sh (issues #251, #227).
//
// Two halves, and the first is the one that matters.
//
// THE PRIVACY HALF. This is a tool that opens private keys in a PUBLIC repository, and
// its output is meant to be pasteable into an issue. The natural debugging instinct —
// echo what you found — is the single thing it must never do, and a leak is exactly the
// kind of defect that ships because it looks like helpfulness. So every fixture file
// below is built out of unique CANARY tokens, one per line, and every path that
// produces output is scanned for every token. A line echoed anywhere, for any reason,
// on stdout or stderr, in a report or in a diagnostic, fails. On top of that the
// fixtures carry a realistic key, a realistic passphrase, a non-documentation IPv4
// literal, a registrable hostname and a provider-shaped name, so that the failure names
// what kind of thing got out. TestTheTraceCannotLeakEitherKeyOrDigest runs the whole
// thing under `sh -x`, which is the case a reader would not think to try and the one
// deploy/install-test.sh already establishes for the installer's key generation.
//
// THE MANIFEST HALF. What a box is allowed to hold is a list, and a list rots. If the
// deployment learns to write a file this script does not know about, every box reports
// a finding forever and the check gets switched off — which is issue #248's complaint
// arriving through a different door. So the manifest is not asserted from memory: the
// paths are read out of deploy/bacchus-coordinator.service, deploy/bacchus-exit.service,
// deploy/coordinator-gates.env.example and cmd/coordinator's own `secrets/…` flag
// defaults, and a name in any of those and not in the script turns this red.
//
// What is deliberately NOT asserted here: that a real box's /etc/bacchus looks like any
// particular thing. Nothing in this repository can observe one, which is the whole
// reason #251 was a discovery. The end-to-end tie lives in deploy/install-test.sh
// instead, where the installer's own output is inventoried and has to come out clean.
package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const keyInventoryRelPath = "deploy/bacchus-key-inventory.sh"

func keyInventory(t *testing.T, args ...string) (string, int) {
	t.Helper()
	return keyInventoryWith(t, "sh", args...)
}

// keyInventoryWith runs the script under a named shell invocation, so that the tracing
// case can drive the same helper as everything else.
func keyInventoryWith(t *testing.T, shell string, args ...string) (string, int) {
	t.Helper()
	argv := append(strings.Fields(shell)[1:], filepath.Join(repoRoot(t), keyInventoryRelPath))
	cmd := exec.Command(strings.Fields(shell)[0], append(argv, args...)...)
	b, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if err != nil {
		if !asExitError(err, &ee) {
			t.Fatalf("running %s: %v\n%s", keyInventoryRelPath, err, b)
		}
		code = ee.ExitCode()
	}
	return string(b), code
}

// -------------------------------------------------------------------------
// fixtures
// -------------------------------------------------------------------------

// The canaries. Each is a value a leak would carry, chosen so that the failure says
// which KIND of thing got out rather than only that something did.
//
// The address is RFC 2544 benchmark space: an IPv4 literal that documentationIPv4 in
// pin_test.go deliberately does not accept, and one IANA has reserved so it can never
// be anybody's real box. The hostname is under a TLD registrableHost matches. Neither
// belongs to this project, and that is the point — they stand in for the values a real
// /etc/bacchus holds, which never enter this repository at all.
const (
	canaryExitKey   = "c0ffee11deadbeef2222333344445555c0ffee11deadbeef2222333344445555"
	canaryOldKey    = "9999888877776666555544443333222211110000ffffeeeeddddccccbbbbaaaa"
	canaryTurnPass  = "CANARY-turn-passphrase-not-a-real-one"
	canaryAddress   = "198.18.7.9"
	canaryHost      = "canary-box-7.cloud"
	canaryProvider  = "CANARY-PROVIDER-NAME"
	canaryPEMBody   = "CANARYMIIBOgIBAAJBAKj34GkxFhDdeadbeefCANARY"
	canaryBootstrap = "CANARY-bootstrap-secret-value"
)

// allCanaries is every token the fixtures put on disk. Anything here appearing in any
// output is a leak, full stop — there is no output this script produces for which any
// of these is the right answer.
func allCanaries() []string {
	return []string{
		canaryExitKey, canaryOldKey, canaryTurnPass, canaryAddress,
		canaryHost, canaryProvider, canaryPEMBody, canaryBootstrap,
		// The bare token, so a fixture line this list forgot is still caught: every
		// line of every file below carries it.
		"CANARY",
	}
}

// nodeEnv is a node box's env file as a real one looks — every line carrying something
// a leak would disclose.
func nodeEnv(key string) string {
	return "# CANARY-comment-line\n" +
		"ADVERTISE=" + canaryAddress + ":20000\n" +
		"COUNTRY=NL\n" +
		"COORDINATORS=" + canaryHost + ":8080\n" +
		"STUN=stun:" + canaryHost + ":3478\n" +
		"TURN_USER=" + canaryProvider + "\n" +
		"TURN_PASS=" + canaryTurnPass + "\n" +
		"EXIT_KEY=" + key + "\n"
}

const canaryPEM = "-----BEGIN PRIVATE KEY-----\n" + canaryPEMBody + "\n-----END PRIVATE KEY-----\n"

// inventoryBox writes a directory of fixture files and returns its path. Modes default to 0600,
// which is what deploy/install.sh writes and what the mode check expects.
func inventoryBox(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("MkdirAll %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}
	return dir
}

// -------------------------------------------------------------------------
// THE PRIVACY HALF
// -------------------------------------------------------------------------

// The headline property, asserted over every path that produces output rather than over
// the happy one. A refusal and a diagnostic are where an echo gets added, because they
// are written while somebody is debugging.
func TestNothingItReadsCanReachItsOutput(t *testing.T) {
	full := inventoryBox(t, map[string]string{
		"node.env":                       nodeEnv(canaryExitKey),
		"node.env.save":                  nodeEnv(canaryOldKey),
		"admission.key":                  canaryOldKey + "\n",
		"op-ca.key":                      canaryPEM,
		"op-ca.crt":                      "-----BEGIN CERTIFICATE-----\nCANARY-cert-body\n-----END CERTIFICATE-----\n",
		"bacchus-bootstrap-secrets.json": `{"CANARY-user":"` + canaryBootstrap + `"}` + "\n",
		"secrets/policy-state.json":      `{"CANARY":"` + canaryBootstrap + `"}` + "\n",
	})
	clean := inventoryBox(t, map[string]string{"node.env": nodeEnv(canaryExitKey)})

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"a box with every finding on it", []string{"--role", "exit", "--dir", full}},
		{"a coordinator reading the same box", []string{"--role", "coordinator", "--dir", full}},
		{"both roles at once", []string{"--role", "exit,coordinator", "--dir", full}},
		{"a clean box", []string{"--role", "exit", "--dir", clean}},
		{"a declared exception", []string{"--role", "exit", "--dir", full, "--expect", "admission.key"}},
		{"the usage text", []string{"--help"}},
		{"no role", []string{"--dir", full}},
		{"an unknown role", []string{"--role", "nonsense", "--dir", full}},
		{"a directory that is not there", []string{"--role", "exit", "--dir", filepath.Join(full, "nope")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := keyInventory(t, tc.args...)
			assertNoCanary(t, out)
		})
	}
}

// The digest is the subtle one, and it is why this test exists separately from the one
// above. Issue #227's own recipe prints two digests and has a person compare them by
// eye; this script compares them in process precisely so that neither has to leave it.
// A digest of a 32-byte random key is not brute-forceable and it is still a value
// derived from a secret, and there is nothing an operator can do with one that the
// verdict does not already tell them.
func TestNoDigestOfAnythingItHashedIsPrinted(t *testing.T) {
	dir := inventoryBox(t, map[string]string{
		"node.env":      nodeEnv(canaryExitKey),
		"node.env.save": nodeEnv(canaryExitKey),
		"op-ca.key":     canaryPEM,
		"op-ca.key.bak": canaryPEM,
	})
	out, code := keyInventory(t, "--role", "exit", "--dir", dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1 — this fixture is two duplicated secrets\n%s", code, out)
	}
	assertNoCanary(t, out)

	// Nothing that could be a digest, a key or half of either. The fixture's own
	// file names carry no hex, so any long hex run in this output came out of a file.
	for _, hex := range longHex.FindAllString(out, -1) {
		t.Errorf("the report carries %q, a %d-character hex run.\n"+
			"Every value this script hashes stays inside it: the report says WHICH files"+
			" share a secret and never what the secret or its digest is.\n%s",
			hex, len(hex), out)
	}
}

// The case a reader would not think to try, and the reason the digests are computed
// inside a subshell that turns tracing off. deploy/install-test.sh establishes the same
// case for the installer's key generation; removing the `set +x` puts every digest into
// the trace, which is what this measures.
func TestTheTraceCannotLeakEitherKeyOrDigest(t *testing.T) {
	dir := inventoryBox(t, map[string]string{
		"node.env":      nodeEnv(canaryExitKey),
		"node.env.save": nodeEnv(canaryExitKey),
		"op-ca.key":     canaryPEM,
	})
	out, _ := keyInventoryWith(t, "sh -x", "--role", "exit", "--dir", dir)
	assertNoCanary(t, out)
	for _, hex := range longHex.FindAllString(out, -1) {
		t.Errorf("`sh -x` on this script put %q into the trace.\n"+
			"A value hashed under tracing is a value in somebody's terminal scrollback and"+
			" in whatever captured it. The digests are computed in a subshell that runs"+
			" `set +x` for exactly this reason — check that it is still there.\n%s", hex, out)
	}
}

// The rule deploy/pin_test.go holds every other deployment artifact to, applied to this
// one: a procedure is written by pasting from a session where the real values were in
// front of whoever wrote them, and this script's header is full of procedure.
func TestTheInventoryScriptNamesNoRealHost(t *testing.T) {
	body := string(readFile(t, filepath.Join(repoRoot(t), keyInventoryRelPath)))
	for _, ip := range ipv4Literal.FindAllString(body, -1) {
		if !documentationIPv4(ip) {
			t.Errorf("%s: %s is an IPv4 literal outside the documentation ranges.\n"+
				"Use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24 (RFC 5737).", keyInventoryRelPath, ip)
		}
	}
	for _, h := range registrableHost.FindAllString(body, -1) {
		if !documentationHost(h) {
			t.Errorf("%s: %q is a registrable hostname.\n"+
				"Use example.invalid (RFC 2606) or a <placeholder>.", keyInventoryRelPath, h)
		}
	}
}

// --label is the one free-text value that reaches the output, so it is the one way a
// hostname gets into a report whose whole property is that it carries none. Same rule
// and same refusal as deploy/bacchus-gate-check.sh and deploy/bacchus-fleet-check.sh.
func TestALabelThatLooksLikeAHostIsRefused(t *testing.T) {
	dir := inventoryBox(t, map[string]string{"node.env": nodeEnv(canaryExitKey)})
	for _, label := range []string{canaryHost, "root@" + canaryHost, canaryHost + ":22", "the box in " + canaryProvider} {
		out, code := keyInventory(t, "--role", "exit", "--dir", dir, "--label", label)
		if code != 2 {
			t.Errorf("--label %q exited %d, want 2 (usage). A host in the label is a host in"+
				" every line of the report.\n%s", label, code, out)
		}
	}
	out, code := keyInventory(t, "--role", "exit", "--dir", dir, "--label", "3")
	if code != 0 {
		t.Fatalf("--label 3 exited %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "box 3: ") {
		t.Errorf("an ordinal label does not prefix the report, so two boxes' runs cannot be"+
			" told apart:\n%s", out)
	}
}

var longHex = regexp.MustCompile(`\b[0-9a-fA-F]{16,}\b`)

// verdictFor returns the lines under one secret's row in the duplicate report, so a
// fixture carrying two duplicated secrets can be asserted about one of them.
func verdictFor(t *testing.T, out, secret string) string {
	t.Helper()
	var got []string
	in := false
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "    "+secret+"  in "):
			in = true
		case in && !strings.HasPrefix(line, "      "):
			// The next row of the table, or the end of it. A continuation of this
			// row is indented deeper than the row itself.
			in = false
		}
		if in {
			got = append(got, line)
		}
	}
	if len(got) == 0 {
		t.Fatalf("the report has no row for %s at all:\n%s", secret, out)
	}
	return strings.Join(got, "\n")
}

func assertNoCanary(t *testing.T, out string) {
	t.Helper()
	for _, c := range allCanaries() {
		if !strings.Contains(out, c) {
			continue
		}
		t.Errorf("the output carries %q, which came out of a file this script read.\n"+
			"It prints PATHS and never CONTENT: no key, no passphrase, no address, no"+
			" hostname, no provider name. This repository is public and this output is"+
			" meant to be pasteable.\n--- output ---\n%s", c, out)
	}
}

// -------------------------------------------------------------------------
// THE TWO CARDS
// -------------------------------------------------------------------------

// Issue #227 as it was found: a stale .save beside the live env, carrying the SAME key.
// The verdict is what an operator acts on, and it is reached without either value being
// read by a person — which is the property the card's own recipe was reaching for when
// it said to compare the hashes rather than print the keys.
func TestASecondCopyOfTheLiveExitKeyIsFoundAndNamedAsTheSameKey(t *testing.T) {
	dir := inventoryBox(t, map[string]string{
		"node.env":      nodeEnv(canaryExitKey),
		"node.env.save": nodeEnv(canaryExitKey),
	})
	out, code := keyInventory(t, "--role", "exit", "--dir", dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1 — a second copy of a live private key is a finding\n%s", code, out)
	}
	for _, want := range []string{
		"MORE THAN ONE COPY OF A SECRET",
		"EXIT_KEY  in 2 files: node.env node.env.save",
		"the SAME value in each",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}
	assertNoCanary(t, out)
}

// The other half of #227's "what to check before deleting", and the reason the card
// says to check at all: a .save whose key DIFFERS holds a previous identity, which may
// still appear in an old signed directory or somebody's cached snapshot. The report has
// to tell those two cases apart, because they call for different actions.
func TestASecondCopyThatDiffersIsNamedAsAPreviousIdentity(t *testing.T) {
	dir := inventoryBox(t, map[string]string{
		"node.env":      nodeEnv(canaryExitKey),
		"node.env.save": nodeEnv(canaryOldKey),
	})
	out, code := keyInventory(t, "--role", "exit", "--dir", dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	// Read the verdict that belongs to the EXIT_KEY group specifically. The two files
	// are a copy of one env file, so they share their TURN_PASS as well, and that group
	// correctly says the values match — asserting over the whole report would measure
	// the wrong one of the two.
	verdict := verdictFor(t, out, "EXIT_KEY")
	for _, want := range []string{"2 DIFFERENT values", "PREVIOUS identity"} {
		if !strings.Contains(verdict, want) {
			t.Errorf("the EXIT_KEY verdict does not say %q, so it reads the same as a spare copy"+
				" of the live key — and destroying it is the wrong move for one of the two:\n%s",
				want, out)
		}
	}
	if strings.Contains(verdict, "the SAME value in each") {
		t.Errorf("the EXIT_KEY verdict says the values match and they do not:\n%s", out)
	}
	assertNoCanary(t, out)
}

// Two unrelated private keys are not a second copy of one thing, and reporting them as
// one would be a finding an operator learns to ignore. Whole-file key material is
// grouped by its digest for exactly this reason; a named variable is grouped by its
// name, because EXIT_KEY in two files is a finding either way.
func TestTwoUnrelatedKeyFilesAreNotReportedAsACopyOfEachOther(t *testing.T) {
	dir := inventoryBox(t, map[string]string{
		"node.env":      nodeEnv(canaryExitKey),
		"op-ca.key":     canaryPEM,
		"admission.key": canaryOldKey + "\n",
	})
	out, code := keyInventory(t, "--role", "exit", "--dir", dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1 — the two stray keys are unaccounted for\n%s", code, out)
	}
	if strings.Contains(out, "MORE THAN ONE COPY OF A SECRET") {
		t.Errorf("two unrelated keys are reported as a duplicated secret:\n%s", out)
	}

	// The same file twice, though, is.
	dir = inventoryBox(t, map[string]string{
		"node.env":      nodeEnv(canaryExitKey),
		"op-ca.key":     canaryPEM,
		"op-ca.key.bak": canaryPEM,
	})
	out, code = keyInventory(t, "--role", "exit", "--dir", dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "key material, whole file  in 2 files: op-ca.key op-ca.key.bak") {
		t.Errorf("a byte-identical copy of a private key file is not reported:\n%s", out)
	}
}

// Issue #251's actual finding, file for file, on the role the box actually runs. The
// point of the card is that none of this was in any record — so every one of them has
// to come out UNACCOUNTED, and the run has to fail rather than merely mention it.
func TestTheStagedMaterialIssue251FoundIsUnaccountedForOnAnExitBox(t *testing.T) {
	staged := []string{
		"admission.key", "account-tls.key", "account-tls.crt",
		"op-ca.key", "op-ca.crt", "op.key", "op.crt", "op.csr",
		"console.key", "console.crt", "console.csr",
	}
	files := map[string]string{"node.env": nodeEnv(canaryExitKey)}
	for i, name := range staged {
		// Distinct bodies, in the shape each extension really carries: the card's set
		// is eleven different things, and a fixture where they were all one blob would
		// exercise the duplicate path instead of this one.
		body := "CANARY-body-" + string(rune('a'+i)) + "-" + canaryPEMBody + "\n"
		switch {
		case strings.HasSuffix(name, ".key"):
			files[name] = "-----BEGIN PRIVATE KEY-----\n" + body + "-----END PRIVATE KEY-----\n"
		case strings.HasSuffix(name, ".csr"):
			files[name] = "-----BEGIN CERTIFICATE REQUEST-----\n" + body + "-----END CERTIFICATE REQUEST-----\n"
		default:
			files[name] = "-----BEGIN CERTIFICATE-----\n" + body + "-----END CERTIFICATE-----\n"
		}
	}
	out, code := keyInventory(t, "--role", "exit", "--dir", inventoryBox(t, files))
	if code != 1 {
		t.Fatalf("exit %d, want 1 — a box holding an operator CA nothing names is a finding\n%s", code, out)
	}
	for _, name := range staged {
		if !strings.Contains(out, name+" ") {
			t.Errorf("%s is not in the report at all:\n%s", name, out)
		}
	}
	if n := strings.Count(out, "UNACCOUNTED"); n != len(staged) {
		t.Errorf("%d rows are UNACCOUNTED, want %d — one per staged file, with node.env"+
			" accounted for:\n%s", n, len(staged), out)
	}
	if !regexp.MustCompile(`node\.env +accounted`).MatchString(out) {
		t.Errorf("the node's own env file is not reported as accounted for, so the manifest"+
			" is not being applied:\n%s", out)
	}
	if strings.Contains(out, "MORE THAN ONE COPY") {
		t.Errorf("eleven different keys and certificates are reported as copies of each"+
			" other:\n%s", out)
	}
	assertNoCanary(t, out)
}

// #251's step 3: material that is KEPT has to be recorded. --expect is where a box says
// so, in the same shape COORDINATOR_GATES declares a deployment's gates — and a run that
// stays red forever is a run somebody stops making.
func TestDeclaredMaterialStopsBeingAFinding(t *testing.T) {
	dir := inventoryBox(t, map[string]string{
		"node.env":      nodeEnv(canaryExitKey),
		"admission.key": canaryOldKey + "\n",
	})
	out, code := keyInventory(t, "--role", "exit", "--dir", dir)
	if code != 1 {
		t.Fatalf("exit %d, want 1 before it is declared\n%s", code, out)
	}
	out, code = keyInventory(t, "--role", "exit", "--dir", dir, "--expect", "admission.key")
	if code != 0 {
		t.Fatalf("exit %d, want 0 once it is declared\n%s", code, out)
	}
	if !strings.Contains(out, "declared with --expect") {
		t.Errorf("the report does not say the row was declared rather than named by the"+
			" deployment, which is the difference between a recorded exception and a"+
			" manifest entry:\n%s", out)
	}

	// Spelled exactly as the report names it, which for anything below the top level
	// carries a separator. A declaration that could not name a nested file would leave
	// that row red forever, and a row that is always red is one nobody reads.
	nested := inventoryBox(t, map[string]string{
		"node.env":             nodeEnv(canaryExitKey),
		"secrets/leftover.key": canaryPEM,
	})
	if _, code := keyInventory(t, "--role", "exit", "--dir", nested); code != 1 {
		t.Fatalf("exit %d, want 1 before the nested file is declared", code)
	}
	out, code = keyInventory(t, "--role", "exit", "--dir", nested,
		"--expect", "secrets,secrets/leftover.key")
	if code != 0 {
		t.Fatalf("exit %d, want 0 once a nested path is declared\n%s", code, out)
	}

	// A path that no walk of this directory could ever produce is a mistake, not a
	// declaration that quietly matches nothing.
	for _, bad := range []string{"/etc/shadow", "../../etc/shadow", "root@" + canaryHost} {
		if out, code := keyInventory(t, "--role", "exit", "--dir", nested, "--expect", bad); code != 2 {
			t.Errorf("--expect %q exited %d, want 2\n%s", bad, code, out)
		}
	}
}

// -------------------------------------------------------------------------
// what could not be read is not what was found clean (issue #248)
// -------------------------------------------------------------------------

// /etc/bacchus is mode 0700, so the ordinary mistake is running this without sudo: every
// NAME is visible and no content is, which means a duplicated key is invisible. Reporting
// that as a clean box would be worse than not running it — the run would close the
// question.
func TestAFileItCouldNotOpenIsNotAFileItFoundClean(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read a 0000 file — this case cannot be built here")
	}
	dir := inventoryBox(t, map[string]string{"node.env": nodeEnv(canaryExitKey)})
	if err := os.Chmod(filepath.Join(dir, "node.env"), 0o000); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "node.env"), 0o600) })

	out, code := keyInventory(t, "--role", "exit", "--dir", dir)
	if code != 4 {
		t.Fatalf("exit %d, want 4 — an unreadable file leaves the box un-inventoried\n%s", code, out)
	}
	for _, want := range []string{"UNREAD", "could not be read", "Re-run\n  it under sudo"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "every entry is accounted for") {
		t.Errorf("a directory it could not read reports as clean:\n%s", out)
	}
}

// A mode of 0000 is more restrictive than 0600, not less. The check reads the group and
// other digits rather than matching the string, because stat prints that mode as "0" and
// a pattern over the text called it the widest thing on the box.
func TestTheModeCheckReadsPermissionsAndNotTheirSpelling(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		flag bool
	}{
		{0o600, false}, {0o400, false}, {0o640, true}, {0o644, true}, {0o606, true},
	} {
		dir := inventoryBox(t, map[string]string{"node.env": nodeEnv(canaryExitKey)})
		if err := os.Chmod(filepath.Join(dir, "node.env"), tc.mode); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
		out, code := keyInventory(t, "--role", "exit", "--dir", dir)
		flagged := strings.Contains(out, "readable beyond its owner")
		if flagged != tc.flag {
			t.Errorf("mode %04o: flagged=%v, want %v (exit %d)\n%s", tc.mode, flagged, tc.flag, code, out)
		}
	}
}

// -------------------------------------------------------------------------
// the manifest cannot go stale
// -------------------------------------------------------------------------

// The tie that keeps this script from becoming a check nobody runs. A file the
// deployment writes and the manifest does not name is reported UNACCOUNTED on every box
// forever — a finding that is always there is a finding that gets ignored, which is how
// the fleet check ended up covering two boxes of three (#224, #248).
//
// So the names are read out of the deployment's own artifacts rather than asserted from
// memory. cmd/coordinator is read and NOT modified: its relative `secrets/…` defaults
// land under /etc/bacchus because bacchus-coordinator.service ships
// WorkingDirectory=/etc/bacchus (#247), so they are files a real coordinator writes there.
func TestTheManifestNamesEveryFileTheDeploymentWrites(t *testing.T) {
	root := repoRoot(t)
	script := string(readFile(t, filepath.Join(root, keyInventoryRelPath)))

	named := map[string]string{}
	for _, rel := range []string{coordUnitRelPath, exitUnitRelPath, gatesEnvRelPath} {
		body := string(readFile(t, filepath.Join(root, rel)))
		for _, m := range etcBacchusPath.FindAllStringSubmatch(body, -1) {
			named[m[1]] = rel
		}
	}
	for _, m := range secretsDefault.FindAllStringSubmatch(string(readFile(t, filepath.Join(root, "cmd/coordinator/main.go"))), -1) {
		named["secrets/"+m[1]] = "cmd/coordinator/main.go"
	}
	if len(named) < 8 {
		t.Fatalf("only %d /etc/bacchus paths were found across the deployment artifacts, which is"+
			" too few to be right — the patterns this test reads with have stopped matching", len(named))
	}

	for name, from := range named {
		// A glob in a comment (`/etc/bacchus/*-revocations.json`) names no one file.
		if strings.ContainsAny(name, "*?<>") {
			continue
		}
		if strings.Contains(script, "'"+name+"\t") {
			continue
		}
		t.Errorf("%s names /etc/bacchus/%s and the manifest in %s does not.\n"+
			"A file the deployment writes and this script does not know about is reported"+
			" UNACCOUNTED on every box that has it, forever — and a finding that is always"+
			" there is one an operator learns to scroll past. Add a row for it, with the"+
			" class that says whether it is key material.", from, name, keyInventoryRelPath)
	}
}

var (
	// An absolute path under /etc/bacchus, capturing what follows. The trailing class
	// excludes the separators a systemd ExecStart continuation and a shell recipe put
	// after a path.
	etcBacchusPath = regexp.MustCompile(`/etc/bacchus/([A-Za-z0-9._*-]+)`)
	// cmd/coordinator's relative flag defaults, which WorkingDirectory=/etc/bacchus
	// turns into files in that directory.
	secretsDefault = regexp.MustCompile(`"secrets/([A-Za-z0-9._-]+)"`)
)

// -------------------------------------------------------------------------
// the rule, where an operator provisioning a node actually reads it
// -------------------------------------------------------------------------

// Issue #227's "Done when" asks for documentation as well as a cleanup: whatever
// deploy/ documents about node provisioning should say where the key lives and that
// there is exactly one copy per node. deploy/node.env.example has said so since #235;
// this holds the two halves that were missing — the provisioning procedure in
// deploy/README.md, which is what a second exit is added from, and the pointer to the
// tool, since a rule nothing can check is the state both cards were filed in.
func TestTheProvisioningDocumentsStateTheOneCopyRule(t *testing.T) {
	root := repoRoot(t)
	for _, tc := range []struct {
		rel  string
		want []string
	}{{
		rel: "deploy/README.md",
		want: []string{
			"ONE copy per node",
			"bacchus-key-inventory.sh",
			"#227",
			"#251",
		},
	}, {
		// The regression guard for the half that already shipped. It is the file an
		// operator edits to set the key, so it is the place the rule is read.
		rel: "deploy/node.env.example",
		want: []string{
			"ONE COPY PER NODE",
			"sha256sum",
		},
	}} {
		body := string(readFile(t, filepath.Join(root, tc.rel)))
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Errorf("%s does not mention %q.\n"+
					"A node's key is a secret AND an identity, and a second copy of it has none"+
					" of the attention the live one gets. The rule has to be where somebody"+
					" provisioning a box will read it, not only in the tool that checks it.",
					tc.rel, want)
			}
		}
	}
}

// The exit codes the README quotes are the script's own, read back out of it. A
// deployment document is written by pasting from a session and goes stale the same way
// deploy/gate_docs_test.go's subject did.
func TestTheREADMEQuotesTheExitCodesTheScriptProduces(t *testing.T) {
	readme := string(readFile(t, filepath.Join(repoRoot(t), "deploy/README.md")))
	dir := inventoryBox(t, map[string]string{
		"node.env":      nodeEnv(canaryExitKey),
		"node.env.save": nodeEnv(canaryExitKey),
	})
	_, code := keyInventory(t, "--role", "exit", "--dir", dir)
	if code != 1 {
		t.Fatalf("a duplicated key exits %d, want 1", code)
	}
	if !strings.Contains(readme, "exits **1**") {
		t.Errorf("deploy/README.md does not say that a finding exits 1, which is the number an" +
			" operator wires into whatever runs this across a fleet")
	}
}
