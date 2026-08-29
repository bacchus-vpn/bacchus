// The guard rail issue #240 asked for: no one-shot invocation of this binary may
// claim the release probation.
//
// # What #240 said, and what is actually true on main
//
// The card's sequence — `-list` claims the marker (`started=false` → `true`),
// exits, and the next real start finds `started=true` and demotes a release that
// was never tried — was real when it was filed and is NOT reachable today. The
// `oneShot` predicate ahead of `checkStartupDemotion` shipped with issue #170
// (ADR-0071), and both `-list` and `-enroll` are exempted by it. Measured on a
// built binary before this file was written: a planted `started=false` marker
// survives both one-shots untouched, a serving start claims it, and a second
// serving start demotes with exit 3. The premise is spent.
//
// **What is not spent is the second half of the card, and it is the half that
// matters.** The exemption is a hand-maintained predicate, `checkStartupDemotion`
// ends in os.Exit(3), and `main()` is not callable from a test — so nothing
// covered the ordering, and the next one-shot flag added to this binary would
// inherit the bug silently. That flag has now arrived: `-version` (issue #263)
// is the third one-shot this binary has grown since the predicate was written.
//
// # Why the flags are DISCOVERED rather than listed
//
// A hard-coded list is the same object as the predicate: something a later author
// has to remember to extend, in a second place. So this asks the built binary for
// its own flags and picks out every boolean whose usage text announces that it
// quits — which is the one description of a one-shot an author cannot omit,
// because it is what an operator reads. A flag added without that phrasing is a
// flag whose own help is wrong.
//
// runners below then requires an argv for each discovered flag, so a new one-shot
// fails this test loudly ("this test does not know how to run -foo") instead of
// being skipped quietly. That is the property #240 asked for: the exemption stops
// being something anybody has to remember.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/update"
)

// knownOneShots is a FLOOR, not the list under test. Discovery is what decides
// which flags are exercised; this only asserts that discovery still finds the
// four that exist, so a renamed flag or a reworded usage string fails here
// rather than silently shrinking the check to nothing.
var knownOneShots = []string{"enroll", "list", "print-acct-pubkey", "version"}

// oneShotArgs is how each one-shot is invoked. Every discovered flag must appear
// here — see the package comment for why a missing entry is a failure and not a
// skip.
//
// None of these needs to SUCCEED. The demotion watchdog runs before any of them
// does its work, so what is being asserted is reached whether the invocation goes
// on to fail on an unreachable coordinator, a missing claim code, or nothing at
// all. What must not happen is a run that dies before flag parsing, which is
// checked separately below.
func oneShotArgs(t *testing.T, flagName string) []string {
	t.Helper()
	switch flagName {
	case "version":
		return []string{"-version"}
	case "print-acct-pubkey":
		// A real key rather than none. This one-shot REFUSES an empty -exit-key
		// (there is no stable identity to print for a node that generates one every
		// start), and a refusal exits before the assertion below, which would make
		// it pass for the wrong reason.
		return []string{"-print-acct-pubkey", "-exit-key", strings.Repeat("ab", 32)}
	case "list":
		// Port 1 on loopback: nothing answers, so this fails on the country-list
		// timeout a few seconds in. Explicit SOCKS and listen addresses so a
		// parallel package cannot collide with the defaults.
		return []string{"-list", "-coordinators", "127.0.0.1:1", "-socks", freeTCP(t), "-listen", freeTCP(t)}
	case "enroll":
		return []string{"-enroll", "-account-service", "https://one.example.com", "-device-cred-dir", t.TempDir(), "-claim-code-file", ""}
	default:
		t.Fatalf("a one-shot flag -%s was added to cmd/node and this test does not know how to run "+
			"it. That is the point of the failure rather than an oversight in it: a one-shot must be "+
			"proved not to claim the release probation, or the next start demotes a release nothing "+
			"tried (issue #240). Add an argv above.", flagName)
		return nil
	}
}

// No one-shot may claim the probation, whichever way it is exempted.
//
// -version returns above checkStartupDemotion entirely and -list/-enroll are
// exempted by the predicate below it. The assertion is deliberately blind to
// which: what an operator needs is that provisioning a freshly deployed node —
// which is exactly when the marker is unconfirmed — does not roll its release
// back.
func TestNoOneShotClaimsTheReleaseProbation(t *testing.T) {
	bin := buildNode(t, t.TempDir(), "")
	found := discoverOneShotFlags(t, bin)

	for _, want := range knownOneShots {
		if !found[want] {
			t.Fatalf("-%s is no longer discoverable as a one-shot: this test reads the binary's own "+
				"-h output and picks out flags whose usage says they quit. Either the flag was renamed "+
				"or its usage stopped saying so, and in both cases this test just stopped covering it. "+
				"Discovered: %v", want, sortedKeys(found))
		}
	}

	for name := range found {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			target := plantProbation(t, dir, bin)

			args := append(oneShotArgs(t, name), "-update-target", target)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			run := exec.CommandContext(ctx, target, args...)
			out, _ := run.CombinedOutput()

			// A run that died in flag parsing would satisfy the assertion below
			// while proving nothing, and a renamed flag is exactly how that
			// happens. flag exits 2 and says so.
			if strings.Contains(string(out), "flag provided but not defined") {
				t.Fatalf("-%s was rejected by the binary's own flag set, so this run never reached "+
					"the demotion watchdog and the assertion below would be vacuous:\n%s", name, out)
			}

			m := readProbation(t, target)
			if m.Started {
				t.Fatalf("-%s CLAIMED the release probation (started=false -> true). A one-shot never "+
					"reaches confirmAfter, so it can never clear what it claimed — the next real start "+
					"finds started=true and demotes a release that was never tried, logging that it "+
					"\"did not confirm\" (issue #240, ADR-0069). Provisioning a freshly deployed node "+
					"is precisely when the marker is unconfirmed.\nBinary output:\n%s", name, out)
			}
			if _, err := os.Stat(update.PreviousPath(target)); err != nil {
				t.Fatalf("-%s disturbed the previous binary at %s: %v", name, update.PreviousPath(target), err)
			}
		})
	}
}

// The positive control, without which every assertion above could be green
// because the watchdog was never live in the first place.
//
// Same binary, same planted marker, same -update-target: a SERVING start claims
// the probation, and a second serving start demotes and exits 3. That is
// ADR-0069's probation working, and it is what makes "the one-shot left it alone"
// mean something.
func TestAServingStartClaimsTheProbationAndTheNextOneDemotes(t *testing.T) {
	if testing.Short() {
		t.Skip("runs two real node processes; -short skips it")
	}
	dir := t.TempDir()
	bin := buildNode(t, t.TempDir(), "")
	target := plantProbation(t, dir, bin)

	serving := func() *exec.Cmd {
		return exec.Command(target,
			"-role", "relay",
			"-coordinators", "127.0.0.1:1",
			"-socks", freeTCP(t),
			"-listen", freeTCP(t),
			"-update-target", target,
		)
	}

	first := serving()
	first.Stdout, first.Stderr = os.Stdout, os.Stderr
	if err := first.Start(); err != nil {
		t.Fatalf("starting a serving node: %v", err)
	}
	// Poll rather than sleep: the claim happens at the top of main, so this
	// normally succeeds on the first read, and a fixed wait would only decide how
	// long a failure takes.
	claimed := false
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if readProbation(t, target).Started {
			claimed = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = first.Process.Kill()
	_ = first.Wait()
	if !claimed {
		t.Fatal("a serving start did NOT claim the release probation, so the demotion watchdog is " +
			"not running in this binary at all — which would make every one-shot assertion in this " +
			"file green over nothing (ADR-0069)")
	}

	// The second start is the demotion: started=true means the first start never
	// confirmed, which under RestartSec=2 is the crash loop the marker exists for.
	second := serving()
	out, err := second.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		t.Fatalf("the second serving start did not exit at all; it must demote and exit 3 so the "+
			"supervisor re-execs the restored binary (ADR-0069).\n%s", out)
	case !errors.As(err, &exit):
		t.Fatalf("running the second serving start: %v\n%s", err, out)
	case exit.ExitCode() != 3:
		t.Fatalf("the second serving start exited %d, want 3 — the distinct status that tells a "+
			"supervisor the binary at the target path is no longer the one running (ADR-0069).\n%s",
			exit.ExitCode(), out)
	}
	if _, err := os.Stat(update.MarkerPath(target)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the marker survived the demotion at %s (%v); a demotion clears it, or the next "+
			"start demotes again with nothing left to demote to", update.MarkerPath(target), err)
	}
}

// discoverOneShotFlags asks the binary for its own flags and returns the boolean
// ones whose usage says they quit.
//
// `flag`'s default usage prints "  -name" for a bool and "  -name type" for
// everything else, then the usage text on the following line indented with a tab.
// Requiring the boolean shape is part of the test: a one-shot is a switch.
func discoverOneShotFlags(t *testing.T, bin string) map[string]bool {
	t.Helper()
	// -h exits 2 by design, so the error is expected and only the bytes matter.
	out, _ := exec.Command(bin, "-h").CombinedOutput()

	found := map[string]bool{}
	name := ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "  -") {
			decl := strings.TrimSpace(strings.TrimPrefix(line, "  -"))
			if strings.ContainsAny(decl, " \t") {
				name = "" // has a type, so not a switch
				continue
			}
			name = decl
			continue
		}
		if name == "" || !strings.HasPrefix(line, "    \t") {
			continue
		}
		usage := strings.ToLower(line)
		for _, phrase := range []string{"and quit", "and exit", "one-shot"} {
			if strings.Contains(usage, phrase) {
				found[name] = true
				break
			}
		}
		name = ""
	}
	if len(found) == 0 {
		t.Fatalf("no one-shot flag found in this binary's own -h output, so this test would assert "+
			"nothing and report success over it. Usage read:\n%s", out)
	}
	return found
}

// plantProbation copies bin into dir and stages exactly what an applied,
// unconfirmed release leaves behind: the binary at the target path, the previous
// binary beside it, and an unstarted marker.
//
// The previous binary has to be there. CheckStartup clears an unstarted marker
// with nothing to restore — correctly, since demoting with nothing to demote TO
// would be worse — so a test without it would prove only that the marker was
// cleared for the other reason.
func plantProbation(t *testing.T, dir, bin string) string {
	t.Helper()
	target := filepath.Join(dir, "bacchus-node")
	copyFile(t, bin, target, update.ExecMode)
	copyFile(t, bin, update.PreviousPath(target), update.ExecMode)

	m := update.Marker{
		Release:  "9.9.9",
		Previous: update.PreviousPath(target),
		Artifact: "0000000000000000000000000000000000000000000000000000000000000000",
		Started:  false,
	}
	// The same encoding core/update.writeMarker produces — MarshalIndent with two
	// spaces — because deploy/bacchus-update-rollback.sh reads this file with grep
	// and sed and ADR-0069 makes the shape a contract.
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatalf("marshalling the marker: %v", err)
	}
	if err := os.WriteFile(update.MarkerPath(target), b, 0o600); err != nil {
		t.Fatalf("planting the marker: %v", err)
	}
	return target
}

// readProbation reads the marker back. Its absence is a failure rather than a
// zero value: every assertion in this file is about what happened to a file that
// was there.
func readProbation(t *testing.T, target string) update.Marker {
	t.Helper()
	b, err := os.ReadFile(update.MarkerPath(target))
	if err != nil {
		t.Fatalf("reading the marker at %s: %v", update.MarkerPath(target), err)
	}
	var m update.Marker
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parsing the marker at %s: %v\n%s", update.MarkerPath(target), err, b)
	}
	return m
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatalf("reading %s: %v", from, err)
	}
	if err := os.WriteFile(to, b, mode); err != nil {
		t.Fatalf("writing %s: %v", to, err)
	}
}

// freeTCP returns a loopback host:port nothing is listening on. The node's
// defaults (127.0.0.1:1080, :20000) would reach for whatever a developer already
// has running and would collide between subtests.
func freeTCP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a loopback TCP port: %v", err)
	}
	defer ln.Close()
	return fmt.Sprintf("127.0.0.1:%d", ln.Addr().(*net.TCPAddr).Port)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
