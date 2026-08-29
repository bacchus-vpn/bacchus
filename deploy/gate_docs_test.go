// The host list is an INSTRUCTION, so it is held to the script it instructs about
// (issues #260, #275, #280).
//
// deploy/testbed.env.example is read by bacchus-pin.sh for COORDINATOR_GATES, so a
// sentence in it about what declaring a gate costs is not prose — it is what an
// operator does or does not type before a pin run. That file spent three weeks telling
// an operator that `account-service` "cannot be read from a journal yet (issue #260) and
// declaring it exits 4", which stopped being true the day #275 taught
// bacchus-gate-check.sh to read the row, and nothing anywhere failed.
//
// This is the tie that was missing: the exit codes the file quotes are read back out of
// the real script, for the three windows a real coordinator produces. It is deliberately
// not a check that the paragraph is well written — it is a check that its NUMBERS are
// the script's numbers, which is the half an operator acts on.
//
// The textual half has precedent one file over: TestDeployArtifactsNameNoRealHost holds
// these same artifacts to a rule about their content, for the same reason (a deployment
// document is written by pasting from a session, and it goes stale the same way).
package deploy

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const testbedEnvRelPath = "deploy/testbed.env.example"

// gatesBlock returns the COORDINATOR_GATES commentary — everything from the "Gates:"
// roster down to the assignment itself. Scoped rather than searching the whole file
// because "exits 4" appearing anywhere in a 90-line host list would satisfy this test
// while telling an operator nothing at the place they are reading.
func gatesBlock(t *testing.T) string {
	t.Helper()
	body := string(readFile(t, filepath.Join(repoRoot(t), testbedEnvRelPath)))
	start := strings.Index(body, "# Gates: ")
	if start < 0 {
		t.Fatalf("%s carries no `# Gates:` roster, so the block this test reads has moved", testbedEnvRelPath)
	}
	end := strings.Index(body[start:], "\nCOORDINATOR_GATES=")
	if end < 0 {
		t.Fatalf("%s has no COORDINATOR_GATES= assignment after its `# Gates:` roster", testbedEnvRelPath)
	}
	return body[start : start+end]
}

// The row #261 is going to be read off, described by the file that decides whether it
// is declared. Every exit code below comes from running the real script; none is
// asserted from memory.
func TestTestbedExampleQuotesTheAccountServiceExitCodesTheCheckProduces(t *testing.T) {
	block := gatesBlock(t)
	p := "Aug 09 10:00:00 box bacchus-coordinator[9]: "

	for _, tc := range []struct {
		name    string
		journal string
		state   string
	}{{
		// Step 2 of coordinator-gates.env.example. Blocked on bacchus-payment#82,
		// so no box is here today — which is exactly why the file has to say what
		// getting here would look like.
		name:    "an address is published",
		journal: coordStart + p + acctPublished + "\n",
		state:   "on",
	}, {
		// What step 1 produces, and what every box in this deployment says now.
		name:    "the coordinator says NONE published",
		journal: coordStart + p + acctNone + "\n",
		state:   "OFF",
	}, {
		// A coordinator predating #260. Merging deploys nothing, so this is the
		// ordinary state of a box that has not been re-pinned, not a hypothetical.
		name:    "a coordinator too old to say",
		journal: gatesOffJournal(),
		state:   "UNKNOWN",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			out, code := gateCheck(t, tc.journal, "--require", "account-service")
			if !strings.Contains(out, "account-service     "+tc.state) {
				t.Fatalf("the check does not report %s for this window, so this test is"+
					" measuring something other than it claims:\n%s", tc.state, out)
			}
			want := "exits " + strconv.Itoa(code)
			if !strings.Contains(block, want) {
				t.Errorf("bacchus-gate-check.sh answers %q with exit %d, and the COORDINATOR_GATES"+
					" commentary in %s does not say %q anywhere.\n"+
					"That file is read by bacchus-pin.sh, so an operator decides whether to declare"+
					" this gate from it — a stale exit code there is a pin that fails for a reason"+
					" the file does not name.\n--- the block says ---\n%s",
					tc.state, code, testbedEnvRelPath, want, block)
			}
		})
	}
}

// The specific sentence #280 was filed about. It is asserted directly because its
// falseness was invisible to everything else: the script grew the ability to read this
// row, its own tests were extended to prove it, and the file telling an operator the
// opposite was in neither change's file set.
func TestTestbedExampleDoesNotSayAReadableRowCannotBeRead(t *testing.T) {
	block := gatesBlock(t)
	for _, dead := range []string{
		"cannot be read from a journal",
		"do not declare it until that lands",
	} {
		if strings.Contains(block, dead) {
			t.Errorf("%s still says %q about `account-service`.\n"+
				"Issue #260 gave cmd/coordinator a startup line for it and #275 taught"+
				" bacchus-gate-check.sh to read it, so the row is answered: `on` for a published"+
				" address, `OFF` for a stated NONE published, and UNKNOWN only for a coordinator"+
				" too old to carry the line. The reason not to declare it is that nothing is"+
				" published (step 2 is blocked on bacchus-payment#82), which is a different"+
				" instruction with a different exit code.", testbedEnvRelPath, dead)
		}
	}
}
