package update_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// anchorSymbol is the linker symbol a build path stamps to give a binary its trust
// anchor. Matched as a substring rather than parsed, because the point is to notice
// a build path acquiring the capability at all, in whatever syntax it uses.
const anchorSymbol = "core/update.rootPubHex"

// requireEnv is what makes TestAReleaseBuildRefusesTheDevelopmentAnchor load-bearing
// rather than skipped.
const requireEnv = "BACCHUS_REQUIRE_RELEASE_ANCHOR"

// buildPaths are the files that stamp binaries today. If one of them learns to stamp
// an anchor, this list is where the check finds it.
var buildPaths = []string{
	"../../.github/workflows/release.yml",
	"../../.github/workflows/ci.yml",
	"../../deploy/install.sh",
	"../../deploy/bacchus-pin.sh",
}

// TestABuildPathThatStampsAnAnchorAlsoTurnsTheGateOn is the check that keeps issue
// #252's guard from being decorative.
//
// The guard itself — TestAReleaseBuildRefusesTheDevelopmentAnchor — reads the anchor
// out of the linked test binary, which is the only way to see past a silently ignored
// `-ldflags -X`. But it SKIPS unless BACCHUS_REQUIRE_RELEASE_ANCHOR is set, because a
// bare `go test` has no anchor to judge and a check that failed there would be
// switched off within a day.
//
// That leaves one gap, and it is the same shape as the bug being guarded against: a
// build path could learn to stamp an anchor and simply not turn the gate on, at which
// point the guard skips forever and reports green over exactly the thing it exists to
// catch. Nobody would notice, because a skip looks like a pass in a CI summary.
//
// So: whichever file first teaches a build to carry an anchor is the file that must
// also set the env var. This test fails at that moment, in the same change, with the
// reason attached — rather than in a year, in an incident.
//
// It deliberately does NOT require any build path to stamp an anchor. None does today
// and none needs to; the release channel is inert until a real ceremony has run
// (ADR-0065 §8). The assertion is only the implication, in one direction.
func TestABuildPathThatStampsAnAnchorAlsoTurnsTheGateOn(t *testing.T) {
	checked := 0
	for _, rel := range buildPaths {
		b, err := os.ReadFile(rel)
		if err != nil {
			if os.IsNotExist(err) {
				// A build path that was renamed or removed is not this test's business,
				// but a list that has quietly gone entirely stale is — see below.
				continue
			}
			t.Fatalf("read %s: %v", rel, err)
		}
		checked++
		body := string(b)
		if !strings.Contains(body, anchorSymbol) {
			continue
		}
		if !strings.Contains(body, requireEnv) {
			t.Errorf("%s stamps %s but never sets %s.\n\n"+
				"A build path that carries a trust anchor must also turn the anchor gate on, or "+
				"TestAReleaseBuildRefusesTheDevelopmentAnchor skips and a binary anchored to the "+
				"PUBLISHED development root can be published. ADR-0052 makes a shipped anchor "+
				"irrevocable, so that is not a mistake with a remedy (issue #252).\n\n"+
				"Set %s=1 for the step that builds or tests the stamped binary.",
				filepath.Base(rel), anchorSymbol, requireEnv, requireEnv)
		}
	}
	if checked == 0 {
		t.Fatalf("none of the %d build paths this test watches exist any more, so it is watching "+
			"nothing: %v. Update buildPaths to wherever binaries are stamped now", len(buildPaths), buildPaths)
	}
}
