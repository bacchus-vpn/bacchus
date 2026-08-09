package update_test

import (
	"os"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/update"
)

// The release workflow's half of this card, asserted from Go.
//
// The reasoning is core/asn.TestReleaseWorkflowGatesTheTable's and is worth
// restating because it is not obvious: a tag-triggered workflow cannot be
// exercised by any run on a branch, so nothing about the release path is tested
// by the pull request that changes it. What DOES gate every pull request is
// ci.yml, which runs this. So the workflow that gates merges is what guards the
// workflow that gates releases.
//
// This asserts the things whose silent removal would leave a green run over
// nothing: the reproducibility rebuild, the read-back of the version stamp, the
// artifact rows the offline signer consumes, and — the one that is a security
// property rather than a build property — that CI does not sign.
const releaseWorkflow = "../../.github/workflows/release.yml"

func readWorkflow(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(releaseWorkflow)
	if err != nil {
		t.Fatalf("read %s: %v", releaseWorkflow, err)
	}
	return string(b)
}

func TestReleaseWorkflowBuildsTheFleetReproducibly(t *testing.T) {
	w := readWorkflow(t)

	for _, want := range []struct{ needle, why string }{
		{"fleet-binaries:", "the job that builds the fleet binaries for the release channel"},
		{"-trimpath", "ADR-0052 §5: without it the absolute source path is baked in and two builds of the same source differ"},
		{"CGO_ENABLED: \"0\"", "ADR-0052 §5: the fleet binaries are the pure-Go ones, and that is what makes them reproducible"},
		{"go-version-file: go.mod", "ADR-0052 §5 wants a PINNED toolchain: the toolchain is an input to the output"},
		{"/tmp/bacchus-rebuild", "the second source path — a rebuild at the SAME path would agree with itself and prove nothing"},
		{"must be byte-identical", "the step that refuses a release whose binaries do not reproduce"},
		{"go list -deps", "which binaries carry a version stamp is DERIVED, because a command that does not link core/version has the -X for it silently ignored"},
		{stampEnv, "the release stamp is read back out of the built artifacts by TestReleaseArtifactsCarryTheStamp, and that test SKIPS unless this names the release"},
		{artifactsEnv, "the artifacts the read-back is pointed at; without it the gate has nothing to read"},
		{"artifacts.json", "the rows the offline signer turns into a manifest"},
	} {
		if !strings.Contains(w, want.needle) {
			t.Errorf("%s no longer contains %q — %s", releaseWorkflow, want.needle, want.why)
		}
	}
}

// The release stamp must never again be read by searching the artifact's bytes
// for the number (bacchus-vpn/bacchus#254).
//
// `strings -a … | grep -qx "$SEMVER"` asks whether the value occupies a whole
// LINE of `strings` output, and Go packs its strings contiguously, so the answer
// is a property of what sits beside the value rather than of the stamp. It went
// red on a correctly stamped binary, and — the half that matters more — it goes
// green on one built with no -X at all, because core/version's own source
// carries the "0.0.0" an unstamped build reports and a dry run asserts exactly
// that. TestAnUnstampedBinaryStillContainsTheNumber pins the premise; this pins
// that the workflow does not act on it.
//
// COMMENTS ARE EXEMPT ON PURPOSE. release.yml explains at length why it does not
// do this, and a check that fired on the explanation would push the reasoning
// out of the file it is about — an earlier test in this file learned that by
// failing on its own documentation.
func TestTheReleaseStampIsNotReadByHuntingForTheNumber(t *testing.T) {
	for i, line := range strings.Split(readWorkflow(t), "\n") {
		code := strings.TrimSpace(line)
		if code == "" || strings.HasPrefix(code, "#") {
			continue
		}
		if strings.Contains(code, "strings -a") {
			t.Errorf("%s line %d runs %q. The release stamp is read by decoding the string header "+
				"at core/version.current out of the artifact (TestReleaseArtifactsCarryTheStamp), "+
				"not by hunting the byte blob for the number: an unstamped binary contains it too.",
				releaseWorkflow, i+1, code)
		}
	}
}

// The artifact roles the workflow emits must be roles a verifier knows. They are
// a CLOSED vocabulary — a manifest row naming an unknown role is refused, not
// skipped — so a workflow emitting one this build does not know would produce a
// release nothing can apply.
func TestReleaseWorkflowEmitsKnownArtifactRoles(t *testing.T) {
	w := readWorkflow(t)
	for _, role := range []string{update.RoleNode, update.RoleCoordinator, update.RoleNetd, update.RoleClient} {
		if !strings.Contains(w, `role="`+role+`"`) && !strings.Contains(w, `role="`+role+`";`) &&
			!strings.Contains(w, `role=`+role) && !strings.Contains(w, `role = "`+role+`"`) {
			t.Errorf("the release workflow emits no row for the %q role, so no release carries that binary", role)
		}
	}
}

// THE ONE THAT IS NOT ABOUT BUILDING. ADR-0052 §6: the update signing key never
// sits on a build machine and CI never holds it, because a build machine that
// can sign is a build machine that can push code to every node — the compromise
// ADR-0015 calls the highest-value attack surface in the system.
//
// A workflow that gained a signing step would be that mistake, and it would look
// like a convenience. This is the cheapest possible thing that notices.
//
// It looks for KEY MATERIAL rather than for the word "sign", and that is the
// load-bearing choice: nothing can sign without the private key, the key can only
// reach a runner as a repository secret or a file, and naming the signer in a
// release note is fine — an earlier version of this test failed on its own
// documentation, which is a check measuring the wrong thing.
func TestTheReleaseWorkflowHoldsNoSigningKey(t *testing.T) {
	w := readWorkflow(t)
	for _, forbidden := range []string{
		"UPDATE_KEY", "update.key", "SIGNING_KEY", "release-sign keygen",
	} {
		if strings.Contains(w, forbidden) {
			t.Errorf("%s mentions %q. CI must never hold the update signing key: a build machine that "+
				"can sign is a build machine that can push code to every node (ADR-0052 §6). Signing is "+
				"a deliberate offline act performed on what CI produced.", releaseWorkflow, forbidden)
		}
	}
	// The only secret this workflow may reference is the token that creates the
	// draft. Any other is a credential arriving on a build machine, which is the
	// shape the rule above is about.
	for _, line := range strings.Split(w, "\n") {
		i := strings.Index(line, "secrets.")
		if i < 0 {
			continue
		}
		t.Errorf("%s references a repository secret: %q. The only credential this file may use is "+
			"github.token, for the draft release.", releaseWorkflow, strings.TrimSpace(line))
	}
}
