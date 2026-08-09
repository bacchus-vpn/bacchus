package update_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/update"
)

// devUpdater builds an Updater with everything except Root defaulted to something
// harmless, and returns what it logged. The log sink is the seam that matters here:
// it is what a GUI embedder supplies, so a warning that only reached the standard
// logger would not reach the person running a rehearsal build with a window open.
func devUpdater(t *testing.T, root ed25519.PublicKey) []string {
	t.Helper()
	var lines []string
	_, err := update.NewUpdater(update.Config{
		Root:      root,
		Source:    update.NewDirSource(t.TempDir()),
		Target:    t.TempDir() + "/target",
		Role:      update.RoleNode,
		StatePath: t.TempDir() + "/state.json",
		Log:       func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) },
	})
	if err != nil {
		t.Fatalf("NewUpdater: %v", err)
	}
	return lines
}

// TestDevRootPubHexIsThePublishedPhrasesKey pins the production constant against the
// published seed phrase, so the two cannot drift apart.
//
// They live in different places on purpose. update.DevRootPubHex is the PUBLIC key
// and is production code, because production code is what has to recognise the
// anchor; devRootSeedPhrase is the secret and is test-only, because nothing shipped
// needs to derive the private half. That split is right, and it is exactly the shape
// in which a later edit to one silently stops describing the other — at which point
// IsDevRoot returns false for the very key it exists to catch, the guard is gone, and
// no test fails. This is that test.
func TestDevRootPubHexIsThePublishedPhrasesKey(t *testing.T) {
	seed := sha256.Sum256([]byte(devRootSeedPhrase))
	want := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	got, err := update.ParseAnchor(update.DevRootPubHex)
	if err != nil {
		t.Fatalf("DevRootPubHex does not parse as an anchor: %v", err)
	}
	if !want.Equal(got) {
		t.Fatalf("DevRootPubHex is %s but the published phrase derives %s — the constant and the phrase have drifted",
			update.DevRootPubHex, hex.EncodeToString(want))
	}
}

// TestIsDevRootRecognisesTheDevelopmentRootAndNothingElse checks both directions,
// and they are not equally dangerous. A predicate that answered true for a real
// ceremony root would refuse every genuine release at the gate — loud, and fixed
// within the hour. One that answers false for the development root is silent, and is
// the entire failure of issue #252.
func TestIsDevRootRecognisesTheDevelopmentRootAndNothingElse(t *testing.T) {
	dev, err := update.ParseAnchor(update.DevRootPubHex)
	if err != nil {
		t.Fatalf("ParseAnchor(DevRootPubHex): %v", err)
	}
	if !update.IsDevRoot(dev) {
		t.Fatal("IsDevRoot said no to the development root itself")
	}

	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if update.IsDevRoot(other) {
		t.Fatal("IsDevRoot said yes to a freshly generated key, so it would refuse a real release at the gate")
	}
	if update.IsDevRoot(nil) {
		t.Fatal("IsDevRoot said yes to a nil key")
	}
	if update.IsDevRoot(dev[:16]) {
		t.Fatal("IsDevRoot said yes to a truncated key")
	}
}

// TestAnUpdaterOnTheDevelopmentRootSaysSoLoudly is the runtime half of the ruling on
// issue #252 — loud at runtime, fatal at the release gate. Loud rather than fatal
// because a development anchor is precisely what a rehearsal needs in order to
// exercise the release channel at all: a build that refused to run would make the
// rehearsal impossible while protecting nothing the gate does not already protect.
func TestAnUpdaterOnTheDevelopmentRootSaysSoLoudly(t *testing.T) {
	dev, err := update.ParseAnchor(update.DevRootPubHex)
	if err != nil {
		t.Fatalf("ParseAnchor: %v", err)
	}
	lines := devUpdater(t, dev)
	if len(lines) == 0 {
		t.Fatal("an Updater anchored to the development root logged nothing at all")
	}
	joined := strings.Join(lines, "\n")
	// The exact wording is not the contract. That it names the condition in terms an
	// operator cannot read past is, and these three are what make it actionable
	// rather than decorative.
	for _, want := range []string{"DEVELOPMENT ROOT", "published", "never reach a user"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("the development-root warning does not mention %q; it said:\n%s", want, joined)
		}
	}
}

// TestAnUpdaterOnAnOrdinaryRootSaysNothingAboutDevelopment is the other half. A
// warning that fires on every build is a warning nobody reads, which would leave
// issue #252 open in a different way.
func TestAnUpdaterOnAnOrdinaryRootSaysNothingAboutDevelopment(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if joined := strings.Join(devUpdater(t, pub), "\n"); strings.Contains(joined, "DEVELOPMENT ROOT") {
		t.Fatalf("an Updater on an ordinary root warned about the development root:\n%s", joined)
	}
}

// requireReleaseAnchorEnv turns the skip below into a failure. Same shape, and the
// same reason, as core/version's BACCHUS_REQUIRE_STAMP: a check that silently skips
// when its precondition is missing reports green over nothing.
const requireReleaseAnchorEnv = "BACCHUS_REQUIRE_RELEASE_ANCHOR"

// TestAReleaseBuildRefusesTheDevelopmentAnchor is the FATAL half of the ruling on
// issue #252, and it is deliberately a test rather than a shell step in a workflow.
//
// The reason is a trap this repository has already been bitten by twice: a
// `-ldflags -X` naming a symbol that does not resolve is IGNORED SILENTLY, with a
// zero exit. So a workflow step that inspects the value it PASSED proves nothing — it
// has to read what ARRIVED, out of a binary linked the same way, which is what a test
// compiled with those flags does by construction.
//
// `strings | grep` cannot stand in for it either, and that reason is new as of this
// change: DevRootPubHex is now a production constant, so its hex appears in every
// binary that merely links this package, stamped or not. A grep would fire on all of
// them and be switched off within a week.
//
// Today NO build path stamps an anchor — not release.yml, not ci.yml, not
// deploy/install.sh — so this skips everywhere and guards nothing. That is the point
// of writing it now: the gate exists before the capability does, so the first build
// path that learns to stamp an anchor cannot ship a development one in the window
// before somebody thinks to write the check.
func TestAReleaseBuildRefusesTheDevelopmentAnchor(t *testing.T) {
	if !update.Stamped() {
		if os.Getenv(requireReleaseAnchorEnv) != "" {
			t.Fatalf("%s is set, but this test binary carries no anchor: the -X did not reach "+
				"github.com/bacchus-vpn/bacchus/core/update.rootPubHex. Check the symbol path in the "+
				"-ldflags that built it — the linker does not report a bad one",
				requireReleaseAnchorEnv)
		}
		t.Skipf("this test binary carries no anchor, so there is none to judge; a release build sets %s",
			requireReleaseAnchorEnv)
	}
	root, err := update.Anchor()
	if err != nil {
		t.Fatalf("this build is stamped but its anchor does not parse: %v", err)
	}
	if update.IsDevRoot(root) {
		t.Fatalf("this build is anchored to the DEVELOPMENT root (%s). Its private key derives from a "+
			"phrase published in this repository, so anyone at all could sign a release it would accept "+
			"and apply — and ADR-0052 makes a shipped anchor irrevocable, so there is no taking it back. "+
			"A release build carries the offline ceremony root (issue #252)",
			update.AnchorFingerprint(root))
	}
}
