package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// rootPubHex is the trust anchor this build carries: the offline root's PUBLIC
// key, hex, stamped at link time —
//
//	go build -ldflags "-X github.com/bacchus-vpn/bacchus/core/update.rootPubHex=<hex>"
//
// — exactly as core/version.current is stamped, and for the same reason: the value
// belongs to a release rather than to the source tree.
//
// # It is EMPTY here, and the emptiness is the mechanism
//
// ADR-0052 §6 rules that the anchor is compiled in and that the choice — the
// existing bacchus-payment#43 root — is irreversible at first ship. What that
// record does NOT say, and what this file must not do, is put the value in a
// public repository as a constant that could drift from the one the ceremony
// actually holds. So the slot is here and the value arrives at build time from
// whoever ran the ceremony.
//
// An empty anchor means UPDATES ARE OFF. Not "off and silent": every entry point
// that could update reports it, because a build that cannot verify a release and
// says nothing is indistinguishable from one that is up to date.
//
// A LINKER FLAG NAMING A SYMBOL THAT DOES NOT EXIST IS IGNORED SILENTLY, with a
// zero exit — this repository has already been bitten by that once, which is why
// ci.yml's release-stamp job reads core/version's value back out of the binary
// rather than trusting that the flag was passed. AnchorFingerprint exists so the
// same read-back is possible for this one: a build that prints a fingerprint was
// stamped, and a build that prints "none" was not, whatever the build log claims.
var rootPubHex = ""

// ErrNoAnchor reports that this build carries no root public key, so it cannot
// verify a release and will not apply one.
var ErrNoAnchor = errors.New("update: this build carries no release trust anchor")

// DevRootPubHex is the PUBLIC half of the development root — the throwaway key
// bacchus-payment's internal/devroot derives from a phrase published in a source
// file, and which every -dev flow and every test in this package signs under.
//
// # Why a production constant, and not only a test one
//
// The published phrase is already in this repository (core/update's test keys) and
// that is deliberate: bacchus-payment's own reasoning is that "a key whose secret is
// a published string in a source file cannot be mistaken for a real one". It cannot
// be mistaken by a READER. It is entirely indistinguishable to a BUILD, which is the
// gap this constant closes — ParseAnchor accepts it, Anchor returns it, and the
// resulting binary verifies releases signed by anyone who can run sha256 over a
// sentence.
//
// bacchus-payment guards its own side with internal/devroot.IsDevRoot, whose comment
// says it "exists to make that swap verifiable rather than assumed". That check lived
// on the side that cannot ship. This is the same check on the side that can.
//
// ADR-0052 §6 is what makes the asymmetry expensive: the compiled-in anchor is
// IRREVOCABLE at first ship, and losing a root costs a manual reinstall by every
// user. One shipped binary carrying this value hands permanent update authority over
// those installs to any reader of this repository, and the mechanism that would
// deliver a revocation is the mechanism being subverted.
//
// The value is the public key only. Production code never needs to derive the
// private half, and a test pins this constant against the published phrase so the
// two cannot drift apart (issue #252).
const DevRootPubHex = "1b7a9efd101a59248e53e34c9795148fdfc4da712bd8f7e0146cdb2fd6878ac6"

// IsDevRoot reports whether pub is the published development root.
//
// It is the one anchor comparison in this package that DOES make a decision —
// AnchorFingerprint deliberately does not — and the decision it drives is stated in
// two places with different severities, per the ruling on issue #252: loud at
// runtime, fatal at the release gate. Loud rather than fatal at runtime because a
// dev anchor is exactly what a rehearsal needs in order to exercise the channel at
// all; fatal at the gate because nothing carrying it may ever be published.
func IsDevRoot(pub ed25519.PublicKey) bool {
	want, err := ParseAnchor(DevRootPubHex)
	if err != nil {
		// Unreachable: the constant is pinned by a test against the published phrase.
		return false
	}
	return want.Equal(pub)
}

// DevRootWarning is what a process anchored to the development root says about
// itself. One sentence, written for an operator reading a log rather than for the
// person who stamped the build, because the person who stamped it is not the one who
// will be surprised.
const DevRootWarning = "update: THIS BUILD TRUSTS THE DEVELOPMENT ROOT. Its private key is derived from a phrase published in this repository, so anyone at all can sign a release this binary will accept and apply. It is for exercising the release channel and must never reach a user; a real build carries the anchor from the offline ceremony. See issue #252"

// Anchor returns the compiled-in root public key, or ErrNoAnchor.
func Anchor() (ed25519.PublicKey, error) { return ParseAnchor(rootPubHex) }

// Stamped reports whether this build carries an anchor.
func Stamped() bool { return strings.TrimSpace(rootPubHex) != "" }

// ParseAnchor reads a root public key from hex. Exported because an operator flag
// takes the same form as the stamp, and because a build with no stamp is still
// usable against a test root that way.
func ParseAnchor(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrNoAnchor
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("update: trust anchor is not hex: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("update: trust anchor is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// AnchorFingerprint renders a short, stable name for a root public key: the first
// eight hex digits of its SHA-256. It is for log lines and for reading a stamp
// back out of a built binary; it is never compared to make a decision.
//
// An unstamped or unreadable anchor renders as "none", which is the honest answer
// to "which root does this build trust" from a build that trusts none.
func AnchorFingerprint(pub ed25519.PublicKey) string {
	if len(pub) != ed25519.PublicKeySize {
		return "none"
	}
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:4])
}
