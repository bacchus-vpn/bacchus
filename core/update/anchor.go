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
