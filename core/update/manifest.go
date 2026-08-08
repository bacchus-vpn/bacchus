package update

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Version is the format version of the manifest. It is checked EXACTLY, not as a
// minimum: a verifier that does not know a format refuses it rather than reading
// the subset it recognises, so an old node never silently misreads a newer
// manifest and applies an artifact row it half-understood.
//
// The rule for bumping is core/policy's, narrowed by what this object authorizes:
// bump when a verifier that does not know a new field would APPLY DIFFERENTLY.
// Roll a bump by shipping verifiers first and signing at the new version second;
// signing first strands every node that cannot update itself, which is the one
// mistake this channel exists to make survivable and cannot survive itself.
const Version = 1

// MaxArtifactBytes bounds a single artifact, and it is enforced BEFORE any bytes
// are written rather than after: a manifest is signed data, so a size it declares
// is a promise, and a source that exceeds it is lying about which artifact it is
// serving. 512 MiB is far above the largest binary this repository produces
// (cmd/node, ~21 MB per ADR-0052 §5) and far below anything that fills a disk.
//
// It is a cap on the DECLARED size at Validate and on the DELIVERED bytes at
// Stage, and both matter: the first stops a signed manifest from asking for an
// unbounded write, the second stops an unsigned source from delivering one.
const MaxArtifactBytes = 512 << 20

// Artifact roles. The role is which BINARY a row describes, not which network role
// runs it: one node process may be reachable as relay and exit, and it is one
// artifact either way.
//
// Closed vocabulary, checked at Validate. A row naming a role a verifier does not
// know is refused rather than skipped — skipping would make a manifest mean
// different things to different builds, and this is the object where "different
// builds disagree about what was authorized" is the whole failure.
const (
	// RoleNode is cmd/node: the client/relay/exit binary, and the one the fleet
	// runs.
	RoleNode = "node"
	// RoleCoordinator is cmd/coordinator.
	RoleCoordinator = "coordinator"
	// RoleNetd is cmd/bacchus-netd, the Linux root helper (ADR-0049). Socket
	// activated rather than Restart=always, so its replacement takes effect on the
	// next activation; that is a property of the unit, not of this row.
	RoleNetd = "netd"
	// RoleClient is clients/fyne, the desktop GUI. ADR-0052 §5 records that this
	// one is NOT reproducible — it needs cgo and a C toolchain — so it ships with a
	// published hash and this channel's signature instead of an independent
	// rebuild.
	RoleClient = "client"
)

// Sentinel errors. Every one names a protocol fact only — never key material,
// never a path, never anything account-scoped — so all are safe to log and safe to
// report back to whoever supplied the object. ADR-0029's rule that a version
// reject names nothing account-scoped is what makes a refusal loggable at all.
var (
	ErrUnsupportedVersion = errors.New("update: unsupported manifest version")
	ErrMalformed          = errors.New("update: malformed manifest")
	ErrInvalid            = errors.New("update: manifest fails validation")
	ErrNotYetIssued       = errors.New("update: manifest not yet issued")
	ErrExpired            = errors.New("update: manifest expired")
	ErrRollback           = errors.New("update: sequence went backwards")
	ErrNoArtifact         = errors.New("update: manifest names no artifact for this build")
	ErrHashMismatch       = errors.New("update: artifact hash does not match the manifest")
	ErrSizeMismatch       = errors.New("update: artifact size does not match the manifest")
)

// Artifact is one row of the manifest: a build, named by what it IS rather than by
// where it lives.
//
// Size is carried beside the hash even though the hash alone is authoritative,
// because a size lets a fetch be refused before it is paid for. A source that
// serves more bytes than the manifest declares is caught at the first byte past
// the limit rather than at the end of an unbounded download.
type Artifact struct {
	OS   string `json:"os"`   // GOOS, e.g. "linux"
	Arch string `json:"arch"` // GOARCH, e.g. "amd64"
	Role string `json:"role"` // one of the Role* constants above
	Size int64  `json:"size"` // exact byte count
	// SHA256 is the digest of the COMPLETE artifact. 32 bytes; JSON-encodes as
	// standard base64 because []byte does.
	SHA256 []byte `json:"sha256"`
}

// Name is the content-addressed name of an artifact: the lowercase hex of its
// digest and nothing else.
//
// It is deliberately NOT built from OS, Arch or Role. Those are signed strings
// that a source could otherwise turn into a path — "../" is a perfectly good
// GOOS as far as JSON is concerned — and a name derived from the digest cannot
// name anything but the bytes it is the digest of. Validate rejects a separator in
// those fields as well, so this is the second of two locks on the same door.
func (a Artifact) Name() string { return hex.EncodeToString(a.SHA256) }

// Matches reports whether a describes the build (goos, goarch, role).
func (a Artifact) Matches(goos, goarch, role string) bool {
	return a.OS == goos && a.Arch == goarch && a.Role == role
}

// Manifest is the signed release description.
//
// The marshaled form is the signed body and verification is always over the bytes
// AS RECEIVED, so field order, whitespace and escaping are deliberately not part
// of the contract — the same rule core/delegation states for every object in this
// family. The json tag names, the domain tag, the Role* values and Version are.
type Manifest struct {
	Version int    `json:"v"`
	Seq     uint64 `json:"seq"`

	// Release is the product version these artifacts are, as bare
	// MAJOR.MINOR.PATCH — the same string core/version stamps into them and the
	// coordinator advertises. It is what a peer compares against its own release to
	// decide whether this manifest is news.
	Release string `json:"release"`

	// Issued and Expires bound the manifest's own life. Expiry is what stops a
	// withholding source from pinning a fleet at an old release forever without
	// violating a signature anywhere: a manifest that has aged out is refused, and
	// the peer is then a peer with no manifest rather than a peer confidently
	// holding a stale one.
	//
	// There is deliberately no grace field, unlike core/policy's. Grace exists there
	// because an enforcer with no policy must fail closed and darken; a peer with no
	// manifest simply does not update, which is the state it was already in.
	Issued  time.Time `json:"issued"`
	Expires time.Time `json:"exp"`

	// Note is an operator label. Never load-bearing, never parsed.
	Note string `json:"note,omitempty"`

	// Artifacts is a LIST, not a map keyed by a composite string, for the reason
	// core/policy.Policy.Tiers gives: a JSON object's behaviour on DUPLICATE keys is
	// implementation-defined, so a map would let two verifiers of the same signed
	// bytes install different binaries with no signature failure anywhere. A list
	// makes a duplicate representable, which lets Validate reject it outright.
	Artifacts []Artifact `json:"artifacts"`
}

// Find returns the artifact for (goos, goarch, role), or ErrNoArtifact.
//
// A manifest that names no artifact for this build is NOT an error condition of
// the manifest — a release that ships a Windows client and no netd is an ordinary
// release — so callers treat this as "nothing for me" rather than as a refusal to
// report. Validate has already rejected duplicates, so the first match is the only
// match.
func (m Manifest) Find(goos, goarch, role string) (Artifact, error) {
	for _, a := range m.Artifacts {
		if a.Matches(goos, goarch, role) {
			return a, nil
		}
	}
	return Artifact{}, fmt.Errorf("%w: %s/%s %s", ErrNoArtifact, goos, goarch, role)
}

// Validate checks the manifest's structural invariants.
//
// It checks what makes a manifest impossible to apply coherently, and nothing
// about whether the release is a GOOD one: which release to ship is the operator's
// call, and bounding what a compromised signer can do is the delegation window's
// job and the revocation list's, not this function's. That is core/policy.Validate's
// line and it holds here for the same reason.
func (m Manifest) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, m.Version)
	}
	if m.Seq == 0 {
		return fmt.Errorf("%w: seq must be at least 1 (0 is the never-loaded sentinel)", ErrInvalid)
	}
	if err := checkRelease(m.Release); err != nil {
		return err
	}
	if m.Issued.IsZero() || m.Expires.IsZero() {
		return fmt.Errorf("%w: issued and exp are both required", ErrInvalid)
	}
	if !m.Issued.Before(m.Expires) {
		return fmt.Errorf("%w: empty window (issued %s >= exp %s)", ErrInvalid, m.Issued.UTC(), m.Expires.UTC())
	}
	if len(m.Artifacts) == 0 {
		return fmt.Errorf("%w: no artifacts (a release that delivers nothing is not a release)", ErrInvalid)
	}
	type key struct{ os, arch, role string }
	seen := make(map[key]struct{}, len(m.Artifacts))
	for _, a := range m.Artifacts {
		if err := checkToken("os", a.OS); err != nil {
			return err
		}
		if err := checkToken("arch", a.Arch); err != nil {
			return err
		}
		switch a.Role {
		case RoleNode, RoleCoordinator, RoleNetd, RoleClient:
		default:
			return fmt.Errorf("%w: unknown artifact role %q", ErrInvalid, a.Role)
		}
		if a.Size <= 0 {
			return fmt.Errorf("%w: artifact %s/%s %s declares size %d", ErrInvalid, a.OS, a.Arch, a.Role, a.Size)
		}
		if a.Size > MaxArtifactBytes {
			return fmt.Errorf("%w: artifact %s/%s %s declares %d bytes, over the %d-byte cap", ErrInvalid, a.OS, a.Arch, a.Role, a.Size, int64(MaxArtifactBytes))
		}
		if len(a.SHA256) != sha256.Size {
			return fmt.Errorf("%w: artifact %s/%s %s carries a %d-byte digest", ErrInvalid, a.OS, a.Arch, a.Role, len(a.SHA256))
		}
		k := key{a.OS, a.Arch, a.Role}
		if _, dup := seen[k]; dup {
			// Two rows for one build means the manifest does not say WHICH bytes are
			// authorized for it, and a verifier that took the first would install
			// something different from one that took the last. Refusing is the only
			// reading both can share.
			return fmt.Errorf("%w: duplicate artifact row for %s/%s %s", ErrInvalid, a.OS, a.Arch, a.Role)
		}
		seen[k] = struct{}{}
	}
	return nil
}

// checkToken rejects an OS or ARCH string that is empty or could become part of a
// path. Name() already derives every filename from the digest, so this is defence
// in depth rather than the only guard — but these strings reach log lines and
// operator tooling, and a signed object is exactly where a value nobody validated
// gets to travel furthest.
//
// The allowed set is lowercase ASCII letters, digits and underscore, which covers
// every GOOS and GOARCH Go defines.
func checkToken(field, s string) error {
	if s == "" {
		return fmt.Errorf("%w: artifact %s is empty", ErrInvalid, field)
	}
	if len(s) > 32 {
		return fmt.Errorf("%w: artifact %s %q is too long", ErrInvalid, field, s)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
		if !ok {
			return fmt.Errorf("%w: artifact %s %q contains %q", ErrInvalid, field, s, string(rune(c)))
		}
	}
	return nil
}

// checkRelease rejects a release string this build's own version parser could not
// read.
//
// It is the same strictness core/policy.checkServingVersion applies to
// min_serving_version, and for the same reason: exactly three runs of ASCII
// digits, no sign, no leading zeros. Everything this accepts parses identically in
// core/version.Parse; the extra strictness removes readings — a leading zero is
// octal to some parsers and decimal to others — that an object verified by an
// independent implementation cannot afford to leave open.
//
// It does not import core/version. This package is verified by binaries that
// compare releases and by cmd/release-sign which does not, and the check is over
// the STRING rather than over a parsed value, so it stays here as bytes.
func checkRelease(s string) error {
	if s == "" {
		return fmt.Errorf("%w: release is required", ErrInvalid)
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: release %q is not MAJOR.MINOR.PATCH", ErrInvalid, s)
	}
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("%w: release %q has an empty component", ErrInvalid, s)
		}
		if len(p) > 1 && p[0] == '0' {
			return fmt.Errorf("%w: release %q has a leading zero in %q", ErrInvalid, s, p)
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return fmt.Errorf("%w: release %q has a non-digit in %q", ErrInvalid, s, p)
			}
		}
		if _, err := strconv.ParseUint(p, 10, 31); err != nil {
			return fmt.Errorf("%w: release %q component %q out of range", ErrInvalid, s, p)
		}
	}
	return nil
}
