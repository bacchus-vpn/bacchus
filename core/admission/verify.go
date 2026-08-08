package admission

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core/atomicfile"
)

// ClockSkew is the tolerance applied to a credential's NotBefore so a node
// whose clock runs slightly ahead of the coordinator's isn't rejected the
// instant it is issued. It is intentionally applied only to the lower bound:
// being lenient about when a credential *starts* is harmless, but being lenient
// about when it *expires* would extend a revoked/rotated credential's life, so
// NotAfter is checked strictly. Two minutes matches the order of magnitude of
// unsynchronized consumer clocks without meaningfully widening the window.
const ClockSkew = 2 * time.Minute

// Authority is one anchored admission authority: a public key together with the
// roles that key is trusted to admit (issue #64).
//
// It is deliberately a different statement from the Roles field inside a
// Credential, and both are checked. A Credential's Roles is the ISSUER's claim
// — "this subject may act as an exit" — and whoever holds a signing key writes
// it freely. An Authority's Roles is the ANCHOR's claim — "this issuer may mint
// exits at all" — and no signing key can reach it. That gap is the whole point:
// the account service mints client credentials automatically, always online, at
// volume; anchoring it for RoleClient alone means compromising it yields client
// credentials and nothing that can join the network as forwarding
// infrastructure, however the roles field of what it mints is filled in.
//
// Roles is empty-means-nothing, not empty-means-everything: an authority no
// caller managed to scope is one that admits no role rather than every role.
type Authority struct {
	Pub   ed25519.PublicKey // the ed25519 public key this authority signs credentials with
	Roles []Role            // the roles it is trusted to admit; empty admits nothing
}

// admits reports whether this authority is anchored for want.
func (a Authority) admits(want Role) bool {
	for _, r := range a.Roles {
		if r == want {
			return true
		}
	}
	return false
}

// Verifier holds the anchored admission authorities and a revocation oracle,
// and turns an encoded credential from the wire into an accept/reject decision.
// It is safe for concurrent use as long as the revoked func is (a
// *RevocationList swapped via atomic.Pointer, as the coordinator does, is): the
// authority set is fixed at construction and never written afterwards.
type Verifier struct {
	authorities []Authority
	revoked     func(serial string) bool
}

// NewVerifier builds a Verifier anchoring exactly ONE authority, trusted for
// every role (AllRoles). revoked reports whether a serial has been revoked; pass
// nil when there is no revocation list (nothing is revoked).
//
// This is not a compatibility shim for the pre-#64 single key — it is the
// single-anchor case, and it stays. A client's admission anchor is genuinely one
// key: its only Verify call is for RoleExit, the authority that mints exits is
// the operator, and a coldstart invite carries exactly one AdmissionKey
// (core/coldstart). The coordinator, which must tell two issuers apart, uses
// NewAuthoritySetVerifier instead.
//
// Note what "every role" does NOT mean: an all-roles authority still only
// admits a credential whose own Roles field authorizes what the peer is asking
// for, because accept still checks that. The anchor check added in #64 is an
// outer gate, not a replacement for the inner one.
//
// It takes pub unvalidated and returns no error, exactly as it did before #64:
// both callers check the key length themselves before they get here, and a bad
// one still surfaces as ErrMalformed at Verify time.
func NewVerifier(pub ed25519.PublicKey, revoked func(serial string) bool) *Verifier {
	return &Verifier{
		authorities: []Authority{{Pub: pub, Roles: AllRoles()}},
		revoked:     revokedOrNothing(revoked),
	}
}

// NewAuthoritySetVerifier builds a Verifier anchoring a role-scoped SET of
// authorities (issue #64) — the coordinator's shape, where the operator's
// offline key mints relay/exit credentials and the account service's own key
// mints client credentials, and neither can mint the other's.
//
// Construction fails CLOSED on anything ambiguous, because every one of these is
// an operator mistake that would otherwise present as a working coordinator
// silently admitting or refusing the wrong thing:
//
//   - no authorities at all — a Verifier that verifies nothing;
//   - a key that is not ed25519.PublicKeySize bytes — after this returns, every
//     anchored key is well-formed, which is what lets Verify treat a parse
//     failure as a fact about the CREDENTIAL rather than about the anchor;
//   - an authority scoped to no roles, or to a role string this build does not
//     know (Role.Known) — both look configured and admit nothing;
//   - the same key anchored twice, which is either a redundant flag or a typo in
//     the roles of one of them, and is never the shortest way to say what was
//     meant.
//
// Errors name an authority by its position in the list, never by its key: these
// go to an operator's log, and the package's rule is that nothing it emits
// carries key material.
func NewAuthoritySetVerifier(authorities []Authority, revoked func(serial string) bool) (*Verifier, error) {
	if len(authorities) == 0 {
		return nil, errors.New("admission: a verifier must anchor at least one authority")
	}
	anchored := make([]Authority, 0, len(authorities))
	seen := make(map[string]int, len(authorities))
	for i, a := range authorities {
		if len(a.Pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("admission: authority %d: key must be %d bytes, got %d", i+1, ed25519.PublicKeySize, len(a.Pub))
		}
		if len(a.Roles) == 0 {
			return nil, fmt.Errorf("admission: authority %d: anchored for no roles", i+1)
		}
		for _, r := range a.Roles {
			if !r.Known() {
				return nil, fmt.Errorf("admission: authority %d: unknown role %q", i+1, r)
			}
		}
		if first, dup := seen[string(a.Pub)]; dup {
			return nil, fmt.Errorf("admission: authority %d: same key already anchored as authority %d; give one authority all of its roles at once", i+1, first+1)
		}
		seen[string(a.Pub)] = i
		// Copy Roles: it is a caller-owned slice retained as part of a trust
		// anchor, and a caller that builds one set of roles and reslices it for
		// the next authority must not be able to edit an anchor after the fact.
		anchored = append(anchored, Authority{Pub: a.Pub, Roles: append([]Role(nil), a.Roles...)})
	}
	return &Verifier{authorities: anchored, revoked: revokedOrNothing(revoked)}, nil
}

// revokedOrNothing normalizes a nil revocation oracle to "nothing is revoked",
// so Verify never has to nil-check it.
func revokedOrNothing(revoked func(serial string) bool) func(string) bool {
	if revoked == nil {
		return func(string) bool { return false }
	}
	return revoked
}

// Verify decodes and checks an encoded wire credential and returns the
// validated Credential, or an error naming why it failed (safe to log/return).
// want is the role the peer is trying to take right now (RoleClient for a
// list/connect, the registering role for a node). subject is the identity the
// credential must be bound to — the node id on a register — or "" to skip the
// binding check, which is how a client credential (bearer, no coordinator-known
// id) is verified. now is passed in rather than read here so tests use a fixed
// clock and the caller controls the time source.
//
// The authority set is FILTERED BY ROLE FIRST and only the survivors get a
// signature verification (issue #64). The inverse — verify against every
// anchored key, then check whether the one that matched was allowed to admit
// want — computes the same answer, and this order is chosen over it for two
// reasons:
//
//   - The role check cannot be forgotten, reordered, or short-circuited by a
//     later edit. A client authority's signature is never a candidate for an
//     exit check, so there is no state in which the anchor scoping is merely
//     "checked afterwards" and might not be.
//   - Signature cost is bounded by the authorities anchored for that ONE role
//     rather than by the whole set, on a path the coordinator runs for every
//     list, connect and capacity-report.
//
// A parse failure that is ErrBadSignature means "not this authority" and the
// loop moves on. Every other parse failure — a malformed envelope, an
// unsupported CredentialVersion — is a fact about the credential itself, which
// no other anchored key would read differently, so it is returned immediately
// rather than masked by a later ErrBadSignature.
func (v *Verifier) Verify(encoded string, now time.Time, want Role, subject string) (Credential, error) {
	signed, err := Decode(encoded)
	if err != nil {
		return Credential{}, err
	}
	candidates := 0
	for _, a := range v.authorities {
		if !a.admits(want) {
			continue
		}
		candidates++
		c, err := parse(a.Pub, signed)
		if err != nil {
			if errors.Is(err, ErrBadSignature) {
				continue
			}
			return Credential{}, err
		}
		if err := accept(c, now, want, subject, v.revoked); err != nil {
			return Credential{}, err
		}
		return c, nil
	}
	// Nothing anchored can admit want at all. Reported distinctly from
	// ErrBadSignature because it is a fact about this coordinator's
	// configuration rather than about the credential — an operator who
	// forgot to anchor an authority for a role needs to be told that, and
	// telling them costs nothing an unauthorized peer could not learn by
	// observing that the role is refused unconditionally.
	if candidates == 0 {
		return Credential{}, fmt.Errorf("%w: %s", ErrNoAuthorityForRole, want)
	}
	// Candidates existed and none of them signed this. Note what this
	// deliberately does NOT distinguish: a forged signature and a genuine
	// signature from an authority anchored for some OTHER role both land
	// here as ErrBadSignature, where before #64 the latter would have
	// reached accept and come back as ErrRoleNotAuthorized. That is the
	// same reasoning ADR-0045 applied to its assertion failures — a
	// verifier that reported which part was right is an oracle for finding
	// the rest — and it is a consequence of filtering first, not a
	// separate mechanism.
	return Credential{}, ErrBadSignature
}

// accept applies the admission policy to an already signature-verified
// Credential and returns nil to admit or a sentinel error to reject. Everything
// cryptographic is done by the time we get here — parse has verified the
// ed25519 signature over c and confirmed the format version — so this is pure
// policy over trusted fields.
//
// The checks run revocation-first: an explicitly revoked credential is the
// freshest, most decisive operator signal, so it is rejected before the static
// window/role/subject checks and surfaces ErrRevoked even when the credential
// has also expired (the operator killed it — that is the more actionable
// reason). The validity window then applies ClockSkew tolerance to the lower
// bound only and is strict on expiry (see ClockSkew's doc for why the
// asymmetry). Finally the role must be authorized, and a node credential
// (subject != "") must be bound to the id presenting it; a client credential
// (subject == "") is bearer and skips the binding check.
//
// The role check here survives #64's anchor scoping and is not made redundant by
// it. The two ask different questions of different parties: Verify's filter asks
// whether the ANCHOR trusts this authority to admit want at all, and this asks
// whether the ISSUER wrote want into the credential it actually signed. An
// operator authority anchored for every role must still not have a client
// credential it minted admitted as an exit, and only this check stops that.
func accept(c Credential, now time.Time, want Role, subject string, revoked func(serial string) bool) error {
	if revoked(c.Serial) {
		return ErrRevoked
	}
	if now.Before(c.NotBefore.Add(-ClockSkew)) {
		return ErrNotYetValid
	}
	if !now.Before(c.NotAfter) {
		return ErrExpired
	}
	if !c.HasRole(want) {
		return ErrRoleNotAuthorized
	}
	if subject != "" && subject != c.Subject {
		return ErrSubjectMismatch
	}
	return nil
}

// RevocationList is a set of revoked credential serials. The coordinator loads
// it from disk and hot-reloads it (like the bootstrap secrets file) so an
// operator can revoke a leaked or rotated credential without a restart. The
// zero value is not usable; construct with NewRevocationList or
// LoadRevocationList.
type RevocationList struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

// revocationFile is the on-disk JSON shape: a version tag and a flat list of
// revoked serials. A plain list keeps it hand-editable by an operator in a
// pinch.
type revocationFile struct {
	Version int      `json:"version"`
	Revoked []string `json:"revoked"`
}

const revocationFileVersion = 1

// NewRevocationList returns an empty list (nothing revoked).
func NewRevocationList() *RevocationList {
	return &RevocationList{set: map[string]struct{}{}}
}

// LoadRevocationList reads and parses the revocation file at path. A missing
// file is reported as os.ErrNotExist (wrapped) so the caller can decide whether
// that means "nothing revoked yet" or a hard failure — a security-relevant
// choice the coordinator makes explicitly rather than this package guessing.
func LoadRevocationList(path string) (*RevocationList, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("admission: read revocation list %s: %w", path, err)
	}
	var f revocationFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("admission: parse revocation list %s: %w", path, err)
	}
	if f.Version != revocationFileVersion {
		return nil, fmt.Errorf("admission: revocation list %s: unsupported version %d", path, f.Version)
	}
	rl := NewRevocationList()
	for _, s := range f.Revoked {
		rl.set[s] = struct{}{}
	}
	return rl, nil
}

// Revoked reports whether serial is in the list.
func (r *RevocationList) Revoked(serial string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.set[serial]
	return ok
}

// Revoke adds serial to the list (used by the issuer tool).
func (r *RevocationList) Revoke(serial string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.set[serial] = struct{}{}
}

// Serials returns every revoked serial, sorted for a stable, diff-friendly
// order (used by SaveFile and by cmd/admission-issue -crl to sign the current
// set as a distributable CRL, old #69).
func (r *RevocationList) Serials() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	serials := make([]string, 0, len(r.set))
	for s := range r.set {
		serials = append(serials, s)
	}
	sort.Strings(serials)
	return serials
}

// SaveFile writes the list to path as the revocationFile JSON shape. Serials
// are written in a stable sorted order so the file is diff-friendly across
// issuer runs.
//
// The write is ATOMIC: a complete file is renamed over the target, and the file
// the coordinator reads is never opened for writing at all (issue #168). That is
// a correctness requirement rather than tidiness, because the two ways a torn
// file can be observed are NOT symmetric and the second one is silent.
//
// cmd/coordinator hot-reloads this file (reloadRevocationsLoop) on its own
// timer, with no coordination with whatever wrote it, and cmd/admission-issue
// -revoke writes by default to secrets/admission-revocations.json — the
// coordinator's own -admission-revocations default. os.WriteFile, which this
// used to be, opens that live file with O_TRUNC and refills it, so between the
// truncate and the last byte the file on disk is empty or short, and a writer
// that dies in that window leaves it that way permanently.
//
//   - A RELOAD that lands in the window is fail-safe. The loop keeps its
//     previous in-memory list when a read or parse fails, so a torn read
//     over-refuses at worst and the next tick repairs it.
//   - A RESTART afterwards is not. At startup there is no previous list, and
//     -admission-revocations says in as many words that a missing or
//     unparseable file means nothing is revoked. So a torn write plants a
//     DELAYED failure that detonates at the next coordinator restart — hours or
//     weeks later, with nothing connecting it to the revocation that caused it.
//
// The mechanics — staged in the target's own directory under a unique name,
// flushed before the rename, cleaned up on every failure path — are
// core/atomicfile's, and its doc carries the reasoning for each. 0600 because
// this file is staged in the coordinator's secrets directory beside its signing
// keys, and because a rename installs the mode every time where os.WriteFile
// applied it only at creation.
//
// # Why this is one of the few writers that fsyncs the DIRECTORY
//
// A file's own flush makes the BYTES durable. It does not commit the directory
// entry, so without a second fsync a machine that loses power immediately after
// the rename can come back holding the PREVIOUS file. Issue #188 ruled that
// boundary per write rather than per file, and this write is on the far side of
// it, for a reason that has nothing to do with how important the file is:
//
//   - Almost every other persistent file here is re-emitted. A policy floor is
//     re-recorded every ten seconds, a quota checkpoint every few megabytes, a
//     selection cache on the next success — so a lost rename costs one
//     generation and the next ordinary write repairs it unprompted.
//   - This list is not. It is the accumulated record of decisions an operator
//     made one at a time, and nothing writes it again until the NEXT revocation.
//     A lost rename un-revokes a credential silently, permanently, and after
//     cmd/admission-issue has already told the operator the revocation was
//     saved. There is no loop that notices and no second chance.
//
// The cost is one fsync on an operation a human runs, once per revocation, on a
// path that has already touched the disk. That is not a trade that needs
// balancing.
func (r *RevocationList) SaveFile(path string) error {
	serials := r.Serials()
	b, err := json.MarshalIndent(revocationFile{Version: revocationFileVersion, Revoked: serials}, "", "  ")
	if err != nil {
		return fmt.Errorf("admission: marshal revocation list: %w", err)
	}
	if err := atomicfile.WriteDurable(path, b, 0o600); err != nil {
		return fmt.Errorf("admission: save revocation list: %w", err)
	}
	return nil
}
