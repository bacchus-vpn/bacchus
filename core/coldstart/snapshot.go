package coldstart

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Entry is one directory record in a Snapshot: an entry point a client can
// try, the coordinator itself, or a service a client addresses out of band.
type Entry struct {
	// Role is what this record names. Four values, and the fourth is not an
	// entry point (bacchus#193, ADR-0061):
	//
	//   - "coordinator", "relay", "exit" — a node in this network. Addr is a
	//     host:port this client dials directly.
	//   - "account" — the account service (ADR-0016 decision 4). It is not part
	//     of the rendezvous fabric and is never dialled as one; it is reached
	//     over HTTPS, so Addr carries a scheme-and-host URL rather than a
	//     host:port. It rides here because a client has no other channel that
	//     can tell it the service moved, and because the directory is signed by
	//     the coordinator and re-shareable without carrying anybody's secret.
	//
	// An "account" entry is a LOCATION and never a trust root. A consumer keeps
	// its own out-of-band audience and pinned CA — see core/accountclient's New,
	// which validates both once for the whole address list — so a coordinator
	// that named a service it controls would be pointing this client at
	// something that still has to present the identity the client already pins.
	Role    string `json:"role"`
	ID      string `json:"id"`
	Country string `json:"country,omitempty"`
	// Addr is host:port for the three node roles, and a scheme-and-host URL
	// ("https://host:port", no path) for role "account". See Role.
	Addr string `json:"addr"`

	// CountrySource says HOW the coordinator arrived at Country (issue #3): one of the
	// Country* provenance values below, or empty from a coordinator predating the
	// field.
	//
	// It ships because Country alone is four different claims wearing one label. A tag
	// the coordinator resolved from an address it observed, a tag the node simply
	// asserted through its -country flag (the fallback, and the ONLY source in a
	// deployment with no database staged), and a tag resolved from an address the
	// coordinator can see disagrees with where the node says it serves traffic from —
	// all three used to arrive here byte-identical in shape. The signature over this
	// snapshot proves the coordinator said it; it says nothing about which of those
	// three it is. A fourth joined them with issue #113 — a country a coordinator
	// ADMINISTRATOR asserted by hand, correcting a derivation they hold evidence is
	// wrong (CountryAdminOverride) — and it is the one a consumer is least able to
	// guess at, since it is neither observed nor claimed by the node.
	//
	// That mattered less when the snapshot was a bootstrap contact list. It matters now
	// because ADR-0042 §9 made it THE exit-discovery path for relay chaining: a
	// chaining client picks its terminating exit — the jurisdiction the whole feature
	// exists to choose — out of this artifact, with no live reply to check it against.
	// See CountryContradicted for what a consumer does with it.
	//
	// Carried for relays as well as exits. A relay's Addr and Ingress are built from
	// the observed source IP so they cannot disagree with each other, but its COUNTRY
	// still falls back to the node's own -country hint whenever that address resolves
	// to nothing.
	CountrySource string `json:"countrySource,omitempty"`

	// DeclaredCountry is what the NODE ITSELF said its country is — its own -country
	// flag, canonicalized — carried beside Country rather than discarded at derivation
	// time (issue #113).
	//
	// The two answer different questions and the project spent a long time with only
	// one name for both. Country answers "what will every destination site conclude
	// about a user egressing here", which is a property of the ADDRESS. This answers
	// "which building does the traffic physically leave from", which is a property of
	// the MACHINE, and only its operator knows it. They disagree routinely and
	// innocently: a large cloud provider's address block is commonly registered to that
	// provider's home country regardless of which datacentre an instance runs in, so an
	// instance in one country resolving to another is the normal case. The first fleet
	// where this was measured disagreed on two exits out of three.
	//
	// **It is a bare self-report and must never be used as a jurisdiction.** A user who
	// picks DE picks it to BE TREATED AS German by every site they visit, and an address
	// that resolves US is treated as US no matter which building it sits in — so
	// selecting, filtering or displaying on this field would deliver the exact
	// misrouting ADR-0042 §8 exists to prevent, from the one input that record removed
	// from the trust path. Nothing in this repository reads it for selection, and
	// nothing should. It is here so an operator-facing surface can say what the node
	// claims, and so the coordinator stops throwing away the one thing the operator
	// actually knows.
	//
	// **A coordinator running -geoip-required omits it entirely** (owner ruling,
	// 2026-08-03). It still derives, stores, logs and allows an admin to override the
	// declaration under that flag; it simply does not publish it here. ADR-0042 §9 made
	// this artifact THE exit-discovery path for relay chaining — a chaining client picks
	// its terminating jurisdiction out of it with no live reply to check it against —
	// and that flag's promise is that no node self-report reaches a client's country
	// choice. Putting a labelled self-claim into the one artifact a client chooses a
	// jurisdiction from is not that promise kept, however carefully it is labelled and
	// however true it is that nothing reads this field today. "Nothing reads it today"
	// is a fact about today, in a file designed to be durable, and what the next
	// implementer sees is a country inside a signed document. The cheapest way to keep a
	// promise is not to hand out the thing you promised not to hand out.
	//
	// So under that flag an entry whose address did not resolve carries NEITHER Country
	// nor this field, and CountrySource alone says why. Without the flag both travel.
	//
	// It is NOT elided when it agrees with Country. Collapsing "made no claim" into
	// "made a claim that checks out" is the exact bug class ADR-0042's own #2 amendment
	// closed for the advertised endpoint, and this field is the same shape: a consumer
	// must be able to tell a node that declared nothing from one whose declaration was
	// confirmed. omitempty therefore means "this node declared no usable country",
	// nothing else.
	//
	// Additive with omitempty in the pattern Ingress and Operator already use, so a
	// pre-#113 snapshot is byte-identical on the wire and SnapshotVersion does not move.
	DeclaredCountry string `json:"declaredCountry,omitempty"`

	// Ingress is the TCP address a client's onion layer dials to reach this node as
	// an INTERMEDIATE relay hop in a multi-hop chain (issue #124, ADR-0038 §9 item 3).
	// It is deliberately distinct from Addr: for a relay, Addr is the coordinator-
	// observed UDP signaling address used for rendezvous and mesh-walk courier fetches
	// (issue #31) — a NAT-punched hole, not a forward-dial target — whereas Ingress is a
	// publicly reachable TCP listener that accepts an onion layer and splices to the next
	// hop (ADR-0038 §5: middle hops must be publicly reachable). This is the courier-
	// address seam ADR-0037 deferred and the field the whole relay-chaining epic (#76)
	// gates on: a client cannot assemble a chain through a node whose forwarding ingress
	// it cannot learn. Set by the coordinator (see cmd/coordinator buildSnapshot) as the
	// OBSERVED source IP joined to the relay's self-reported listener port — the host is
	// never a node self-report, so a relay cannot claim an ingress in an AS it does not
	// occupy. Only relay entries carry it, and only relay-eligible ones (RelayEligible);
	// empty for coordinators, exits, and any relay that advertised no forwarding ingress.
	// omitempty keeps a pre-#124 snapshot byte-identical on the wire (backward-compat).
	Ingress string `json:"ingress,omitempty"`

	// Operator is the coordinator-known operator / vouch-subtree tag, used for
	// operator-diversity hop selection (issue #124, ADR-0038 §6): §4 avoids routing two
	// hops of one chain through nodes a single operator controls. It belongs in the
	// SIGNED directory precisely because operator identity is NOT derivable from an IP —
	// unlike an AS number, which a self-report cannot be trusted to state (a Sybil
	// operator would fabricate diversity in a signed tag), which is why NO AS field is
	// carried here at all: real AS-diversity is derived client-side from each hop's
	// OBSERVED IP against an independent routing table in §4, never from this snapshot.
	// The coordinator sets this from its own operator registry, never from a node's
	// self-report; empty when the coordinator has no assignment for the node.
	Operator string `json:"operator,omitempty"`
}

// Country provenance values carried in [Entry.CountrySource] (issue #3, ADR-0042 §1/§8).
//
// These are the wire values, so they are defined HERE, in the package that owns the
// signed artifact's schema — cmd/coordinator holds an identical set of unexported
// constants because that binary deliberately does not import core (see its wire doc),
// and TestCountrySourceWireContract on each side pins the two copies against each
// other, exactly as TestQuotaStateWireContract does for the quota literals (#97).
const (
	// CountryObserved: the coordinator resolved the country from the address it
	// observed the node register from, and — for an exit — the data-plane endpoint the
	// node advertises is that same address. The strongest statement available.
	CountryObserved = "observed"
	// CountryHinted: the observed address resolved to nothing, so the country is the
	// node's own -country flag. A self-report, and the only source of a country at all
	// in a deployment with no geo database staged.
	CountryHinted = "hint"
	// CountrySignalingOnly: the observed address resolved, but the node advertises a
	// data-plane endpoint that is a DIFFERENT address (or a name the coordinator will
	// not resolve). The country describes where the node signals from, which the
	// coordinator can see is not where it says it serves traffic from.
	CountrySignalingOnly = "observed-signaling-only"
	// CountryNoEndpoint: the observed address resolved, but under -geoip-required the
	// node advertises no data-plane endpoint at all, so there is nothing to corroborate
	// the resolution against (issue #2). Such an entry carries no Country.
	CountryNoEndpoint = "unverifiable-no-endpoint"
	// CountryAdminOverride: neither observed nor claimed (issue #113, ADR-0042 §8
	// update 2026-08-03). A coordinator ADMINISTRATOR asserted this country for this
	// node id out of band, and the assertion replaced whatever the coordinator derived.
	//
	// It exists as its own value because an admin correction is a third kind of thing
	// and folding it into either neighbour would misreport it: calling it observed
	// would claim a resolution that did not happen, and calling it a hint would credit
	// the NODE with a statement the node did not make.
	//
	// What it is FOR is correcting the derivation — "your table is wrong, this address
	// really does present as DE", an assertion about the ADDRESS that an admin can
	// check against what real sites say and the coordinator cannot. What it must never
	// be used for is promoting [Entry.DeclaredCountry] — "the machine is physically in
	// DE even though its address resolves US" — which is the same misrouting ADR-0042
	// §8 exists to prevent, arriving from the operator's side instead of the node's.
	// The two are indistinguishable on the wire, so the guarantee here is narrower than
	// for an observed tag and is stated where the admin edits rather than only here.
	CountryAdminOverride = "admin-override"
)

// CountryContradicted reports whether the coordinator itself observed this entry's
// country to disagree with where the node says it serves traffic from — the exit that
// signals through a host in one country and egresses in another.
//
// It is the fail-closed test for choosing a JURISDICTION out of this directory, and it
// is deliberately narrower than "not verified". Refusing everything unverified would
// refuse [CountryHinted], which is every entry in a deployment with no geo database
// staged — the default, and today's fleet — so a client would stop being able to chain
// at all against a coordinator that is behaving exactly as it always has. What this
// names instead is the case where the coordinator holds two facts that do not agree and
// published both: a country tag that describes a machine other than the one the traffic
// leaves from. A user who asked to egress in one jurisdiction and was given that is not
// under-informed, they are misrouted.
//
// An empty CountrySource is NOT contradicted: it means the coordinator predates the
// field, which is the pre-#3 status quo rather than a discovered disagreement.
//
// # DeclaredCountry is NOT this, and must never be folded into it (issue #113)
//
// The disagreement this names is between two things the coordinator OBSERVED — the
// address the signaling arrived from and the data-plane endpoint the node advertises —
// and it is an anomaly precisely because both are checkable and they do not match.
// [Entry.DeclaredCountry] disagreeing with Country is a different animal: a node CLAIM
// disagreeing with an observation, which #113 measured as the ordinary case rather than
// an anomaly. A large cloud provider's address block is commonly registered to that
// provider's home country whatever datacentre the instance runs in, so on a real fleet
// two exits in three disagreed.
//
// Feeding that into this predicate would therefore fail closed on most of a cloud fleet
// and stop a client chaining at all against a coordinator behaving exactly as it always
// has — the same failure the paragraph above rejects for [CountryHinted], one step
// further out. Use [Entry.DeclaredCountryDiffers] to observe the difference; it is
// deliberately not a refusal.
//
// Note the asymmetry with -geoip-required, and that it is intentional. Under that flag
// a contradicted exit carries no country at all and never reaches a country filter in
// the first place; this predicate is what protects the -geoip-WITHOUT-required
// deployment, where such an exit keeps its signaling-derived tag and is assignable.
func (e Entry) CountryContradicted() bool {
	return e.CountrySource == CountrySignalingOnly
}

// DeclaredCountryDiffers reports whether this node's own declaration ([DeclaredCountry])
// disagrees with the country the coordinator published for it (Country) — issue #113.
//
// **It is not an anomaly, not a refusal, and not a fail-closed test.** Read
// [Entry.CountryContradicted]'s doc before wiring the two together: the disagreement
// this reports is the expected steady state for a fleet on cloud address space, so
// gating selection on it would refuse most of that fleet. It exists so an operator- or
// admin-facing surface can LIST the disagreement — which today it cannot, because until
// #113 the second answer was computed and dropped, and nothing downstream could tell
// there had ever been one.
//
// Both values must be present for there to be a disagreement at all. A node that
// declared nothing has not disagreed with anything, and an entry with no Country has
// published nothing to disagree WITH — that case is already named by CountrySource
// (unresolved, or one of the -geoip-required refusals) and reporting it here as well
// would blur a missing country into a disputed one.
//
// Note what it compares: the PUBLISHED country, not the derived one. Where an admin
// override is in force (CountryAdminOverride) this reports the node's declaration
// against the admin's correction, which is the comparison that matters — the admin's
// value is the one clients act on.
func (e Entry) DeclaredCountryDiffers() bool {
	return e.DeclaredCountry != "" && e.Country != "" && e.DeclaredCountry != e.Country
}

// RelayEligible reports whether this entry can serve as an intermediate hop in a
// client-assembled relay chain (issue #76): a relay that advertises a forwarding
// Ingress. It is the directory-side field-level gate the #124 acceptance names —
// "a node advertising no ingress is simply not relay-eligible." Hop SELECTION among
// eligible entries (operator/AS diversity, ordering, and the telescoping dial itself)
// is §2/§4 and lives in the client; this predicate does none of that, it only reports
// whether the wire record carries the ingress a selector would need.
func (e Entry) RelayEligible() bool {
	return e.Role == "relay" && e.Ingress != ""
}

// Snapshot is the directory bundle a client bootstraps with: a few entry
// points and a validity window. It carries no secret — the per-user secret
// is a separate credential (see secret.go) delivered out of band and used
// only to authenticate the fetch, never embedded in the snapshot itself, so
// snapshots can be freely re-shared by a mesh-walk courier (issue #31) or the
// coordinator pool (issue #6) without leaking anyone's credential.
type Snapshot struct {
	Version   int       `json:"version"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Entries   []Entry   `json:"entries"`
}

const SnapshotVersion = 1

var (
	ErrSnapshotExpired   = errors.New("coldstart: snapshot expired")
	ErrBadSignature      = errors.New("coldstart: snapshot signature invalid")
	ErrMalformedSnapshot = errors.New("coldstart: malformed snapshot")
)

// signedLen is the fixed ed25519 signature size; Sign/Verify split on it
// rather than a length prefix since every signature is exactly this long.
const signedLen = ed25519.SignatureSize

// Sign encodes snap as canonical JSON and appends an ed25519 signature over
// those bytes, producing the wire form carried in the SNAPSHOT attribute
// (and cached to disk as-is by [SaveCache]).
func Sign(priv ed25519.PrivateKey, snap Snapshot) ([]byte, error) {
	body, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("coldstart: marshal snapshot: %w", err)
	}
	sig := ed25519.Sign(priv, body)
	return append(body, sig...), nil
}

// Verify checks signed against pub and, if valid and unexpired, returns the
// decoded Snapshot. It does not check ExpiresAt against a caller-supplied
// clock beyond time.Now — callers that need a fixed clock (tests) should
// unmarshal separately.
func Verify(pub ed25519.PublicKey, signed []byte) (Snapshot, error) {
	snap, err := VerifySigned(pub, signed)
	if err != nil {
		return Snapshot{}, err
	}
	if time.Now().After(snap.ExpiresAt) {
		return Snapshot{}, ErrSnapshotExpired
	}
	return snap, nil
}

// VerifySigned checks signed against pub and returns the decoded Snapshot
// WITHOUT enforcing ExpiresAt. Verify is the normal entry point — a client
// adopting a directory wants a live one. This variant exists for the mesh-walk
// courier's proof-of-prior-contact check (issue #31, design §4.3): a recovering
// client presents a previously-received snapshot to prove it has met the network
// before, and that proof is legitimately stale — the whole reason recovery is
// running is that time has passed and coordinators have moved. What must still
// hold is that the coordinator once signed it (an attacker can't mint a proof),
// so this keeps the signature check and drops only the freshness check.
func VerifySigned(pub ed25519.PublicKey, signed []byte) (Snapshot, error) {
	if len(signed) <= signedLen {
		return Snapshot{}, ErrMalformedSnapshot
	}
	body := signed[:len(signed)-signedLen]
	sig := signed[len(signed)-signedLen:]
	if !ed25519.Verify(pub, body, sig) {
		return Snapshot{}, ErrBadSignature
	}
	var snap Snapshot
	if err := json.Unmarshal(body, &snap); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrMalformedSnapshot, err)
	}
	return snap, nil
}

// AddrsForRole returns the addresses of every entry with the given role, in
// snapshot order. Mesh-walk recovery (issue #31) uses it two ways: "coordinator"
// to find fresh rendezvous points to reconnect through, and "relay"/"exit" to
// find peer couriers to ask when the coordinators are unreachable.
func (s Snapshot) AddrsForRole(role string) []string {
	var out []string
	for _, e := range s.Entries {
		if e.Role == role && e.Addr != "" {
			out = append(out, e.Addr)
		}
	}
	return out
}
