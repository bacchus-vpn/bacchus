package coldstart

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Entry is one directory record in a Snapshot: an entry point a client can
// try, or the coordinator itself.
type Entry struct {
	Role    string `json:"role"` // "coordinator" | "relay" | "exit"
	ID      string `json:"id"`
	Country string `json:"country,omitempty"`
	Addr    string `json:"addr"` // host:port

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
