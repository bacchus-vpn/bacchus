// Package version defines Bacchus's product *release* version (semantic
// MAJOR.MINOR.PATCH) and the two policy rules built on it: which node versions a
// coordinator will still assign work (fencing stale nodes), and when a client is
// too old to keep using the network (force on MAJOR, skip MINOR/PATCH).
//
// This release version is deliberately distinct from
// core/handshake.ProtocolVersion. That is the wire *shape* peers must agree on
// before any role logic (ADR-0016); this is the product release the update
// policy turns on (ADR-0015). A release can ship many times without the wire
// shape changing, and a wire-breaking change is exactly a MAJOR bump here —
// keeping the two on separate axes lets each move without dragging the other.
//
// Like core/handshake and core/coldstart, this package has no dependency on the
// rest of core (or the WebRTC/transport stack), so the small coordinator binary
// can import it for the min-serving-version gate without that weight.
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// current is this build's release version as a bare "MAJOR.MINOR.PATCH" string.
// It is a var, not a const, so a release build can stamp the real number in at
// link time —
//
//	go build -ldflags "-X github.com/bacchus-vpn/bacchus/core/version.current=1.4.2"
//
// — without editing source. It stays pre-1.0 while the protocol is still moving
// (ADR-0011: v1 scope is narrow); a 0.x line also means MINOR carries the
// breaking-change weight MAJOR will once we hit 1.0, which the client policy
// (ClientMustUpdate) must keep in mind.
var current = "0.1.0"

// Version is a parsed semantic release version. Only the three numeric
// components are modeled: the entire fence/force policy (ADR-0015) turns on
// MAJOR/MINOR/PATCH ordering, so pre-release or build metadata would be noise
// neither the node fence nor the client check ever consults.
type Version struct {
	Major, Minor, Patch int
}

// Current returns this build's release version. It panics if current was
// stamped with a malformed value: a build that cannot state its own version has
// no safe conduct in a policy that fences on version, so failing loudly at
// startup beats mis-comparing a zero Version silently forever.
func Current() Version {
	v, err := Parse(current)
	if err != nil {
		panic("version: malformed build version " + strconv.Quote(current) + ": " + err.Error())
	}
	return v
}

// Parse reads a canonical "MAJOR.MINOR.PATCH" string. All three components are
// required and must be non-negative integers; anything else is an error, never
// a best-effort guess — a garbled version arriving on the wire from a peer must
// be rejected outright, not coerced into some neighbouring version that then
// silently passes or fails the fence.
func Parse(s string) (Version, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version: %q is not MAJOR.MINOR.PATCH", s)
	}
	var out Version
	for i, dst := range []*int{&out.Major, &out.Minor, &out.Patch} {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("version: %q has an invalid component %q", s, parts[i])
		}
		*dst = n
	}
	return out, nil
}

// String renders the canonical "MAJOR.MINOR.PATCH" form; it round-trips Parse.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare orders two versions: -1 if v is older than o, 0 if equal, +1 if v is
// newer. MAJOR dominates MINOR dominates PATCH — the ordinary semver precedence
// the policy predicates below are written in terms of.
func (v Version) Compare(o Version) int {
	for _, d := range []int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		switch {
		case d < 0:
			return -1
		case d > 0:
			return 1
		}
	}
	return 0
}

// ServingAllowed reports whether a node running version node may still be
// assigned work by a coordinator enforcing minimum serving version floor. This
// is the node fence from ADR-0015: after a release, an operator raises floor to
// the new version once the grace window elapses, and every node below floor is
// dropped from matchmaking until it updates. The coordinator — which already
// gates matchmaking — is the enforcement point, because a stale or hostile node
// cannot be trusted to fence itself.
//
// A node serves iff it is not strictly older than floor: a node exactly AT floor
// keeps serving (floor is the oldest *acceptable* release, not the first
// rejected), and a NEWER node serves too (operators raise the floor behind
// releases, they never ceiling the fleet). Only a strictly-older node is fenced.
func ServingAllowed(node, floor Version) bool {
	return node.Compare(floor) >= 0
}

// ClientMustUpdate reports whether a client running version client must
// force-update before it can keep using a network whose current version is
// network. This is the client half of ADR-0015: a client may SKIP MINOR/PATCH
// releases and keep working (UX slack — we do not nag users onto every point
// release), but a MAJOR bump is a hard cutoff, because a MAJOR is by definition
// a wire/protocol-breaking change and an older-major client can no longer speak
// to the fleet at all.
//
// Only a MAJOR gap forces an update; a client behind on MINOR/PATCH keeps
// working. A client whose MAJOR is NEWER than the network's (a canary build, or
// one that updated before the coordinator it reached) is not "too old" — we
// never force a downgrade, so that case does not trigger an update.
func ClientMustUpdate(client, network Version) bool {
	return client.Major < network.Major
}
