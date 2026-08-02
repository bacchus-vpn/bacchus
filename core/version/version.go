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
	"log"
	"strconv"
	"strings"
	"sync"
)

// current is this build's release version as a bare "MAJOR.MINOR.PATCH" string.
// It is a var, not a const, so a build stamps the real number in at link time —
//
//	go build -ldflags "-X github.com/bacchus-vpn/bacchus/core/version.current=$(cat VERSION)"
//
// — without editing source. The number comes from the VERSION file at the root
// of this repository, which is the single source of truth every build path reads
// (issue #128): deploy/install.sh, the builds documented in docs/RUNNING.md, and
// CI. A file rather than `git describe --tags` because a file still works from a
// source tarball with no git history, is deterministic (ADR-0052 §5 wants the
// fleet binaries byte-identical), and makes a release bump one reviewable line.
// CI asserts that a tagged build's tag is v + this file, so the two cannot drift.
//
// It is EMPTY in source, and the emptiness is the mechanism rather than an
// oversight: it is the one value no build can be stamped WITH, so it is what
// tells a binary that nothing stamped it. Until #128 the default was the
// then-current release, which cannot separate those two cases — a build stamped
// 0.1.0 and a build stamped by nobody are the same bytes — and since nothing
// stamped anything, every binary this repository had ever produced reported
// 0.1.0 into a fence, an update check and a skew warning that were all comparing
// it against another 0.1.0.
//
// The line stays pre-1.0 while the protocol is still moving (ADR-0011: v1 scope
// is narrow); a 0.x line also means MINOR carries the breaking-change weight
// MAJOR will once we hit 1.0, which the client policy (ClientMustUpdate) must
// keep in mind.
var current = ""

// Stamped reports whether this build was told its release version at link time.
//
// An unstamped build is a development build — a bare `go build` — and it is
// perfectly usable; what it cannot do is state which release it is, so nothing
// that compares releases can say anything true about it. Callers that report a
// build identity can use this to say so; Current says it on its own (below).
func Stamped() bool { return current != "" }

// warnUnstamped fires the unstamped warning at most once per process. Once, not
// per call, because a node re-states its release on every register — 8,640 times
// a day — and a warning that scrolls is a warning nobody reads.
var warnUnstamped sync.Once

// Version is a parsed semantic release version. Only the three numeric
// components are modeled: the entire fence/force policy (ADR-0015) turns on
// MAJOR/MINOR/PATCH ordering, so pre-release or build metadata would be noise
// neither the node fence nor the client check ever consults.
type Version struct {
	Major, Minor, Patch int
}

// Current returns this build's release version.
//
// A stamped build returns what it was stamped with, and panics if that was
// malformed: a build that cannot state its own version has no safe conduct in a
// policy that fences on version, so failing loudly at startup beats
// mis-comparing a zero Version silently forever.
//
// The two build-time errors therefore have OPPOSITE failure modes, and that is
// deliberate rather than inherited. Unstamped is the default state of an
// ordinary `go build`: every developer produces one every day, and the binary is
// fully functional — it simply has no release to name, which 0.0.0 represents
// exactly. Malformed is not a state a build falls into; it takes someone passing
// a -X whose value is not a version, and there is nothing to fall back to,
// because the only alternative to failing is inventing a release for a fence
// (ADR-0015) that must never be handed one. "No answer" is representable; "an
// answer that is not a version" is not.
//
// That asymmetry is only defensible while a malformed stamp cannot reach a
// shipped binary, so three things reject one before it can be linked:
// deploy/install.sh validates VERSION and refuses to build (version_valid), the
// tests below parse that file on every push (TestVersionFileIsCanonical), and CI
// checks the shape of VERSION and of the tag on a tagged build.
//
// All three are front-loaded because NOTHING DOWNSTREAM WOULD CATCH IT. No CI
// job runs a coordinator or a node binary, and the two that do launch the GUI
// smoke-test it without connecting — clients/fyne reaches this function from
// connectAsync (appstate/controller.go), not from startup. A client stamped
// 1.0.0-rc1 therefore builds, installs, launches and sits there looking healthy,
// and panics the first time its user presses Connect. That is the worst shape
// this failure could have, and it is the reason the validation is at the front
// rather than anywhere later. The case worth
// naming outright is a release candidate, because `v1.0.0-rc1` is an entirely
// ordinary tag to want and this package cannot carry it: Version models three
// integers and nothing else, on purpose (see its doc comment), so a pre-release
// or build-metadata suffix is not a release this project has at any layer. If
// that is ever wanted, it is a change to the model here and to the policy
// predicates that order on it — not a tag someone can simply push.
//
// An UNSTAMPED build returns the zero version, 0.0.0, and warns once, loudly.
// It does not refuse: a development build must work and every bare `go build`
// makes one (issue #128). What it must not do is pass for a release build,
// which is exactly what returning a plausible number silently did — 0.0.0 is
// the honest answer to "which release are you" from a binary nobody told, it is
// visible in the coordinator's registration line as release=0.0.0, and it is
// below any enabled -min-serving-version floor, which is the correct posture
// for a build whose release cannot be established.
//
// The warning lives in this query rather than in an init(), on two grounds. A
// package whose own doc comment sells its weightlessness should not print from
// every process that merely links it — including every test binary in the
// repository, where the noise would train the reader to skip the one line that
// matters. And "the first time this binary is asked what it is" is startup in
// practice for everything that has a release to state: cmd/coordinator computes
// coordRelease while parsing its flags, and core.Engine.Start computes the
// release it registers with before the first register goes out.
func Current() Version {
	if !Stamped() {
		warnUnstamped.Do(func() { log.Print(unstampedWarning) })
		return Version{}
	}
	v, err := Parse(current)
	if err != nil {
		panic(malformedStampMessage(current, err))
	}
	return v
}

// malformedStampMessage is the panic text for a build stamped with something
// that is not a release. Split out so a test can read it, and written for the
// one person who can ever see it — whoever set the -X — because by the time it
// prints, the wrong value is already inside a linked binary and nothing about
// the process it came out of is visible from here.
func malformedStampMessage(stamp string, err error) string {
	return "version: this build was stamped with " + strconv.Quote(stamp) +
		", which is not a release version (" + err.Error() + "). The stamp comes from " +
		"-ldflags -X …core/version.current, which every build path sets from the " +
		"repository's VERSION file. Only a bare MAJOR.MINOR.PATCH is a release here: a " +
		"pre-release or build-metadata suffix (1.0.0-rc1, 1.0.0+build.7) is not one, and " +
		"neither is a leading v — the tag is v1.0.0, the file and the stamp are 1.0.0. " +
		"Fix VERSION, or the -X that went around it, and rebuild"
}

// unstampedWarning is what an unstamped binary says at startup. It is a
// constant so a test can pin it without reproducing the wording, and it names
// the three mechanisms that silently compare a constant when it fires, because
// the operator reading it is the one whose fence or skew warning is about to say
// nothing useful.
const unstampedWarning = "WARNING: this binary was not stamped with a release version, " +
	"so it reports 0.0.0 — no release — everywhere its release is compared: a coordinator's " +
	"-min-serving-version fence and the client's force-update check (both ADR-0015), and " +
	"the coordinator's warning about a node built from a different commit (issue #114). " +
	"It runs normally and is not refused; a development build must work. But every build path " +
	"that produces a shipped binary stamps the release from this repository's VERSION file — " +
	"deploy/install.sh, the builds documented in docs/RUNNING.md, and CI — so a binary printing " +
	"this line was produced by something that does not, normally a bare `go build` (issue #128)"

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
