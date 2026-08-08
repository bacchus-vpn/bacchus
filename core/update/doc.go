// Package update verifies and applies signed releases — the
// `bacchus/update-manifest/v1` object and the apply sequence beneath it.
//
// # The property this exists to create
//
// A fleet can be patched, and NOTHING that carries the bytes is trusted with what
// they are. ADR-0015 called the release channel "the highest-value attack surface
// in the system"; ADR-0052 designed it; this package is its build half (issue #34,
// ADR-0065).
//
// Two rules do all the work, and both are ADR-0052's:
//
//   - THE MANIFEST NAMES HASHES AND NEVER LOCATIONS. A URL inside a signed manifest
//     would make the fetch path part of the trust object and hand whoever serves
//     that path a lever over a fleet that had cryptographically committed to asking
//     it. A hash is a name any source can satisfy and none can own. Everything
//     else — that a coordinator can announce but not substitute, that a mirror needs
//     no trust, that a USB stick is as good as a CDN — falls out of it.
//   - NOTHING UNVERIFIED IS EVER REACHABLE BY THE NAME A SUPERVISOR EXECUTES. The
//     artifact is downloaded to a staging file beside the target, hashed COMPLETE,
//     and published by a single rename(2). A failed verification deletes the staging
//     file and touches nothing else. See Stage and Apply.
//
// # What is verified, and in what order
//
// Four tiers, each fully checked before the next is used (ADR-0052 §1):
//
//  1. the ROOT public key, the anchor this build carries;
//  2. the DELEGATION CERT, verified against the root with delegation.RoleUpdate
//     matched exactly, its window checked, its serial checked against revocation;
//  3. the MANIFEST SIGNATURE, by the key that cert delegates to;
//  4. the ARTIFACT HASH, over the complete downloaded bytes.
//
// Tiers 1–3 are Verifier.Verify; tier 4 is Stage. They are separate calls because
// they happen at different times against different bytes, and the split is what
// lets a caller decide whether to download at all.
//
// # What this package is not
//
// It does not decide WHERE bytes come from, and it does not poll. Source is an
// interface with two implementations here (a directory and an HTTP base URL) and
// nothing in this package prefers one; the whole point of content addressing is
// that the choice is not a trust decision. Who checks, when, and whether an apply
// is immediate or deferred to a boundary is the caller's — cmd/node polls because a
// node is infrastructure, clients/fyne is edge-triggered by an announcement it was
// already receiving and fetches only through its own tunnel. ADR-0065 §3 is why.
//
// The signer is cmd/release-sign and runs OFFLINE on an air-gapped machine
// (ADR-0052 §6). The key never sits on a coordinator, never on a build machine, and
// CI never holds it: a build machine that can sign is a build machine that can push
// code to every node. Sign lives here because verification and signing must agree
// byte for byte and a second implementation of the framing is the thing that drifts.
package update
