// Package revocation verifies the two signed revocation bundles a coordinator
// fetches from the untrusted hop past bacchus-payment's revocation-sync (issue
// #199, ADR-0017, ADR-0063) — the `bacchus/revocations/v1` object.
//
// # Why this exists
//
// -device-revocations and -admission-revocations already let a coordinator
// hot-reload a plain revoked-serials FILE, trusted because the coordinator reads
// its own disk. ADR-0017 (bacchus-payment) rules the hop that CARRIES those
// bytes from the account-service host to that disk untrusted, and signs the two
// lists under the offline root instead — the exact shape core/policy already
// runs in production for a different artifact (ADR-0043). This package is the
// bacchus-side verifier for that shape, mirroring core/policy's split from
// core/delegation for the identical reason: this package signs and opens the
// BYTES, core/delegation owns the domain tag and the signing framing.
//
// # What this package is not
//
// It does not fetch or install anything into a coordinator's live state — that
// is cmd/coordinator/revocations.go's job, mirroring how core/policy does not
// fetch or apply either. Verify turns a Bundle into a Doc or an error, and Cache
// persists what an enforcer must not forget across a restart.
//
// The signer, the schema's authoring half, and the reference verifier live in
// bacchus-payment (internal/revocation), a private repository this module
// cannot import, so the wire format is the contract and the frozen fixtures in
// testdata — copied verbatim from there — are what keep the two implementations
// agreeing. See vectors_test.go.
//
// # Rollback, not a plain-file replacement
//
// A revocation document carries AsOf instead of a Seq: the direct analogue of
// policy.Policy.Seq, and for the identical reason — an untrusted hop can replay
// an OLD, validly-signed bundle from before some serial was revoked, and every
// check except this one accepts it. What a revocation document deliberately
// does NOT carry, unlike a policy document, is an activation window
// (Issued/Expires/Grace): a coordinator wants the freshest list it can verify,
// full stop, and inventing an expiry here would be a second staleness mechanism
// sitting on top of the one bacchus-payment's revocation-sync already has. See
// ADR-0017 decision 2 for the reasoning this package inherits rather than
// re-derives.
//
// # Two namespaces, one root
//
// Two Bundles exist per fetch cycle, one per namespace (device, admission), both
// signed by the SAME operational key under the SAME delegation cert — ADR-0017
// decision 2's ceremony mints one role, not two. A single Verifier therefore
// serves both; what differs per namespace is the rollback floor passed to
// Verify and the Cache it is persisted in. See cmd/coordinator/revocations.go.
package revocation
