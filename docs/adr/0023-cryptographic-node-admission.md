# 23. Cryptographic node and client admission

- Status: accepted
- Date: 2026-07-03

## Context

Nothing in the wire protocol stops an unauthorized party from joining the
network. Anyone who can reach the coordinator and speak the protocol can
`register` as a relay/exit — and then see traffic routed through them — or
`connect` as a client and enumerate the network. Both are squarely in the threat
model (`docs/threat-model.md`): the **malicious node operator** ("anyone can run
a relay or exit node, including the censor itself") and the censor who can "pose
as an ordinary user to enumerate the network."

This is an **authentication** problem, not a licensing one. The AGPL decision
(ADR-0019, issue #47) governs the source; it does nothing to stop a fork from
pointing at and joining our live network. Membership has to be enforced in
cryptography, independent of the license, which is what issue #42 scopes.

We already have the pieces to build on: an operator signing authority is assumed
by the forced-update channel (ADR-0015, "the update/release channel is signed"),
the coordinator is already the single matchmaking chokepoint and policy point
(ADR-0015), and `core/coldstart` already established the house signature
envelope (canonical JSON + a fixed-length ed25519 signature) and the
out-of-band, per-recipient credential-distribution model (the invite).

## Decision

An **admission credential** is a statement — `{serial, subject, roles, window}`
— signed by the operator's admission authority (an ed25519 root key, the same
kind of operator trust root ADR-0015 describes). It is verified at the one place
that already gates matchmaking: the coordinator.

- **New leaf package `core/admission`**, standard-library-only like
  `core/coldstart` and `core/handshake`, so the small dependency-light
  coordinator binary imports it directly instead of duplicating a verifier. Its
  `Sign`/`parse` mirror `coldstart.Sign`/`Verify` byte-for-byte.
- **Node admission** — a relay/exit's `register` must carry a credential whose
  `subject` equals the node id it is registering, and whose roles include the
  role it is taking. The subject binding is what stops a valid-but-leaked node
  credential from being replayed under a different id (an exit's id *is* its
  X25519 public key, ADR-0009, so the binding is cryptographically meaningful).
  A rejected node is never added to the directory, so it is never advertised to
  clients.
- **Client admission** — `list` and `connect` must carry a credential with the
  `client` role. It is **bearer**: a client has no coordinator-known stable id on
  the signaling channel, so there is nothing to bind to, exactly as the coldstart
  per-user secret is bearer. Its protection is the out-of-band channel it is
  delivered over.
- **Enforcement is on when the trust anchor is configured.** With
  `-admission-pubkey` set the coordinator rejects anything unsigned/invalid; with
  it unset the network is open (pre-#42 behavior) and the coordinator logs a
  loud startup warning. This makes rollout staged — an operator issues
  credentials, then turns enforcement on — rather than a flag day.
- **Revocation** is a serial list the coordinator hot-reloads (like the bootstrap
  secrets file); a malformed file keeps the last-known-good list (fail-safe,
  never silently un-revokes). `cmd/admission-issue` is the operator tool that
  holds the root key, mints credentials, and appends revocations.
- **Rejection reuses the `reject`/`Reason` pair** (ADR-0016). A node's
  register loop re-announces every 10s, so an expired or revoked node is fenced
  within one interval — the same "fence stale nodes" property ADR-0015 wanted,
  now keyed on credential validity, not just version.

## Consequences

- Enforces network membership in cryptography regardless of the license: a
  hostile exit cannot be advertised, network enumeration is gated, and a fork
  cannot join the live network without a credential we signed.
- Builds on existing, already-reviewed machinery (the coldstart envelope, the
  coordinator chokepoint, the ADR-0015 trust root, the ADR-0016 reject path), so
  the blast radius is small and the feature is off by default for every existing
  caller and test (`Config.AdmissionCred` empty, `-admission-pubkey` unset).
- The admission root becomes a high-value key, on par with the update-channel
  signing key — it demands the same key-management discipline (kept offline on
  the issuing machine, never on a serving node).
- **Client credentials are bearer.** A shared or leaked client credential admits
  whoever holds it until it expires or is revoked. Node credentials are
  subject-bound and therefore stronger. Per-device client identity (binding a
  client credential to a key the client proves possession of) is a future
  hardening.
- **Open-by-default is not fail-closed.** Until an operator configures the
  anchor, the network serves anyone; the loud warning is the mitigation. Making
  admission mandatory is a deliberate later step, once the fleet is credentialed.
- **Coordinator-enforced only (v1).** A client does not yet independently verify
  the exit's node credential during the Noise_NK handshake (ADR-0009) — the
  coordinator gates which exits are advertised, but end-to-end verification would
  be defense in depth against a compromised coordinator. Follow-up (#60).
  Likewise, an admission `reject` on `list`/`connect` is surfaced as a logged
  client event but does not yet fast-fail the client's connect result — an
  ergonomic follow-up.
- Deliberately separate from payments/accounting (ADR-0021): admission decides
  *who may participate*; accounting measures *what was delivered*.

See `docs/design/node-admission.md` for the wire format, the verification-order
reasoning, the subject-binding analysis, and the operator workflow.
