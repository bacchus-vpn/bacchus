# 26. End-to-end exit admission verification

- Status: accepted
- Date: 2026-07-04

## Context

Node admission (ADR-0023, issue #42) is enforced at **one** place: the
coordinator. An honest coordinator refuses to advertise an exit that lacks a
valid admission credential. But the client still trusts the coordinator's exit
list — it picks an exit id from `list`/the snapshot and completes the Noise_NK
handshake (ADR-0009) against whoever holds that id's key. Noise_NK proves *"this
peer is the id you asked for"*; it does **not** prove *"this id is an
admission-authorized exit."* Those are different claims.

That gap is squarely in the threat model (`docs/threat-model.md`), which lets the
censor "run its own nodes (relay/exit/**coordinator** peers)." With the
coordinator pool (ADR-0020, issue #6) a client already rotates across several
coordinators, any one of which could be hostile. A hostile coordinator can
advertise a hostile exit whose id it legitimately controls; the client completes
Noise_NK successfully and routes traffic through it. Coordinator-side admission
does nothing here — the coordinator *is* the adversary. ADR-0023 itself flagged
this as the #60 follow-up.

## Decision

The exit presents its admission credential inside the Noise_NK exchange, and the
client verifies it **end-to-end** against the admission root.

- **Carry the credential in msg2's Noise payload.** In NK, msg2's payload is
  AEAD-sealed under a key that already mixes the exit's static key (`es`+`ee`),
  and the AEAD's associated data commits to the same key. So the credential is
  confidential, tamper-proof against a relay in the path, and cryptographically
  bound to the very key the handshake authenticates. This reuses the preamble
  ADR-0021 already extended for accounting; no extra round trip, no coordinator
  protocol change.
- **The client's check** (`verifyExitCredential`): the credential must be signed
  by the admission root, name the exit's authenticated static pubkey as its
  `subject` (the binding that makes it non-transferable — a hostile exit cannot
  replay another exit's credential), authorize the `exit` role, and be within its
  validity window. Any failure **aborts the session before the target is sent**,
  surfaced as a clear client event.
- **The anchor reaches the client two ways (both).** The admission root public
  key is carried in the coldstart invite — a new **v2 invite** appends it beside
  the snapshot-signing key, so a client bootstrapped purely from an invite is
  protected with no extra step — and can also be set directly
  (`-admission-pubkey` / `Config.AdmissionPubKey`), which **overrides** the
  invite for self-hosters, testing, and ops. The version byte doubles as the
  presence flag (v1 = no anchor, v2 = anchor), so there is never an ambiguous
  all-zero key on the wire.
- **Fail-open when the client has no anchor**, matching ADR-0023's coordinator
  behavior when `-admission-pubkey` is unset; a *malformed* anchor is a
  construction error (fail-loud). v1 verifies offline — signature, subject, role,
  window — with no revocation oracle, leaning on short-lived exit credentials.
- **Direct and relay mode both**, unchanged: Noise_NK is end-to-end in both, so a
  relay simply forwards the payload-bearing handshake it already can't read.

## Consequences

- **Defense in depth.** ADR-0023 makes an *honest* coordinator reject hostile
  exits; this makes a *client* reject them even via a *dishonest* coordinator.
  Together they close the same-id-replay / directory-hijack gap ADR-0023 accepted,
  now from the client side too.
- **Backward compatible.** An exit with no credential presents an empty payload;
  an old client ignores the payload; a client with no anchor requires none. The
  only newly-rejecting combination is *client-with-anchor × exit-without-valid-
  credential* — exactly the intended enforcement. Rollout stays staged like
  ADR-0023: credential the exits, then distribute client anchors (bake them into
  new invites, or set the flag).
- **No coordinator-protocol/capability change** (ADR-0016): the credential rides
  the end-to-end Noise channel and is negotiated implicitly by the fail-open
  default. Accounting streams (ADR-0021) verify too — each is a fresh Noise_NK to
  the same exit.
- **No live client-side revocation in v1.** An offline client can't see the
  coordinator's hot-reloaded revocation list; short-lived exit credentials bound
  the exposure. Signed short-TTL revocation bundles carried in the snapshot are
  the staged follow-up.

  > **Update (2026-07-05):** closed by issue #69. The follow-up shipped as a
  > signed CRL (`core/admission.CRL`, `SignCRL`/`ParseCRL`/`VerifyCRL`) — the
  > same "canonical JSON + trailing ed25519 signature" envelope as a
  > Credential, verified against the same admission root the client already
  > holds, so it is trustworthy independent of whatever relayed it, exactly
  > like the credential itself. `buildExitVerifier` (`core/exit_admission.go`)
  > now wires a real `revoked` predicate into the `admission.Verifier` instead
  > of the permanent nil oracle, so `Verifier.accept`'s existing
  > revocation-first check (see `docs/design/node-admission.md`) actually has
  > something to consult.
  >
  > It travels alongside the anchor over the invite, not the snapshot as
  > speculated above: a new v3 `coldstart.Invite` appends a length-prefixed,
  > opaque CRL blob right after the admission key (v1 = neither, v2 = anchor
  > only, v3 = anchor + CRL — a CRL is unverifiable without the anchor, so
  > `EncodeInvite` rejects one without the other). `cmd/admission-issue -crl`
  > signs the operator's current revocation file as a short-TTL bundle (24h
  > default); `cmd/coldstart-issue -admission-crl <path>` embeds it;
  > `cmd/coldstart-bootstrap -crl-out <path>` extracts it back out for a
  > client to consume; `bacchus-node -admission-crl <path>` sets or overrides
  > it directly, mirroring `-admission-pubkey` exactly. A bundle that fails to
  > parse, fails signature verification, or has already expired is a
  > construction error, not a silent reversion to "nothing is revoked" — the
  > same fail-loud posture as a malformed anchor; a CRL configured without an
  > anchor is likewise an error, since there is no key to check it against.
  > Configuring neither remains unchanged fail-open.
  >
  > This is still not a *live* channel: like `AdmissionPubKey` before it, a
  > client loads its CRL once at construction and does not hot-reload it
  > mid-run, so a long-lived process can run past a bundle's TTL without
  > noticing. Bounded by the same short-lived-exit-credential backstop v1
  > already leaned on; an actual hot-refresh loop (mirroring the coordinator's
  > own `reloadRevocationsLoop`) is a candidate follow-up if that gap matters
  > in practice.

  > **Update (2026-07-11):** the hot-refresh follow-up shipped as issue #90,
  > and a related hardening gap closed as issue #91.
  >
  > **#90 — hot-reload.** `-admission-crl <path>` / `Config.AdmissionCRLPath`
  > (a new field alongside the existing inline `Config.AdmissionCRL`; at most
  > one of the two may be set) is loaded once synchronously at construction —
  > exactly as fail-loud as inline `AdmissionCRL` always was — and then
  > re-read every **5 minutes** by `Engine.reloadCRLLoop`
  > (`core/exit_admission.go`), the client-side mirror of
  > `cmd/coordinator/admission.go`'s `reloadRevocationsLoop`. Five minutes was
  > chosen only to stay comfortably under `cmd/admission-issue -crl-ttl`'s 24h
  > default — frequent enough that an operator's emergency revocation
  > propagates promptly, without polling the filesystem needlessly often; it
  > is a field (`Engine.crlReloadInterval`), not a constant, so nothing stops
  > a future release from making it configurable if that ever matters. A
  > reload that fails to read, parse, or verify the file — including finding
  > it has itself expired — is logged as a non-fatal event and the previously
  > loaded bundle keeps being enforced unchanged: the same fail-safe,
  > keep-serving-the-last-known-good-bundle posture the coordinator's own
  > loop already has, chosen over both silently reverting to fail-open (which
  > would defeat the whole point of a revocation check) and tearing down an
  > otherwise-healthy connection over what is often a transient operator
  > mid-write. `Config.AdmissionCRL` (inline content, no path to re-read)
  > remains load-once by design — it exists for a caller that already holds
  > the bytes rather than a file path, and reload only makes sense once
  > there's somewhere to reload *from*.
  >
  > Relatedly, `cmd/coldstart-issue -admission-crl` sanity-checked an embedded
  > bundle with `ParseCRL` (signature + anchor) but not `VerifyCRL` (+
  > expiry), so it could silently mint a v3 invite carrying an
  > already-expired CRL. It now uses `VerifyCRL`, so that mistake is a mint-
  > time `log.Fatalf` an operator can't miss, instead of a client that
  > silently never enforces revocation until someone notices.
  >
  > **#91 — opt-in require-CRL.** `-require-crl` / `Config.AdmissionRequireCRL`
  > (opt-in, **default false — no change to existing behavior**) turns
  > "anchor configured, no CRL of either kind" from the fail-open-on-revocation
  > this ADR always accepted into a construction error instead. It exists for
  > an operator who wants a hostile or buggy coordinator that delivers a v3
  > invite's anchor while stripping its CRL to be a hard failure the client
  > refuses to start with, rather than a silent, unsignaled reversion to "not
  > checking revocation." `-require-crl` with no anchor configured at all is
  > likewise a construction error (there is nothing for it to enforce), not a
  > quiet no-op an operator could mistake for protection. Configuring neither
  > `-require-crl` nor a CRL remains unchanged fail-open, exactly as every
  > revision of this ADR has accepted.
- **The admission root is now distributed to clients.** It is a public key, so
  distribution is not secret — but the channel that carries it (the invite) is
  the trust anchor, exactly as it already is for the coordinator address and the
  snapshot-signing key (ADR-0013, issue #18). An adversary who could forge an
  invite end-to-end could substitute their own root; that is the pre-existing
  out-of-band-channel assumption, not new exposure.

See `docs/design/node-admission.md` for the client-verification details and the
invite v2 format, and `docs/threat-model.md` for the hostile-coordinator case
this closes.

## Amendment (issue #29, 2026-07-28): the subject binding is now unforgettable, not merely present

This record states the check as `subject == hex(exitPub)`, and that binding is the whole
of what makes a credential non-transferable — Noise_NK proves *this peer holds the id you
dialed*, the credential proves *the root authorized that id*, and only the binding joins
the two. Without it a client verifies that some exit somewhere was authorized, which is
not a statement about the exit it is talking to.

**What #29 reported, and what was actually found.** The issue describes
`Engine.exitVerifyFunc` closing over an `e.exitPub` engine field that `connectPooled`
never sets, so the pooled path reached the verifier with an empty subject. That field no
longer exists: country-only assignment (#146, ADR-0042) made the exit key **per-path**
rather than engine state, precisely because the coordinator may assign a different exit on
any reconnect, and `exitVerifyFunc` took the key as a parameter in the same change. The
reported defect was therefore already closed, as a side effect rather than deliberately.
Verified rather than assumed: the test this issue asks for — a pooled client with an
anchor must reject an exit presenting a valid credential issued to a **different** exit —
passes with no code change.

What was missing is what the issue also says: **no test covered pooled + anchor
together**, so nothing would have caught it coming back. That barrier now exists, and a
mutation restoring the engine-state shape reproduces the original bug exactly — exit A
presenting exit B's valid credential is accepted.

**Two structural gaps were still live, and both are closed here**, because "already
fixed" and "cannot come back" are different properties:

- **An empty exit key is no longer a bearer credential.** `hex.EncodeToString(nil)` is
  `""`, and `admission.accept` reads an empty subject as bearer and skips the binding.
  That default is correct where it comes from — a client has no coordinator-known id, so
  its own credential genuinely is bearer — and it is exactly wrong on this path, in a way
  no caller can see: a path that fails to thread the key through does not get an error, it
  gets a check that silently passes. Reaching `verifyExitCredential` means a static key
  was just authenticated, so an empty one is a plumbing bug rather than a state the
  protocol produces, and it is now refused. That is the difference between fixing the
  instance and closing the class: the next path that forgets fails closed and loudly.
- **The pooled SOCKS accept loop now checks the key, not just the session.** The
  single-transport loop has always tested both (`sess == nil || len(exitPub) == 0`); the
  pooled one tested only the session. Nothing can currently produce a session without a
  key — `setActivePath` writes both from one `dialedPath` — which is the point: that
  invariant was held by every writer remembering, and the reader now does not depend on
  it. One path holding a guard the other does not is the exact shape #29 describes.

The residual is unchanged and worth restating: this check is **fail-open when
unconfigured**. A client with no `AdmissionPubKey` verifies nothing and accepts any exit
it can complete Noise_NK with, matching the coordinator's own behaviour with
`-admission-pubkey` unset (#42). Nothing here narrows that; what it fixes is a client
that *did* configure an anchor getting less than it asked for.
