# 45. The coordinator verifies device credentials offline at connect, alongside admission rather than instead of it

- Status: accepted (issue #50)
- Date: 2026-07-29

## Context

R1's exit criterion reads: *"issue a free-grant credential, verify it offline at
connect against the anchored root, fetch+enforce a signed policy blob, promote a
test identity to stable via 3 vouches."* Three of those four shipped. Issuance,
the signed policy blob (#39, ADR-0043) and vouching all landed, and the account
service's R1 milestone reads zero open. **Verifying at connect is the
coordinator's job and no code in this repository performed it.**

The account service mints a two-tier chain: an offline root signs an issuer cert
delegating "may issue device credentials" to an issuer key, with a window and a
cap on what that key may mint; the issuer key signs a short-lived device
credential naming a device public key, an account generation and a window. A
device presents both plus an assertion proving it holds the credential's private
key.

The wire format is frozen, specified where the signer lives, and carries frozen
conformance vectors. This record does not restate it and does not design any part
of it. What it records is the set of decisions the **verifying** side has to make,
which the format deliberately leaves open.

Two things made this cheap now that were not cheap before. ADR-0043 landed
`core/delegation`, which already implements the `tag || 0x00 || body` framing,
offline root-anchored verification, revocation, validity windows and clock skew.
And `core/policy/verify.go` is a worked example of the same tier-by-tier descent,
including the ordering discipline. The device chain is the same shape with
different tags.

## Decision

### 1. This does not replace the admission gate. They coexist.

`core/admission` and `core/devicecred` answer different questions against
different trust anchors, and **both are asked on every connect**:

| | `core/admission` (#42, ADR-0023) | `core/devicecred` (this record) |
|---|---|---|
| Whose credential | the **network's** own membership | the **account service's** entitlement |
| Anchored to | the operator's admission key | an offline root the operator does not hold |
| Shape | one tier, bearer | two tiers, challenge-bound |
| Carries | client/relay/exit roles, the `Vouched` marker, a subject binding | a device key, an account generation, a window |
| Answers | "may this party be on the network at all?" | "does this device hold a live entitlement right now?" |

Neither can express the other's question. Admission cannot say "this device, this
account generation, until Tuesday" — it has no device binding and no issuer tier.
The chain cannot say "this node may serve as an exit" — it deliberately carries no
role, because every field in it is visible to a coordinator on every connect and
each one is a fingerprinting surface that has to be justified.

**Nothing is folded into the other and nothing is deleted.** A connect passes
admission first and the chain second. This is written down because the next lane
to touch either would otherwise have to guess, and the plausible guess — "these
are both credential checks, unify them" — would either give the operator's
admission key the power to mint entitlements or give the account service's root
the power to admit nodes. Those are different authorities on purpose.

### 2. The gate fails OPEN when unconfigured, and hard once configured

With `-device-root-pubkey` unset the gate is **disabled** and connects proceed on
admission alone. This is the same direction as `-admission-pubkey` and
`-min-serving-version`, and the **opposite** of `-policy-root-pubkey`, which
stops assigning new work once its policy goes stale (ADR-0043).

The direction follows from the same test ADR-0043 applied — **is the failure
sheddable?** — and lands the other way:

- A coordinator whose **policy** went stale sheds to its peers. Coordinators are a
  pool a client rotates away from (ADR-0020), and the peer it rotates to has a
  fresh policy, because staleness is a per-coordinator condition about one
  coordinator's fetch loop.
- An **unconfigured trust anchor is not a per-coordinator condition a client can
  rotate away from.** Every coordinator in the pool reads the same configuration
  posture during a rollout. Failing closed on it would darken every connect at
  every coordinator simultaneously, with nothing to shed to.

There is a second difference that matters more than the first. A stale policy is
an operator's **own signed expiry arriving** — someone authored that deadline and
chose its grace. An absent anchor is not a deadline; it is a feature that has not
been switched on. Treating "never configured" as "the operator's signed licence to
run has lapsed" reads an intent out of a zero value.

**What does not differ: once a root IS configured, a failed verification refuses
that connect outright.** There is no fallback, no soft mode, no cached admit and
no degraded path. The open direction covers *"not configured"*, never *"configured
and failing"*. Two guards keep the distinction from eroding:

- `devicecred.NewVerifier` fails **closed** on a missing or malformed root: it
  returns an error rather than a verifier that admits everything, so there is no
  way to hold an object named `Verifier` that verifies nothing.
- A malformed `-device-root-pubkey` is **fatal at startup**, not a fall-through to
  the disabled state. A coordinator told to enforce entitlement with an unusable
  anchor must not quietly serve everyone.

### 3. The anchor is configured as the root public key, and only ever that

`-device-root-pubkey` takes the **offline root's** public key in hex, exactly as
`-admission-pubkey` and `-policy-root-pubkey` do. The coordinator holds no issuer
key, contacts nothing, and caches no trust decision. The issuer cert arrives on the
wire from whoever is connecting and is verified against the root every time.

Revocation is a local file of serials, hot-reloaded, reusing the same machinery
admission uses (`-device-revocations`, separate from `-admission-revocations`
because the two authorities' serial namespaces are unrelated). Revocation latency
is the price of verifying offline, and it is bought back by short credential
lifetimes: the credential's own window, capped by the issuer cert's `max_cred_ttl`,
means "stop renewing" is most of revocation.

### 4. The audience is what the client already knows, not what the coordinator says

`-device-audience` defaults to `-advertise`: the address a client dialled to get
here, which it knows **independently** because it chose it.

This is load-bearing rather than a configuration nicety. Bacchus runs a pool of
coordinators, so if the audience were whatever the coordinator announced in its own
challenge reply, a hostile pool member would simply announce an honest
coordinator's audience, relay the challenge to a device, collect the signature, and
present the device's entire chain as its own — spending someone else's entitlement.
The binding only works while the client already knows who it meant to talk to.

An enabled gate with no audience to bind to is **fatal at startup** for the same
reason a malformed key is: it would verify perfectly well and bind nothing, which
is the failure mode that looks exactly like success.

### 5. The challenge is coordinator-chosen, single-use, and bounded

A device cannot prove possession without a nonce the verifier chose, so a client
asks for one (`challenge`) immediately before connecting. The nonce is 32 bytes,
lives two minutes, and is **consumed on use** — including on a failed attempt, so
a captured chain cannot be retried against a nonce still outstanding. Without
single use, a captured connect would be replayable at the same coordinator for the
nonce's whole lifetime, and the challenge would be bounding the damage rather than
preventing it.

"Single use" means **one request**, not one datagram, and the distinction is
load-bearing. `core`'s `sendN` puts three copies of every connect on the wire
against UDP loss. A gate that spent a challenge per *datagram* would answer one
request with one session and two rejects — so the challenge is bound to the
connect nonce (issue #1's per-request idempotency key), which identifies the
request rather than the datagram. Retransmissions of that request are answered; a
*different* request re-presenting a spent challenge is a replay and is refused.

For the same reason the gate runs **after** `replayMintedConnect`, not before it:
once a request has been answered, its later copies must replay that answer without
re-entering the gate at all. This was found by testing the gate against `sendN`'s
actual retransmission behaviour rather than against single datagrams.

A **failed** verification drops the challenge outright, so a rejected attempt
cannot be retried against a nonce that is still live.

`devicecred.MinChallenge` (16 bytes) is enforced on **both** sides: a verifier
refuses a weak challenge and a device refuses to sign one. The coordinator picks
the connect challenge and is not trusted to pick it well, so a device that signed
whatever short or fixed value it was handed would be issuing a reusable token.

The store is keyed on the source address and capped. UDP sources are **spoofable**,
so anything keyed on them is fillable by an attacker who never completes a
handshake. At capacity the coordinator **refuses to issue** rather than evicting a
live entry: evicting would let a spoofer knock honest clients out of the store,
turning a memory bound into a denial of service against exactly the traffic it
protects. Sweeping expired entries is rate-limited rather than per-request, so a
flood cannot make each spoofed packet pay for a scan of every other one.

### 6. Verification order is normative

Tier by tier, and the ordering is what makes it a chain rather than a set of
checks:

1. The **issuer cert against the anchored root** — signature, version, revocation,
   window — before anything inside it is trusted. Until the root's signature
   verifies, `ipub` is just bytes whoever connected supplied.
2. Only then is the issuer key usable to check the **device credential**.
3. Only then **decode**, so untrusted bytes never reach the decoder.
4. Then structure, then the **TTL cap**, then freshness, then the challenge-bound
   **assertion** against the credential's device key.

Within a tier, revocation precedes the window, so an explicitly revoked object
reports revoked even when it has also expired — the operator killed it, and that is
the more actionable reason.

The `max_cred_ttl` cap binds **at verification**, not only at issuance. An issuer
key in the wrong hands mints whatever it likes; the only party that can constrain
it is the offline root, through that field. Checking it only where credentials are
minted would put the constraint inside the thing being constrained.

**Every signature is checked over the bytes as received.** Nothing re-marshals a
body to verify it. Whoever presented the credential supplied every part of it, and
a verifier that re-marshaled would be checking a signature over bytes it invented
rather than bytes it was given. JSON field order, whitespace and escaping are
therefore deliberately not part of the wire contract.

### 7. A refusal stops the connect, and says why

`admitDevice` replies with a `reject` naming the reason and the handler returns
immediately: no session is minted, no exit is assigned, no idempotency record is
written. The gate sits after the ADR-0043 policy drain, so a coordinator that is
not assigning anything does not spend signature verifications on connects it would
refuse regardless.

Every `devicecred` error names a protocol fact only — never key material, never
anything account-scoped — so it is safe to log and safe to hand to a rejected peer.
The assertion failures deliberately do **not** distinguish a wrong key from a wrong
audience from a wrong challenge: a verifier that reported which part was wrong
would be an oracle for finding a part that is right.

On success the coordinator logs the credential serial and epoch and **not** the
device public key. That key is stable across renewals, so logging it would build
exactly the linkage the credential format works to avoid handing a coordinator.

## Consequences

- **R1's last exit criterion closes.** Offline connect-time verification exists,
  and the arrangement is no longer half-shipped.
- The gate is **off by default**. Turning it on is `-device-root-pubkey` plus an
  audience, and the startup log states which mode is active either way.
- **A client must be taught the exchange.** The coordinator half is complete and
  the wire fields are additive, so a client predating this connects exactly as it
  does today — but until the client sends a `challenge` and presents a chain, the
  gate can only be enabled on a network whose clients have been updated. That work
  is not in this change.
- **Residual linkability is unchanged and known.** The device public key is stable
  across renewals, so a coordinator can link one device's connects over time. This
  is the accepted stepping stone; closing it is a change to how the credential is
  signed, not to this protocol, and the connect exchange would not change.
- **Revocation is not immediate.** A revoked serial takes effect within one
  reload interval, and a credential revoked at the account service is only really
  dead when it expires. That is the cost of never calling that service, paid
  deliberately.
- **Two tags now verified here are declared outside `core/delegation`.**
  `bacchus/issuer-cert/v1` and `bacchus/device-cred/v1` live in `core/devicecred`,
  while that package's own doc asks that every tag this repository verifies be
  registered together, since domain separation is a property of the **set**. The
  cryptographic property is unaffected — what separates two domains is the tag
  string, not where the constant is declared — but the single-registry
  auditability is. Moving them is a two-line additive edit to
  `core/delegation/delegation.go`, deferred here only because that file is outside
  this change's boundary.

  > **Resolved by #54 — see the amendment below.** Both tags are now registered in
  > `core/delegation` and `core/devicecred` no longer declares or re-exports them.
  > The prediction that it was a two-line additive edit was very nearly right, and
  > the way it was wrong is the part worth reading.

## Testing

The frozen conformance fixtures are copied verbatim from the repository that owns
the signer and are the arbiter, since that repository cannot be imported:

- The positive chain must verify at the fixture's own clock **and** the device-side
  signer must reproduce the frozen assertion **byte for byte**. A verifier and
  signer that agreed with each other but disagreed with the spec would pass every
  test either side wrote alone.
- All **26 negative cases** must be refused, each with the error its case names. A
  verifier that accepts everything passes every positive vector there is.

Every key in both files is a published throwaway. That claim is **re-proved in
this repository** by deriving the development root from the seed phrase printed in
its own source and comparing public keys, rather than trusting the note in the
file — these bytes live in a public repository, and "the fixture says it is a test
key" is exactly what a leaked real key would also say.

The refusals were **mutation-checked**: twenty mutations, each neutralising one
check or reordering one pair, confirming the matching test fails and then
restoring. The first pass found **five checks that nothing actually tested** —
version treated as a minimum rather than matched exactly on both tiers, the
challenge floor on the verifying side, and `VerifyIssuerCert`'s own fail-closed
guard — all of which had passing tests that could not fail. Two mutations are
expected to stay green and are recorded as such: the device-key and issuer-key
length checks are each redundant with a guard in the framing layer, and the
device-key pair is *jointly* load-bearing — removing either alone changes nothing,
removing both crashes every coordinator that verifies a forged credential.

---

## Amendment (issue #54, 2026-07-30): the device-chain tags are in the registry

The consequence above is discharged. `bacchus/issuer-cert/v1` and
`bacchus/device-cred/v1` are now declared in `core/delegation` alongside
`bacchus/delegation/v1` and `bacchus/policy/v1`, `core/devicecred` references them
as `delegation.TagIssuerCert` / `delegation.TagDeviceCred`, and the "NOTE" paragraph
explaining why they were local is gone.

**Nothing about verification changed, and that is the point.** What separates two
domains is the tag *string*, and both strings are byte-identical to what they were —
the frozen conformance vectors are the proof, and all 23 `core/devicecred` tests
including the positive and negative vector sets stay green. This was an
**auditability** change: `core/delegation`'s package doc claims you can read one file
and see every tag this repository verifies, and until now that claim was false.

The tags are **not re-exported** from `core/devicecred`. A second name for one tag is
a second place to change it, which is the same drift the single-registry rule exists
to prevent.

### The part the issue got wrong, recorded because it is the reusable lesson

Issue #54 stated that "nothing outside that package uses them today", and concluded
the change was not a compatibility concern. The first half was false:
`core/devicecred_connect_test.go` — in package **`core`**, not `core/devicecred` —
minted its throwaway chain with `devicecred.TagIssuerCert` and
`devicecred.TagDeviceCred`. Deleting the constants without retargeting those two
lines stops package `core` compiling.

What makes this worth writing down is *why* the issue's author could look and not
see it: **the caller is a `_test.go` file, so `go build ./...` reports success.**
That was confirmed rather than assumed here — with the test file left unretargeted,
`go build ./...` exits clean while `go vet ./core/` reports
`undefined: devicecred.TagIssuerCert`. A change that moves or deletes an exported
identifier is only verified by `go vet ./...` or `go test ./...`; a green
`go build ./...` says nothing about it.

### Not covered, deliberately

`devicecred.PurposeConnect` (`bacchus/assert-connect/v1`) stays in `core/devicecred`.
It is the first field of an assertion message, not a `tag || 0x00 || body` framing
tag, and its set (renew/approve/enroll) is mostly not verified in this repository.
Widening the registry to cover purposes would change what "the tag registry" means
and is a separate decision, which #54 explicitly declined to take by implication.
