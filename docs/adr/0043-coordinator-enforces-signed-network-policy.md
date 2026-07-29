# 43. The coordinator enforces signed network policy it cannot author, and fails closed when it goes stale

- Status: accepted (issue #39); amended (issue #15, issue #67 — see the amendments at the end)
- Date: 2026-07-28

## Context

Every number this coordinator applies to matchmaking is a constant it chose itself:
the version fence comes from `-min-serving-version`, the serve floor is a package
variable pinned at zero (ADR-0041), and the backpressure reserves do not exist yet.
That is fine while the operator and the coordinator are the same party. It stops
being fine the moment a coordinator is one of a pool, some of which the operator
does not run, because a hostile or compromised coordinator could then lower the
serve floor to admit Sybils, raise its own accounts' limits, or loosen the vouch
parameters — and nothing on the wire would be violated.

The counterpart to that already exists elsewhere in this repo. Admission enforces
credentials it cannot forge (ADR-0023). The signed directory serves snapshots it
cannot forge. The gap was that the *policy* — the numbers themselves — had no such
property.

The signing half of the fix landed outside this repository: a schema, a signer, and
a reference verifier, rooted in the same offline root the admission chain uses. None
of it did anything here. This repo had **zero** occurrences of
`VerifyDelegationCert`, `bacchus/delegation/v1` or `bacchus/policy/v1` before this
change, so the arrangement was half-shipped: signed policy existed and nothing
enforced it.

The wire format is frozen and is specified where the signer lives. This record does
not restate it and does not design any part of it. What it records is the set of
decisions the ENFORCING side has to make, which the format deliberately leaves open.

## Decision

### 1. The delegation verifier is general, not policy-private

`core/delegation` implements `bacchus/delegation/v1` as a standalone verifier taking
the expected role as an argument. It is not built inside the policy package.

The same offline root delegates to a policy signer, an update signer, and in time
others; the certs are identical in shape and differ only by a role string in the
signed body. A policy-private verifier would have to be written a second time the
moment the client needs the `update` role (#34) or a relay role lands (#26), and a
second copy of a signature check is exactly what drifts silently: both copies keep
verifying, and only one keeps checking the role.

It sits in `core/` beside `core/admission` rather than under it, so the admission
path can reach it without an import cycle when it needs to.

**The role is matched exactly.** A cert cut for `update` is refused for policy. This
is the one check that has no cryptographic backstop — same root, same shape, same
window — so it is tested adversarially rather than incidentally.

### 2. Policy wins over the flag, decided in one function

`policyServingFloor()` is the single place the precedence between a loaded policy's
`min_serving_version` and the `-min-serving-version` flag is decided. `servingCheck`
calls it rather than comparing anything itself.

The flag remains the pre-policy default and applies until a policy loads. It is not
removed: a deployment that has not adopted signed policy must keep working exactly
as before.

Written as explicit code rather than left to fall out of read order because two
sources of truth for one fence is the kind of thing that gets discovered during an
incident, by someone trying to work out why a node they just fenced is still
serving.

### 3. Failing closed, and exactly what that touches

Past `exp + grace`, and equally when no policy has ever loaded, a coordinator **with
a policy root configured** stops assigning new work:

- **register** — the node does not enter the serve pool. It is not advertised, so it
  draws no new sessions.
- **connect** — no new session is matched.

It does **not** touch established sessions, heartbeats, or capacity reports. Nothing
is torn down and no timer is needed, because matchmaking and live sessions are
already decoupled here — the same soft-drain shape the version fence has. An
already-registered node keeps its entry and ages out on the normal prune.

**Why fail closed here when admission and the version fence fail open.** The
direction follows from whether the failure is *sheddable*. Coordinators are a pool
with client rotation (ADR-0020), so one failing closed sheds to its peers rather
than darkening the network; the client's response to the refusal is to rotate. The
admission gate and the version fence are single points with nothing to shed to.

**Why not keep enforcing the last policy indefinitely.** A coordinator that simply
stopped refreshing would have *authored policy by omission* — pinned the network at
the most permissive generation it ever held, with no signature violated anywhere.
Expiry is what makes "cannot author" true over time rather than at one instant.

`grace` is inside the signed body, so a coordinator cannot extend its own licence to
run stale. Within grace the policy is still enforced and **logged loudly on every
refresh**, not once on entry: the window closes into a hard stop with no further
warning, and that line is the only notice an operator gets, so it must not scroll
away.

### 4. Persistent state: one file, holding bytes and a floor

`-policy-state` (default `secrets/policy-state.json`) holds two things:

- **The sequence floor** — the highest `seq` ever accepted. A genuinely signed,
  correctly delegated, unexpired document from an older generation passes every
  cryptographic check there is; the floor is the only thing that refuses it. Keeping
  it in memory would mean anyone who can make the coordinator restart can roll it
  back, so it is persisted, and it only ever ratchets up. Re-accepting the **same**
  seq succeeds, because the coordinator re-fetches the same document every refresh.
- **The last verified bundle, verbatim** — so a restart does not begin unpoliced.

The bundle is cached as **bytes and re-verified on load**, against the current clock
and the configured root. The file on disk is as untrusted as the network — more so,
in that it persists. Caching the parsed struct would mean trusting a local file to
have been checked at some point in the past by some earlier build.

Writes are atomic (temp file, then rename) and mode 0600. The floor is the one value
that cannot be re-derived from signed data, so **write access to this file is
equivalent to the ability to roll this coordinator back one generation**. It belongs
with the other secrets, not in a world-writable spool. That is a deployment
property; the code cannot enforce it.

### 5. Fetch: 10s, backoff capped at 2 minutes, URL or path

`-policy-source` takes an `http(s)` URL or a filesystem path. A path is the shape
every other trust artifact here already has (bootstrap secrets, the revocation list,
the operator map), so an operator who pulls the bundle with existing tooling does
not need this process to speak HTTP at all.

Refresh is 10s, matching the directory snapshot. On repeated fetch failure the
interval doubles, capped at **2 minutes**. The cap matters more than the growth: a
coordinator approaching its deadline must keep getting frequent chances to refresh,
so the backoff must never be the reason it failed closed.

**A failed fetch is not a stale policy.** What is held keeps being enforced until its
own deadline passes. And a bundle that fails verification does **not** replace a good
one — otherwise a hostile upstream could disarm a coordinator by serving nonsense.
The age-out runs regardless of whether the fetch succeeded, so a source that simply
stops answering cannot leave one generation enforced forever.

### 6. `tiers` and `vouch` are parsed, validated, and ignored

The coordinator never scores trust and never sees the vouch graph. These fields are
validated because a malformed document must be refused whole, and are then unused.
No lookup is built for them on this side; the account service resolves the tier table
and stamps the numbers into credentials, and this coordinator enforces a number it is
handed.

> **The `tiers` half of this decision was reversed — see the amendment (issue #67) at
> the end of this document.** The `vouch` half stands unchanged: the coordinator still
> never scores trust and never sees the vouch graph. The paragraph above is kept as the
> record of what was decided in #39, not as a description of current behaviour.

## Consequences

- A coordinator with `-policy-root-pubkey` set and no reachable policy source
  **assigns nothing**. That is the intended failure mode and it is loud in the log,
  but it is a real availability change for anyone who sets the flag without staging
  a bundle — which is why the flag is opt-in and why a root with no source is a fatal
  misconfiguration at startup rather than a coordinator that quietly never enforces.
- `-min-serving-version` becomes a default rather than the answer. An operator
  raising it on a coordinator that holds a policy will see no effect, and the log
  line at load names the policy floor so the reason is visible.
- **Revocation is not wired.** The verifier takes a revocation predicate and the
  tests exercise it, but nothing feeds it: the format specifies distribution via a
  signed short-TTL CRL that does not exist yet, and the delegation's own `not_after`
  bounds exposure until it does. Keep delegation windows no longer than the rotation
  cadence. Wiring it later is a wiring change, not a verifier change.
- The conformance fixtures are **copied**, not generated here, and are the arbiter:
  one bundle that must be accepted with every field parsed, and 26 cases that must
  each be refused with the specific error named. The negative file is the one that
  matters — a verifier that accepts everything passes every positive vector there is.
  A test re-derives the published development root from its seed phrase and fails if
  the fixtures ever chain to a root whose private key is not public, so a real key
  cannot reach this repository through testdata.
- The refusals were **mutation-checked**: removing the role check, the staleness
  check and the sequence check each made the corresponding frozen case fail, and only
  that case. A verifier whose tests have never been seen to reject is not yet a
  verifier.
- `min_measured_bps` and `min_declared_quota_bytes` are loaded and enforced by
  nothing yet. #15 [B3] is where they reach the serve-eligibility gate.

---

## Amendment (issue #15) — the serve-eligibility floor reads the policy, and applies only to trusted ratings

`min_measured_bps` now reaches the gate. Two decisions were needed that the card did
not settle, both about *which number* the floor is compared against.

### The floor has no constant default

`policyMeasuredFloor()` returns the held policy's `min_measured_bps`, and **zero when
no policy is held**. There is deliberately no fallback constant: a floor with one is a
floor the coordinator authored, which is the exact property this ADR exists to deny.
That is not a hole — a coordinator with policy configured and none held is already
refusing to assign anything at all, and one with policy unconfigured never had a floor.

This replaces the `serveFloor` package variable ADR-0041 shipped pinned at zero as
"the machinery with the gate off". That variable and its `meetsServeFloor` remain in
place at the *assignment* surfaces, still zero; this gate is at **register**, which is
where a node joins the serve pool, and registers repeat every ~10s so the gate
re-applies continuously.

### The floor reads the TRUSTED rating, never `Measured`

This is the load-bearing part, and getting it wrong would have stranded the fleet.

The untrusted estimator forces `HardCeiling` at `Ceiling` (5 Mbit), and the trusted
stream is **permanently unfed in this build** — nothing stamps vouched-ness into a
credential yet. So `Measured()` falls back to the untrusted estimate for every node,
and that estimate is bounded by the ceiling no matter how fast the node actually is.
Measured against `core/capacity`:

```
REAL 100 Mbit node, 200 windows, 8 distinct ASes attesting (untrusted):
   Measured()               = 5Mbit    -> fails a 25 Mbit floor
UNMEASURED node, same declaration:
   Usable(declared 100Mbit) = 100Mbit  -> passes
```

A floor applied to `Measured` would therefore fence **every measured node** and admit
**every unmeasured one** — fleet-stranding, and an inversion of the incentive to be
measured at all. This is what ADR-0041 meant when it shipped the floor off; the card's
premise that "B2 is done, so this just turns it on" understated it, because B2 built
the machinery while the *trusted* stream that makes a rating comparable to a
real-world floor is still unfed.

So the gate reads `capacity.RatingStore.TrustedRating` (added by this change: purely
additive, no behaviour change to existing callers) and treats a node with no trusted
rating exactly as it treats one with no rating at all — **not fenced**. An unmeasured
node is not a slow node (design §5.3), and neither is one whose only evidence is
ceiling-bounded.

The consequence is that **today this gate withholds nobody**, and that is intended: it
is live machinery that starts biting the moment the account service feeds the trusted
stream, with no further coordinator change. Same shape as the seams ADR-0041 used for
that stream and ADR-0040 used for `Vouched`. Two tests pin the safety property — one
at the helper, one at the register surface — so a future change that switches the gate
back to `Measured` fails rather than strands the fleet.

### `min_declared_quota_bytes` is loaded and NOT enforced

The coordinator has no input for it. The register wire carries `SpeedCap` (bits/s) and
`QuotaState` — **one bit**, `ok` | `exhausted` — and `core/engine.go` states that
choice normatively: byte counts would hand a coordinator, untrusted by standing
assumption, a per-node monthly usage curve about a residential operator's household
for no matchmaking benefit. The node holds the number and deliberately does not send
it.

Enforcing this floor therefore needs a new byte-valued field on the register wire,
which reverses an explicit ADR-0040 privacy decision. That is deferred to its own card
rather than smuggled in here. The field is parsed and validated; nothing reads it.

---

## Amendment (issue #67) — the network reads the `tiers` table; the credential carries only the key

§6 above decided that the account service resolves the tier table and stamps the
resulting numbers into a credential, and that this repository would never build a
lookup for `tiers`. **That half is reversed.** The division is now:

- the **signed policy** carries the limits — `speed_cap_bps`, `priority`, `endpoint_quality`, per `(trust, plan)` row;
- the **credential** carries only the `(trust, plan)` pair that indexes them;
- the **network** — coordinator and exit — resolves the pair against the policy it already holds and enforces what it finds.

The producer side of this shipped in `bacchus-payment#6`: an issued credential now
carries `trust` and `plan` and does not carry limits. The consumer side is **#58**,
which is where `core/admission.Credential` grows the matching fields and the
coordinator and exit start resolving them. This amendment records the ruling so the
public repository states it before #58 rather than after.

### Why this direction

§6's arrangement made every limit a **number frozen at issuance**. A credential minted
under one policy keeps enforcing that policy for its whole lifetime, so changing a
tier's speed cap could not take effect until every outstanding credential had aged
out — and the network had no way to know which policy any given credential was
stamped under. Carrying the key instead means the limits are resolved from the
document the network already re-fetches, re-verifies and fails closed on (§2, §3), so
a re-signed policy takes effect at its own cadence and the sequence floor and grace
window that protect every other number protect these too.

It also removes a signed assertion the network had no way to check. Under §6 the
coordinator enforced a speed cap it was handed and could not verify was the one the
operator's own policy specified; now it enforces one it read out of a document it
verified against the policy root itself.

The cost is that a credential is no longer self-contained: an enforcer without a
policy cannot resolve a tier at all. That is the correct failure and it is already
this ADR's standing rule — a coordinator with `-policy-root-pubkey` set and no
policy held **assigns nothing** (§3, Consequences). There is no state in which a
missing policy silently means "no limits".

### An unknown `(trust, plan)` pair is an error, never a default

`Policy.Limits` already implements this and its doc already says why; the rule is
restated here because it is the one place this reversal could turn into a hole rather
than an outage.

A zero `TierLimit` means **uncapped** — zero `SpeedCapBps` is "no cap", zero
`EndpointQuality` "admits anything". So a permissive fallback row would hand full
speed and unrestricted endpoint access to exactly the credential whose tier nobody
signed a policy row for: the failure mode is silent, and it opens at the moment
someone ships a new plan and forgets the policy. A restrictive fallback is not the
answer either — it is an outage with no diagnosable cause, since the enforcer would be
applying a number that appears nowhere in the signed document.

Both are refused. The lookup returns `ErrUnknownTier` naming the missing pair, and
#58 decides how each surface reports it — but not by substituting a number.

### What this does not change

- **`vouch` is still parsed, validated, and unread here.** The coordinator does not score trust and does not see the vouch graph. Nothing in this amendment gives it a reason to.
- **`Policy.Limits` is unchanged.** It was already correct; what was wrong was the surrounding documentation asserting nothing would ever call it.
- **No wire change in this repository, and none in this change.** `core/admission.Credential` gains its fields in #58.
- **`min_declared_quota_bytes` is still enforced by nothing**, for the reason the #15 amendment gives above.
