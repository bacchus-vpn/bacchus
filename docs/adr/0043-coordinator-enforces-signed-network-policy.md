# 43. The coordinator enforces signed network policy it cannot author, and fails closed when it goes stale

- Status: accepted (issue #39)
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
