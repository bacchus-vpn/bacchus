# Cryptographic node & client admission (issue #42)

Enforces who may join the network, in cryptography, independent of the license.
Implements ADR-0023. See also `docs/threat-model.md` (the adversaries this
addresses), ADR-0015 (the operator trust root reused here), and
`docs/design/rendezvous-cold-start.md` (the out-of-band credential-distribution
model this follows).

## What it stops

Without admission, anyone who can reach the coordinator and speak the wire
protocol can:

- **register a hostile exit/relay** and see traffic routed through it — the
  "malicious node operator" of the threat model, which explicitly includes the
  censor joining as a volunteer; or
- **connect as a client** and enumerate the network (crawl the coordinator,
  harvest node addresses) — the censor "posing as an ordinary user."

Admission also closes the "a fork just points at our live network" gap: the
network's membership is a signature check, not a property of the source.

This is authentication, deliberately separate from the license decision
(ADR-0019). A permissive *or* a proprietary license does nothing here.

## The credential

A `core/admission.Credential` is a signed statement by an admission authority the
coordinator anchors (see [The authority set](#the-authority-set-issue-64-adr-0047)):

| Field       | Meaning                                                             |
|-------------|---------------------------------------------------------------------|
| `Version`   | format version; a verifier rejects anything it doesn't know          |
| `Serial`    | random, unique; names this credential for revocation                 |
| `Subject`   | node id (an exit's X25519 pubkey) for relay/exit; a user label for a client |
| `Roles`     | which of `client` / `relay` / `exit` this credential authorizes      |
| `NotBefore` / `NotAfter` | validity window (UTC)                                   |
| `Note`      | free-form operator label; not security-relevant                     |

The wire/disk form is the house envelope from `core/coldstart`: the canonical
JSON body followed by a fixed-length ed25519 signature over it, base64url-encoded
behind a `bacchusc1:` tag. It carries **no secret** — it is an authorization to
present, not a key to protect — so like a coldstart invite it can be handed to a
recipient out of band, and a client credential travels the same way.

## Where it is enforced

The coordinator is the single matchmaking chokepoint (ADR-0015), so that is the
one place a credential is checked. The credential rides in the `cred` field of
the existing coordinator envelope; the engine attaches it to every message that
needs it (`register`, `list`, `challenge`, `connect`).

| Handler   | Role checked | Subject binding | On reject |
|-----------|--------------|-----------------|-----------|
| `register`| the registering role (`relay`/`exit`) | bound to `m.ID` (the node id) | not added to the directory; `reject` sent |
| `list`    | `client`     | none (bearer)   | no exit list; `reject` sent |
| `challenge` | `client`   | none (bearer)   | no nonce issued; `reject` sent |
| `connect` | `client`     | none (bearer)   | no session; `reject` sent |

### `connect` is judged on a credential that may have arrived a round trip earlier

`challenge` (ADR-0045) and `connect` are two messages of one exchange, and before
ADR-0057 a client put the credential on **both** — 437 bytes of the same value,
twice, per connect attempt. That is what pushed `connect` to 1453 bytes and off
any path at the IPv6 minimum MTU (#183).

A client now sends it once. Which message it rides is decided by whether the
challenge exchange completed:

- **A challenge was answered** — the coordinator issued a live nonce for this
  source, so the credential rode the `challenge` and the `connect` carries none.
  The coordinator verified it there, stashed it beside the nonce, and re-verifies
  it — revocation and all — when the `connect` arrives.
- **Anything else** — no device credential to present, the entitlement gate is
  off, the challenge store is at capacity, or the reply was lost. The credential
  rides the `connect`, which is the only place it can be.

The condition is a challenge **answered**, not a challenge sent: a client cannot
see whether the coordinator's entitlement gate is enabled, and a deployment
running admission with that gate off answers with an empty challenge and stores
nothing. The table above is unchanged by this — every handler still checks the
same role with the same binding, and a `connect` with neither its own credential
nor a stash behind it is refused exactly as before. See ADR-0057 §2–§3.

`reject` reuses the ADR-0016 handshake-reject pair, so the reason (which names
only credential facts, never a secret) is surfaced through the client's existing
event path. Because a node's register loop re-announces every ~10s, a node whose
credential just expired or was revoked is fenced within one interval — the
"fence stale nodes" property ADR-0015 asked for, now keyed on credential
validity.

## The authority set (issue #64, ADR-0047)

A verifier anchors a **set** of authorities, each scoped to the roles it may
admit — not one key trusted for everything. Two structurally different issuers
mint this format: the operator by hand (`cmd/admission-issue`; `relay`/`exit`,
bound to a node id, low volume, offline) and the account service automatically
(`client`, bearer, short-lived, reissued on every renewal, always online). Under
a single anchor those two would share a private key, putting the credentials that
admit a host as **forwarding infrastructure** behind the busiest and most exposed
issuer.

| Statement | Written by | Reachable from a signing key? |
|-----------|------------|-------------------------------|
| `Credential.Roles` — "this subject may act as an exit" | the **issuer** | yes: whoever holds the key writes it freely |
| `Authority.Roles` — "this issuer may mint exits at all" | the **anchor** (operator config) | no |

Both are checked, and only the second constrains a compromised issuer. The
coordinator anchors the set (`-admission-pubkey` + `-admission-authority`, see
[RUNNING.md](../RUNNING.md)); a **client** anchors one key, because its only check
is `exit`, the authority that mints exits is the operator, and a coldstart invite
carries exactly one anchor.

## Verification order

`Verifier.Verify` decodes, **filters the anchored authorities by the role the
peer is taking**, checks the ed25519 signature and version of each survivor in
turn (`parse`), then applies the policy (`accept`) over the now-trusted fields.

The role filter runs before any signature verification, so a client authority's
key is never even a candidate for an exit check — the scoping is structural
rather than a check that follows verification and could be reordered away. One
consequence, deliberate: a credential correctly signed by an authority anchored
for some *other* role comes back `ErrBadSignature`, not `ErrRoleNotAuthorized`,
because no signature was ever checked against its key. A role no anchored
authority covers is reported distinctly (`ErrNoAuthorityForRole`) — that is a
fact about the coordinator's configuration, not about the credential.

`accept` then runs in this order:

1. **Revocation** — `revoked(serial)`. Checked first: an explicitly revoked
   credential is the freshest, most decisive operator signal, and surfacing
   `ErrRevoked` even when the credential has *also* expired gives the operator
   the more actionable reason ("we killed this" beats "this aged out").
2. **Validity window** — `NotBefore` with a `ClockSkew` (2 min) tolerance on the
   **lower bound only**; `NotAfter` strict, no skew. Being lenient about when a
   credential *starts* is harmless; being lenient about when it *ends* would
   extend a rotated/revoked credential's life, so expiry is strict.
3. **Role** — the credential must authorize the role the peer is taking now.
   Not redundant with the anchor filter above: that one asks whether the
   *authority* may admit this role, this one whether the *credential* it signed
   says so. An operator authority anchored for every role must still not have a
   client credential it minted admitted as an exit.
4. **Subject binding** — for a node (`subject != ""`), the credential's subject
   must equal the id presenting it.

## Subject binding: nodes vs clients

The asymmetry is the subtlest part of the design.

- A **node** has a stable, cryptographically meaningful id on the wire (an exit's
  id *is* its X25519 static public key, ADR-0009). Binding the credential to that
  id means a valid-but-leaked node credential is inert in anyone else's hands —
  they can't register a hostile exit under it, because they can't present the id
  it is bound to and separately authenticate as that exit end-to-end.
- A **client** has no coordinator-known stable id on the signaling channel — just
  a UDP address that changes. There is nothing to bind to, so a client credential
  is **bearer**, protected the same way the coldstart per-user secret is: by the
  out-of-band channel it is delivered over. A shared or leaked client credential
  admits whoever holds it until it expires or is revoked. This is a known,
  documented weakness (ADR-0023 consequences); per-device client identity is a
  future hardening.

## Revocation

The coordinator loads a serial list from disk and hot-reloads it on an interval
(mirroring the bootstrap-secrets reload), so an operator can revoke a leaked or
rotated credential without a restart. A missing file means "nothing revoked
yet"; any other read/parse error keeps the last-known-good list rather than
failing open (a malformed file must never silently un-revoke everyone).

**Those two rules are not the same rule at startup, and the difference is what
makes the WRITE side load-bearing** (issue #168). Keeping the last-known-good
list needs a last-known-good list to keep. At startup there is none, so the
missing-file rule is the one that applies to an unparseable file too, and it
reads as *nothing is revoked*.

`admission-issue -revoke` writes by default to the coordinator's own
`-admission-revocations` path, so the tool and the process it exists to inform
are pointed at one file with no coordination between them. Two failure shapes
follow, and only the first is benign:

- a **reload** that catches a half-written file is fail-safe — it keeps the
  previous in-memory list, and the next tick repairs it;
- a **restart** afterwards is not. A file left truncated by a writer that died
  mid-write is a delayed failure that detonates whenever the coordinator is next
  restarted — hours or weeks later, with nothing connecting it to the revocation
  that caused it.

So `RevocationList.SaveFile` writes a complete file to a temporary name in the
same directory, flushes it, and renames it over the target. The live file is
never opened for writing, and there is no moment at which the path holds
anything but a whole list. A save killed between staging and rename leaves the
previous list in place and a `.<name>.tmp*` file beside it, which is inert.

## Enforcement toggle & rollout

Admission is **on when the coordinator is configured with `-admission-pubkey` or
`-admission-authority`**, open otherwise, with a loud startup warning when off.
(`-admission-pubkey` anchors one authority for every role; `-admission-authority`
is the role-scoped, repeatable form — ADR-0047.) This is deliberate for a
staged rollout: an operator can issue credentials to the fleet first, then flip
enforcement on, rather than needing a synchronized flag day. It is *not*
fail-closed — until the anchor is configured the network serves anyone — and
making admission mandatory is a later hardening once the fleet is credentialed.

## Operator workflow

```sh
# One-time: generate the admission root key; it prints the public key to
# configure the coordinator with.
admission-issue -pubkey                     # prints the pubkey (key auto-generated on first use)

# Coordinator: turn enforcement on.
bacchus-coordinator -turn-public-ip <IP> -turn-user <u> -turn-pass <p> \
    -admission-pubkey <PUBKEY>

# Issue a 30-day exit-node credential bound to the exit's node id (its X25519
# pubkey), then run the exit with it.
admission-issue -subject <exit-pubkey-hex> -roles exit -ttl 720h > exit.cred
bacchus-node -role exit -exit-key <hex> -admission-cred exit.cred  ...

# Issue a client credential and hand it to the user out of band.
admission-issue -subject alice -roles client -ttl 2160h > alice.cred

# Revoke a leaked credential by serial (hot-reloaded by the coordinator).
admission-issue -revoke <serial>

# Sign the current revocation list as a short-lived bundle for clients (issue
# #69, below) and re-run periodically before it lapses.
admission-issue -crl -crl-ttl 24h > revocations.crl
```

## End-to-end exit verification (issue #60, ADR-0026)

Coordinator gating decides which exits are *advertised*; it cannot help a client
that reaches a hostile coordinator (the threat model allows censor-run
coordinators, and the pool — ADR-0020 — has a client rotate across several, any
one of which could be hostile). So the client **also** verifies the exit
end-to-end:

- **The exit presents its `-admission-cred` inside the Noise_NK handshake**
  (ADR-0009), carried in msg2's Noise payload. That payload is AEAD-sealed under a
  key already mixing the exit's static key, so it is confidential, tamper-proof
  against a relay in the path, and bound to the exact key the handshake
  authenticates. (The same preamble ADR-0021 reused for accounting.)
- **The client verifies against the admission root**: signature under the root,
  `subject` == the exit static pubkey it just authenticated, `exit` role, in
  window. Any failure aborts *before the destination is sent*, surfaced as a
  client event. This is the identical `subject`-binding check the coordinator runs
  on `register`, now run by the client against the key it terminates Noise_NK with
  — which is exactly why an exit's credential is bound to its id (its X25519
  pubkey) in the first place.
- **The anchor reaches the client** in the coldstart invite (a v2 invite appends
  the admission root beside the snapshot-signing key, so a client bootstrapped
  purely from an invite is covered) or via `-admission-pubkey`, which overrides
  the invite. No anchor → the client does not verify (fail-open, matching the
  coordinator). Direct and relay mode both, since Noise_NK is end-to-end in both.

```
# Issue an invite that also carries the admission anchor (a v2 invite), so a
# fresh client verifies exits with no extra setup:
coldstart-issue -coordinator <HOST:PORT> -pubkey <SNAPSHOT_PUBKEY> \
    -admission-pubkey <ADMISSION_PUBKEY>

# Or point a client straight at the anchor (overrides any invite):
bacchus-node -role client -admission-pubkey <ADMISSION_PUBKEY>
```

v1 verified offline only (no revocation oracle on the client) — see
"Client-side revocation" below for how that gap closed.

## Client-side revocation (issue #69)

v1's client verifier ran with a permanently nil revocation oracle: a revoked
exit credential was still accepted until it naturally expired, leaning on
short-lived credentials to bound the window (ADR-0026 accepted this
explicitly). This wires in a real check.

- **The bundle.** `core/admission.CRL` is a short-TTL, signed list of revoked
  serials — the same signed envelope as a `Credential` (canonical JSON +
  trailing ed25519 signature), so it is trustworthy independent of whatever
  relayed it, exactly like the credential itself. This matters because a CRL
  reaches the client the same way the credential's exit did: potentially via
  the hostile coordinator ADR-0026 already assumes may lie. An unsigned local
  file (like the coordinator's own `RevocationList`) would let that
  coordinator simply omit the entry for its own compromised exit.
- **Verification.** `buildExitVerifier` (`core/exit_admission.go`) parses and
  checks the bundle against the same admission root the anchor uses, then
  closes over its `Revoked(serial)` method as the verifier's revocation
  predicate — the same `accept()` policy from "Verification order" above, now
  with something to consult instead of an always-false stub.
- **Distribution mirrors the anchor exactly**, per the table below.

  | Source | Anchor (issue #60) | CRL (issue #69) |
  |---|---|---|
  | Coldstart invite | `AdmissionKey` (v2) | `CRL` (v3; requires `AdmissionKey`) |
  | Direct override | `-admission-pubkey` / `Config.AdmissionPubKey` | `-admission-crl` / `Config.AdmissionCRLPath` (reloaded on an interval, issue #90) or `Config.AdmissionCRL` (inline, static) |
  | Mint | `admission-issue -pubkey` | `admission-issue -crl -crl-ttl <dur>` |

  A CRL without an anchor is unverifiable and therefore a construction error,
  not a silent no-op; configuring **neither** is unchanged fail-open, exactly
  like an unset anchor alone. A bundle that fails to parse, fails signature
  verification, or has already expired is likewise a construction error — an
  operator who turned revocation checking on must not have it silently
  degrade to "nothing is revoked" on a stale or corrupt file. This applies
  identically to both `Config.AdmissionCRL` (inline content) and
  `Config.AdmissionCRLPath` (a file, issue #90) — at most one of the two may
  be set at once, since they are alternate sources for the same state.

```
# Sign the operator's current revocation list as a 24h bundle, embed it
# alongside the anchor in a v3 invite:
admission-issue -crl -crl-ttl 24h > revocations.crl
coldstart-issue -coordinator <HOST:PORT> -pubkey <SNAPSHOT_PUBKEY> \
    -admission-pubkey <ADMISSION_PUBKEY> -admission-crl revocations.crl

# Or hand a client the bundle directly (overrides any invite):
bacchus-node -role client \
    -admission-pubkey <ADMISSION_PUBKEY> -admission-crl revocations.crl
```

**Hot-reload (issue #90).** `-admission-crl <path>` is loaded once
synchronously at construction — a bad path, like a bad inline
`-admission-crl` value used to be, is a construction error — and again every
few minutes thereafter by `Engine.reloadCRLLoop`, the client-side mirror of
the coordinator's own `reloadRevocationsLoop`. A reload that fails to read,
parse, verify, or that finds the file has itself expired is logged as a
non-fatal event and the previously loaded bundle keeps being enforced
unchanged: a transient misread (an operator mid-write) or an operator late
to rotate a lapsed bundle must not silently degrade an active revocation
check to fail-open, or take down an otherwise healthy connection. This
closes the gap the previous revision of this doc flagged as a candidate
follow-up: a long-lived client no longer runs past a bundle's TTL forever,
provided the operator keeps re-minting and dropping a fresh bundle at that
path (`admission-issue -crl -crl-ttl <dur>` on a cron, or repeating
`coldstart-bootstrap -crl-out <path>` against a refreshed invite) before the
previous one lapses. `Config.AdmissionCRL` (inline content, no path to
reload from) is unaffected and remains load-once, matching pre-#90 behavior
exactly — it exists for a caller that already holds the bytes rather than a
file path.

**Windows GUI client adoption (issue #116).** `cmd/node`'s `-admission-pubkey`/
`-admission-crl` flags have mapped straight to `Config.AdmissionPubKey`/
`Config.AdmissionCRLPath` since #90 shipped — but `clients/windows` (the tray
GUI, a separate binary from `cmd/node`) had no admission config surface at
all until this issue: neither field was ever wired into any of its three
`core.New` call sites (`listExits`, `connect`, `resetLearnedPaths`), so it
ran fully fail-open regardless of what an operator configured. #116 adds
"Admission authority public key" and "Revocation list file path" fields to
the Settings window (`clients/windows/settings.go`), persisted in
`bacchus.config.json` (`Config.AdmissionPubKey` / `Config.AdmissionCRLPath`,
`clients/windows/config.go`) and applied identically at all three call
sites — mirroring `cmd/node`'s own shape exactly (a public-key hex string and
a CRL *file path*, never inline `Config.AdmissionCRL`) rather than inventing
a new one. An end user who fills in both gets the same interval hot-reload
described above; leaving them blank reproduces this client's exact pre-#116
behavior (fail-open).

**Settings-side validation (issue #123a).** #116's two fields are independent
`LineEdit` controls, but core (`buildExitVerifier`) has always rejected "CRL
path set, pubkey blank" as a construction error — a user who fills in only
the revocation-list path made `connect()` show a raw `Error: ... requires
AdmissionPubKey` and `listExits()` silently return no exits, both fail-closed
but confusing, since nothing in the Settings window itself explained why.
`clients/windows/settings.go`'s save handler now runs
`validateAdmissionConfig` (a pure, unit-tested function mirroring the shape
of `sanitizePoolOrder`/`validateRelayChainConfig`) before either field reaches
`Config`, and refuses to save with an inline message
("revocation list path requires the admission public key above") instead of
passing the invalid pair through to core. Both blank (admission off) and the
public key alone (verify exits, skip revocation) are unaffected — only the
one combination core already rejected is caught earlier, and closer to the
user's mistake.

**Require-CRL (issue #91).** By default, an anchor configured with no CRL of
either kind is unchanged fail-open-on-revocation (v1's original shape) — the
same as configuring neither. The opt-in `-require-crl` flag
(`Config.AdmissionRequireCRL`) turns that specific combination — anchor
present, CRL absent — into a construction error instead, for an operator who
wants a hostile or buggy coordinator that strips the CRL from a v3 coldstart
invite to be a hard failure the client refuses to start with, rather than a
silent downgrade to "not checking revocation." `-require-crl` with no anchor
configured at all is also a construction error (there would be nothing to
enforce), not a quiet no-op an operator could mistake for protection. The
default is unchanged either way — this is purely additive hardening for
operators who opt in.

## Open questions / follow-ups

- ~~**End-to-end exit verification (#60).**~~ **Done — ADR-0026** (see the section
  above): the client verifies the exit's admission credential during the Noise_NK
  handshake, defense in depth against a compromised coordinator advertising a
  hostile exit.
- ~~**Live client-side revocation (#60 follow-on).**~~ **Done — issue #69** (see
  "Client-side revocation" above): a signed, short-TTL bundle travels alongside
  the admission anchor and is verified against the same root, so a revoked exit
  credential is rejected before it naturally expires.
- ~~**Client-side CRL hot-refresh.**~~ **Done — issue #90** (see "Hot-reload"
  above): `-admission-crl`/`Config.AdmissionCRLPath` is re-read on an interval,
  mirroring the coordinator's own `reloadRevocationsLoop`, so a long-lived
  client picks up an operator's rotated bundle without a restart.
- ~~**One authority for every role.**~~ **Done — issue #64, ADR-0047** (see "The
  authority set" above): a verifier anchors a role-scoped set, so the account
  service can hold a `client`-only key and a compromise of the always-online
  issuer cannot mint credentials that admit a host as forwarding infrastructure.
- **Mandatory (fail-closed) admission** once the fleet is fully credentialed.
- **Per-device client identity** to make client credentials non-bearer.
- **Fast-fail on the client.** An admission `reject` on `list`/`connect` is
  logged but does not yet short-circuit the client's connect result (it times out
  and rotates); surfacing it as a clean, immediate failure is an ergonomic
  follow-up.
- **Credential lifecycle** — renewal/rotation tooling and short-lived credentials
  with automated refresh, once the manual flow has proven out.
