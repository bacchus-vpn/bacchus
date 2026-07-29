# 47. Admission anchors a role-scoped SET of authorities, filtered by role before any signature is verified

- Status: accepted (issue #64)
- Date: 2026-07-29

## Context

`core/admission` anchored exactly one key. `Verifier` held a single `pub`, read
in one place — `parse(v.pub, signed)` — so the network had exactly one admission
authority and every credential any issuer minted had to be signed by that one
private key.

Two structurally different issuers mint this format, and they are not alike:

- **The operator, by hand.** `cmd/admission-issue`, minting `relay` and `exit`
  credentials bound to a node id. Low volume, offline, deliberate.
- **The account service, automatically.** Client credentials — bearer, subject
  unbound, short-lived, reissued on every renewal. Always online, high volume.
  `Credential.Vouched`'s own comment already named it as an issuer this
  repository does not contain: *"stamped by the account service, NOT by any
  issuer in this repo."*

With one anchor those two must share a private key. The busiest and most exposed
issuer would hold the key that admits a host as **forwarding infrastructure**,
and the blast radius of compromising it would be the whole role space rather than
the one role it needs. There was no way to say "this authority may mint `client`
and nothing else".

The alternative under the old shape — give the account service its own key and
accept that the coordinator cannot verify it — is not an alternative.
bacchus-payment#38 already ruled that the account service gets its own
admission-scoped key; that ruling could not be deployed until this landed.

## Decision

### 1. A `Verifier` anchors a set of `Authority`, each scoped to the roles it may admit

```go
type Authority struct {
    Pub   ed25519.PublicKey // the key this authority signs with
    Roles []Role            // the roles it is trusted to admit; empty admits nothing
}
```

An `Authority`'s `Roles` and a `Credential`'s `Roles` are different statements by
different parties and both are checked. A credential's roles field is the
**issuer's** claim, and whoever holds a signing key writes it freely. An
authority's roles are the **anchor's** claim, and no signing key reaches it. That
gap is the entire mechanism: anchoring the account service for `RoleClient` alone
means compromising it yields client credentials and nothing that can join the
forwarding path, however the roles field of what it mints is filled in.

Empty `Roles` admits nothing rather than everything. An authority nobody managed
to scope is a mistake, and the direction that mistake fails in should not be
"trusted for all of it".

### 2. Filter by role FIRST, then verify — not verify, then check the role

The issue proposed the natural reading: find the authority whose key verifies the
signature, then require that authority be authorized for `want`. This inverts it.
`want` is already passed at every `Verify` call site, so the authority set is
filtered by role and only the survivors get a signature verification.

Both orders compute the same answer. This one is chosen for two reasons:

- **The role check cannot be forgotten or reordered away.** A client authority's
  signature is never even a candidate for an exit check, so there is no state in
  which the anchor scoping is merely something checked afterwards and might one
  day not be. A verify-then-check shape puts the security property in a
  conditional that a later edit can move, delete, or fall through; this puts it
  in which keys exist at all.
- **Signature cost is bounded by the authorities for that one role**, not by the
  whole set, on a path the coordinator runs for every `list`, `connect` and
  capacity-report.

### 3. That changes which error a wrong-authority credential returns, deliberately

A credential correctly signed by an authority anchored for some *other* role now
comes back `ErrBadSignature`, where before it would have reached `accept` and
come back `ErrRoleNotAuthorized`. Its key was never a candidate, so no signature
was ever checked against it.

This is the better answer and not merely a side effect. It is the same reasoning
ADR-0045 applied to its assertion failures — a verifier that reports which part
was right is an oracle for finding the rest. A forged signature and a genuine
signature from an unanchored-for-this-role authority are now indistinguishable
from outside.

`accept`'s own role check survives and is not made redundant. An operator
authority anchored for every role must still not have a client credential it
minted admitted as an exit, and only that check stops it.

### 4. A role no anchored authority covers is reported distinctly

`ErrNoAuthorityForRole`, not `ErrBadSignature`. That case is a fact about the
coordinator's configuration rather than about the credential: an operator who
forgot to anchor an authority for a role needs to be able to tell it apart from a
peer presenting garbage, and telling them costs nothing an unauthorized peer
could not learn by observing that the role is refused unconditionally.

It has one visible consequence for a single-anchor deployment, and it is the only
one. `cmd/coordinator` passes the register message's `role` field straight into
`Verify`, so an unknown role string is peer-controlled: `"courier"` now stops at
the anchor with `ErrNoAuthorityForRole` instead of reaching the credential's roles
field and returning `ErrRoleNotAuthorized`. Same rejection, named closer to its
cause, and one ed25519 verification cheaper. For every **known** role a single
anchored authority behaves exactly as it did before this change.

### 5. Construction fails closed on an ambiguous anchor set

`NewAuthoritySetVerifier` refuses: no authorities at all; a key that is not
`ed25519.PublicKeySize` bytes; an authority scoped to no roles or to a role string
this build does not know; the same key anchored twice. Each of these would
otherwise produce a coordinator that looks configured and trusts something other
than what its unit file says.

Validating key length at construction is also what lets `Verify` treat a parse
failure as a fact about the credential rather than about the anchor — which is
what makes the next decision sound.

### 6. Only `ErrBadSignature` means "try the next authority"

Every other `parse` failure — a malformed envelope, an unsupported
`CredentialVersion` — is a fact about the credential that no other anchored key
would read differently, so it is returned immediately rather than masked by a
later `ErrBadSignature`. Without this, a credential from a future build would be
reported as a bad signature and the version fence would be invisible in the log.

### 7. `NewVerifier` keeps its signature and its meaning: one authority, every role

It is not a compatibility shim. It is the single-anchor case, and it stays,
because **the client's anchor is genuinely one key**: the client's only `Verify`
call is `admission.RoleExit` (`core/exit_admission.go`), the authority that mints
exit credentials is the operator, and a coldstart invite carries exactly one
`AdmissionKey` (`core/coldstart`, the v2/v3 shape). The key it already holds is
the authority it needs. `core.Config.AdmissionPubKey` therefore does not become a
set, and `buildExitVerifier` is unchanged by this ADR beyond its documentation.

Keeping the constructor source-compatible also keeps the change off every other
file that builds a verifier — four test files, one of them the test file of a
source file another change owns concurrently. A signature change there would be a
compile break that neither branch's CI could see, which is a failure mode this
project has already paid for once.

### 8. The flag surface: `-admission-authority`, repeatable, additive

`-admission-pubkey` keeps its exact meaning — **one authority, every role** — so
an operator who changes nothing sees no behaviour change. Alongside it:

```
-admission-authority role[,role...]:hexkey     # repeatable, one per authority
```

Roles come first because a key contains no colon and role names cannot, so
splitting on the first colon is unambiguous however many roles are listed. The
two flags compose, which is what makes the rollout additive rather than a
rewrite:

```bash
# today
-admission-pubkey <operator>

# split the account service off — one flag added, nothing changed
-admission-pubkey <operator> -admission-authority client:<account>

# narrow the operator key afterwards
-admission-authority relay,exit:<operator> -admission-authority client:<account>
```

Admission is disabled only when **both** are unset. Every malformed anchor is
fatal at startup: a coordinator that came up looking configured while trusting a
different set of keys than its unit file names is the failure this must not have.

**Flags and not a file**, unlike the revocation list sitting next to it. Anchors
change only across a restart; nothing here is reloaded and nothing should be. The
revocation list is a file precisely because an operator must be able to kill a
leaked credential in seconds without a restart — but a trust anchor hot-reloaded
from disk means a bad write can silently *widen* who may join the network, which
is the one direction this package exists to prevent. A file would also want
versioning, a parser, and a reload story, for a set of two or three entries that
belongs in the same unit file as `-device-root-pubkey` and `-policy-root-pubkey`
where it can be reviewed in one place.

The startup line now names each authority's roles and the first 8 hex of its key.
A wrong scope is the misconfiguration this flag makes newly possible and it is
invisible in every other line the coordinator prints.

### 9. `-admission-pubkey` means two different things in two binaries; documented, not renamed

On `cmd/coordinator` it is one member of the anchored authority set. On
`cmd/node` it is the **client's** single anchor for verifying an exit's
credential end-to-end (issue #60, ADR-0026). Those were already different things
before this change — one is "who may join my network", the other is "who must
have authorized the exit I am about to route through" — and this change does not
make either meaning move; it only gives the coordinator's one company.

Renaming either would break every deployed unit file, every invite-generation
path, and every doc, to fix an ambiguity that costs one sentence to state. The
coordinator's flag help now states it and points here. A matching one-line note
on `cmd/node`'s help text is proposed, not applied, across this change's
file-ownership boundary.

## Consequences

- **No wire change.** `Credential` is untouched. Credentials minted before this
  keep verifying, and a coordinator that anchors one key admits exactly what it
  admitted before.
- **bacchus-payment#38 is deployable.** The account service can hold an
  admission-scoped key of its own, anchored for `client` and nothing else.
- **Revocation is unaffected**, as #64 scoped it: one list still covers every
  authority, because a serial names a credential and not an issuer, and both
  issuers draw 8-byte serials from `crypto/rand`.
- **Issue #26 (per-hop relay-role verification) shipped a separate relay anchor
  rather than the free reuse this paragraph predicted** — see the amendment at
  the end of this file for why the free-reuse path was set aside once it came to
  it, and for the one respect in which the new anchor's construction-time
  guarantee is narrower than every other field in `Config` carries.
- **A new way to misconfigure a coordinator**: anchoring an authority for the
  wrong roles. Mitigated at both ends — construction refuses anything ambiguous,
  and the startup line prints the scoping — but a set anchoring the account key
  for `exit` is a valid configuration that silently gives back exactly what this
  change removed. The set is small and it lives in the unit file; review is the
  control.
- **Roles are now a closed vocabulary in one place** (`AllRoles`). Adding a role
  means adding it there, or a single-key deployment silently stops admitting it.
  A test pins the list against the `Role` constants.

## Amendment (issue #26, 2026-07-29): a separate relay anchor, not the free `RoleRelay` reuse this ADR predicted

Issue #26 added per-hop relay-role admission verification to the client's chain
dial. §7/Consequences predicted how it would be built: `NewVerifier`'s AllRoles()
scoping means the client's existing exit anchor would already answer a
`RoleRelay` question if a caller simply asked it one — no new anchor required.
That remains true as a fact about `admission.Verifier`. It was not what shipped,
because of a consequence neither this ADR nor issue #26 had reason to consider
at the time: reusing the exit anchor would make per-hop verification's fail-open
gate `AdmissionPubKey`'s mere presence, so every client that had configured an
exit anchor for exit verification alone — every deployment before #26 existed —
would silently start verifying hops too, the moment it upgraded, against relays
that were never asked to present a `RoleRelay`-authorized credential under the
old code. Issue #26's own text ruled exactly that out ("must neither silently
start failing chains nor silently stop checking something it was checking"), so
the free reuse this ADR predicted was set aside in favor of a second,
independently-configurable anchor (`Config.RelayAdmissionPubKey`) that gates
only on its own presence. `admission.NewAuthoritySetVerifier` is still what
builds it, exactly as predicted — scoped to `RoleRelay` alone this time, rather
than `AllRoles()`, since there is no reason for a relay-only anchor to answer a
`RoleClient` or `RoleExit` question the way the client's single exit anchor
harmlessly does.

One respect in which the new anchor's guarantee is narrower than
`AdmissionPubKey`'s, worth recording here rather than only in ADR-0038: it is
not threaded through `New()`'s eager construction the way every other
`Config`-level admission field is. `core/relaychain.go` reads
`Config.RelayAdmissionPubKey` directly and builds the small per-hop verifier
itself, once per chain dial, rather than `New()` building and caching it on an
`Engine` field. A malformed value is still a hard failure, but it surfaces from
the first chain dial that needs it rather than from construction — traded to
land this change entirely within `core/relaychain.go`, `core/exit_admission.go`,
and the `Config` struct, without touching `Engine`'s construction path or its
field list. See the issue #26 amendment to ADR-0038 for the full account,
including the fail-closed-whole-chain decision for a hop that fails this check.
