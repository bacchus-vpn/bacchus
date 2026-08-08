# 63. The coordinator verifies signed revocation bundles offline, and a node's build revision joins the register wire

- Status: accepted
- Date: 2026-08-07
- Tracking: issue #199 (bacchus-payment#77, ADR-0017), issue #182
- Builds on: ADR-0043 (the signed-policy fetch-verify-cache mechanism this
  copies), the `core/delegation` general verifier ADR-0043 §1 established,
  issue #114 (the release-visibility line this extends)
- Implementation: `core/delegation` (`RoleRevocations`, `TagRevocationsDoc`);
  `core/revocation` (new — `Doc`, `Bundle`, `Verifier`, `Cache`);
  `cmd/coordinator/revocations.go` (new); `setupAdmission`
  (`cmd/coordinator/admission.go`), `setupDeviceCred`
  (`cmd/coordinator/devicecred.go`); `cmd/coordinator/main.go` (five new
  flags, the `"register"` handler's two log lines, the `wire.Build` field);
  `core/engine.go` (`wire.Build`, `nodeBuildRevision`, `renderBuildRevision`)

> Per-repo numbering: this `0063` is unrelated to anything the private
> `bacchus-payment` repository numbers the same, including its own `0017`
> this record ports.

## Context

Two independently-scoped cards share this record because they share a lane
and a reserved ADR number, not because they share a mechanism. Each is
recorded in its own decision section below.

**Issue #199** is the `bacchus` half of `bacchus-payment#77` / ADR-0017.
That record rules the hop from the account-service host to a coordinator's
`secrets/` directory untrusted (decision C3) and signs the two revocation
lists — the bytes `-device-revocations` and `-admission-revocations` already
hot-reload as plain files — under the offline root instead of trusting
whoever staged them. It built the entire authoring side in
`bacchus-payment`: a new role, a new signed-document package, the signing
wired into `revocation-sync`. Before this record, this repository had zero
occurrences of `RoleRevocations` or `bacchus/revocations/v1`, so the
arrangement was half-shipped exactly the way ADR-0043 found signed policy
half-shipped before it: a signer existed and nothing verified.

**Issue #182** is unrelated in mechanism and related only in spirit: `#114`
gave the coordinator a way to name its own build (`coordBuild`,
`describeBuild`) but explicitly not a node's, because a node's revision was
never on the register wire — `coordBuild`'s own comment says so: *"pairing
this against a node still means reading the node's own binary (`go version
-m`)."* On 2026-08-07 the live coordinator was found running a commit two
waves stale, and the only thing that revealed it was that startup line; its
three nodes had no equivalent and all reported `release=0.1.0` regardless of
which commit they actually ran. This record closes the field's absence; it
does not change what `#114`'s own warning line says (see decision 6).

## Decisions

### 1. `RoleRevocations` is additive to `core/delegation`, and inert by itself

`core/delegation.Role` admitted `policy` and `update`. This record adds
`RoleRevocations = "revocations"`, the same shape `RolePolicy`/`RoleUpdate`
already have, and extends `Role.Known()` to recognise it.

**This alone does nothing**, and the card that carried it was emphatic about
that for a reason worth restating here rather than only in a code comment:
`Known()` is advisory only — `VerifyDelegationCert` checks the *exact* role
its caller asked for, never consults `Known()`, and a caller that never asks
for `RoleRevocations` would behave identically whether or not this constant
existed. `TestVerifyDelegationCertAcceptsARevocationsRoleCert`
(`core/delegation/delegation_test.go`) is the proof that the role is live by
the same general verifier used for `policy` and `update`, not a value that
merely exists in the type; decision 2 is what actually asks for it.

### 2. The coordinator's fetch-verify-cache loop mirrors `-policy-root-pubkey` / `-policy-source`, in full

**"In full" means the cache, not only the fetch loop.** ADR-0017 §5 states
why explicitly: verify-before-replace alone protects steady state, but a
coordinator's own restart is the case ADR-0014 named as the sharp one — *"a
coordinator starting on an absent file logs nothing at all"* — and nothing
about refusing a bad fetch touches a process that has nothing held yet to
refuse replacing. What closes it is `core/policy.Cache`'s exact shape: the
last verified bundle plus the rollback floor, persisted on the coordinator's
own disk, re-verified against the current clock and root on every load,
restored *before* the first fetch of a new process.

**New package `core/revocation`** (`doc.go`, `revocation.go`, `verify.go`,
`cache.go`) is the port of `bacchus-payment/internal/revocation`, mirroring
how `core/policy` already ports `internal/policy` — same package name,
different import path, because that repository cannot be imported here and
the wire format is the contract:

- `Doc{Version, AsOf, Revoked}` and `Bundle{Revocations, Cert}`, field names
  and JSON tags matching `internal/revocation`'s byte for byte (`[]byte`
  members so `encoding/json`'s default standard-base64 encoding does the
  work, exactly like `policy.Bundle`).
- `Verifier.Verify` is the two-tier descent `policy.Verifier.Verify` already
  runs: tier 1 is `delegation.VerifyDelegationCert(rootPub, cert,
  RoleRevocations, now, revoked)` — decision 1's role, doing real work for
  the first time; tier 2 is `delegation.OpenSigned(cert.Pub,
  TagRevocationsDoc, ...)`, unmarshal, check `Version`. Rollback is `AsOf`
  where policy has `Seq` — `Verify` refuses `AsOf` strictly before the
  caller's floor and accepts equal, matching a healthy refresh loop
  re-verifying an unchanged bundle every tick.
- `Cache` is `core/policy.Cache` with `MinAsOf time.Time` in place of
  `MinSeq uint64` — same on-disk shape, same untrusted-file posture (every
  load re-verifies against the current root and clock), same atomic
  temp-file-then-rename write at `0600`.

**`cmd/coordinator/revocations.go`** (new) is the coordinator-specific
orchestration, mirroring `policy.go`'s `startPolicy` /
`refreshPolicyLoop` / `refreshPolicyOnce`: `startRevocations` (an empty root
disables the whole mechanism, exactly like `-policy-root-pubkey`),
`startRevocationsNamespace`, `refreshRevocationsLoop`,
`refreshRevocationsOnce`, `revocationsBackoffFor`. It reuses `policy.go`'s
own `policySource` / `newPolicySource` (an `http(s)` URL or a filesystem
path) directly — same package (`main`), no duplication, and a closer reading
of "mirror the mechanism" than reimplementing a parallel source abstraction
would have been.

**Two independent instances, one shared root.** `-revocations-root-pubkey`
is one flag because ADR-0017 decision 2's ceremony mints one role for both
lists — there is exactly one key whose authority this coordinator ever
checks here, so one `*revocation.Verifier` serves both namespaces.
`-device-revocations-source` / `-admission-revocations-source` and
`-device-revocations-state` / `-admission-revocations-state` are four flags
because the two namespaces' sources, on-disk state and rollback floors are
independent, matching how `-device-revocations` / `-admission-revocations`
already are.

**Installs into the SAME `atomic.Pointer[admission.RevocationList]`
`reloadRevocationsLoop` already populates**, per the card's explicit
requirement — not a parallel structure. `setupAdmission`
(`cmd/coordinator/admission.go`) and `setupDeviceCred`
(`cmd/coordinator/devicecred.go`) each already build exactly one such pointer
internally and start the plain-file reload loop against it; both now return
that pointer as an additional value (`nil` exactly when that namespace's own
gate is disabled — the same condition under which the plain-file loop
already does not start). `main()` passes each pointer into
`revocationsNamespaceConfig.target`, and a successful verify calls
`target.Store(...)` on a freshly built `admission.RevocationList`
(`installRevocationsDoc`) — literally the same "build fresh, then atomically
swap" shape `reloadRevocationsLoop` already uses, so a concurrent `Revoked()`
read can never observe a torn list.

**Additive, never a replacement, and additive in a stronger sense than
"turned off by default."** With `-revocations-root-pubkey` unset — the state
every coordinator ships in, and stays in until `bacchus-payment#79`'s
ceremony has run — behaviour is byte-for-byte what it was before this
record. Once configured, `-device-revocations` / `-admission-revocations`
are untouched: they keep hot-reloading the same file on the same 30s ticker,
completely unaware anything new exists. Both writers race the same pointer
by design, and whichever verified most recently wins — which is what lets an
operator run the plain file and the signed source side by side during a
migration, and simply stop maintaining the file once the signed path is
trusted, rather than needing a cutover step.

**A namespace whose gate is disabled is skipped with a warning, not an
error.** `-revocations-root-pubkey` set with, say, `-device-root-pubkey`
unset is a legal state — an operator may stage the signed source ahead of
turning the credential gate on — and there both nothing would ever install
into and nothing would ever read a device-namespace list, so
`startRevocationsNamespace` logs why and returns cleanly rather than either
crashing on a nil pointer or silently doing nothing. A namespace whose gate
*is* enabled but whose source is empty is the opposite case and is fatal,
mirroring `startPolicy`'s identical refusal: a root with nothing to verify
would fail closed forever, and a coordinator that came up looking configured
while silently never fetching anything is the confusion that check exists to
prevent.

### 3. The propagation figure was checked, not assumed

The card's first stop-and-return condition: *"if the 10-second refresh
interval turns out not to produce ADR-0017 decision 3's ~70-second worst-case
propagation figure, stop and say so rather than adjusting the number."*
ADR-0017 decision 3's corrected formula is *"revocation-sync's own interval
[60s, unchanged by that record] plus whatever interval the coordinator's
fetch-and-verify loop uses, one hop, not two,"* and it recommends this loop
mirror `policyRefresh` (10s) specifically because that is the number that
makes the corrected figure ~70s.

`revocationsRefresh = 10 * time.Second`, equal to `policyRefresh`, and
`TestRevocationsRefreshIntervalMatchesADR0017sPropagationFigure`
(`cmd/coordinator/revocations_test.go`) pins both the equality and the
arithmetic — `60s + revocationsRefresh == 70s` — as a standing regression
check rather than a one-time mental note. The figure holds; the condition
did not fire.

### 4. What was deliberately not mirrored from policy, and why that is not the second stop condition

The card's second stop-and-return condition: *"if mirroring the policy
mechanism 'in full' turns out to require behaviour the policy path does not
have, stop rather than inventing it."* Two things below look like omissions
and are not — both are decisions ADR-0017 already made on the authoring
side, restated here because the coordinator has to agree with them rather
than rediscover them:

- **No fail-closed drain, no `policyGate`/`policyAllowsAssignment`
  equivalent.** Signed policy blocks matchmaking when it is absent or stale
  because a coordinator that kept assigning on a stale policy would have
  authored policy by omission. A revocation list has no such property to
  preserve: it is *additive* to what `-device-revocations` /
  `-admission-revocations` already enforce, never the sole source of truth,
  so there is nothing here for an absent or unverified signed source to
  authorize by omission — the plain-file loop, unaffected, keeps enforcing
  whatever it last loaded either way.
- **No `Issued`/`Expires`/`Grace`, no age-out step in
  `refreshRevocationsOnce`.** `core/revocation.Doc` has no activation window
  because ADR-0017 decision 2 declined to invent one: a coordinator wants the
  freshest list it can verify, full stop, and a document-level expiry would
  be a second staleness mechanism sitting on top of `revocation-sync`'s own
  `-max-stale` escalation. With no window, there is nothing to age out of,
  so `refreshRevocationsOnce` has no `clearPolicy`-shaped branch — a
  deliberately smaller function than `refreshPolicyOnce`, not an
  incompletely-ported one.

Both are the authoring side's decisions, not this lane's; mirroring "in
full" bound the fetch/verify/cache *machinery*, and neither of these is
machinery.

### 5. A node's build revision joins the register wire, kept off `Release` (issue #182)

`Release` is a wire field a client and a coordinator both parse as semver
(ADR-0015); a release ships many commits, so two builds from either end of
one report the identical string and are not the same binary — the exact skew
`#114` was filed about, now visible on the coordinator's own side
(`coordBuild`) and invisible on a node's. The fix is a **separate** field,
`wire.Build`, never folded into `Release`, for the reason `coordBuild`'s own
comment already gives for keeping the coordinator's revision off every wire.

**Where the sending half actually lives is a correction to the card, stated
plainly rather than worked around.** The brief names `cmd/node/` as the
sending half's home; `cmd/node/main.go` is a thin flag-parsing wrapper around
`core.Config` and `core.New` and has no register-construction code at all —
the `wire` type, `registerLoop`, and the two `wire{Type: "register", ...}`
literals it stamps `Release` onto all live in `core/engine.go`. No other
lane's brief claims `core/engine.go` (Lane 1's `core/coordpool.go` and
`core/client.go`'s connect fields, Lane 2's `core/coordpool.go`,
`core/client.go`'s connect-field construction and
`core/devicecred_connect.go` are all distinct files), so the sending half is
built there instead.

**`nodeBuildRevision()` / `renderBuildRevision()`** (`core/engine.go`) mirror
`coordBuild()` / `describeBuild()`'s own split (`cmd/coordinator/main.go`)
for the identical reason stated in that function's own comment: a test
binary carries the VCS settings the toolchain gave *it*, so the
`debug.ReadBuildInfo()`-calling half is untestable and everything about the
format lives in the split-out half instead, where
`TestRenderBuildRevision` (`core/build_revision_test.go`) can pin it against
synthetic settings the way `TestDescribeBuildNamesTheBuild`
(`cmd/coordinator/release_visibility_test.go`) already does for the
coordinator's own. The wire value is terser than `describeBuild`'s
human-readable `", uncommitted changes"` — a `-dirty` suffix, `git
describe --dirty`'s convention — because this rides a register sent every
10 seconds rather than only a startup banner. Computed once, alongside
`release`, in `Start`; both ride the same per-role `wire{...}` template
`registerLoop` re-sends unchanged.

**Empty is the ordinary case and must not read as suspicious**, the second
constraint the card already established: the toolchain records VCS data only
from a checkout with a real `.git` directory, and a build made in a git
**worktree** — how every lane in this project builds, this one included — or
under `go test` carries none.
`TestRegisterCarriesTheNodesBuildRevision` (`core/build_revision_test.go`)
doubles as the end-to-end proof of exactly that: run from this worktree, it
asserts the register's `Build` field equals whatever `nodeBuildRevision()`
answers for this binary — which is empty here — so the same test exercises
both the populated and the empty path depending on where it runs, without
special-casing either.

**The coordinator's receiving half is the register handler's own log
line** — the region this lane owns in `cmd/coordinator/main.go` — not a new
function. Both `"relay registered:"` and `"exit registered:"` gain
`build=%s` beside `release=%s`, with a local `"unknown"` fallback for an
empty field, mirroring `releaseOrUnknown`'s existing shape inline rather than
adding a new top-level helper next to functions this lane does not own.
`TestRegisterLogsNodeBuild` / `TestRegisterLogsUnknownBuildForAWorktreeNode`
(`cmd/coordinator/register_build_test.go`) mirror `#114`'s own
`TestRegisterLogsNodeRelease` / `TestRegisterLogsUnknownReleaseForLegacyNode`
(`cmd/coordinator/release_visibility_test.go`) precisely.

**A second, small correction, stated for the same reason as the first.**
Populating `wire.Build` required one field addition to the `wire` struct in
`cmd/coordinator/main.go`, which sits outside the two regions
(`"register"`'s branch and its log line; the revocation-source flags and
their `start…` calls) this lane's file ownership names. There is no way to
satisfy the card without it — the field the register handler reads has to
exist on the struct it is a member of — so it was added, placed immediately
beside `Release` with a comment in the same style, and is called out here so
the merge is expected rather than discovered, exactly as the brief asks for
the two owned regions themselves.

### 6. Conformance is bytes: the frozen vectors, and an out-of-band cross-repo check

`core/revocation/testdata/{vectors,negative_vectors}.json` are copied
verbatim from `bacchus-payment/internal/revocation/testdata` — byte-identical,
confirmed with `diff` — the same discipline `core/policy/testdata` already
follows for the signed-policy fixture. `core/revocation/vectors_test.go`
(mirroring `core/policy/vectors_test.go`) loads them and: verifies the frozen
positive bundle at its own instant and checks every `expect_*` field parses
correctly, including that re-verifying at a floor equal to its own `AsOf`
still accepts (steady-state) while one nanosecond past refuses
(`ErrRollback`); runs all 15 frozen negative cases and requires the *named*
error, not merely a refusal; and re-derives the published development root
from its seed phrase to prove the fixtures are rooted in the public throwaway
rather than trusting their own claim to be one.

**Out of band, not committed**: a throwaway Go module in this lane's
scratchpad, `go.mod`-`replace`d onto this worktree, consumed
`bacchus-payment`'s own canonical `testdata` files — read from their real
path in the sibling repo, not this repository's copy — through
`core/revocation`'s public API alone, and independently reached the same
accept/refuse verdicts and the same parsed values `bacchus-payment`'s own
`go test ./internal/revocation` (also run, read-only, immediately beforehand)
already confirmed. Neither repository gained a dependency on the other:
`bacchus-payment` has no importable package outside `internal/`, so no
throwaway module can import its signer regardless of a replace directive —
what crossed the repository boundary was bytes on disk, read twice, by two
independent implementations, which is the whole of what this check can prove
and the whole of what it needs to.

## Consequences

1. **Item 4 of `bacchus-payment#77`** — whether the untrusted hop can
   un-revoke a serial — **is closed by design once this record's mechanism is
   live**, per ADR-0017 decision 5's two-property specification
   (verify-before-replace, a persisted cache restored before the first
   fetch), both built here. It is not yet closed *in this deployment*:
   nothing on this side consumed a Bundle before this record, and going live
   needs the real `revocations` delegation from `bacchus-payment#79`'s
   ceremony, which is the owner's and is not gated by this PR.
2. **`RoleRevocations` and `core/revocation` exist and are inert until a real
   delegation is minted.** `-dev`-style throwaway-root testing (this
   record's own vectors and cache tests) exercises the complete path today;
   nothing mints a production cert for this role yet.
3. **`-device-revocations` / `-admission-revocations` are untouched.** No
   existing test needed to change; every new one is additive, matching the
   scope note issue #199 itself states.
4. **`#114`'s `reportUnansweredNodes` warning still does not name a node's
   build revision.** The wire now carries it and the register handler's log
   line now prints it, but wiring it into the *silent-node* warning
   specifically touches `forwarderHealth`, `carryHealth` and
   `reportUnansweredNodes` — none of which this lane's file ownership names,
   and none of which this card's own "done when" bar (*"a node's revision
   reaches the coordinator's log beside `release=`"*) requires. Left as a
   natural, and now trivial, follow-up: the field already exists on every
   register.
5. **Revocation of the `revocations` DELEGATION itself is not wired.**
   `revocation.NewVerifier` in `startRevocations` is built with a `nil`
   revoked-predicate, mirroring `startPolicy`'s identical, identically-reasoned
   choice: the delegation's own window bounds the exposure until a signed
   short-TTL CRL for this hop exists, which — like policy's equivalent gap —
   is a follow-up rather than something invented here.

## Verification

- `core/delegation`: `TestRoleKnown` extended to `RoleRevocations`;
  `TestVerifyDelegationCertAcceptsARevocationsRoleCert` proves the role is
  live through the general verifier, not merely declared.
- `core/revocation`: `revocation_test.go` (`ParseBundle` malformed-input
  cases, `NewVerifier`'s fail-closed direction, an empty-`Revoked` `Doc`
  round trip, the standard-base64 wire encoding of `Bundle`'s two `[]byte`
  members); `cache_test.go` (eleven cases mirroring `core/policy`'s Cache
  suite — cold start, round-trip re-verification, storing bytes rather than
  a parsed struct, refusing a cache entry whose delegation has passed its
  window while still keeping the floor, re-verifying against a foreign root
  and against a revoked delegation, the floor ratcheting under both `Store`
  and `StoreFloor`, re-accepting the same `AsOf`, atomic writes with no
  stray temp files); `vectors_test.go` (positive and all 15 negative frozen
  cases, the rollback boundary at exactly the accepted floor, the
  published-devroot self-check).
- `cmd/coordinator`: `revocations_test.go` (opt-in when unset, fatal
  misconfiguration mirroring `startPolicy`'s, a disabled-gate namespace
  skipped rather than panicking on a nil target, a successful verify
  installing into the exact `atomic.Pointer[admission.RevocationList]`
  passed in, persistence surviving a simulated restart with an older
  generation refused at the restored floor, a garbage or unreachable fetch
  leaving an already-installed serial revoked, backoff shape, and the
  ADR-0017 propagation-figure arithmetic pinned as a standing check);
  `register_build_test.go` (`build=` on both role branches,
  `build=unknown` for an empty field, mirroring `#114`'s own release
  tests).
- `core`: `build_revision_test.go` (`renderBuildRevision` against synthetic
  `debug.BuildSetting`s — stamped, dirty, unstamped, a short revision left
  unpadded; an end-to-end register carrying whatever `nodeBuildRevision()`
  answers for the running binary, which is empty in every worktree build,
  this one included).
- An out-of-band, uncommitted throwaway module (decision 6) independently
  re-verified `bacchus-payment`'s own canonical frozen vectors through
  `core/revocation`'s public API via a `go.mod replace`, agreeing with
  `bacchus-payment`'s own reference verifier run immediately beforehand.
- `gofmt -l .` clean, `go vet ./...` clean, `go build ./...` clean,
  `go test -race -count=1 ./core/... ./core/delegation/... ./core/revocation/...
  ./cmd/coordinator/...` green, `go test -count=1 ./...` green across the
  whole repository.

## Follow-ups

1. **The signing ceremony** (`bacchus-payment#79`, `needs-owner-test`,
   filed on the payment side) mints the real `revocations` delegation and
   gates this mechanism going live in production. Not gated by this PR, per
   ADR-0017 decision 6's "build, then ceremony, then live" sequencing.
2. **`#114`'s `reportUnansweredNodes` naming a node's build divergence
   directly**, per consequence 4 — a small change now that the field exists
   on the wire, out of this record's stated scope.
3. **A signed short-TTL CRL for the `revocations` role's own delegation**,
   per consequence 5 — the same residual `-policy-root-pubkey` already has,
   named rather than newly discovered.
4. **`#173`** (revoke a serial, watch a real client be refused, end to end)
   becomes runnable through the untrusted hop only once follow-up 1 has
   landed; ADR-0017 already states this and this record does not change it.
