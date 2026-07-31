# 50. The macOS tunnel mechanism: `NEPacketTunnelProvider` in a system extension, because `pf` has no arbitration scheme

- Status: accepted
- Date: 2026-07-31

## Context

#36 `[E9]` brings macOS to the enforcement level Windows reached in #59. macOS has less
than Linux did: `clients/internal/enforcement/enforcement_darwin.go` returns a
`NotImplementedError`, `internal/appstate`'s autostart falls through to a no-op stub, and
there is no build target, no CI job and no macOS client code of any kind.

The card names two routes and says they are not equivalent — `NEPacketTunnelProvider`, or
a privileged helper plus `utun` — and asks for one to be picked and the reasoning
recorded. It also flags, in its Depends-on section, that an unsigned or un-notarized macOS
app is refused by Gatekeeper outright, which makes the Apple dependency a purchasing
decision rather than a polish item.

ADR-0049 settled the equivalent question for Linux one commit ago, and the shape of its
argument — reject an option by naming the specific mechanism that kills it, not by
comparing features — is the shape used here. **The answer is different, and the reason it
is different is that on macOS the OS supplies and supervises the privileged half rather
than leaving us to build it.** Where the two records agree and where they part is set out
below.

**What #36 has to build is not the same shape as #37's, and that is the finding that
drives everything else.** ADR-0049 could open by observing that a Linux backend implements
`osNet` and inherits `tunnel.go`, `poolroutes.go`, `splittunnel.go`, `tun2socks.go`,
`addrs.go` and `redact.go` unchanged — 1,317 of `clients/windows`' 1,969 enforcement lines,
per ADR-0039's costing, which #59 moved. That is true of Linux. It is **not** true of
macOS under the decision below, and two files on `main` currently assert that it is (§5).

ADR-0039's parity bar applies to macOS in full: the eight enforcement items, plus items
9–12, the configuration axis added by its 2026-07-30 amendment (#93). The two halves
arrive differently, and the difference is worth stating because it is easy to over-scope
#36: items 9–12 are not platform-specific, and ADR-0039 says so directly — `[E9]`/`[E10]`
*"inherit them satisfied rather than owing them."* So macOS owes items **1–8** and
inherits **9–12**. Item 7 is this record's direct subject — *"Elevated execution is real
and documented for the platform ... and what happens when it's missing — silently
degrading to unprotected is the one failure mode this whole bar exists to rule out."*
Item 2, the fail-closed kill-switch, is what decides the mechanism.

## The Apple dependency, priced

This section exists because #36's build half can be blocked for weeks by a purchase nobody
made, and the owner should learn the number and the calendar here rather than from a
failing build. Everything below was checked against Apple's own current documentation and
Developer Technical Support statements rather than taken from the card.

### What the money is, and what it gates

**99 USD per year**, the Apple Developer Program, billed annually and lapsing if unpaid.
It is not a one-time cost and it is not refundable per-build.

What it gates is a single certificate: **Developer ID Application**. That certificate is
issued only to paid members, and it is the only key Apple's notary service will accept.
The chain is short and every link is mandatory:

Apple Developer Program membership → Developer ID Application certificate → notarization →
Gatekeeper admits the app.

Since macOS 10.15, all software distributed outside the Mac App Store must be notarized.
Gatekeeper denies unsigned or un-notarized software, and macOS 15 removed the
Control-click override that used to let a determined user bypass it — the remaining escape
is a per-app approval buried in System Settings › Privacy & Security. For a
censorship-circumvention tool aimed at non-technical users under pressure, an install flow
that begins with "your Mac says this is malware, here is how to override it" is not a
shippable flow.

### Notarization is required for both routes, not one

This is the finding that matters most, and it inverts the card's framing.

#36 presents the helper route as the one that escapes Apple: *"no entitlement, ships as a
direct download."* The entitlement half is true. The escape is not. **Gatekeeper gates the
application bundle, not the tunnel mechanism inside it.** A privileged-helper build is
still a macOS app distributed outside the App Store, so it still needs a Developer ID
certificate and still needs notarizing, and it needs the paid membership to get either.

The helper route is in fact slightly *more* entangled with code signing, not less. Both
`SMJobBless` and its replacement require the privileged helper to be signed with a
Developer ID Application certificate and require the app and helper to pin each other by
code-signing requirement — that mutual pinning is the entire security model of the install.
So the helper route needs the same account, the same certificate and the same notarization,
plus a second signed binary with a signing-requirement string that must be kept in sync.

**Neither route avoids Apple. The Apple dependency therefore cannot be used to choose
between them, which is why the decision below turns on something else entirely.**

### The NetworkExtension entitlement is self-serve, and is not reviewed

The card treats the NetworkExtension entitlement as a gate. It has not been one for nearly
a decade.

Originally every Network Extension facility required a *managed capability* — an
application to Apple, granted or refused. **That policy changed in November 2016.** Packet
tunnel providers, app proxy providers and content filter providers became ordinary
capabilities that any paid member enables themselves, in Xcode or in the developer portal,
with no request and no review. Apple's Developer Technical Support restated this as
recently as March 2026, in answer to a developer asking this exact question: there is no
approval process for creating a Network Extension packet tunnel provider, and any paid
developer can do it.

Two details the build half needs:

- For Developer ID distribution — which is our channel — the entitlement takes the
  **`-systemextension` suffixed values**, and the Developer ID provisioning profile is what
  allow-lists them. The unsuffixed values are for development signing. Mixing the two is
  the single most common way this is reported as broken, and it is a signing-configuration
  error rather than an entitlement refusal.
- The container app additionally needs `com.apple.developer.system-extension.install`, and
  Developer ID builds need their provisioning profile generated manually rather than by
  Xcode's automatic signing.

What *does* still require a managed-capability request is the Hotspot Helper and the
Network Extension app-push provider. Neither is anything this project uses, so **there is
no Apple review anywhere on our path**.

### The lead time is enrollment, and it is the only real calendar item

Since the entitlement is self-serve and notarization is a per-build step that returns in
minutes, the only thing on this path with a lead time measured in days is **getting into
the program in the first place**:

| Step | Lead time |
|---|---|
| Individual enrollment | 24–48 hours, typically |
| Organization enrollment | 1–2 weeks typically, reports of 2–4 |
| D-U-N-S number, if the organization lacks one | up to 5 business days to issue, up to 2 more to reach Apple |
| Entitlement | none — self-serve, no request |
| Notarization, per build | minutes; a per-release step, not a gate |

Individual enrollment needs no D-U-N-S number; organization enrollment does, registered to
the legal entity. There are also standing reports through 2026 of enrollments sitting in
"processing" for weeks with no recourse, which is not a documented SLA but is a real risk
to plan against.

**The practical instruction: start enrollment before #36's build half is scheduled, not
when it begins.** Nothing else on this path takes calendar time, and this one cannot be
accelerated by paying more or by choosing a different tunnel mechanism.

### What a Developer ID binds, which is not a cost but is a disclosure

A Developer ID certificate is issued to a verified legal identity — a named individual for
individual enrollment, a D-U-N-S-registered entity for an organization — and the signature
travels in every shipped binary. Anyone who downloads the client can read who signed it,
and Apple can revoke that certificate, which disables the software on machines that check.

This is a distribution-channel property, not a flaw in either tunnel route, and it applies
identically to both. It is recorded here because it is a fact about shipping a
circumvention tool on macOS that the owner should decide about knowingly rather than
discover at signing time, and because "individual or organization" is a threat-model
question as much as an accounting one.

## Decision

### 1. `NEPacketTunnelProvider`, shipped as a system extension inside the app bundle

macOS enforcement is a Network Extension packet tunnel provider, packaged as a **system
extension** (`Contents/Library/SystemExtensions`), signed with Developer ID, notarized, and
distributed as a direct download. The user approves the extension once, through the
system's own flow.

macOS supplies and supervises the privileged half. There is no `bacchus-netd` on macOS, no
unix socket, no `SO_PEERCRED` check, no root daemon of our making, and no install step that
requires root.

### 2. Rejected: a privileged helper plus `utun` — `pf` has no arbitration scheme

This is the option ADR-0049 chose for Linux, and on macOS it is rejected. Not on taste,
not on Apple's preferences, but on a specific mechanism that breaks a specific parity item.

**The kill-switch is parity item 2**: a fail-closed, default-deny OS-level filter with a
narrow allowlist, which must survive the client process being killed. On macOS, the only
filter a root helper can install is `pf`.

`pf` cannot carry that guarantee, and Apple's own Developer Technical Support says why:
there is no documented arbitration scheme for `pf` rules, so a third-party developer's
rules may be incompatible with those installed by macOS features, by other third-party
products, by the user, or by a site administrator. There is no ownership, no locking, and
no reservation. Another product doing the equivalent of a full flush removes our rules;
our anchor can equally disrupt theirs.

Compare what ADR-0049 relied on. On Linux the helper owns a **named nftables table**, added
and removed in atomic transactions, which nothing else touches — that ownership is what
lets §8 of that record promise the lockdown survives, and lets `recoverKillSwitch` reap
*its own* orphan with no heuristic about whose lockdown it is. macOS `pf` has no
equivalent. The Linux design's central safety property does not port, and the thing that
fails is precisely the item the whole parity bar exists to protect.

A kill-switch that a third party can silently flush is not fail-closed; it is a kill-switch
that reports armed and is not. ADR-0039's bar calls that failure by name — a partial
`Enforcer` shipped as if it were parity is *"this ADR's Scope-section lie"* — and parity
item 8 exists to catch exactly it with a traffic-level test. We would be shipping a
mechanism we knew could not be proven.

Apple's broader position is consistent and is recorded here rather than argued with:
DTS does not support the ad hoc techniques — `pf`, a `utun` interface, network kernel
extensions — and directs anyone building a product like this to create a Network Extension
provider, on the stated grounds that ad hoc techniques are brittle and not supportable long
term. That policy alone would not decide a design question for us. Paired with a concrete
mechanism failure on a security-critical parity item, it stops being an opinion and starts
being a description of what we would be maintaining.

Two further costs of the helper route, neither decisive on its own:

- `SMJobBless`, which the card names, was **deprecated in macOS 13** in favour of
  `SMAppService` registering a launch daemon. The card's mechanism is stale; this does not
  change the answer, but any estimate built on the card's wording is costing the wrong API.
- macOS's resolver would have to be fought by hand rather than configured (§8).

### 3. The card's objection to NE does not apply on macOS

#36 says NE *"constrains the architecture: the tunnel runs in a separate extension process
with its own memory ceiling."* The separate process is real (§4). **The memory ceiling is
not — it is an iOS constraint imported into a macOS card.**

iOS enforces a hard memory limit on Network Extension providers: 15 MB historically, raised
to roughly 50 MB in iOS 15 and later. That limit is why lean cores matter on iOS and why
heavy ones crash there. macOS does not impose it. Apple's DTS states that macOS does not
limit Network Extension providers, and the jetsam properties that encode these limits carry
`-1` — no enforced limit — for both `com.apple.networkextension.packet-tunnel` and
`com.apple.networkextension.app-proxy`.

Recorded with its caveat, because the caveat matters for how much weight to put on it: the
file that shows this is explicitly not API and must not be relied on in shipping code. The
sound conclusion is the negative one — **there is no documented macOS memory ceiling to
design against, and the iOS figure must not be used to size the macOS core.** It remains
true that this constraint is real and binding for any future iOS work, where our core's
size would be a live question.

So the one architectural objection the card raises against NE is, on macOS, not a
constraint at all. The real cost of NE is a different one, and the card does not mention it.

### 4. What this costs: ADR-0039's in-process core does not survive on macOS

Stated plainly, because it is the largest consequence of this decision and it contradicts
a decision already on the books.

ADR-0039 is titled *"Cross-platform client: all-Go Fyne UI calling core in-process, no
webview,"* and its Decision states the seam in full — *"Fyne UI calling `core.Engine`
in-process, no FFI layer, no webview."* On macOS, under NE, the core is **not** in-process
with the UI.

A Network Extension provider runs in a process macOS creates and supervises, and its
principal class must be a class the Objective-C runtime can instantiate from a properly
structured extension bundle. A plain Go binary cannot be an NE provider. The packet
interface — `NEPacketTunnelFlow` — exists only inside that process, so the netstack must be
there too: `tun2socks.go`'s gVisor bridge, `core.Engine`, the transport pool, the WebRTC
and Reality transports. All of it moves into the extension.

That means, concretely:

- the Go core is built as a C archive (`-buildmode=c-archive`) and linked into a
  Swift/Objective-C system extension target;
- the Fyne GUI stays a Go binary in the app bundle and becomes a **controller**, driving
  the tunnel over `NETunnelProviderSession` rather than calling into the core directly.

This is a well-trodden path rather than a speculative one, which is the main reason it is
acceptable: WireGuard's own Apple port does exactly this, building its Go implementation as
`libwg-go.a` and linking it into a Swift Network Extension target. The precedent is a Go
VPN core of comparable shape shipping on Apple platforms this way.

The scope of the contradiction should not be overstated, and it is narrower than the ADR's
title suggests:

- **ADR-0039's UI ruling survives intact.** Fyne is still the client on macOS; #35's "Fyne
  everywhere" decision is untouched, and items 9–12 are inherited satisfied because the
  settings surface is the same Go code.
- **ADR-0039's "no FFI layer" clause becomes platform-conditional.** It holds on Windows
  and Linux. It does not hold on macOS, and it cannot be made to.

This record does not amend ADR-0039 — it identifies where ADR-0039's premise runs out and
leaves the amendment to whoever takes #36's build half, which is when the bridge's actual
shape will be known.

### 5. The `osNet` seam does not fit macOS, and two files on `main` say it does

`osNet` is the porting surface `#59` created: fourteen primitives a platform implements,
inheriting `tunnel.go`'s bring-up sequencing and the rest. Under NE, macOS does not
implement those primitives, because NE does not offer them. You do not add routes, create a
TUN, or install a split default; you construct an `NEPacketTunnelNetworkSettings` object —
addresses, `includedRoutes`/`excludedRoutes`, DNS settings — and hand it to the system,
which applies it atomically.

What the fourteen methods become:

| # | `osNet` method | Under NE on macOS |
|---|---|---|
| 1 | `defaultGateway` | not needed — the system owns the physical route and preserves it |
| 2–3 | `addExclusionRoutes` / `V6` | `excludedRoutes` on the tunnel settings |
| 4 | `addInclusionRoutes` | `includedRoutes` on the tunnel settings |
| 5 | `removeRoutes` | re-apply settings; there is no incremental route removal |
| 6 | `createTUN` | the system creates it; the provider gets `packetFlow` |
| 7 | `configureTunInterface` | `NEIPv4Settings` on the tunnel settings |
| 8 | `addSplitDefaultRoute` | `includedRoutes` containing the default route |
| 9–10 | `disablePhysicalIPv6` / `enable` | no IPv6 settings on the tunnel; leak analysis per item 6 |
| 11–13 | `enableKillSwitch` / `disable` / `recover` | `includeAllNetworks` on the protocol configuration |
| 14 | `refreshKillSwitchAllowIP` | re-apply settings, or `excludeLocalNetworks` scoping |

Five of the fourteen collapse into one declarative object, and the kill-switch trio
collapses into a flag the system enforces.

**Two files on `main` assert the opposite, and #36's build half must correct both:**

- `clients/internal/enforcement/enforcement_darwin.go` scopes the card as *"the same shape
  as `[E10]`'s: implement osNet (osnet.go) and inherit the rest,"* with the from-scratch
  half named as *"a BSD routing socket or `route`/`networksetup`, plus `pf`/`pfctl` for the
  kill-switch."* That is the rejected option, written into the stub as though it were
  settled.
- `clients/internal/enforcement/osnet.go`'s package doc lists the per-platform mechanisms
  and gives macOS as *"a BSD routing socket plus `pf` on macOS (`[E9]`, bacchus#36)."*

Both predate this decision and neither is wrong about anything that had been decided at the
time. They are wrong now, and a reader estimating #36 from either will cost the wrong
design. Correcting them is a code change, so it belongs to the build half rather than to
this record.

One consequence of the seam not fitting, which is easy to miss and is a genuine loss:
`tunnel_test.go`'s five pinned orderings — control-plane exclusion before the route flip,
kill-switch armed last, a failed bring-up orphaning nothing, include mode never installing
a split default, `Close` restoring egress before removing the tunnel — are inherited
*structurally* on Linux, because Linux inherits `tunnel.go`. macOS does not inherit them.
The system applies settings atomically, so most of the orderings have no macOS analogue at
all; the ones that do — what happens when bring-up fails partway, what `Close` restores —
must be re-established against the NE lifecycle rather than assumed. That file's own doc
says it exists to tell `[E9]` and `[E10]` what correct means. It does that job for `[E10]`.
For `[E9]` it now describes a design macOS does not use.

### 6. What NE supplies that the helper route would have had to build

Recorded so the decision reads as a trade rather than a capitulation:

- **The kill-switch.** `NEVPNProtocol.includeAllNetworks` is Apple's own fail-closed
  primitive — available on macOS since 10.15, alongside `excludeLocalNetworks` — and
  Apple documents its semantics as exactly what parity item 2 asks for: when it is set and
  the tunnel is unavailable, the system drops all network traffic. It is enforced by the
  system, so there is no arbitration problem and nothing for a third party to flush. This
  is the item that decided the mechanism.
  Held to the same standard as everything else here: there are developer reports of
  `includeAllNetworks` not behaving as documented in some releases, so #36 must **prove**
  the drop with parity item 8's traffic-level test on hardware rather than trust the flag.
  The difference from `pf` is not that NE is assumed correct — it is that NE's failure
  would be an OS bug to file, while `pf`'s is the documented absence of a guarantee.
- **The privileged half, supervised.** ADR-0049's §9 — the full account of what a
  compromised GUI can make a root helper do — has no macOS counterpart, because there is no
  root helper of ours to compromise. That entire attack surface does not get created.
- **Crash recovery.** Parity item 3's stale-lockdown problem largely dissolves: the system
  owns the tunnel's lifecycle and tears down its configuration when the provider stops.
  What remains for #36 is to verify that claim rather than assume it.
- **Installation.** No root install step, no group, no unit file, no version-matched second
  binary. ADR-0049 lists all of those as Linux's cost; macOS does not pay them. Against
  that, macOS pays 99 USD a year and a notarization step that Linux does not have.

### 7. Autostart is smaller than it looks, and carries a build-tag trap

`internal/appstate/autostart_other.go` is the no-op stub, and its doc already names macOS
as the platform falling through it. #36's autostart item replaces it with a launchd
registration — a login item via `SMAppService` on macOS 13+, rather than a hand-written
LaunchAgent plist.

Two things worth having written down:

- **Under NE, launch-on-boot and connect-on-boot are separate problems, and only the first
  is this item.** The tunnel does not need the GUI running to come up: NE has on-demand
  rules and the system starts the provider. So `SetLaunchOnBoot` on macOS governs whether
  the *controller* appears at login, which is a smaller and less security-relevant question
  than it is on Windows or Linux. Connect-on-boot, if wanted, is an NE on-demand
  configuration and is not this item.
- **The stub's build tag is `//go:build !windows && !linux`, which matches darwin.** Adding
  `autostart_darwin.go` without narrowing that tag to `!windows && !linux && !darwin` gives
  a redeclared `SetLaunchOnBoot` and a build break on the one platform being added. This is
  a two-file change, not a one-file change.

### 8. DNS: macOS's problem is real, and it is not systemd-resolved's

#104 splits the DNS primitive out of #37 and names macOS explicitly as needing an answer at
the same time as Linux. Here is what macOS's answer looks like, because its resolver
situation is structurally different.

**Linux's problem is that the query is unroutable.** systemd-resolved puts `127.0.0.53` in
`/etc/resolv.conf`, the kernel consults the `local` table before `main`, and so no
split-default route can capture loopback. The interceptor never sees the query.

**macOS has no equivalent loopback stub.** Queries go to the actual configured resolver
addresses, which are ordinary routable addresses, so a split default would capture them and
`tun2socks.go`'s `handleDNSUDP` would see them. That failure mode does not exist here.

What macOS has instead is **scoped DNS**. `mDNSResponder` maintains per-interface resolver
configurations and can bind a query to a specific interface, at which point the query
follows that interface rather than the routing table — so a query can leave the physical
adapter while a tunnel is up, without any route being wrong. This is not hypothetical: there
are current reports of macOS re-ranking interfaces after a connectivity failure and sending
DNS out the physical adapter instead of the tunnel, and of stale VPN resolver entries
surviving disconnection.

The consequences match Linux's exactly even though the mechanism does not, which is why
#104's Exit criteria apply unchanged:

- **Kill-switch armed:** the scoped query egresses the physical interface to a plaintext
  resolver the allowlist deliberately does not cover. Dropped. A tunnel and no DNS.
- **Kill-switch off:** it leaves in the clear. A leak.
- Either way `splittunnel.go`'s bypass-domain learning stops seeing queries, which is the
  mechanism ADR-0025 built for `old #40`.

**The decision above changes what fixing this costs on macOS, and this is a point in NE's
favour that only became visible after the mechanism was chosen.** Under the helper route,
macOS would have needed the same new `osNet` primitive Linux needs, implemented against
System Configuration by hand. Under NE, the tunnel's DNS configuration is declarative:
`NEDNSSettings` on the tunnel settings object, with a match-domains list, is the supported
way to make the tunnel's resolver authoritative, and `mDNSResponder` honours it as system
configuration rather than as a third party fighting it.

**#104's macOS half stays open.** This record notes that macOS's mechanism is
scoped DNS rather than an uncapturable loopback address, that NE gives a declarative answer
where the helper route would have given a manual one, and that the interface-ranking
behaviour above is an OS behaviour no design of ours controls — so #36 must verify DNS
egress on hardware rather than infer it. #104 stays open and keeps its three-platform
framing; what changes is that macOS's answer is now expected to be a settings field rather
than a fourteenth-method sibling.

### 9. Release scope is client-only

#36 asks, and says it assumes client-only unless changed. **Confirmed: client-only for the
release.** The reasoning, and the reason it is cheap to revisit:

macOS is fully node-capable — unlike iOS, nothing about the OS prevents relaying or
exiting — so this is a product decision, not a technical limit. Two facts make it a clean
one:

- **The node role costs nothing to keep available.** `cmd/node` imports no enforcement code
  and carries no build tags; it cross-compiles to `darwin/arm64` from this Linux
  workstation today, with cgo disabled, producing a working binary. Verified rather than
  assumed. The tunnel-mechanism decision and the node role share no code and no
  constraint.
- **The client is the part that cannot be cross-compiled.** `clients/fyne` fails to build
  for darwin without cgo — its GL binding excludes every file — which is what forces a
  macOS CI runner and is the actual content of #36's build-target item. That asymmetry is
  worth stating precisely: the node is free, the client is not.

Shipping a macOS node would mean a second distribution artifact, its own launchd lifecycle,
its own update path and its own support burden, for capacity from laptops that sleep and
roam — the weakest kind of relay. None of that is blocked by anything here, and adding it
later reopens no decision in this record.

One consequence of #36 landing at all, which belongs to the volunteer switch rather than to
this decision but is triggered by it: `appstate.ErrVolunteerWhileRouted` currently reads
*"`[E9]` macOS and `[E10]` Linux are proxy-only and can serve now."* Once macOS routes the
device, that stops being true and macOS joins Windows in refusing to serve. The refusal is
driven by a `deviceRouted bool` fed from `Controller.DeviceEnforced()`, so it is
mechanism-agnostic by construction — **but under NE that boolean must be fed from the
extension's state rather than from an in-process `Enforcer`, and a wrong answer turns a
security refusal into a silent no-op.** #12's stored-opt-in case (#101) meets the same
seam.

## Where this parallels ADR-0049, and where it diverges

Asked for explicitly, because a reader coming from #37 will expect the Linux answer and
should be told precisely which parts transfer.

**It parallels ADR-0049 in method, not in outcome.** Both records reject options by naming
the mechanism that kills them rather than by comparing feature lists; both find the card
mis-scoped and say so; both decline to close their issue.

**Genuine parallels:**

- **The decisive argument is a mechanism, not a preference.** Linux's was the TUN file
  descriptor — the netstack runs in the client process, and only a unix socket can pass an
  fd. macOS's is `pf`'s missing arbitration scheme. In both cases one specific technical
  fact eliminates the alternatives, and in both cases it is a fact about where the packets
  and the privilege have to live.
- **The card under-costs the platform's own OS integration and over-costs the port.**
- **Neither record closes its card.** Both are design halves.

**Genuine divergences, and they are the substance:**

- **Linux keeps the `osNet` seam; macOS does not.** This is the largest one. `[E10]` is a
  port behind an existing interface plus a helper; `[E9]` is a different client
  architecture on one platform.
- **Linux builds the privileged half; macOS is given it.** ADR-0049 spends four sections on
  what crosses the boundary, what the privileged side validates, and what a compromised GUI
  can do, because it creates a root attack surface. macOS creates none, so those sections
  have no counterpart.
- **The fd argument does not carry over, though the mechanism exists.** The vendored
  wireguard-go splits on darwin exactly as it does on Linux — `CreateTUN`
  (`tun_darwin.go:85`) opens the `AF_SYSTEM` control socket and connects to
  `com.apple.net.utun_control`, the privileged step, then hands the descriptor to
  `CreateTUNFromFile` (`tun_darwin.go:135`), which does unprivileged work on a descriptor it
  is given. So ADR-0049's fd-passing design *would* have worked on macOS. It is not the
  reason the helper route was rejected, and recording that keeps the rejection honest: the
  helper route fails on the firewall, not on the tunnel device.
- **One Linux finding has a macOS twin that is now moot, and it is worth not losing.**
  ADR-0049 §8 records that `refreshKillSwitchAllowIP` has no fails-closed window on Linux,
  because nftables named sets take an atomic element add, so ADR-0025's Windows
  remove-and-recreate must not be ported. `pf` tables have the same atomic-add property, so
  the same warning would have applied to a `pf` kill-switch. Under NE there is no allowlist
  of ours to refresh, so the finding does not apply — but the general instruction stands
  for any future platform: **Windows' remove-and-recreate is a Windows API limitation, not
  the design.**
- **Cost shape is inverted.** Linux's cost is an installation step and a root daemon, and
  it buys a single-file distribution being impossible. macOS's cost is 99 USD a year, a
  notarization step, and a Go/Swift bridge, and it buys a supervised privileged half.

## Corrections to the card

Collected because #36's Scope section is the estimate someone will build from:

1. **The helper route does not avoid the Apple dependency.** Both routes need the paid
   membership, a Developer ID certificate and notarization. The card's contrast between an
   entitlement-gated route and a direct-download route is not a real fork.
2. **The NetworkExtension entitlement is not a gate.** Self-serve since November 2016, no
   review, restated by Apple DTS in March 2026.
3. **The memory ceiling is an iOS constraint, not a macOS one** (§3). The card's only
   stated architectural objection to NE does not apply on the platform the card is about.
4. **`SMJobBless` is deprecated** as of macOS 13, superseded by `SMAppService`.
5. **The scope is not "implement `osNet` and inherit the rest."** That is `[E10]`'s shape
   and the darwin stub's doc asserts it, but it does not survive this decision (§5).
6. **The real calendar risk is enrollment, not the entitlement** — days to weeks, and it is
   the only step here that cannot be compressed.

## Consequences

- **A recurring 99 USD/year cost appears in the project's budget**, with the client's
  ability to run on macOS at all depending on it staying paid. A lapsed membership does not
  break already-notarized builds, but it stops new ones.
- **macOS gets a different client architecture from Windows and Linux.** One core, two
  process topologies. This is the price of the decision and the thing most likely to be
  regretted; it is accepted because the alternative fails parity item 2 on a mechanism we
  do not control.
- **A Go/Swift bridge enters the build.** `-buildmode=c-archive`, an Xcode project or an
  equivalent build invocation, and a signed, notarized bundle containing a system
  extension. None of that is expressible in this repo's current all-Go build, and it is
  what makes #36 size L rather than M.
- **`[G8]`'s signing and notarization work becomes a hard dependency of #36, not a
  neighbour of it.** The card already lists it under Depends-on; this record makes the
  reason unambiguous — there is no macOS build that runs on a user's machine without it,
  under either route, so `[G8]` cannot be sequenced after `[E9]`.
- **`enforcement_darwin.go` and `osnet.go` carry doc comments that this decision falsifies**
  (§5). Until #36's build half corrects them, `main` describes a macOS design the project
  has decided against.
- **`clients/fyne` must fail the connect when the extension is unavailable or
  unapproved**, exactly as #59 made it do when Windows enforcement fails, with
  `Controller.DeviceEnforced` staying false. The user declining the system-extension
  approval prompt is the most likely way to reach that state on macOS, and it is parity
  item 7's failure mode if it degrades quietly to a working SOCKS proxy under a "Protected"
  banner.
- **`tunnel_test.go`'s five pinned orderings do not cover macOS** (§5). Whatever #36 builds
  needs its own equivalent assertions against the NE lifecycle; inheriting them is the one
  thing `[E9]` cannot do that `[E10]` can.
- **Hardware verification is unavoidable and is not CI.** Item 8's traffic-level test, the
  DNS egress behaviour in §8, and the crash-recovery claim in §6 all depend on a real
  macOS machine with a real resolver and a real physical adapter. This is the same
  limitation #59 recorded on Windows and #88 still holds open; macOS should state it in the
  same terms rather than imply coverage it does not have.

## Scope: what this record does not decide

- **The bridge's shape** — how the Go core is packaged as a C archive, what the controller
  protocol over `NETunnelProviderSession` looks like, and how the Xcode/Go build is driven.
  §4 fixes that there is a bridge and why; the design is #36's build half.
- **The CI job.** A `macos-latest` runner, and whether a headless smoke launch is possible
  on it, is the build half's — as is the correction to the two doc comments in §5.
- **Any amendment to ADR-0039.** §4 records where its in-process premise stops holding;
  the amendment belongs with the change that proves the shape.
- **#104's macOS half.** §8 records that macOS's problem is scoped DNS rather than an
  uncapturable loopback stub, and that NE answers it declaratively. Which settings, and
  verified how, stays with #104.
- **`[G8]`'s own work.** This record prices the Apple dependency; it does not do the signing
  and notarization work or design the release pipeline.
- **iOS.** Its memory ceiling is real (§3) and its distribution problem is entirely
  different. Nothing here is an iOS decision, and macOS's answer must not be read as
  settling one.
- **#36 itself, which stays open.** This is its design half; the card's Exit criteria — a
  signed, notarized build that connects, with a CI job keeping it building — are unmet.
