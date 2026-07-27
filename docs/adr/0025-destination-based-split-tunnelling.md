# 25. Destination-based split tunnelling rides the same exclusion routes as the control plane, and bypass domains are learned live

- Status: accepted
- Date: 2026-07-03

## Context

Issue #40: RU banking/gov/streaming sites geo-block or degrade a foreign exit
IP, so users need a configured `bypass` list of destinations to keep egressing
the user's real IP while everything else tunnels. ADR-0014 already made the
kill-switch allowlist aware of `bypass`, but nothing routed those destinations
off the tunnel — this issue wires that up.

The obvious-looking implementation is "in `handleTCP`, dial the destination
directly instead of via SOCKS when it's a bypass entry." That's necessary but
not sufficient. The tunnel's route is a split-*default*
(`0.0.0.0/1` + `128.0.0.0/1` via the tunnel adapter, routes.go) that beats the
real default for any address without a more specific route pointing
elsewhere. A "direct" `net.Dial` for a destination that isn't otherwise
excluded is itself a fresh OS-level connection attempt, which the routing
table would send straight back into the tunnel adapter — re-entering the
netstack and looping forever rather than ever reaching the internet. This is
exactly the failure mode the control-plane (coordinator/STUN/TURN) exclusion
routes already exist to avoid; bypass destinations need the same treatment.

Domains complicate this further: their IPs aren't known until resolved, a
CDN-backed domain's answer can change mid-session, and the config's bypass
entries include plain domain names (e.g. `sberbank.ru`) that aren't valid
Windows Firewall `-RemoteAddress` values on their own.

## Decision

- **Static bypass entries** (literal IPs/CIDRs) get an exclusion route via the
  real gateway at tunnel startup, generalizing routes.go's
  `addExclusionRoutes`/`removeExclusionRoutes` (previously hardcoded to `/32`)
  to accept arbitrary CIDR prefixes — the same functions now serve
  control-plane endpoints and bypass ranges alike.
- **Domain bypass entries** are resolved once at connect (via the OS's own
  resolver — safe, since bypass destinations are explicitly meant to be
  reached with the real IP rather than hidden behind the tunnel) to seed an
  initial address set, and then matched continuously against every query the
  DNS interceptor already sees (`tun2socks.go`'s `handleUDP`, which
  DNS-over-TCPs every request regardless of resolver). Each newly-seen answer
  address is "learned": its exclusion route is installed, and — if the
  kill-switch is armed — the live allowlist is refreshed, **before** the
  answer is handed back to whatever asked for it, so the route exists before
  the requester's follow-up TCP connect can race it.
- `handleTCP` picks `net.Dial` (direct) vs. `dialSOCKS` (tunnel) per
  destination via a single `bypassPolicy.direct()` check, which also carries
  a mode: `"exclude"` (default) tunnels everything except `bypass`;
  `"include"` tunnels only `bypass`, sending everything else direct.
- The shipped default bypass list (`config.example.json`) is **domains only**
  (sberbank.ru, gosuslugi.ru, vk.com, etc.) — real, well-known, easy to verify
  — rather than hardcoded RU GeoIP CIDR ranges. Fabricated or stale CIDR data
  would be worse than no default: wrong ranges either miss the sites they're
  meant to protect or bypass unrelated address space, and there's no way to
  verify a plausible-looking CIDR block by inspection the way a domain name
  can be. Real GeoIP ranges remain fully supported as user-supplied `bypass`
  CIDR entries; the project just isn't the one asserting a specific range is
  authoritative.

Rejected alternatives:

- **Binding the direct dial's local address to the physical adapter, no
  exclusion route.** Windows' weak-host send model doesn't guarantee this
  overrides a routing-table entry — the split-default route can still win,
  so this doesn't reliably avoid the loop.
- **Resolving bypass domains only once, at connect.** Rejected because a
  CDN-backed domain's address can rotate within a session (load balancing,
  TTL expiry); a stale one-time snapshot would silently stop matching without
  the live DNS-interception path this issue already has to build for
  first-sight resolution anyway.
- **A hardcoded RU GeoIP CIDR default.** Rejected — see Decision above.

## Consequences

- Bypass IPs/CIDRs and the control-plane exclusions now share one mechanism
  (`addExclusionRoutes`/`removeExclusionRoutes`), so there's one code path to
  reason about for "what keeps a destination off the tunnel's route," not two.
- The kill-switch allowlist (ADR-0014) is no longer a static startup snapshot
  for bypass domains — `refreshKillSwitchAllowIP` keeps it current for the
  life of the session. This required removing and recreating the one
  firewall rule (NetSecurity has no in-place address-list edit), which has a
  narrow window with no explicit allow rule for the addresses it covered.
  That fails *closed* (default action is already Block), so a connection
  racing the gap is blocked, not leaked — worse UX for that one connection,
  never a leak.

  > **Update (2026-07-04):** closed by issue #73. The claim above didn't
  > actually hold in one narrow case: a bypass IP learned between the netstack
  > going live and the kill-switch actually arming could miss *both* sides —
  > not in the initial allowlist (built from a snapshot taken before that
  > window even opened) and not live-refreshed either (the armed check, a
  > plain `atomic.Bool` read, still said "not armed yet" at the moment
  > `onLearn` fired). `bypassPolicy` (splittunnel.go) now owns a single lock
  > covering both the dynamic set *and* the armed transition itself
  > (`arm()`), so `learn()` and arming can never interleave: whichever runs
  > first completes entirely before the other proceeds, and every learned IP
  > lands on exactly one side — the initial snapshot, or the live refresh —
  > never neither. Same fails-closed posture as before (a connection racing
  > the original narrow window was already blocked, not leaked); this closes
  > the gap where it could stay wrongly blocked *indefinitely*, past the
  > point where the live-refresh path should have caught it.
- A bypass domain resolved via the OS's own DNS cache from before connect
  (rather than a fresh query the interceptor observes) won't be recognized
  until something re-queries it. Known limitation, documented in the client
  README; fails toward tunnelling (safe), not toward leaking.
- Per-app split tunnelling remains explicitly out of scope (issue #40's own
  scope cut), consistent with ADR-0011's narrow-v1 stance — Windows has no
  `addAllowedApplication`-equivalent API, and destination-based bypass covers
  the RU banking/gov/streaming case this issue targets.
- `include` mode ("only this list") is **not yet functional**: in include mode the
  complement of the bypass set has no exclusion route, so non-bypass traffic loops
  (kill-switch off) or is blocked (kill-switch on). It fails *closed* (no leak), but
  the mode is unusable — the default `exclude` mode ("everything except bypass") is
  unaffected. Tracked in #64.

  > **Update (2026-07-04):** closed by issue #64. The problem was never "the complement
  > of the bypass set is missing exclusion routes" — computing that complement as CIDR
  > blocks over the entire IPv4 space, and recomputing it every time a bypass domain
  > resolves to a newly-seen IP mid-session, doesn't scale and was never actually
  > attempted. The real bug was that the split-default route was being installed
  > unconditionally, in both modes. `include` mode now skips it entirely
  > (`routes.go`'s new `addSplitDefaultRoute`, called only outside `include` mode) and
  > instead pulls the bypass/include set *into* the tunnel adapter with a new mirror-image
  > `addInclusionRoutes`, so the real default route stays authoritative for "direct"
  > traffic (the majority, in this mode) and it never touches the netstack at all —
  > rather than being captured and then re-dialed direct from inside the intercepting
  > process, which is what looped. `staticExclusions`/`removeExclusionRoutes` above are
  > renamed `staticEntries`/`removeRoutes` since the same list and the same removal call
  > now serve either direction depending on mode.
  >
  > Two consequences of the fix worth being explicit about rather than silently glossed
  > over:
  > - The "domains are matched continuously" bullet above only actually holds in
  >   `exclude` mode. It depends on the netstack seeing *every* DNS query, which is only
  >   true when the split-default captures everything. In `include` mode, only
  >   already-included destinations' traffic reaches the netstack at all, so a bypass
  >   domain's mid-session IP rotation (a CDN rebalancing, say) isn't observed — that one
  >   flow keeps its original, possibly-stale route from connect time. Fails toward that
  >   connection going direct/untunnelled, not toward an OS-level leak, but it is a real
  >   gap versus `exclude` mode's live-tracking behavior.
  > - Arming the kill-switch (ADR-0014) together with `include` mode now blocks — rather
  >   than leaking — all "direct" traffic (most traffic, by construction in this mode)
  >   for as long as it's armed, because the kill-switch's allowlist has no concept of
  >   "this traffic was never meant to be protected in the first place." Fails safe, but
  >   is a real, undecided UX question: should `include` mode's kill-switch exempt
  >   never-tunnelled traffic instead of blocking it? Flagged for the owner rather than
  >   decided here; candidate follow-up if it matters in practice.
