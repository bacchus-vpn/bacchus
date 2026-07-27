# App distribution into Russia

- Status: **research + recommendation (issue #19)**
- Date: 2026-07-03
- Track: rendezvous (M3)

> A perfect cold-start bootstrap ([rendezvous-cold-start.md](design/rendezvous-cold-start.md))
> is worthless if a user can't get the app itself. This document maps attack
> A5 (block the app/store/installer host) and recommends a primary +
> fallback distribution path with a build-integrity story, per issue #19's
> acceptance criteria.

---

## 1. Problem statement

Getting the client binary onto a fresh device is a *separate* asymmetry
problem from cold-start rendezvous, but the same shape: whatever channel is
easy for a real user to find is easy for a censor (or a platform complying
with the censor) to find and remove. Unlike rendezvous, this fight is mostly
fought on **platforms we don't control** (Google, Apple) rather than on our
own infrastructure, which changes the leverage available to us.

## 2. Current state (as of 2026-07, evidence-based)

This is an active, fast-moving fight, not a stable baseline — re-check
before relying on any of this in a launch decision.

- **Apple App Store: actively hostile to this app category in Russia.**
  Apple removed VPN/proxy apps (Streisand, V2Box, v2RayTun, Happ Proxy
  Utility, and "dozens" more) from the RU storefront in March–April 2026 at
  Roskomnadzor's request, citing "content that is illegal in Russia."
  Already-installed copies keep working; new installs and updates in the RU
  region stop. ([TechRadar](https://www.techradar.com/vpn/vpn-privacy-security/russian-censors-target-google-in-vpn-takedown-push),
  [Cybernews](https://cybernews.com/privacy/apple-removes-vpn-apps-russian-app-store/))
- **Google Play: under the same pressure but currently resisting.**
  Roskomnadzor issued removal orders for 233 apps in March 2026 alone;
  Google complied with only ~6. Russia has separately fined Google ~22.8M
  rubles (~$298k) for "promoting" VPN apps in search/Play results.
  ([TechRadar](https://www.techradar.com/vpn/vpn-privacy-security/russia-demands-212-vpns-are-removed-from-the-play-store-but-google-is-resisting),
  [AndroidHeadlines](https://www.androidheadlines.com/2026/02/russia-slaps-298000-fine-on-google-over-vpn-promotion-on-play-store.html))
  This makes Play the **more resilient of the two official stores today**,
  the opposite of the naive assumption that a US platform is uniformly
  safer — but "currently resisting" is not "will resist indefinitely."
- **~100 VPN apps already unavailable on the RU App Store** as of 2025 data,
  and the pace of Play removal orders (233 in one month) shows the pressure
  is accelerating, not stabilizing.
  ([appcensorship.org](https://appcensorship.org/news/is-google-complying-with-russian-government-censorship-of-vpn-apps))
- **GitHub, Google Drive, Dropbox are generally reachable in Russia today.**
  GitHub was fully blocked once (Dec 2014, over unrelated content, lifted
  after ISPs found whole-site HTTPS blocking too costly) and has had
  intermittent partial blocks since, but is not currently under a standing
  block. None of the three sit behind Cloudflare, so the Cloudflare ban that
  rules out CDN-fronting for rendezvous (see [threat-model.md](threat-model.md))
  doesn't apply to them directly — but "generally reachable" is not "safe to
  be the only channel"; GitHub's own history proves the opposite.
  ([Wikipedia: Censorship of GitHub](https://en.wikipedia.org/wiki/Censorship_of_GitHub))
- **Telegram is unblocked and heavily used in Russia** (blocked 2018–2020,
  unblocked since) and is already a proven circumvention-tool distribution
  channel: the Tor Project runs GetTor, which hands out Tor Browser download
  links (hosted on Dropbox/Google Drive/GitHub) over **email and a Telegram
  bot** ([gettor.torproject.org](https://gettor.torproject.org/)), and Tor's
  own 2025 retrospective specifically credits their Telegram distributor as
  effective in Russia — "the censor has a harder time extracting all the
  bridges from it" than from a scrapeable website.
  ([Tor Project blog](https://blog.torproject.org/staying-ahead-of-censors-2025/))
- **A forward-looking platform risk, not RU-specific (yet):** Google's new
  Android "Developer Verification" requirement — unverified APKs become
  uninstallable/unupdatable on certified devices — starts enforcing
  2026-09-30 in Brazil, Indonesia, Singapore, and Thailand. Russia isn't in
  the initial rollout, but this is the direction of travel for sideloading
  generally and is worth tracking, since it could eventually narrow the
  direct-APK fallback this document leans on.

## 3. Options and their fragility

| Channel | Blockability | User friction | Verification story | Notes |
|---|---|---|---|---|
| **Google Play** | Medium — app-specific delisting, not a whole-store block; currently resisted by Google for most apps | Lowest (already trusted, auto-updates) | Play's own signing | Best mainstream reach *while listed*; treat as burnable, not guaranteed |
| **Apple App Store** | High for this app category, proven in 2026 | Low | Apple's own signing | Actively hostile right now; list opportunistically, don't rely on it |
| **Direct APK, our domain** | High — a single domain is trivial to add to a blocklist | Medium (unknown-publisher install friction, "why is this not on Play" fear) | Our own APK signing key (Android verifies on install/update) + published SHA-256 | Necessary as the payload every other channel points to, insufficient alone |
| **GitHub Releases / static mirror** | Medium — generally reachable, but GitHub has a block precedent (2014) and is a named target of past RU action | Medium | Same signed APK + checksum | Good secondary host, not sufficient alone |
| **Telegram bot / channel** | Low — proven resilient for exactly this purpose (GetTor's own experience in RU) | Low (users already have Telegram) | Checksum/signature travels in the same message as the link | Best asymmetric-distribution fit: hard to enumerate every handout |
| **F-Droid** (self-hosted repo or eventual index submission) | Low-medium — niche today, not yet a named target | Medium (technical audience, requires adding a repo or knowing F-Droid) | F-Droid's reproducible-build culture + our own signing | Strong for the auditability-minded user; not a mass-market primary |
| **Social / in-person APK sharing** | Effectively unblockable (it's not a network channel) | Requires the recipient to trust the sender | Our signing key is the only defense — Android rejects a re-signed/tampered APK on install | The genuine last resort; same "per-user secret makes harvested things inert" logic as cold-start doesn't apply here (the *binary* isn't user-specific) — the signature is what has to hold |

## 4. Recommendation

Consistent with the rendezvous design's core principle — **coverage, not
perfection; a union of partial channels, not one channel hardened to
perfection** — no single row above should be "the" distribution plan.

**Primary: Google Play**, for as long as it's listed. It's the lowest-friction
path for the median user and, per §2, currently the more resilient of the
two mainstream stores. Do not depend on it exclusively — track removal risk
and design the fallback to activate with zero notice, not as a break-glass
scramble.

**Day-one fallback, not an afterthought: a Telegram bot**, mirroring GetTor's
proven pattern. A user messages the bot (or a fixed keyword in a public
channel); it replies with a signed download link (pointing at one of a
rotating set of mirrors — our own domain, GitHub Releases, and 1–2 other
neutral static hosts) **and** the SHA-256 checksum in the same message, so
the verification data survives on the same resilient channel as the binary
itself, exactly as GetTor pairs its links with `.asc` signatures. This is the
single highest-leverage addition this research identifies: it's cheap to
build, reuses infrastructure we already understand (bots, static file
hosting), and has a multi-year track record specifically in Russia.

**Secondary technical channel: F-Droid.** Self-host a repo (or pursue
inclusion in the main F-Droid index once the client is public per
[ADR-0002](adr/0002-open-monorepo-with-separate-private-payment-repo.md)/[ADR-0019](adr/0019-relicense-to-agpl-3-0.md)).
Lower reach, but the reproducible-build culture is a credibility asset for
the users most likely to evangelize the tool to others.

**Apple App Store: list opportunistically, plan for removal.** Given the
2026 evidence, treat any RU-region iOS listing as temporary from day one —
this matches ADR-0011's "v1 scope is narrow" (iOS is v2 anyway) and defers
the harder problem.

## 5. Build-integrity and verification plan

1. **Every release is signed with one Android app signing key**, kept
   offline/HSM-protected like the coordinator's bootstrap key
   ([bootstrap-protocol.md](design/bootstrap-protocol.md) §4) is meant to
   be. Android's package manager enforces this automatically: an update
   whose signing certificate doesn't match the installed app's is rejected
   outright, which is the primary defense against a swapped-in malicious
   "update" from an untrusted mirror.
2. **Publish a SHA-256 checksum alongside every mirror and in the Telegram
   bot's reply**, so a user (or a script) can verify a sideloaded APK
   independently of Android's own install-time check — defense in depth,
   and the only check available *before* installing.
3. **Same signing discipline the cold-start bootstrap already established**
   (`core/coldstart`, Ed25519 snapshot signing, issue #18): this document
   recommends the *same pattern*, not the same key, for a future in-app
   updater — a signed update manifest the client verifies against a baked-in
   public key, the way it already verifies a directory snapshot. That
   updater is separate client work, not built by this issue; flagged here
   so whoever picks it up doesn't reinvent the verification model.
4. **No unverified auto-update from an untrusted source.** The Telegram bot
   and mirrors are for *acquisition*; once a client has a working install,
   it should update itself only through the signed-manifest path in (3), so
   compromising a mirror after the fact can't push a malicious update to an
   already-onboarded user.

## 6. Open questions (tracked, not yet decided)

1. **Telegram bot operational ownership** — who runs it, on what
   infrastructure, and how it's kept from becoming a single point of
   failure itself (mirrors the coordinator-pool question from issue #6).
2. **F-Droid: self-hosted repo vs. mainline index submission** — mainline
   gives more reach but requires the client to already meet F-Droid's
   reproducibility/no-proprietary-blob bar; self-hosted is available sooner.
3. **iOS distribution specifics** — explicitly out of scope per issue #19
   (iOS is v2).
4. **Whether to obscure the app's category/branding** (e.g., not leading
   with "VPN") to reduce automated takedown-request targeting. This has a
   real tension with Play/App Store's own deceptive-listing policies —
   getting the *developer account* banned for policy violation would be
   worse than a single app delisting. Needs a considered decision, not a
   default.

## 7. Relationship to other work

- **#18 / core/coldstart** — the signing pattern this document recommends
  reusing for a future update mechanism.
- **#6 coordinator pool** — the closest existing analogue for "avoid a
  single point of failure in an infrastructure component we run" (§6 Q1).
