# 19. Relicense the open source from Apache-2.0 to AGPL-3.0

Status: Accepted (2026-07-03) — supersedes [ADR-0004](0004-license-apache-2-0.md)

## Context

[ADR-0004](0004-license-apache-2-0.md) licensed the public repo Apache-2.0 for
maximum adoption, explicitly accepting that a fork could go closed because "the
network effect and the proprietary payment service are the moat, not the code."

The moat reasoning still holds. But two properties of *this* project sharpen the
license choice:

1. **It is a censorship-circumvention tool.** Users route all of their traffic
   through it under a hostile state, so auditability is existential — "trust us,
   it is safe" is not acceptable. The whole anti-censorship ecosystem (WireGuard,
   Amnezia, Tor) is open for this reason. Staying fully open is a hard
   requirement; source-available or proprietary licensing is off the table.

2. **We operate a shared network, not just ship code.** Amnezia (GPL-3.0) has
   every user self-host, so it has no shared network to protect. Bacchus runs a
   coordinator, exits, and a mesh. Under Apache-2.0 a commercial competitor could
   run a modified service against our users and contribute nothing back.
   AGPL-3.0's section 13 network-use clause closes exactly that gap: anyone
   operating a modified version over a network must offer its users the modified
   source.

Controlling who may *connect to* the network — freeloading clients, outside
nodes — is a separate concern and not a licensing question; it is cryptographic
node admission, tracked as #42.

## Decision

Relicense the public `bacchus` repo from Apache-2.0 to **AGPL-3.0**, superseding
ADR-0004. The `LICENSE` file is replaced with the AGPL-3.0 text; ADR-0004 is
retained and marked superseded (per the ADR log convention). The proprietary
payment/token repo
([ADR-0002](0002-open-monorepo-with-separate-private-payment-repo.md)) is
unaffected.

## Consequences

- **+** Maximum auditability, matching the ecosystem users already trust — no
  adoption cost from an unverifiable license, which for a censorship tool is the
  cost that matters most.
- **+** The one piece of copyleft teeth that fits: a closed commercial fork
  operated as a service must publish its changes (section 13), at zero trust cost
  since we were staying open regardless.
- **+** GPL-family compatibility: we may now incorporate GPL/AGPL dependencies
  that Apache-2.0 could not. (Current dependencies — e.g. gVisor's netstack,
  Apache-2.0/BSD — remain compatible.)
- **−** AGPL deters some corporate contributors and integrators whose policies
  ban it. Accepted: the contributor base here is the anti-censorship community,
  not enterprises embedding a proprietary VPN.
- **−** It is not permissive — a downstream cannot embed Bacchus in a closed
  product. That is the intended effect, and the deliberate reversal of ADR-0004's
  "a fork may go closed."
- **−** Any operator running a fork inherits the section 13 obligation to offer
  source to its network users; for the canonical project this is satisfied by the
  public repo itself.
- Patent protection is preserved: Apache-2.0's explicit patent grant is replaced
  by AGPL-3.0's section 11, so the patent concern that motivated ADR-0004 still
  holds.
