# 10. The client is full-device (TUN + kill-switch), not a browser proxy

- Status: accepted
- Date: 2026-07-02

## Context

The current Windows client is a PAC/browser-scoped proxy: only
browser-routed traffic goes through Bacchus, and there is no fail-closed
behavior if the connection drops. `docs/threat-model.md` protects "what the
user browses" and "the user's real IP," but a browser-only proxy leaves every
other application's traffic — and all traffic during a dropped connection —
exposed at the OS network layer, regardless of how strong the transport or
encryption is upstream.

## Decision

The client routes at the OS level via a TUN interface, covering all
device traffic, not just a browser. It includes a fail-closed kill-switch
(no traffic egresses in the clear if the tunnel drops) and handles DNS so
lookups don't leak outside the tunnel. Tracked as issue #13, milestone M1
(the client must be safe before it's useful).

## Consequences

- Closes the gap between "the protocol is safe" and "the user is safe" — a
  leak at the OS/application-routing level would defeat the threat model
  regardless of transport or encryption quality.
- Higher implementation cost than a browser proxy (OS-level TUN driver,
  routing table management, DNS interception) — accepted because M1 is
  explicitly "safe before useful."
- v1 targets one platform pair; TUN implementation is platform-specific and
  does not itself unlock other platforms (those are v2).
