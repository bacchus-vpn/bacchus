# 9. End-to-end encryption is client-to-exit; relays forward ciphertext

- Status: accepted
- Date: 2026-07-02

## Context

The current data path (client → relay → exit) has the relay forwarding
plaintext: `own-stack.md` flagged this as a known gap ("add E2E client↔exit
so the relay only forwards ciphertext (onion property)"). `docs/threat-model.md`
defines the trust boundary a relay must respect: ciphertext and a next hop
only, never plaintext content or enough to deanonymize a user. Volunteers run
relays without wanting visibility into what crosses their box, and a relay
operator can be the adversary (Sybil) — the design must hold even then.

## Decision

Traffic is encrypted end-to-end from client to exit. A relay forwards
ciphertext and knows only the next hop; it cannot read content and gains no
more from participating than a passive router would. The exit decrypts at
the point of egress, because someone has to speak plaintext to the open
internet — that boundary is inherent and out of scope to remove (see
`docs/threat-model.md` trust boundaries table). Tracked as issue #12,
milestone M1 (client must be safe before it's useful).

## Consequences

- Relays are safe to run for volunteers who don't want exposure to user
  content or destinations — this is what makes volunteer relay-running a
  reasonable ask.
- A malicious relay operator (including a censor running Sybil nodes) cannot
  read or tamper with content by virtue of relaying; it can still see
  traffic timing/volume and that a hop occurred, which the threat model
  explicitly does not defend against (not Tor-grade anonymity).
- Direct client→exit connections (no relay) still expose the client's IP to
  the exit — an accepted trade-off for performance, documented as a
  Non-goal in `docs/threat-model.md`.
