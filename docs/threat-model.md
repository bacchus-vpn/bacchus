# Threat model

Bacchus is a censorship-circumvention mesh VPN. This is the reference every
safety-relevant decision (end-to-end encryption, logging, relay trust, the
kill-switch) points back to. If a decision here changes, the decisions that
cite it need to be revisited.

## Adversaries

**The state censor** — a national censorship apparatus (in our primary target
environment, TSPU-style centralized DPI enforced per-operator) sitting on the
network path between users and the internet. Goal: detect and block Bacchus
traffic and endpoints, and identify who is using it.

**The malicious node operator** — anyone can run a relay or exit node,
including the censor itself (Sybil: the adversary joins as a volunteer). Goal:
observe or tamper with traffic passing through nodes they control, or map the
network by participating in it.

These are treated separately because they have different capabilities and
different mitigations: the censor sits *outside* the mesh and attacks the
network path; the malicious operator sits *inside* the mesh and attacks via
participation.

## Capabilities

**The state censor can:**
- Run deep packet inspection and protocol fingerprinting on traffic crossing
  its network (DPI/TSPU).
- Classify and selectively block by destination IP (e.g. flag foreign
  datacenter IPs independent of protocol).
- Pose as an ordinary user to enumerate the network: register as a client,
  crawl the coordinator, harvest node addresses.
- Run its own nodes (relay/exit/coordinator peers) to observe or disrupt from
  inside the mesh (see malicious operator, above).
- Block or throttle bootstrap/rendezvous channels (the coordinator, any
  fronting domain, app-distribution channels).
- Pressure app stores and hosting/CDN providers operating in or serving its
  jurisdiction to remove or restrict the client.

**The state censor cannot (assumed, see Non-goals):**
- Passively observe and correlate *all* global network traffic simultaneously.
- Break the cryptography used for transport or end-to-end encryption.

**The malicious node operator can:**
- See everything a relay or exit legitimately handles at that hop (see Trust
  boundaries) — nothing more, if the design holds.
- Log, delay, drop, or attempt to tamper with traffic it forwards.
- Join the mesh at volume (Sybil) to increase the odds of being selected as a
  hop for a given user, or to map the network's membership and topology.

## Assets to protect

1. **The user's real IP / identity** — must not be learnable by an exit node,
   an on-path observer, or a censor enumerating the network, from the
   traffic itself.
2. **What the user browses** — destinations and content must not be linkable
   to the user by any single node.
3. **The network's continued existence** — endpoints (coordinator, relays,
   exits) must keep working under active blocking pressure; losing
   reachability is a live threat, not just a privacy one.
4. **Volunteer safety** — a person running a relay or exit node must not be
   exposed to legal or physical risk disproportionate to what they signed up
   for (e.g. an operator's identity or location must not leak through the
   protocol; role separation limits what a relay is asked to carry, see ADR
   on end-to-end encryption).

## Trust boundaries

What each role is allowed to know, by design:

| Role | Knows | Must not know |
|---|---|---|
| **Relay** | Ciphertext, and the next hop to forward it to | Plaintext content; the original client's identity beyond "whoever handed me this hop," once E2E is in place |
| **Exit** | The destination being requested, and plaintext at the point of egress (egress is unavoidable — someone has to speak to the open internet) | The user's real IP/identity, if a relay sits between client and exit; if the client connects direct, the exit does learn the client's IP as an inherent property of direct connections (see Non-goals) |
| **Coordinator** | As little as possible — enough peer/session metadata to introduce client and node (addresses, session identifiers for signaling) | Traffic content; ideally, which client ultimately talks to which exit, once E2E and enough indirection exist |

A relay that only ever sees ciphertext and a next hop cannot itself
deanonymize a user or read their traffic — that's the point of routing
client↔exit traffic end-to-end encrypted, so relays are safe to run even for
volunteers who don't want visibility into what crosses their box.

## Non-goals

- **Not defending against a global passive adversary.** We assume the censor
  can observe traffic on paths within its own jurisdiction, not simultaneous
  global traffic correlation across every network in the world.
- **Not Tor-grade anonymity.** Bacchus optimizes for *reachability under
  active blocking* (getting a connection out of a censored network at all),
  not for strong anonymity against a well-resourced traffic-correlation
  adversary. A direct client→exit connection is deliberately allowed (see
  README) for performance, which is a privacy trade-off relays-as-fallback
  don't fully close.
- **Not resistant to a censor that controls the client device itself**
  (compromised OS, malware, physical seizure). Device security is out of
  scope for the network design.

## References

- Design constraints this threat model assumes: `docs/design/v1.md`.
- Cited by: end-to-end encryption ADR, logging policy (`SECURITY.md`), the
  client kill-switch design, and node/client admission — ADR-0023 (the
  coordinator-side mitigation for the malicious node operator and the
  network-enumeration capabilities above) and ADR-0026 (client-side end-to-end
  exit verification, which defends the "run its own coordinator peer, advertise a
  hostile exit" capability even when the coordinator itself is the adversary).
