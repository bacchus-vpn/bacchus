# 60. The rendezvous port answers any well-formed STUN Binding Request

- Status: accepted (issue #202)
- Date: 2026-08-06

## Context

ADR-0059 §8 ruled that the rendezvous hop should carry a STUN connectivity-check
prefix (**S2**) and deliberately did not build it, for two reasons. The first has
expired: it said the coordinator half alone is *"all cost and no benefit"*
because nothing would emit a prefix until slice 2. That is still true of the
benefit, and it is also the reason the coordinator half must land **first** — a
client that emits a prefix at a coordinator which does not answer stalls its own
handshake. The same argument that deferred it is what now sequences it ahead.

The second reason has not expired and is what this record settles.

### Why the prefix is needed at all

A real WebRTC endpoint runs ICE connectivity checks — STUN Binding
Request/Response — on a 5-tuple, and only then runs DTLS on that same 5-tuple.
What ADR-0059 shipped is a DTLS ClientHello arriving from nowhere. That is
*DTLS-shaped*, not *WebRTC-shaped*, and the difference is free for a classifier
to read: no other traffic on the internet begins a DTLS association without a
preceding connectivity check on the same 5-tuple.

`docs/design/rendezvous-cold-start.md` §4.1 asks for the shape a video call has.
`core/ice_fingerprint.go` — which draws browser-shaped ufrag/pwd precisely
because pion's own are a distinguisher — has **no caller at this hop at all**
without this half.

### The question ADR-0059 left open

`MESSAGE-INTEGRITY` on an ICE connectivity check is keyed on the peer's ICE
`pwd`, which real ICE exchanges in SDP. **This hop has no such channel** — the
same finding that killed option A2-a, since the desktop client holds no
coordinator key whatsoever (`MeshPubKey`/`MeshPeers`/`MeshProof` appear nowhere
under `clients/`). The coordinator therefore cannot verify the attribute, and
three postures were available:

| | Posture | Argument for | Argument against |
| --- | --- | --- | --- |
| **a** | Answer any well-formed Binding Request | Best **blend**: the port resembles the generic VoIP infrastructure §4.1 wants to hide among, and banning that class of traffic is expensive for a censor | A reflection vector on a spoofable source, and it confirms to an active prober that something is listening |
| **b** | Answer only requests padded to at least the response size; silence otherwise | Amplification ≤ 1 by construction, and design principle 4's own words: *"a prober without the per-user secret must see silence or a plausible decoy"* | We then resemble no STUN server at all — we resemble nothing, and principle 3 says *"looking like nothing is now itself a signal"* |
| **c** | Derive the `pwd` from `AdmissionPubKey` and verify | Looks like authentication | It is fleet-wide, so anyone holding a client binary has it. A2-a's exact weakness, and calling it authentication would be a lie |

The two design principles genuinely cut against each other here, which is why
this was carried to a card rather than settled inside a lane.

## Decision

**Option (a): the rendezvous signaling port answers any well-formed STUN Binding
Request, from anyone, with a Binding Success Response carrying
XOR-MAPPED-ADDRESS and FINGERPRINT.**

(c) is rejected outright. A check against a fleet-wide secret provides no
authentication against any adversary who can obtain a client binary, and
recording it as authentication would put a false claim in the threat model. If
the `pwd` ever becomes per-coordinator or per-user — #193 is the card that would
do it — this is revisited from a position where the check would mean something.

(a) is chosen over (b) on the balance of two costs that are not symmetric.

**What (b) buys is small.** The reflection factor here is **2.0x over IPv4** (a
20-byte bare Binding Request draws 40 bytes: header 20 + XOR-MAPPED-ADDRESS 12 +
FINGERPRINT 8) and **2.6x over IPv6** (52 bytes). Both figures are pinned by
`TestTheReflectionFactorIsWhatTheADRClaims` so they cannot drift silently. A
reflector is worth building a campaign around at 50x–500x, which is where DNS and
the old NTP `monlist` sat. At 2x an attacker gains almost nothing over sending
the packets directly, and pays the cost of a spoofing-capable position to get it.

**What (b) costs is the entire point of the feature.** A port that returns
silence to an ordinary Binding Request is not blending with anything. The whole
reason to speak STUN here is to look like the infrastructure a censor cannot
cheaply ban.

**And the exposure is already taken.** This coordinator **already** runs a real
STUN/TURN server on `-turn-addr`, with `coldstart.Demux` blended onto it, which
answers a bare Binding Request with the same two attributes. (a) adds a second
instance of an exposure the deployment has accepted, on a different port — not a
new class of one. The signaling port is also already probeable: a `hello` with
bad magic draws a `reject` from `handle()`, so *"something is listening"* was
never a secret this port kept.

### The reply is byte-identical to the TURN port's

`core/coldstart` already owned this repository's STUN codec, and pion/turn's
`handleBindingRequest` builds exactly XOR-MAPPED-ADDRESS then Fingerprint over
the request's transaction ID — attribute for attribute what `buildResponse`
produces with a nil snapshot. The codec is therefore **shared** rather than
reimplemented, through a new exported `coldstart.BindingResponse`.

This is not tidiness. Two UDP ports on one host that answer the same question
with differently-shaped bytes are themselves a distinguisher, and it is one this
feature would have created while trying to remove another.
`TestTheSTUNReplyIsByteIdenticalToWhatTheTURNPortSends` builds the expected value
through `pion/stun` the way pion/turn does and compares bytes, so the claim is
tested rather than asserted.

### Scope limits that are part of the decision

- **Only Binding Requests.** An Allocate, Refresh or ChannelBind gets nothing and
  falls through to the path it always took. The signaling port is not a TURN
  server and must not start drawing traffic it has no handler for.
- **No SOFTWARE attribute.** Real servers often send one; ours would name an
  implementation and become the fingerprint this exists to avoid.
- **No MESSAGE-INTEGRITY in the response**, for the same reason we cannot verify
  one in the request.
- **Gated on the existing `-rendezvous-dtls` flag**, not a new one. S1 and S2 are
  one shape, and an operator able to enable half of it would be able to deploy a
  coordinator that is neither shaped nor unshaped.

## Consequences

**An operator who enables the shaped hop acquires a new unauthenticated reply
path.** That is the decision, priced above. An operator who has not enabled it is
unaffected: the mux is nil and nil is the whole switch.

**The hop is now WebRTC-shaped rather than merely DTLS-shaped**, and
`core/ice_fingerprint.go` acquires its first caller at this hop when slice 2
lands. Until then the coordinator answers checks nothing sends — deliberately, so
that it is deployed before the client that needs it.

**Classification stays conclusive.** STUN is separated from DTLS by the magic
cookie and the exact method, not by the first byte, because a DTLS ContentType
(20, 21, 22, 23, 25) also has its two high bits clear. The three classifiers are
mutually exclusive, so the order of the tests changes no behaviour — a property
kept true by `TestLooksLikeSTUNIsDisjointFromTheOtherTwoShapes` rather than
assumed.

**A dual-stack bind was the one real trap.** Production binds a wildcard
(`-addr :8080`), and `ReadFromUDP` then reports a v4 peer as a 16-byte 4-in-6
*mapped* address whose `Is4` is false. Encoding that without unmapping sends a v4
client the 20-byte IPv6 form of XOR-MAPPED-ADDRESS — it parses, nothing breaks,
and it is a shape no real STUN server emits. Every test that binds `127.0.0.1`
explicitly receives a 4-byte IP and **cannot see the bug**;
`TestAV4PeerOnAWildcardSocketGetsTheV4Form` binds the wildcard for that reason
alone, and was written after a mutation showed the rest of the suite passing
without the unmap.

**What this does not do.** It does not authenticate anything, in either
direction, and no part of the security argument moved. The admission credential
inside the association remains the only thing that gates anything. ADR-0059's
§8 fork is now closed; its other open items are not.

## References

- Issues #202 (this), #175 (slice 1 landed; slices 2 and 3 open), #193
  (per-coordinator keys, which would make a verifiable `pwd` possible), #201
- ADR-0059 §8 (the fork this closes), ADR-0017 (`coldstart.Demux`, the existing
  STUN blend on `-turn-addr`), ADR-0018 (the DTLS/ICE fingerprint profiles),
  ADR-0057 (the datagram budget — the prefix is a separate datagram and spends
  none of it), ADR-0023/0047 (the admission credential that does the gating)
- `docs/design/rendezvous-cold-start.md` §4.1 (the bar), §3 principles 3 and 4
  (the two that cut against each other above)
- RFC 5389 §6 (the STUN header and magic cookie), §15.2 (XOR-MAPPED-ADDRESS),
  §15.5 (FINGERPRINT); RFC 8445 §7.2.5 (ICE connectivity checks)
