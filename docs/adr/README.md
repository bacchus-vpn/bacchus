# Architecture Decision Records

Short records of significant decisions. Format: **Status, Context, Decision,
Consequences**. Numbered sequentially; superseded records are kept and marked, not
deleted. New significant decisions ship as an ADR in the same PR (see ADR-0007).

- [0001](0001-record-architecture-decisions.md) — Record architecture decisions
- [0002](0002-open-monorepo-with-separate-private-payment-repo.md) — Open monorepo, private payment repo
- [0003](0003-single-go-module.md) — Single Go module
- [0004](0004-license-apache-2-0.md) — Apache-2.0 license *(superseded by [0019](0019-relicense-to-agpl-3-0.md))*
- [0005](0005-mobile-shares-the-go-core-via-gomobile.md) — Mobile shares the Go core via gomobile
- [0006](0006-udp-signaling-for-rendezvous-reachability.md) — UDP signaling for reachability
- [0007](0007-documentation-is-part-of-done.md) — Documentation is part of "Done"
- [0008](0008-transport-is-pluggable-webrtc-is-one-implementation.md) — Transport is pluggable, WebRTC is one implementation
- [0009](0009-end-to-end-encryption-client-to-exit.md) — End-to-end encryption client-to-exit
- [0010](0010-full-device-client-not-a-browser-proxy.md) — Full-device client, not a browser proxy
- [0011](0011-v1-scope-is-narrow.md) — v1 scope is narrow
- [0012](0012-cold-start-rendezvous-without-domain-fronting.md) — Cold-start rendezvous without domain fronting
- [0013](0013-bootstrap-wire-protocol.md) — Cold-start bootstrap wire protocol
- [0014](0014-kill-switch-enforced-by-firewall-default-block.md) — Kill-switch enforced by an OS firewall default-block
- [0015](0015-version-policy-and-forced-updates.md) — Version policy and forced updates
- [0016](0016-protocol-version-and-capability-handshake.md) — Protocol version + capability handshake
- [0017](0017-blend-bootstrap-onto-shared-stun-turn-port.md) — Blend bootstrap onto the shared STUN/TURN port
- [0018](0018-randomized-dtls-fingerprint.md) — Randomize the WebRTC DTLS ClientHello fingerprint
- [0019](0019-relicense-to-agpl-3-0.md) — Relicense to AGPL-3.0 (supersedes 0004)
- [0020](0020-coordinator-pool-and-client-rotation.md) — Coordinator pool + client rotation
- [0021](0021-co-signed-usage-receipts-stub.md) — Co-signed usage receipts (metering stub, no payout)
- [0022](0022-reduce-residual-ice-and-serverhello-tells.md) — Reduce residual WebRTC ICE / DTLS-ServerHello tells (extends 0018)
- [0023](0023-cryptographic-node-admission.md) — Cryptographic node & client admission (signed membership credentials)
- [0024](0024-second-transport-reality-tcp.md) — Second transport: Reality over TCP :443 (implements 0008)
- [0025](0025-destination-based-split-tunnelling.md) — Destination-based split tunnelling (exclusion routes + live-learned bypass domains)
- [0026](0026-end-to-end-exit-admission-verification.md) — Client verifies the exit's admission credential end-to-end (extends 0023)
- [0027](0027-reality-active-probing-response.md) — Reality active-probing response: reverse-proxy unknown connections to a real origin (follow-up to 0024)
- [0028](0028-transport-pool-and-per-user-failover.md) — Transport/exit selection is a validated priority ladder with per-network learning (drives 0008, 0024)
- [0029](0029-version-fencing-implementation.md) — Min-version fencing: implementation of the version policy (implements 0015)
- [0030](0030-auto-reconnect-and-relay-failover.md) — Auto-reconnect + relay failover on the single-transport path (non-pooled counterpart to 0028)
- [0031](0031-first-class-session-and-peer-expiry.md) — First-class session & peer expiry: engine idle-reaper + activity-based coordinator TTLs (server-side counterpart to 0030)
- [0032](0032-reality-borrowed-certificate-clienthello-fork.md) — Reality borrowed certificate: authenticate in the ClientHello, fork unauthenticated connections to the real origin (follow-up to 0024, extends 0027)
- [0033](0033-prefer-peer-relays-over-turn-for-the-data-plane.md) — Prefer peer relays over TURN for the data plane: coordinator hands a peer-relay candidate, TURN as fallback (refines 0028's node tier)
- [0034](0034-udp-relay-forwarding.md) — General UDP relay forwarding rides the same E2E channel as CONNECT, via a target sentinel
- [0035](0035-surface-assigned-relay-to-client-for-rotation-dedup.md) — Surface the assigned relay to the client as an opaque tag for rotation dedupe (extends 0020, follows 0033)
- [0036](0036-windows-client-connection-strategy-and-invite-qr-ui.md) — Windows client gets a real GUI (lxn/walk) for connection-strategy settings (drives 0028) and invite QR display
- [0037](0037-mesh-walk-recovery-via-signed-peer-exchange.md) — Mesh-walk recovery: relay/exit couriers serve a cached coordinator-signed snapshot to a client that lost all coordinators (warm re-bootstrap, generalizes 0020; shares the snapshot with issue #6)
- [0038](0038-configurable-multi-hop-relay-chaining.md) — Configurable multi-hop relay chaining: client-assembled onion of nested Noise_NK layers so no single relay sees both endpoints, default 1 hop == today (generalizes 0033, lives in 0028's relay tier, preserves 0009/0026 E2E)
- [0039](0039-cross-platform-fyne-client-in-process-core.md) — Cross-platform client: all-Go Fyne UI calling core in-process, no webview, no FFI bridge (spike-proven seam; new cgo/mingw-w64 build prerequisite)
- [0040](0040-node-capacity-declared-limits-and-attested-measurement.md) — Node capacity: declared limits are self-reported (lying is self-limiting), measured capacity never is (lying pays) — usable = min(declared, measured); measurement is serving, not testing, so there is no tester. #143 built; #144 is a spike whose Sybil residual is stated openly (extends 0021, priced by 0023)
- [0041](0041-attested-capacity-feed-and-two-rating-estimator.md) — Attested-capacity feed + coordinator two-rating estimator: a co-signed receipt + one client-asserted saturation bit feeds a per-node `trusted`/`untrusted` pair (trusted decides, untrusted clamped to the ceiling); `Usable` at the assignment surfaces with the serve floor shipped off; the reality splice is now metered too (implements #157/#158, wires 0040, amends 0021 and 0027)
- [0042](0042-country-only-exit-assignment.md) — Country-only exit assignment: the coordinator derives a node's country from the address it OBSERVED (never the node's `-country` claim), the client names a country rather than an exit (killing a stable tracking handle), and a country with no headroom is reported busy rather than as a bare error (implements #136/#146/#147, amended by #1/#2/#3)
- [0043](0043-coordinator-enforces-signed-network-policy.md) — The coordinator enforces signed network policy it cannot author: a general `bacchus/delegation/v1` verifier (role matched exactly, reusable for the update/relay roles), policy `min_serving_version` overriding the flag in one place, a persisted sequence floor and byte-cached bundle re-verified on load, and a fail-closed soft drain past `exp + grace` that stops new assignments and leaves live sessions alone (implements #39, turns on what 0041 shipped off); amended by #15 — the serve floor reads `min_measured_bps` from the policy with no constant default, applied to the TRUSTED rating only, since a floor on the ceiling-clamped untrusted rating would fence every measured node and admit every unmeasured one
- [0044](0044-as-lookup-seam-and-as-diverse-hop-selection.md) — An independent IP→AS lookup behind one seam (`core/asn.Lookup`), AS-diverse hop selection derived from each hop's OBSERVED address rather than any signed tag, and the coordinator's `observedAS` moved behind the same interface with the prefix mask kept as the NAMED fallback; an unresolved AS is accepted but counts no diversity (never diverse-from-everything) and the degradation is reported rather than silent (implements #23, unblocks the ADR-0041 line 173 follow-up). **How the table ships and refreshes is left OPEN for the owner** — §6 measures the options rather than ruling on them
- [0045](0045-connect-time-device-credential-verification.md) — Connect-time device-credential verification: the coordinator verifies the account service's two-tier chain (offline root → issuer cert → device credential) OFFLINE at connect, tier by tier with the issuer cert fully validated before its key is used, the `max_cred_ttl` cap bound at verification, and a single-use coordinator-chosen challenge bound to an audience the client knows independently; coexists with `core/admission` rather than replacing it (different authorities, different questions, both checked), and fails OPEN when unconfigured — the opposite of 0043, because an absent anchor is read identically by every coordinator and so has nothing to shed to (implements #50, closes R1)
