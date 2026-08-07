// Bacchus coordinator v3 — directory + matchmaker with DIRECT or RELAY pairing.
//
// A client picks a COUNTRY and this coordinator picks the exit inside it (issue #146,
// ADR-0042). There is no exact-exit pinning for anyone:
//
//	list                             -> countries[]{country, exits, available, busy}
//	                                    the per-country capacity map, aggregate only
//	connect{country, mode:"direct"}  -> pair client <-> a chosen exit in that country
//	                                    (exit egresses directly); the reply names the
//	                                    chosen exit in exitId, which the client needs
//	                                    because an exit's id is its Noise static key
//	connect{country, mode:"relay"}   -> prefer a Bacchus peer relay to splice
//	                                    client <-> relay -> exit; when none is
//	                                    registered, fall back to pairing the client
//	                                    directly with the exit (TURN-relayed by ICE
//	                                    only if it can't hole-punch). Issue #17, ADR-0033.
//	                                 -> error{reason:"country-busy"|"no-such-country"}
//	                                    when nothing in the country is assignable
//	                                    (issue #147)
//
// Each node's country is DERIVED from the source address this coordinator observes it
// register from, never taken from its own claim (issue #136); its -country flag is a
// fallback hint for an address that resolves to nothing. That claim is also KEPT beside
// the derived tag rather than discarded (issue #113) — the two answer different
// questions, "what will sites conclude about this address" and "which building is the
// machine in", and they disagree routinely on cloud address space. Only the derived one
// is ever selected on. An admin can correct that derivation, and only that one, through
// -country-overrides.
//
// Plus registry (exits/relays, heartbeat TTL) and session-tagged signaling relay.
// See ../research/05-network-pairing.md.
//
// Also runs the real STUN/TURN server (pion/turn) and, blended onto that
// same UDP socket and port, the cold-start bootstrap listener (issue #18,
// core/coldstart): a STUN-shaped, per-user-secret-authenticated request gets
// a signed snapshot of this registry; every other packet on that port passes
// through to pion/turn unchanged (issue #30, core/coldstart.Demux). See
// docs/design/bootstrap-protocol.md and ADR-0017.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/capacity"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/geoip"
	"github.com/bacchus-vpn/bacchus/core/handshake"
	"github.com/bacchus-vpn/bacchus/core/version"
	"github.com/pion/turn/v4"
)

const (
	ttl = 35 * time.Second
	// sessionTTL is the idle window for a signaling rendezvous entry: its state is
	// dropped this long after the last offer/answer/candidate relayed for it, so a
	// vanished client (which never heartbeats) is reaped on inactivity rather than
	// lingering to a fixed age. Generous enough to outlast any real handshake or
	// trickle-ICE exchange.
	sessionTTL = 2 * time.Minute

	// reselectInterval is how often the coordinator sweeps live sessions to check
	// the peer relay each one actually rides is still alive (issue #96), driven by
	// a timer rather than by incoming packets so it fires on an otherwise-idle
	// coordinator too. One heartbeat window (a forwarder re-announces every 10s,
	// core/engine.go registerLoop), so a relay that stops heartbeating is caught
	// about as fast as the directory itself notices it go stale.
	reselectInterval = 10 * time.Second

	// answerGrace is how long an assigned forwarder has to say ANYTHING at all about
	// a session before reportUnansweredNodes counts that session against it (issue
	// #114). A node answers as a consequence of receiving its assign, not of the
	// client's offer — core's startFwdSession runs transport.Accept the moment the
	// assignment lands — so this window is not waiting on a negotiation, only on one
	// datagram being processed.
	//
	// Set past the client's own patience on every path (core gives a direct attempt
	// 12s and a relayed one 18s), so a session that trips this has already outlived
	// the connect it was minted for and no live attempt is being second-guessed. Well
	// inside sessionTTL, so a direct session is still in the table when it trips.
	answerGrace = 30 * time.Second

	snapshotTTL     = 5 * time.Minute
	snapshotRefresh = 10 * time.Second
	secretsReload   = 30 * time.Second
)

// wire mirrors core's wire envelope byte-for-byte (kept as a separate copy so
// this binary does not need to import core and its transport stack). See
// core/handshake and ADR-0016 for the Magic/Version/Capabilities/Reason
// fields: a node's first message is "hello", before register/list/connect;
// this coordinator replies "reject" with Reason on a version mismatch and
// stays silent on a match.
type wire struct {
	Type    string `json:"type"`
	Role    string `json:"role,omitempty"`
	ID      string `json:"id,omitempty"`
	Country string `json:"country,omitempty"` // on register: the node's self-reported -country tag, a HINT only (issue #136) — the coordinator derives the real tag from the observed source IP and uses this solely when that resolves nothing. On connect: the country the USER chose, which is the entire input to exit selection (issue #146). On a refusal: the country the refusal is about (issue #147).
	Addr    string `json:"addr,omitempty"`
	Mode    string `json:"mode,omitempty"` // "direct" | "relay"
	Session string `json:"session,omitempty"`
	// ExitID is the coordinator's ANSWER, not the client's request (issue #146,
	// ADR-0042): it names the exit this coordinator chose inside the requested
	// country, and it is carried on the "session" reply because the client needs it —
	// an exit's id IS its Noise static public key (ADR-0009), so the client cannot
	// bring up the end-to-end channel without knowing which exit it got. A client
	// does NOT send it: there is no exact-exit pinning for anyone, so a country is
	// the only thing a connect names.
	ExitID string `json:"exitId,omitempty"`
	// FirstHop is the one node a client MAY name on a connect (issue #142, ADR-0038;
	// the field ADR-0042 §9 reserved for it). It is the head of a relay chain the
	// client assembled itself out of the signed directory, NOT an exit request: this
	// coordinator pairs the client with that node and never learns where the path
	// terminates, because the real exit is named only inside an onion layer it cannot
	// read. Country is absent alongside it, and the session this coordinator mints
	// records no exit id at all — see the connect handler.
	//
	// It is accepted ONLY on a relay-mode connect (the handler refuses any other mode
	// with refuseHopNotRelayMode): outside relay mode there is no onion, so the node
	// named would be the node the client egresses from, and honouring it would be the
	// exact-exit pinning #146 removed.
	//
	// For an honest client this is not pinning by another door — the node named is
	// drawn fresh from a shuffled candidate set on every connect and is not the node
	// it egresses from. That is a property of the CLIENT, though, not one this
	// coordinator can verify: a client may ask for relay mode, name the node it
	// wants, and terminate there rather than peeling, and a chained connect is
	// indistinguishable from that by design, since the terminating exit is inside a
	// layer this coordinator must not be able to read. ADR-0042 §9 states the
	// residual and why it was accepted rather than closed.
	FirstHop string `json:"firstHop,omitempty"`
	// Nonce is the client's per-connect idempotency key (issue #1, ADR-0042 §2): one
	// fresh value per pairing REQUEST, repeated byte-identically across the copies
	// core's sendN puts on the wire against UDP loss. This coordinator answers the
	// first copy by minting a session, remembers that answer under (source address,
	// nonce), and REPLAYS it for every later copy rather than assigning again.
	//
	// Without it one request was several assignments. sendN sends each connect three
	// times and this handler processed every copy independently, minting a session per
	// copy through a fresh randomized chooseExit — so one Connect() drew three
	// independent exits inside the country and the client could simply keep the reply
	// naming the exit it wanted. That is exact-exit pinning reconstructed out of packet
	// loss handling, and it inflated exitSessions by the same factor, which is the one
	// ranking term a node cannot forge but a CLIENT could.
	//
	// REQUIRED on a connect, not optional (refuseNoNonce). An idempotency key a client
	// may omit is not a guard, it is an opt-in: the client that wants several draws is
	// exactly the one that would leave the field off. ADR-0042 already broke this wire
	// once for #146 on the owner's "no installed base before v1" call, and both halves
	// of this one land together too.
	//
	// It is scoped per pairing request, NOT per Connect(): connectVia walks the mode
	// ladder and each mode is a genuinely different request (a direct pairing and a
	// relayed one are not interchangeable answers), so each carries its own nonce and
	// is answered on its own merits. What is collapsed is retransmission, which is the
	// thing that was never a decision.
	Nonce string `json:"nonce,omitempty"`
	// ExcludeSessions names sessions THIS coordinator minted for this client whose
	// exits it has just failed against, so a retry is not handed the same broken exit
	// (issue #146; the rotation-dedupe idea ADR-0035 gave relays). The coordinator
	// resolves each to the exit it assigned and avoids those — see excludedExits.
	//
	// Sessions, not exit ids, and that is the whole design (ADR-0042 §7). A client that
	// could exclude by id could name the complement of the exit it wants and get it
	// deterministically, which is exact-exit pinning reconstructed out of the one
	// affordance left behind. Naming sessions means you can only exclude an exit you
	// were actually ASSIGNED, so the complement has to be walked one randomized
	// assignment at a time rather than asserted. Advisory and bounded either way:
	// excluding cannot name what you get, only what you do not, and only while a real
	// choice survives.
	ExcludeSessions []string               `json:"excludeSessions,omitempty"`
	ExitAddr        string                 `json:"exitAddr,omitempty"`
	Countries       []countryInfo          `json:"countries,omitempty"` // the per-country capacity map a client picks from (issue #146): aggregate counts and busy-ness per country, replacing the pre-#146 per-exit list. Strictly less than that list gave — a count is not a network map, and not the raw material for a pin.
	SDP             string                 `json:"sdp,omitempty"`
	Cand            json.RawMessage        `json:"cand,omitempty"`
	Magic           string                 `json:"magic,omitempty"`
	Version         int                    `json:"version,omitempty"`
	Capabilities    []handshake.Capability `json:"capabilities,omitempty"`
	Reason          string                 `json:"reason,omitempty"`
	Cred            string                 `json:"cred,omitempty"`        // admission credential (issue #42); verified on register/list/connect
	Release         string                 `json:"release,omitempty"`     // product release version, semver (issue #36, ADR-0015): a node stamps it on register (this coordinator fences a stale one); this coordinator stamps its own on client replies so a client can force-major/skip-minor. Distinct from Version, the wire-shape int (ADR-0016).
	Relay           string                 `json:"relay,omitempty"`       // relay disposition on a relay-mode "session" reply (issue #17, ADR-0033): relayPeer = a Bacchus relay node splices client<->exit (preferred); relayTURN = no peer relay available, the client reaches the exit directly and its ICE relays through TURN only if it can't hole-punch (fallback). Empty on direct-mode replies.
	RelayTag        string                 `json:"relayTag,omitempty"`    // stable opaque tag identifying the assigned peer relay (issue #56, ADR-0035), so a client rotating the coordinator pool can skip a second member that assigns the SAME relay it just failed on. Set only on the peer-relay path; empty for direct/TURN-fallback (no distinct relay to dedupe). Additive/optional — a client predating #56 ignores it.
	IngressPort     int                    `json:"ingressPort,omitempty"` // a relay's onion-forward TCP listener port (issue #124, ADR-0038): the port a client's onion layer dials to use this node as an intermediate hop. Self-reported on register — the coordinator cannot observe a TCP listener from a UDP register — but only the PORT is trusted: buildSnapshot advertises the ingress as the coordinator-OBSERVED source IP joined to this port, so a relay cannot assert an ingress IP (see Entry.Ingress). Zero/absent => this relay advertises no ingress and is not relay-eligible. Additive/optional; a relay predating #124 omits it.
	SpeedCap        uint64                 `json:"speedCap,omitempty"`    // a forwarder's DECLARED aggregate speed cap in bits/s (issue #143, ADR-0040): what its operator is WILLING to carry, which is not what it CAN carry. Self-reported, and trusted, because this claim can only ever bind downward: under-declaring merely reduces what the node is given (its operator's uplink, their ISP bill, their call), and over-declaring is inert because usable = min(declared, measured) and the measured term is NOT a self-report. Contrast Operator/Ingress, where the self-report is exactly the thing an attacker profits from and is therefore not trusted. Zero/absent = no declared cap; additive/optional, so a node predating #143 is treated exactly as it is today.
	// DeclaredQuotaBytes is a forwarder's DECLARED monthly traffic quota in BYTES
	// (issue #49, ADR-0040 amendment): the cap its operator configured, which is the
	// input the signed policy's serve_floor.min_declared_quota_bytes is compared
	// against. Mind the unit split against SpeedCap directly above — that is a RATE
	// in bits/s, this is a VOLUME in bytes; both carry the unit in the field name
	// because the two are never interconvertible and never compared.
	//
	// The CONFIGURED CAP only, never the counter and never a usage series. That
	// distinction is what makes this disclosable where the byte counts are not: a cap
	// is a constant its operator chose, a usage curve is a measurement of their
	// household (ADR-0040, ADR-0020, #60).
	//
	// Self-reported and trusted on SpeedCap's argument — it binds only downward, so a
	// node under-declaring merely fails this floor and lies itself out of traffic.
	// Zero/absent = no declared quota; additive/optional, so a node predating #49 is
	// treated exactly as it is today.
	DeclaredQuotaBytes uint64 `json:"declaredQuotaBytes,omitempty"`
	// SessionCapBps is the RESOLVED per-session speed cap in bits/s that this
	// coordinator stamps on an "assign" for the exit to shape the session to (issue
	// #58, ADR-0048). It is the speed_cap_bps of the signed policy's tier row for the
	// connecting account's (trust, plan) pair — read out of a document verified
	// against the policy root, never authored here and never asserted by a peer.
	//
	// Coordinator -> exit only, and only on an assign the EXIT receives: a peer-relay
	// assign carries ExitAddr and goes to the relay, which terminates nothing. Zero
	// or absent means unshaped, which is what an unpoliced coordinator sends and what
	// every coordinator predating #58 sends; a node reading it builds
	// capacity.NewLimiter(0), which is nil and inert, so no branch is needed either
	// side. Additive/optional throughout.
	//
	// Distinct from SpeedCap above: that is a NODE's declared AGGREGATE cap on
	// register, this is one USER's per-session entitlement. They compose rather than
	// override — the node's own limiter still paces every byte, so this cannot raise
	// what an operator already refuses to exceed (ADR-0040).
	//
	// Byte-for-byte the same field as core/engine.go's wire (that binary does not
	// import this one, by design — see this type's doc); TestSessionCapWireContract
	// pins both copies so they cannot drift, the same way TestQuotaStateWireContract
	// pins the quota literals.
	SessionCapBps uint64              `json:"sessionCapBps,omitempty"`
	QuotaState    string              `json:"quotaState,omitempty"` // quotaOK | quotaExhausted (issue #143, ADR-0040): whether this forwarder's declared monthly quota — its operator's own ISP data cap — is spent for the current billing cycle. Re-sent on EVERY register (core/engine.go registerLoop) because the handler below replaces the registry entry wholesale, so a state carried once would be forgotten 10s later. One BIT rather than the byte counts, deliberately: matchmaking needs only "may I assign to you", and a per-node monthly usage curve would hand this coordinator — untrusted by standing assumption (ADR-0020, #60) — a linkability signal about a residential operator's household in exchange for nothing. Empty = no declared quota; additive/optional.
	Receipt       *accounting.Receipt `json:"receipt,omitempty"`    // capacity-report payload (issue #158, ADR-0041): a co-signed usage receipt (ADR-0021) the CLIENT sends to feed the coordinator-side capacity estimator. Carries the client-asserted Saturated bit; bound to the co-signing client by ReportSig. Absent on every other message. A leaf import (core/accounting), like admission — not the transport stack this binary avoids.
	ReportSig     []byte              `json:"reportSig,omitempty"`  // client signature over the capacity-report receipt + its saturation bit (accounting.SignReport, issue #158): proves the un-co-signed Saturated bit came from the client that co-signed the receipt, so a node that merely holds the receipt cannot forge or flip it.

	// Connect-time device-credential verification (issue #50, ADR-0045). These four
	// carry the account service's two-tier entitlement chain, which is a DIFFERENT
	// credential from Cred above: Cred is the network's own membership (one tier,
	// bearer, operator-anchored), these are an entitlement bound to one device
	// (two tiers, challenge-bound, anchored to a root the operator does not hold).
	// Both are checked on a connect and neither replaces the other.
	//
	// All four are additive/optional: with -device-root-pubkey unset the gate is off
	// and a client predating #50 connects exactly as it does today.
	Challenge    string `json:"challenge,omitempty"`    // standard base64. Coordinator -> client on a "challenge" reply: the fresh nonce a device must sign. Client -> coordinator on a "connect": the nonce it signed, echoed back so a mismatch is a clear refusal rather than an opaque assertion failure. Single use — spending it removes it, so a captured connect cannot be replayed inside the nonce's own lifetime.
	DeviceCred   string `json:"deviceCred,omitempty"`   // the device credential in its "bacchusd1:" envelope form: tier two, signed by the issuer key, carrying the device pubkey, the account generation and a short window.
	IssuerCert   string `json:"issuerCert,omitempty"`   // the issuer cert in its "bacchusi1:" envelope form: tier one, signed by the OFFLINE ROOT, delegating "may issue device credentials" with a cap on what it may mint. Verified against the anchored root before anything inside it is trusted.
	DeviceAssert string `json:"deviceAssert,omitempty"` // standard base64. The device's signature over purpose || audience || challenge, proving it holds the key inside DeviceCred. The audience and challenge bindings are what stop this being replayed at another coordinator or a later connect.
}

// Declared-quota dispositions (issue #143, ADR-0040) carried in wire.QuotaState.
// Mirrors core's constants of the same name; the literals are duplicated because
// this binary deliberately does not import core (see wire's doc above).
// TestQuotaStateWireContract in capacity_test.go pins both copies so they cannot
// drift, exactly as TestRelayDispositionWireContract does for relayPeer/relayTURN
// (issue #97).
const (
	quotaOK        = "ok"        // quota unset, or unspent this cycle: assignable
	quotaExhausted = "exhausted" // this cycle's declared quota is spent: do not assign
)

// Relay-mode dispositions (issue #17, ADR-0033), stamped on the client's
// "session" reply so it knows whether it got the preferred Bacchus peer relay
// or the TURN fallback. Mirrors core's constants of the same name.
//
// The literals are duplicated in core/engine.go (that binary does not import
// this one). TestRelayDispositionWireContract in relay_metadata_test.go pins both
// copies so they cannot drift (issue #97).
const (
	relayPeer = "peer"
	relayTURN = "turn"
)

// relayTag derives the stable, opaque rotation-dedupe tag (issue #56, ADR-0035)
// the client receives for an assigned peer relay. It is a domain-separated hash
// of the relay's node id, chosen so that:
//   - two coordinators that assign the SAME relay produce the SAME tag — the id
//     is the relay's own identity, registered identically with every pool member
//     (registerLoop broadcasts one reg to all), which is exactly what lets a
//     rotating client tell "same bad relay again" from "a fresh one to try";
//   - it is not the relay's routable address, and a hash rather than the raw id
//     keeps the wire tag decoupled from the internal id format while revealing
//     nothing the client could not already infer from the relay's ICE candidates
//     (ADR-0009's blind-relay model).
//
// Set only on the peer-relay path; direct and TURN-fallback replies carry no tag
// (there is no distinct relay to dedupe). Eight bytes is ample against collision
// in a relay pool this size and keeps the datagram small.
func relayTag(id string) string {
	sum := sha256.Sum256(append([]byte("bacchus-relay-tag\x00"), id...))
	return hex.EncodeToString(sum[:8])
}

// forwarderHealth is what this coordinator remembers about a registered forwarder
// that is NOT restated on every register: the build it says it is running, and what
// this coordinator has already said about it (issue #114). Embedded in both
// relayNode and exitNode, because both roles are assigned work and both can fail to
// do it without failing to register.
//
// It is the one part of a registry entry that must be CARRIED across the wholesale
// replacement each register performs (carryHealth) rather than rebuilt from the
// register itself. A forwarder re-announces every 10s (core/engine.go registerLoop)
// and this handler replaces its entry each time, so state that exists precisely to
// stop something being said twice would be forgotten before its second chance to
// say it.
type forwarderHealth struct {
	// release is the node's self-reported product release (semver, ADR-0015) as of
	// its last register. Stored rather than only logged so the NEXT register can be
	// compared against it: the "registered" line below fires only for a node not
	// already in the registry, so a node rebuilt and restarted under a running
	// coordinator — a staged rollout, which is when skew actually appears — would
	// otherwise change build entirely silently. A restart takes about a second and
	// the entry survives 35s (ttl), so the new build never reaches that line.
	release string
	// silentWarned latches reportUnansweredNodes's warning so it is said once per
	// episode rather than once per 10s sweep. Cleared the moment the node answers
	// anything, so a node that fails, recovers and fails again is reported both
	// times rather than once forever.
	silentWarned bool
}

// carryHealth builds the health record for a node that has just registered: the
// release this register states, plus whatever this coordinator has already said
// about the node. prior is nil for a node not currently in the registry.
func carryHealth(prior *forwarderHealth, release string) forwarderHealth {
	h := forwarderHealth{release: release}
	if prior != nil {
		h.silentWarned = prior.silentWarned
	}
	return h
}

type relayNode struct {
	forwarderHealth
	id   string
	addr *net.UDPAddr
	// ingressPort is the relay's self-reported onion-forward TCP listener port (issue
	// #124). buildSnapshot advertises the forwarding ingress as addr.IP (observed) joined
	// to this port; zero means the relay advertised none and is not relay-eligible.
	ingressPort int
	// Declared limits (issue #143, ADR-0040). exhausted means this operator's monthly
	// quota is spent for the cycle, and pickRelay will not choose this relay while it
	// is set. A relay spends its operator's uplink exactly as an exit does, and their
	// ISP meters it identically, so it declares limits the same way.
	//
	// speedCap (bits/s the operator is willing to carry; 0 = uncapped) is recorded off
	// every register but deliberately has NO reader yet: it is one half of
	// usable = min(declared, measured), and the measured half needs the attested-sample
	// feed that ADR-0040 §8.6 defers to a child issue. Gating on it now would compare
	// against a rating that is always the floor. The node enforces its own cap
	// regardless (core/capacity).
	speedCap uint64
	// declaredQuota is the operator's declared monthly quota in BYTES (issue #49) —
	// the volume to speedCap's rate. Recorded off every register for the same reason
	// speedCap is: the entry is replaced wholesale, so a field carried once would be
	// dropped 10s later. It is read by the serve-eligibility gate (servingCheck) to
	// apply the policy's min_declared_quota_bytes; it is NOT usage, so nothing here
	// changes as the node spends it — that is what the exhausted bit reports.
	declaredQuota uint64
	exhausted     bool
	lastSeen      time.Time
	// country is the coordinator-DERIVED country tag (issue #136): resolved from the
	// observed source IP in addr, falling back to the node's self-reported hint only
	// when that resolves nothing. countrySource records which of the two it was, for
	// the operator log. Empty means no country could be established.
	//
	// A relay registers a -country tag exactly as an exit does, but before #136 this
	// struct had no field for it and buildSnapshot never advertised it, so relay
	// country was silently discarded. It is carried now: ADR-0038's hop selection
	// wants to know where a relay is, and #136 covers relays explicitly.
	//
	// declaredCountry is the node's OWN -country tag, canonicalized, kept beside the
	// derived one rather than discarded when it loses (issue #113). A bare self-report:
	// it is never what country holds, is never read by assignment, and travels only so
	// an operator-facing surface can say what the node claims. See countryClaims and
	// coldstart.Entry.DeclaredCountry.
	country         string
	countrySource   string
	declaredCountry string
}
type exitNode struct {
	forwarderHealth
	id, tcpAddr string
	udp         *net.UDPAddr // signaling addr (for direct mode)
	// Declared limits (issue #143, ADR-0040; declaredQuota is issue #49); see
	// relayNode. An exhausted exit is withheld from the country aggregate and refused
	// at connect.
	speedCap      uint64
	declaredQuota uint64
	exhausted     bool
	lastSeen      time.Time
	// country / countrySource: coordinator-derived, as for relayNode (issue #136). An
	// exit with no country is unreachable, because a country is the only thing a
	// client can ask for (issue #146) — see exitAssignable.
	// declaredCountry: the exit's own -country tag, carried beside the derived one
	// (issue #113); see relayNode.
	country         string
	countrySource   string
	declaredCountry string
}

// claims gathers a relay's stored country claims back into the value the derivation
// works in. The registry keeps them as flat fields because assignment reads e.country
// directly and that seam is deliberately untouched by issue #113.
func (r *relayNode) claims() countryClaims {
	return countryClaims{derived: r.country, source: r.countrySource, declared: r.declaredCountry}
}

// setClaims stores a fresh derivation on a relay. displaced is deliberately not kept: it
// describes one act of overriding, and every heartbeat re-derives.
func (r *relayNode) setClaims(c countryClaims) {
	r.country, r.countrySource, r.declaredCountry = c.derived, c.source, c.declared
}

func (e *exitNode) claims() countryClaims {
	return countryClaims{derived: e.country, source: e.countrySource, declared: e.declaredCountry}
}

func (e *exitNode) setClaims(c countryClaims) {
	e.country, e.countrySource, e.declaredCountry = c.derived, c.source, c.declared
}

type session struct {
	client, peer *net.UDPAddr // peer = relay (relay mode) or exit (direct mode)
	// relayID names the peer relay actually carrying this session, set only on the
	// peer-relay path (issue #17); empty for direct and TURN-fallback sessions,
	// which have no relay to monitor. reselectDeadRelays keys in-session liveness
	// off it — a session whose named relay has gone stale is one whose data plane
	// has died under it (issue #96).
	relayID string
	// exitID names the exit terminating this session, on every path (direct,
	// peer-relay and TURN-fallback alike). It is the load half of country-scoped
	// assignment (issue #146): exitSessions counts these to learn how busy each exit
	// is, which is the one input to the ranking that this coordinator observed itself
	// rather than being told. Unlike relayID it is never empty for a live session —
	// every session has an exit.
	exitID string
	// signaled records whether ANY offer/answer/candidate has been relayed for this
	// session since it was minted — that is, whether the client ever tried to bring
	// the transport up over it. Every transport in the repo drives its handshake
	// through this coordinator (core.Signaler; WebRTC exchanges SDP and candidates,
	// Reality an offer and an answer), so a session that has never seen a frame was
	// paired and then abandoned.
	//
	// It exists because prune EXEMPTS peer-relay sessions from the idle sweep (their
	// liveness is their relay's — issue #96/#105), and that exemption was load-bearing
	// for the harvest #1 describes: a client minting relay-mode sessions it never used
	// accumulated entries that no reaper would ever touch, so the exits it had been
	// assigned stayed nameable in ExcludeSessions indefinitely while a direct-mode
	// client's aged out in two minutes. Distinguishing "never brought up" from "up and
	// quiet" reaps the first without weakening the second.
	signaled bool
	// answered records whether the ASSIGNED FORWARDER — the peer, so the exit on a
	// direct or TURN-fallback session and the relay on a peer-relayed one — has ever
	// spoken on this session. It is the other half of signaled, and the two answer
	// genuinely different questions (issue #114): signaled is true as soon as EITHER
	// side speaks, and a client speaks first on every path, so a session the assigned
	// node never even received is signaled. That is what made the failure this field
	// exists for invisible — the client posted its candidates, the coordinator relayed
	// them, and the session looked used.
	//
	// A node answers as a consequence of its ASSIGN, not of the client's offer:
	// core's startFwdSession calls transport.Accept the moment the assignment lands,
	// and the responder's answer and candidates come straight back through this
	// coordinator. So !answered does not mean "the client gave up early" — it means
	// the assignment was never acted on. A client walking away before it ever spoke
	// leaves !signaled instead, which reportUnansweredNodes deliberately ignores.
	answered bool
	lastSeen time.Time // last signaling activity; the rendezvous state is reaped sessionTTL after it goes quiet
}

var (
	mu       sync.Mutex
	relays   = map[string]*relayNode{}
	exits    = map[string]*exitNode{}
	sessions = map[string]*session{}
	pc       *net.UDPConn

	// rendezvous demultiplexes the signaling socket between DTLS and raw JSON
	// (issue #175 slice 1, ADR-0059). Nil when -rendezvous-dtls=false and in
	// every test that drives handle() directly, which is why replyTo tolerates a
	// nil receiver: a nil mux means "nobody is on the new shape", and every reply
	// goes out in the clear exactly as before.
	rendezvous *rendezvousMux

	// operators maps a node id to its coordinator-known operator / vouch-subtree tag,
	// advertised in the signed directory for operator-diversity hop selection (issue
	// #124, ADR-0038 §6). It is coordinator-side truth, NOT a node self-report — a node
	// cannot be trusted to state its own operator or a Sybil would fabricate diversity.
	// Loaded once at startup from -operators (before any goroutine reads it) and never
	// mutated after, so buildSnapshot reads it under mu alongside the registry maps
	// without a separate write path. Empty (every tag "") when unset: fail-open, like
	// admission (issue #42) — with no assignments, hops are simply unlabeled and §4 falls
	// back to its IP-derived AS diversity.
	operators = map[string]string{}

	// Version policy (issue #36, ADR-0015). servingFloor is the minimum node
	// release this coordinator will assign work to; a register below it is fenced
	// (dropped from matchmaking). The zero value (0.0.0) disables the fence.
	// coordRelease is this coordinator's own release, advertised to clients so
	// they can apply the force-major / skip-minor rule. Both are set once in main.
	servingFloor version.Version
	coordRelease string
)

// send delivers one reply to a peer, in whichever shape that peer reached us in
// (issue #175 slice 1, ADR-0059). A peer with an established DTLS association
// gets the reply inside it; every other peer — which is every client on the
// current build — gets the cleartext datagram this has always sent.
//
// The choice lives here, in the one function every handler already replies
// through, rather than in the handlers. That is what kept the DTLS half from
// touching handle() at all.
func send(to *net.UDPAddr, m wire) {
	b, _ := json.Marshal(m)
	if rendezvous.replyTo(to, b) {
		return
	}
	_, _ = pc.WriteToUDP(b, to)
}
func randID() string { b := make([]byte, 8); _, _ = rand.Read(b); return hex.EncodeToString(b) }

func main() {
	addr := flag.String("addr", ":8080", "UDP listen address for signaling")
	advertise := flag.String("advertise", "", "coordinator's public host:port, as clients should dial it (defaults to -addr; set explicitly when -addr is a wildcard bind)")
	turnAddr := flag.String("turn-addr", ":3478", "UDP listen address for the real STUN/TURN server; the cold-start bootstrap listener is blended onto this same port (issue #30)")
	turnPublicIP := flag.String("turn-public-ip", "", "VPS public IP (required, for TURN relay)")
	turnRealm := flag.String("turn-realm", "bacchus", "TURN realm")
	turnUser := flag.String("turn-user", "bacchus", "TURN username")
	turnPass := flag.String("turn-pass", "", "TURN password (required)")
	bootstrapKeyPath := flag.String("bootstrap-key", "secrets/coordinator-bootstrap.key", "path to the snapshot-signing ed25519 key (hex seed); generated on first run if missing")
	bootstrapSecretsPath := flag.String("bootstrap-secrets", "secrets/bootstrap-secrets.json", "path to the per-user bootstrap secrets file (see cmd/coldstart-issue); reloaded periodically")
	admissionPubKey := flag.String("admission-pubkey", "", "admission authority public key (hex, from cmd/admission-issue), trusted for EVERY role. When set, every node (register) and client (list/connect) must present a credential this key signed (issue #42). Empty disables admission only if -admission-authority is also unset — the network then serves anyone. NOTE this flag names a different thing here than it does on bacchus-node: there it is the client's single anchor for verifying an EXIT's credential end-to-end (issue #60); here it is one member of this coordinator's anchored authority set. See ADR-0047.")
	var admissionAuthorities authorityFlags
	flag.Var(&admissionAuthorities, "admission-authority", "an admission authority scoped to the roles it may admit, \"role[,role...]:hexkey\" — repeatable, one occurrence per authority (issue #64, ADR-0047). Roles are client, relay, exit. Use it to keep the always-online issuer off the credentials that admit forwarding infrastructure: -admission-authority relay,exit:<operator key> -admission-authority client:<account service key>. Composes with -admission-pubkey, which is the same thing scoped to every role. A credential is admitted only if an authority anchored for the role being taken signed it, so the scoping holds even against an issuer that writes any roles it likes into what it mints.")
	admissionRevocations := flag.String("admission-revocations", "secrets/admission-revocations.json", "path to the revoked-credential-serials file (hot-reloaded); a missing file means nothing is revoked. One list covers every anchored authority — serials are unique per credential regardless of who signed it.")
	deviceRootPubKey := flag.String("device-root-pubkey", "", "offline ROOT public key (hex) that the account service's device-credential chain anchors to (issue #50, ADR-0045). When set, every client connect must additionally present a device credential, the issuer cert it chains through, and an assertion over a challenge this coordinator issued — all verified OFFLINE, so this coordinator never calls the account service. Empty DISABLES the gate and leaves connects gated by -admission-pubkey alone. This is a DIFFERENT credential from -admission-pubkey's: that one is the network's own membership, this one is an entitlement bound to one device, and both are checked. Direction of failure matches -admission-pubkey (unset = off) and is deliberately the opposite of -policy-root-pubkey; see ADR-0045 for why an absent anchor is not sheddable the way a stale policy is.")
	deviceAudienceFlag := flag.String("device-audience", "", "the audience string a device must bind its connect assertion to (issue #50). Defaults to -advertise, which is what a client knows independently because it chose to dial it. Set explicitly only when clients reach this coordinator under a name it does not advertise itself as. An assertion bound to an audience the coordinator merely announced would bind nothing — a hostile pool member would announce someone else's and relay.")
	deviceRevocations := flag.String("device-revocations", "secrets/device-revocations.json", "path to the revoked device-credential and issuer-cert serials file (hot-reloaded); a missing file means nothing is revoked. Separate from -admission-revocations because the two credentials come from different authorities and their serial namespaces are unrelated.")
	operatorsPath := flag.String("operators", "secrets/operators.json", "path to the node->operator-tag assignment file (JSON object {\"nodeID\":\"operatorTag\"}), advertised in the signed directory for operator-diversity hop selection (issue #124, ADR-0038); a missing file means no operator tags")
	geoipDir := flag.String("geoip", "", "path to an unzipped MaxMind GeoLite2-Country-CSV directory, used to derive each node's country from the source address this coordinator OBSERVES it register from (issue #136). Staged out of band and never committed; see docs/RUNNING.md. Empty DISABLES derivation and falls back to each node's self-reported -country tag.")
	geoipRequired := flag.Bool("geoip-required", false, "refuse to fall back to a node's self-reported -country when its observed address does not resolve (issue #136). The hardened posture: no node self-report can reach a client's country choice. Off by default because every node in a local stack registers from loopback, which no database resolves. Requires -geoip. NOTE two things this deliberately does NOT do (issue #113). The node's -country claim is still RECORDED and published as a labelled DECLARATION beside the country, because carrying a claim is not choosing one — under this flag the country is empty precisely because the claim was refused, and nothing in this project selects, filters or groups on a declaration. And an admin correction staged in -country-overrides still wins over the derivation, because that is this coordinator's own operator speaking rather than a node self-report; see that flag.")
	countryOverridesPath := flag.String("country-overrides", "secrets/country-overrides.json", "path to the admin's per-node country corrections (JSON object {\"nodeID\":\"CC\"}, two-letter ISO-3166-1 alpha-2 codes), hot-reloaded every 30s; a missing file means no corrections and an empty path disables it (issue #113, ADR-0042 §8). Coordinator-side truth, NOT a node self-report — the same standing -operators has. An entry REPLACES what this coordinator derived for that node, in the country list, in assignment and in the signed directory, and it wins even under -geoip-required. READ THIS BEFORE EDITING IT: an override is a correction to the DERIVED country — \"your GeoIP table is wrong, this address really does present as DE\", which is an assertion about the ADDRESS that you can check against what real sites conclude. It is NOT a way to state where the machine physically sits. If the box is in DE but its address resolves US, the correct value is US: a user picks DE to be TREATED AS German by every site they visit, and an address that resolves US is treated as US regardless of which building it is in, so \"correcting\" that misroutes exactly the user who cared enough to choose. The node's own claim about its location is already carried separately and is deliberately not selectable. One more consequence to know: an override is terminal, so for an exit it also suppresses the signaling-vs-advertised-endpoint comparison and the contradiction label a chaining client refuses on — the coordinator logs a warning naming that when it happens. A file with any unusable row is refused whole: fatal at startup, and on a reload the corrections already in effect are kept.")
	asnTablePath := flag.String("asn-table", "", "path to a disjoint IP->ASN table (`prefix<TAB>asn` rows, see core/asn), used to resolve a capacity attester's autonomous system from the source address this coordinator OBSERVES its report arrive from (issue #23, ADR-0044). The AS is the unit of Sybil cost the ~4:1 attestation bound is denominated in (ADR-0041). Staged out of band and never committed. Empty falls back to masking the observed IP to a routing prefix (/24, /48), which is what this coordinator did before the table existed.")
	minServingVersion := flag.String("min-serving-version", "0.0.0", "minimum node release (MAJOR.MINOR.PATCH) this coordinator will assign work to; nodes below it are fenced from matchmaking until they update (issue #36, ADR-0015). Raise it past the grace window after a release to pull stragglers up. 0.0.0 disables the fence — every node serves regardless of version.")
	policyRootPubKey := flag.String("policy-root-pubkey", "", "offline ROOT public key (hex) the signed network policy chains to (issue #39, ADR-0043). When set, this coordinator fetches a signed policy bundle and enforces the floors, fences and reserves inside it — numbers it cannot author, because it does not hold the key that signs them. Empty DISABLES signed policy and leaves this coordinator enforcing only its own flags. NOTE the direction of failure flips here: unlike -admission-pubkey and -min-serving-version, which fail OPEN when unset, a coordinator WITH a policy root configured stops assigning new work once its policy goes stale. Coordinators are a pool with client rotation, so one failing closed sheds to its peers.")
	policySource := flag.String("policy-source", "", "where to fetch the signed policy bundle from: an http(s) URL, or a filesystem path an operator stages the bundle at. Required when -policy-root-pubkey is set. Re-fetched every 10s and re-verified from scratch every time, delegation included.")
	policyStatePath := flag.String("policy-state", "secrets/policy-state.json", "path to this coordinator's persistent policy state (issue #39): the last VERIFIED bundle, so a restart does not begin unpoliced, and the highest policy sequence ever accepted, which is what refuses a rollback. The sequence floor cannot be re-derived from signed data, so write access to this file is equivalent to being able to roll this coordinator back one generation — keep it with the other secrets.")
	rendezvousDTLS := flag.Bool("rendezvous-dtls", true, "accept the shaped rendezvous handshake on -addr — a STUN connectivity check and DTLS, alongside raw JSON, on the same port (issues #175/#202, ADR-0059/0060). READ THIS BEFORE TURNING IT OFF. It was written as a free valve for shedding the per-source association table under a spoofed-source flood, and it is no longer free: since #175 slice 2 (ADR-0062) the client speaks this shape and has DELIBERATELY NO CLEARTEXT FALLBACK, because a censor dropping the handshake and a coordinator that never learned it are the same silence, and answering that silence with plaintext would send exactly what the shape exists to hide. So switching this off does not degrade this coordinator, it REMOVES it: no current client can reach it at all, they rotate away on the existing 30-second cooldown, and this coordinator's share of the pool goes to its peers. The cost it still sheds is real but small — a bounded table of per-source DTLS associations that a spoofed-source flood can hold slots in for the length of a handshake timeout, and no further, because DTLS's own cookie exchange is never answered from a spoofed source. Under attack, shedding the whole coordinator to save that table is almost certainly the wrong trade; the right lever is upstream filtering.")
	printBootstrapPub := flag.Bool("print-bootstrap-pubkey", false, "load (or generate) the snapshot-signing key at -bootstrap-key, print its public key (hex) to stdout, and exit. Provision this to mesh-walk clients (bacchus-node -mesh-pubkey) so they can verify coordinator-signed snapshots recovered via a peer (issue #31, design §4.3). Couriers get the same key inside their -courier-invite.")
	flag.Parse()

	// One-shot: print the snapshot-signing public key and exit. This is the
	// operator's distribution path for the key that verifies signed snapshots —
	// baked into client config/invites for cold-start, and handed to relay/exit
	// couriers so they can check a recovering client's proof of prior contact.
	if *printBootstrapPub {
		priv, err := loadOrGenerateBootstrapKey(*bootstrapKeyPath)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
		return
	}

	if *turnPublicIP == "" || *turnPass == "" {
		log.Fatal("need -turn-public-ip and -turn-pass")
	}
	floor, err := version.Parse(*minServingVersion)
	if err != nil {
		log.Fatalf("invalid -min-serving-version %q: %v", *minServingVersion, err)
	}
	servingFloor = floor
	coordRelease = version.Current().String()
	if servingFloor == (version.Version{}) {
		log.Printf("version fence DISABLED (-min-serving-version 0.0.0) — any node version may serve (issue #36); coordinator release %s", coordBuild())
	} else {
		log.Printf("version fence ENABLED — nodes below %s are dropped from matchmaking (issue #36); coordinator release %s", servingFloor, coordBuild())
	}
	v, admissionAnchors, err := setupAdmission(context.Background(), *admissionPubKey, admissionAuthorities, *admissionRevocations)
	if err != nil {
		log.Fatal(err)
	}
	admissionVerifier = v
	if v == nil {
		log.Printf("WARNING: admission DISABLED (neither -admission-pubkey nor -admission-authority set) — any client or node can join this network (issue #42)")
	} else {
		// The anchored roles are logged, not just "enabled": under #64 an
		// operator can scope an authority wrongly, and a coordinator whose
		// account key is anchored for exit is indistinguishable from a
		// correct one in every other line it prints.
		log.Printf("admission ENABLED — nodes and clients must present a credential from an authority anchored for the role they take; anchors: %s (issue #42, #64)", describeAuthorities(admissionAnchors))
	}
	// Connect-time device-credential verification (issue #50, ADR-0045). Started
	// here, next to admission, because it is the same kind of thing — a gate on the
	// connect path built from an operator-configured public key — and NOT folded
	// into admission, because it answers a different question against a different
	// trust anchor. A malformed key, or an enabled gate with no audience to bind
	// assertions to, is fatal rather than degraded.
	dv, audience, err := setupDeviceCred(context.Background(), *deviceRootPubKey, *deviceAudienceFlag, coordAdvertise(*advertise, *addr), *deviceRevocations)
	if err != nil {
		log.Fatal(err)
	}
	deviceVerifier, deviceAudience = dv, audience
	if dv == nil {
		log.Printf("device-credential gate DISABLED (-device-root-pubkey not set) — connects are gated by admission alone; no entitlement is checked (issue #50)")
	} else {
		log.Printf("device-credential gate ENABLED — every connect must present a credential chaining to the configured offline root, bound to audience %q (issue #50)", audience)
	}
	// Signed network policy (issue #39, ADR-0043). Started before the packet loop so
	// the cached policy is restored — and the fail-closed state is established —
	// before the first register or connect is handled. A misconfigured root or a
	// missing source is fatal; a source that is merely unreachable right now is not,
	// because the cache may still carry a usable policy and the refresh loop keeps
	// trying.
	if err := startPolicy(context.Background(), *policyRootPubKey, *policySource, *policyStatePath); err != nil {
		log.Fatal(err)
	}
	// Announce the one configuration in which the signed policy's tier limits are
	// present but unenforceable — policy on, admission off, so no connect carries the
	// (trust, plan) pair they are keyed by (issue #58, ADR-0048). It sits after
	// startPolicy because it reads both flags' resolved state, and it is a warning
	// rather than a fatal because that configuration is legal and worked before this
	// change; what it must not be is silent.
	warnTierEnforcementIsOff()
	// Load the operator/vouch-subtree assignments once, before any goroutine that reads
	// the map (the snapshot refresh loop) starts. Failing hard on a malformed file keeps
	// a typo from silently blanking the operator-diversity signal (issue #124).
	ops, err := loadOperators(*operatorsPath)
	if err != nil {
		log.Fatal(err)
	}
	operators = ops
	if len(operators) == 0 {
		log.Printf("operator tags: none loaded (-operators %s absent/empty) — directory advertises unlabeled hops (issue #124)", *operatorsPath)
	} else {
		log.Printf("operator tags: %d node->operator assignments loaded from %s (issue #124)", len(operators), *operatorsPath)
	}
	// Country derivation (issue #136). Loaded before the packet loop starts, because
	// the register handler reads geoDB without a lock. Fatal on a configured-but-bad
	// database: an operator who asked for derived countries must not silently get
	// self-reported ones.
	if err := setupGeoIP(*geoipDir, *geoipRequired); err != nil {
		log.Fatal(err)
	}
	// The admin's per-node country corrections (issue #113). After setupGeoIP because it
	// corrects that derivation and the startup log reads better in that order, and before
	// the packet loop because the register handler reads the map. Fatal on a
	// present-but-unusable file, matching -operators and -geoip: an admin who staged a
	// correction must not get a coordinator that came up looking configured while
	// publishing the country they were correcting. Unlike those two the file is then
	// re-read on a ticker — see setupCountryOverrides for why this one is not load-once.
	if err := setupCountryOverrides(context.Background(), *countryOverridesPath); err != nil {
		log.Fatal(err)
	}
	// Same discipline for the AS table (issue #23): loaded once here, before the packet
	// loop, so handleCapacityReport reads asnTable without a lock. Fatal on a
	// configured-but-bad table, for the same reason — an operator who asked for real AS
	// resolution must not silently get the prefix-mask fallback under its name.
	if err := setupASNTable(*asnTablePath); err != nil {
		log.Fatal(err)
	}
	ua, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	pc, err = net.ListenUDP("udp", ua)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("bacchus coordinator v3 (UDP) listening on %s", *addr)

	// The rendezvous hop stops being cleartext (issue #175 slice 1, ADR-0059).
	// Built before the packet loop below, because the loop's first act is to ask
	// it whether a datagram is DTLS-shaped. Fatal on a failure to build: an
	// operator who asked for the shaped hop must not silently get a coordinator
	// that came up serving only cleartext, which is the same discipline
	// -geoip/-operators/-asn-table already take.
	if *rendezvousDTLS {
		mux, err := newRendezvousMux(pc)
		if err != nil {
			log.Fatalf("rendezvous: %v", err)
		}
		rendezvous = mux
		go rendezvous.sweepLoop(context.Background())
		log.Printf("rendezvous: accepting DTLS alongside raw JSON on %s (issue #175)", *addr)
	}

	turnCfg := turnConfig{
		addr:     *turnAddr,
		publicIP: *turnPublicIP,
		realm:    *turnRealm,
		user:     *turnUser,
		pass:     *turnPass,
	}
	if _, err := startTurnAndBootstrap(turnCfg, *bootstrapKeyPath, *bootstrapSecretsPath, coordAdvertise(*advertise, *addr)); err != nil {
		log.Fatal(err)
	}

	// In-session relay liveness (issue #96): sweep sessions on a timer so a peer
	// relay that dies mid-session is noticed and its client nudged to re-establish
	// within a heartbeat window, not left riding a dead splice until it times out.
	go reselectLoop(context.Background())

	// Coordinator-side capacity estimator (issue #158): build the per-node rating store
	// and tick its scoring window so attested samples move (or decay) the estimates.
	// Fatal on a params error — a coordinator told to measure must not silently not.
	if err := setupRatings(); err != nil {
		log.Fatal(err)
	}
	go ratingsAdvanceLoop(context.Background())

	servePackets(pc)
	// Only reachable once the signaling socket is closed, which nothing in this
	// process does. Reaching it means the coordinator has no way to hear a client
	// and must say so rather than sitting there looking alive.
	log.Fatal("signaling socket closed — the coordinator can no longer receive")
}

// servePackets is the signaling read loop: decode, demultiplex, dispatch. It is
// a function rather than main()'s tail so a test can run the PRODUCTION path
// instead of a copy of it — the property #175 slice 1 has to prove is that one
// port serves two shapes, and a reimplemented loop would prove it about the
// reimplementation.
//
// A transient read error is skipped, exactly as it always was. A CLOSED socket
// returns instead of spinning, which is the one behavioural difference: before
// this the loop would busy-spin at full CPU forever on a socket that could never
// produce another datagram.
func servePackets(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		// The rendezvous hop stops being cleartext (issue #175 slice 1,
		// ADR-0059) and gains the STUN prefix that precedes DTLS in a real
		// WebRTC flow (issue #202, ADR-0060). A conclusively STUN-shaped
		// Binding Request is answered in place; a conclusively DTLS-shaped
		// datagram is routed to this source's association and its decrypted
		// contents re-enter at handle() below; anything else takes the path it
		// always took, byte for byte. The polarity is deliberate — see
		// looksLikeSTUN and looksLikeDTLS.
		if rendezvous.answerSTUN(buf[:n], src) {
			continue
		}
		if rendezvous.route(buf[:n], src) {
			continue
		}
		var m wire
		if json.Unmarshal(buf[:n], &m) != nil {
			continue
		}
		handle(m, src)
	}
}

func handle(m wire, src *net.UDPAddr) {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	prune(now)

	switch m.Type {
	case "hello":
		// The first thing a node sends, before any role logic (issue #8,
		// ADR-0016). A match needs no reply — register/list/connect proceed
		// exactly as before this existed. A mismatch gets a reject with a
		// reason that names only protocol/version data, safe to log and to
		// return to the peer as-is.
		peer := handshake.Hello{Magic: m.Magic, Version: m.Version, Capabilities: m.Capabilities}
		if ok, reason := handshake.Check(peer); !ok {
			log.Printf("hello from %s: rejected (%s)", src, reason)
			send(src, wire{Type: "reject", Reason: reason})
		}
	case "register":
		// Node admission (issue #42): a relay/exit must present a credential
		// bound to the id it is registering, or it is not advertised to clients.
		// The subject binding (m.ID) is what stops a valid-but-leaked exit
		// credential from being replayed under a different node id.
		// The credential is discarded here: a node's standing is not a tier. Tier
		// limits are what a CLIENT's account is entitled to consume (issue #58); what
		// a node may offer is ADR-0040's declared limits and ADR-0041's measured
		// rating, neither of which rides a credential.
		if _, ok := admit(m, src, admission.Role(m.Role), m.ID); !ok {
			return
		}
		// Serve-eligibility gate (issues #36/#15/#49, ADR-0015/0043, ADR-0040
		// amendment): the version fence, the policy's declared-quota floor and its
		// measured-throughput floor. A node too old to carry the current transport
		// shape is dropped from matchmaking until it updates — a stale node still
		// advertises the old, now-detectable fingerprint and would burn the users
		// routed through it — and a node declaring less capacity than the policy
		// requires never enters the serve pool at all. Enforced here, at register,
		// because a stale or under-provisioned node cannot be trusted to fence itself.
		//
		// The declared quota is read straight off the register rather than from the
		// registry entry, because this runs BEFORE the entry is built (and must: a
		// fenced node is never stored).
		if reason, ok := servingCheck(m.Release, m.ID, capacity.Bytes(m.DeclaredQuotaBytes)); !ok {
			log.Printf("register %s (%s): fenced (%s)", m.ID, src, reason)
			send(src, wire{Type: "reject", Reason: reason})
			return
		}
		// Fail-closed drain (issue #39, ADR-0043): with signed policy configured but
		// none currently enforceable — never loaded, or past exp + grace — this
		// coordinator adds NO new nodes to the serve pool. A node that is already
		// registered keeps its entry and its sessions; it simply stops being refreshed
		// into the pool, and ages out on the normal prune. Nothing is torn down here.
		if !policyAllowsAssignment() {
			const reason = "coordinator has no enforceable network policy — not accepting new nodes into the serve pool; retry shortly or use another coordinator"
			log.Printf("register %s (%s): refused (%s)", m.ID, src, reason)
			send(src, wire{Type: "reject", Reason: reason})
			return
		}
		// Country is derived from the source address this coordinator OBSERVED the
		// register arrive from, never from the node's claim (issue #136). m.Country is
		// consulted only as a fallback when the observed address resolves to nothing —
		// an unmapped range, or the loopback every node registers from in a local
		// stack — and not at all under -geoip-required. See deriveCountry.
		// What the node CLAIMED is kept beside what was derived rather than dropped on
		// the floor (issue #113): claims carries both, plus an admin's correction
		// where one is staged. Only claims.derived is ever assigned or advertised.
		claims := deriveCountry(m.ID, src, m.Country)
		switch m.Role {
		case "relay":
			// prior is this node's health record from before this register, and nil
			// exactly when the node is new to the registry. Both readers below need it
			// BEFORE the assignment at the end of this branch replaces the entry.
			// priorClaims is that same before-this-register snapshot for the COUNTRY, which
			// noteCountryOverride needs to tell a change from the steady state (issue #113).
			var prior *forwarderHealth
			var priorClaims *countryClaims
			if r, ok := relays[m.ID]; ok {
				prior = &r.forwarderHealth
				pc := r.claims()
				priorClaims = &pc
			}
			if prior == nil {
				log.Printf("relay registered: %s (%s) country=%s (%s) release=%s", m.ID, src, countryOrUnknown(claims.derived), countryClaimLabel(claims), releaseOrUnknown(m.Release))
			}
			noteCountryOverride("relay", m.ID, priorClaims, claims)
			noteRelease("relay", m.ID, prior, m.Release)
			// ingressPort is the relay's onion-forward listener port (issue #124); the
			// coordinator pairs it with the observed src IP in buildSnapshot to advertise a
			// forwarding ingress. Absent (zero) => this relay is not advertised as a hop.
			// It is range-checked on the way in (issue #11) — see validIngressPort.
			// Declared limits (issue #143) are read off every register because this
			// assignment replaces the entry wholesale — a field carried once would be
			// silently dropped 10s later.
			port := m.IngressPort
			if port != 0 && !validIngressPort(port) {
				log.Printf("relay %s (%s) reported ingress port %d, outside 1..65535 — ignoring it; this relay advertises no forwarding ingress and is not relay-eligible (issue #11)", m.ID, src, port)
				port = 0
			}
			relays[m.ID] = &relayNode{forwarderHealth: carryHealth(prior, m.Release), id: m.ID, addr: src, ingressPort: port, speedCap: m.SpeedCap, declaredQuota: m.DeclaredQuotaBytes, exhausted: m.QuotaState == quotaExhausted, lastSeen: now, country: claims.derived, countrySource: claims.source, declaredCountry: claims.declared}
		case "exit":
			// An exit, unlike a relay, advertises a data-plane endpoint of its own, so
			// its country is derived against that too: signaling arriving from one
			// country while traffic egresses from another is the jurisdiction
			// misrouting country selection exists to prevent (issue #136, ADR-0042 §8).
			claims = deriveExitCountry(m.ID, src, m.Country, m.Addr)
			// See the relay branch: prior is nil exactly for a node new to the
			// registry, and is read before the assignment below replaces the entry.
			var prior *forwarderHealth
			var priorClaims *countryClaims
			if e, ok := exits[m.ID]; ok {
				prior = &e.forwarderHealth
				pc := e.claims()
				priorClaims = &pc
			}
			if prior == nil {
				log.Printf("exit registered: %s -> %s country=%s (%s) release=%s", m.ID, m.Addr, countryOrUnknown(claims.derived), countryClaimLabel(claims), releaseOrUnknown(m.Release))
				if claims.source == countrySplit {
					// Loud, because it is the one case where a client is shown a
					// country this coordinator has NOT tied to the egress path.
					log.Printf("WARNING: exit %s signals from %s but advertises %s — its country tag (%s) describes where it SIGNALS from, not necessarily where traffic egresses; run -geoip-required to refuse this shape (issue #136, ADR-0042 §8)",
						m.ID, src.IP, m.Addr, claims.derived)
				}
				if claims.derived == countryUnknown {
					// Loud, because it is silently disqualifying: with a country the
					// only thing a client can ask for (issue #146), an exit without one
					// is registered, healthy, and unreachable.
					//
					// The reason is named, because the three ways to get here have
					// nothing in common from an operator's desk. An unresolved address
					// is a database or a staging problem; a split endpoint is a
					// deliberate forwarding setup; and no endpoint at all is a missing
					// flag on an otherwise perfectly ordinary direct-mode exit — the
					// last of which would be actively misdiagnosed by a message saying
					// the address did not resolve, since it resolved fine (issue #2).
					switch claims.source {
					case countryNoEndpoint:
						log.Printf("WARNING: exit %s has NO country: its address resolved, but it advertises no data-plane endpoint and -geoip-required is set, so this coordinator cannot tie the resolution to where its traffic egresses. Set -advertise to the address it serves from. It will not be offered to any client (issues #2/#136/#146)", m.ID)
					case countrySplit:
						log.Printf("WARNING: exit %s has NO country: it signals from %s but advertises %s, and -geoip-required refuses a country this coordinator cannot tie to the egress path. It will not be offered to any client (issues #136/#146, ADR-0042 §8)", m.ID, src.IP, m.Addr)
					default:
						log.Printf("WARNING: exit %s has NO country (observed address did not resolve and no usable -country hint) — it will not be offered to any client (issues #136/#146)", m.ID)
					}
				}
			}
			noteCountryOverride("exit", m.ID, priorClaims, claims)
			noteRelease("exit", m.ID, prior, m.Release)
			exits[m.ID] = &exitNode{forwarderHealth: carryHealth(prior, m.Release), id: m.ID, tcpAddr: m.Addr, udp: src, speedCap: m.SpeedCap, declaredQuota: m.DeclaredQuotaBytes, exhausted: m.QuotaState == quotaExhausted, lastSeen: now, country: claims.derived, countrySource: claims.source, declaredCountry: claims.declared}
		}
	case "heartbeat":
		// A heartbeat refreshes the observed address, so the derived country is
		// refreshed with it (issue #136). Re-deriving here is not redundant with
		// register: a node whose address changes under it — a NAT rebinding, a new
		// uplink — would otherwise carry a country resolved from its OLD address
		// until its next register, and for a relay that stale tag would sit
		// alongside a fresh observed Ingress in the signed directory, disagreeing
		// with it. The hint is re-read from the stored value, not from a heartbeat
		// (heartbeats carry no country), so this cannot upgrade an observed tag into
		// a hinted one.
		if r, ok := relays[m.ID]; ok {
			prior := r.claims()
			r.lastSeen = now
			r.addr = src
			c := rederiveCountry(m.ID, src, r.claims())
			r.setClaims(c)
			// A heartbeat can be the first re-derivation after an admin edits the override
			// file, so it reports the change too and the register 10s later finds nothing
			// left to say (issue #113). It is passed the fresh value rather than re-reading
			// the entry, because what an override DISPLACED is not stored on the entry.
			noteCountryOverride("relay", m.ID, &prior, c)
		}
		if e, ok := exits[m.ID]; ok {
			prior := e.claims()
			e.lastSeen = now
			e.udp = src
			// Re-checked against the STORED advertisement: a heartbeat carries none,
			// and an exit whose signaling address moves must not keep an endpoint
			// agreement that was established against the address it has left.
			c := rederiveExitCountry(m.ID, src, e.tcpAddr, e.claims())
			e.setClaims(c)
			noteCountryOverride("exit", m.ID, &prior, c) // see the relay branch
		}
	case "list":
		// Client admission (issue #42): only credentialed clients may enumerate
		// exits, closing the "pose as an ordinary user to enumerate the network"
		// capability in the threat model. No subject binding — a client has no
		// coordinator-known id on this channel, so its credential is bearer.
		cred, ok := admit(m, src, admission.RoleClient, "")
		if !ok {
			return
		}
		// The country aggregate is computed under THIS client's tier limits (issue
		// #58, ADR-0048), because two of them — the endpoint-quality floor and the
		// priority-scaled fullness floor — are part of what "assignable" means. A
		// snapshot built under different limits than the connect will enforce would
		// break exitAssignable's whole reason for existing: Available would promise
		// what connect then refuses.
		//
		// An unresolvable pair refuses the list too. A coordinator that cannot resolve
		// a tier cannot honestly say what is available to it, and answering with an
		// error rather than a number leaves the client to rotate to another pool
		// member (ADR-0020) instead of acting on a figure that will not hold.
		limits, refusal := resolveTier(cred)
		if refusal != refuseNone {
			send(src, wire{Type: "error", Reason: string(refusal)})
			return
		}
		// The client picks a COUNTRY, so what it gets is the per-country capacity map,
		// not an exit list (issue #146, ADR-0042). countrySnapshot applies the same
		// withholding rules assignment does — spent quota (#143), the serve floor
		// (#145, off), share-based fullness (#147, off) — so Available can never
		// promise something connect would then refuse. A country whose exits are all
		// withheld stays in the list marked Busy, which is what lets the client say
		// "<country> is busy" instead of silently losing the country (#147).
		//
		// Advertise this coordinator's release too, so the client can apply the
		// force-major / skip-minor rule (issue #36, ADR-0015).
		send(src, wire{Type: "countries", Countries: countrySnapshot(now, limits), Release: coordRelease})
	case "challenge":
		// Device-credential challenge (issue #50, ADR-0045). A device cannot prove
		// possession of its credential's key without a nonce THIS coordinator chose,
		// so it asks for one immediately before connecting.
		//
		// Gated by admission like every other client message, so an uncredentialed
		// party cannot spin the challenge store. The nonce is single use and
		// short-lived; see admitDevice.
		//
		// No tier resolution here, deliberately: issuing a nonce is not an assignment
		// and consults no policy, so refusing it for an unresolvable tier would spend
		// this coordinator's answer to a misconfiguration on the step BEFORE the one
		// that can explain it. The connect that follows resolves the tier and refuses
		// there, where the reason names the pair.
		if _, ok := admit(m, src, admission.RoleClient, ""); !ok {
			return
		}
		// The credential just verified is stashed with the nonce, so the connect that
		// answers it does not have to carry a second copy of the largest field on the
		// wire (issue #183, ADR-0057). issueDeviceChallenge keeps it only when there
		// was an authority to verify it against — see stashCred.
		//
		// The issuer cert on this message is stashed the same way and for the same
		// reason (issue #206, ADR-0062): 362 bytes, identical for every device from one
		// issuer, and previously re-sent on every connect. Its gate is the anchored
		// ROOT rather than admission, because that is the authority that can speak for
		// it — see stashIssuerCert, which also records why reusing stashCred's gate
		// would refuse every connect on an admission-off deployment.
		c := issueDeviceChallenge(src, m.Cred, m.IssuerCert)
		if c == "" {
			// Either the gate is off — in which case a client that asks anyway gets an
			// empty challenge and simply has nothing to sign — or the store is at
			// capacity, which is a refusal to issue rather than an eviction of someone
			// else's live nonce. Both are reported the same way: no challenge.
			send(src, wire{Type: "challenge"})
			return
		}
		send(src, wire{Type: "challenge", Challenge: c})
	case "connect":
		// A client that completed the challenge exchange put its admission credential
		// on THAT message and leaves it off this one, because carrying it twice per
		// connect attempt is what pushed this datagram past a 1280-byte path (issue
		// #183, ADR-0057). Resolved before admit rather than inside it: what is
		// verified below is a credential, wherever it arrived, and the rest of this
		// handler should see the one this connect is actually being judged on.
		m.Cred = admissionCredFor(m, src)
		// The issuer cert is resolved the same way and in the same place (issue #206,
		// ADR-0062). Unlike the credential above it is not a conditional move: a
		// current client puts it on the "challenge" and never on a connect, so this is
		// where the connect gets it back. Resolved here rather than inside admitDevice
		// so that one function keeps verifying a chain it was handed rather than
		// deciding where the chain came from.
		m.IssuerCert = issuerCertFor(m, src)
		// Client admission (issue #42): matchmaking is gated too, so a leaked
		// exit list can't be turned into a live session without a credential.
		cred, ok := admit(m, src, admission.RoleClient, "")
		if !ok {
			return
		}
		// Fail-closed drain (issue #39, ADR-0043): with signed policy configured but
		// none currently enforceable, no NEW session is matched. Established sessions
		// are untouched and run to their natural end — matchmaking and live sessions
		// are decoupled here, so the drain needs no teardown and no timer.
		//
		// The client's response to this is to rotate to another coordinator (ADR-0020),
		// which is exactly why failing closed is affordable here: the failure sheds to
		// the pool rather than darkening the network.
		if !policyAllowsAssignment() {
			const reason = "coordinator has no enforceable network policy — not assigning new sessions; retry shortly or use another coordinator"
			log.Printf("connect from %s: refused (%s)", src, reason)
			send(src, wire{Type: "reject", Reason: reason})
			return
		}
		// Per-connect idempotency (issue #1, ADR-0042 §2). Each connect is sent
		// several times against UDP loss, and before this every copy was assigned
		// independently — so one request drew several exits and the client could keep
		// whichever it liked. The nonce identifies the REQUEST rather than the
		// datagram: the first copy is assigned, its answer is remembered, and every
		// later copy replays it.
		//
		// Refused rather than tolerated when absent. A client that omitted the field
		// would get back exactly the pre-#1 behaviour, which is the behaviour the
		// attacker wants, so an optional key would guard only the honest.
		if m.Nonce == "" || len(m.Nonce) > maxNonceLen {
			send(src, wire{Type: "error", Reason: string(refuseNoNonce), Country: geoip.Canonical(m.Country)})
			return
		}
		if replayMintedConnect(src, m.Nonce, now) {
			return
		}
		// Connect-time device-credential verification (issue #50, ADR-0045). The
		// account service's entitlement chain, verified offline against the anchored
		// root and bound to the challenge issued to this source above.
		//
		// AFTER the idempotency replay, and that ordering is load-bearing rather than
		// incidental. core's sendN puts three copies of every connect on the wire
		// against UDP loss, and the challenge this gate spends is SINGLE USE. Run
		// before the replay, the first copy spends the nonce and mints a session while
		// copies two and three find it spent and are refused — one request answered
		// with one session and two rejects. A retransmission is not a replay attack:
		// it is the same request arriving twice, which is precisely what the
		// idempotency layer already identifies and answers, so the later copies must
		// never reach this gate at all.
		//
		// Reaching here means this is a genuinely new (source, nonce) pair. Still
		// after the drain check, so a coordinator that is not assigning anything does
		// not spend ed25519 verifications on connects it would refuse regardless, and
		// still before any assignment work, because a connect that fails here mints
		// nothing at all.
		if !admitDevice(m, src) {
			return
		}
		// Resolve what this account's tier is entitled to, out of the signed policy
		// this coordinator already fetches and verifies (issue #58, ADR-0048). The
		// credential carries only the (trust, plan) pair; the numbers come from the
		// document, so this coordinator enforces limits it could not author.
		//
		// Here rather than earlier for the same reason admitDevice sits where it does:
		// a retransmitted copy is answered by replayMintedConnect above and must not
		// be resolved a second time, and a connect refused here mints nothing at all.
		// Before the exit choice because the tier is an INPUT to it — endpoint quality
		// decides which exits are candidates and priority how full one may be.
		limits, tierRefusal := resolveTier(cred)
		if tierRefusal != refuseNone {
			send(src, wire{Type: "error", Reason: string(tierRefusal), Country: geoip.Canonical(m.Country)})
			return
		}
		// The client names a COUNTRY; this coordinator picks the exit inside it
		// (issue #146, ADR-0042). There is no exact-exit pinning for anyone, so a
		// client cannot ask for a node — only for a place, and, for retries, for "not
		// the exits these sessions of mine just failed on" (m.ExcludeSessions).
		//
		// The country always names where the client wants to EGRESS — the terminating
		// exit's country, never an intermediate hop's. That is a wire commitment, not
		// an implementation detail: client-assembled onion routing (#142, ADR-0038)
		// adds a first hop the client names itself, and it must be able to do so
		// without changing what `country` means. See ADR-0042 §9.
		//
		// The one exception is a client assembling its own relay chain (issue #142,
		// ADR-0038): it names a FIRST HOP, which is a node but is not an exit request
		// — see wire.FirstHop and resolveFirstHop. Everything downstream of the pick
		// is identical; what differs is that `e` is then a hop rather than a
		// terminating exit, which is why chained holds on to the distinction.
		chained := m.FirstHop != ""
		var e *exitNode
		var refusal assignRefusal
		switch {
		case chained && m.Mode != "relay":
			// A named node is only ever a chain's first PEELING hop. In direct mode
			// there is no onion and nothing to peel, so the node named here would be
			// the node the client egresses from — and honouring that is exact-exit
			// pinning, the thing #146/ADR-0042 §2 removed from this wire, arriving
			// through the field §9 opened for chaining. The client cannot ask for
			// this by accident: chainFor builds a plan only in relay mode, so an
			// honest client never populates FirstHop here. Refused rather than
			// silently ignored, because a client that sent it wanted a specific node
			// and must not be told it got one when it did not.
			//
			// This is the guard's whole extent, and §9 now says so: it closes the
			// case where the wire itself asks to be paired directly with a named
			// node. It does NOT stop a client from claiming relay mode and simply
			// terminating at the node it named — that path stays open by
			// construction, since not being able to see inside the onion is the
			// point of the feature. What is refused is the pin with no cover story.
			refusal = refuseHopNotRelayMode
		case chained:
			e, refusal = resolveFirstHop(m.FirstHop)
		default:
			e, refusal = chooseExit(m.Country, excludedExits(src, m.ExcludeSessions), now, limits)
		}
		if refusal != refuseNone {
			// Country-granularity admission control (issue #147): "this country is
			// busy, try another" is a materially different instruction to a client
			// than "that failed", so the refusal is named. Both facts it can reveal
			// are already in the country list this same credentialed client just
			// fetched — see assignRefusal on why the pre-#146 reticence does not
			// apply here.
			send(src, wire{Type: "error", Reason: string(refusal), Country: geoip.Canonical(m.Country)})
			return
		}
		// What this coordinator RECORDS as the session's terminating exit, and what it
		// tells the client. On a chained connect both are empty, and neither is an
		// oversight (ADR-0042 §9):
		//
		//   - Recording e.id would charge a hop with a terminator's load, and the
		//     session count is the only term in §3's ranking that discriminates at all.
		//     Empty keeps a chained session invisible to exit ranking rather than
		//     misattributed; exitSessions already skips empty ids.
		//   - Replying with it would be this coordinator asserting an exit for a path
		//     whose exit it does not know. The client named the hop, so it already
		//     holds the only static key it needs from us, and it ignores this field on
		//     a chained attempt precisely so a coordinator cannot redirect the
		//     innermost layer.
		exitID := e.id
		if chained {
			exitID = ""
		}
		// The tier's speed cap rides the assignment to whichever party moves the bytes
		// (issue #58/#74/#84, ADR-0048): the exit shapes a direct session and the relay
		// shapes a peer-relayed one, so the coordinator stays out of the data path
		// (ADR-0009/0033) and never sees a byte of it either way.
		//
		// EVERY path, including a CHAINED connect. This used to be zeroed for a chained
		// connect, on the same ground that leaves exitID empty above — the client
		// assembled its own onion and this coordinator does not know the terminating
		// exit (ADR-0042 §9). That reasoning conflated ACCOUNTING for a path with
		// PACING its entry, and only the first needs to know where the path ends
		// (issue #84).
		//
		// The chain's head is the right party for #74's reason exactly: it terminates
		// nothing, but every byte of the session passes through it, so it can pace
		// them. Pacing needs custody of the bytes, not comprehension of them.
		//
		// Stamped ONCE, at the entry, not per hop. The tier cap is a property of the
		// session and the head is where the session enters the chain; each hop's own
		// declared cap (ADR-0040) goes on applying independently and inside it.
		//
		// ADR-0042 §9 is untouched: this coordinator still does not learn the
		// terminating exit, and enforcement never needed it. What the head learns is a
		// coarse rate for a session it is already forwarding and already knows to be
		// chained — the same disclosure #74 accepted, to the same class of party.
		//
		// The bypass this closes was not cosmetic: a chained connect goes through the
		// same peer-relay assign as any other relayed session, so zeroing here meant a
		// capped user who switched relay chaining on got a session with no tier ceiling
		// at all, making the cap opt-out via a client setting.
		sessionCap := limits.SpeedCapBps
		sid := randID()
		if m.Mode == "direct" {
			if e.udp == nil {
				send(src, wire{Type: "error"})
				return
			}
			sessions[sid] = &session{client: src, peer: e.udp, exitID: exitID, lastSeen: now}
			// ExitID tells the client WHICH exit it was given (issue #146). It is not
			// informational: an exit's id is its Noise static public key (ADR-0009),
			// so without it the client cannot bring up the end-to-end channel at all.
			pairAndReply(src, m.Nonce, e.udp,
				wire{Type: "assign", Session: sid, SessionCapBps: sessionCap}, // no exitAddr => egress directly
				wire{Type: "session", Session: sid, ExitID: exitID, Release: coordRelease}, now)
			log.Printf("session %s DIRECT: client %s <-> exit %s(%s)%s", sid, src, e.id, e.country, capNote(sessionCap))
		} else if r := pickRelay(e.id); r != nil {
			// Peer relay (issue #17, ADR-0033): a Bacchus relay node blind-splices
			// client<->exit — the preferred data-plane path. The exit still
			// terminates the end-to-end Noise channel, so #60/#69 exit-admission
			// verification is unaffected by the extra hop. relayID records which
			// relay carries the session so reselectDeadRelays can notice if it later
			// dies mid-session and nudge the client to re-establish (issue #96).
			sessions[sid] = &session{client: src, peer: r.addr, relayID: r.id, exitID: exitID, lastSeen: now}
			// The reply carries the relay's opaque dedupe tag (issue #56) so a client
			// rotating the pool can skip a second member that hands back this same relay
			// after a failed dial. It is derived from r.id, not r.addr, so it is stable
			// across coordinators but never a routable address.
			//
			// A chaining client reads it for a second purpose: it recomputes the tag for
			// every hop of its own chain and refuses the path on a match, because a relay
			// that is also a hop holds both ends of the chain (core/relaychain.go
			// verifyChainDisjoint). pickRelay already excludes the node it paired — the
			// chain's head — but not the client's later hops, which it cannot see.
			//
			// SessionCapBps rides this assign too (issue #74/#84, ADR-0048 §5): the
			// RELAY shapes a peer-relayed session. It terminates nothing, but it moves
			// every byte, so it can pace them — which is what makes this enforceable at
			// a party that never learns the destination or the plaintext. That holds
			// whether or not the client is chaining: on a chained connect this relay is
			// the chain's HEAD, and the head has the same custody of the same bytes.
			//
			// The EXIT is not involved and learns nothing new: no session identity, no
			// token, no credential reaches it, so ADR-0048 §4's linkability property is
			// untouched. And what the relay learns is a coarse number it could already
			// derive by measuring the throughput it forwards, which is why this is a
			// materially smaller disclosure than the credential-to-exit design §4
			// rejected. The splice stays transparent either way — the limiter wraps the
			// copies, never the bytes' meaning (TestPeerRelaySplicePreservesE2E).
			pairAndReply(src, m.Nonce, r.addr,
				wire{Type: "assign", Session: sid, ExitAddr: e.tcpAddr, SessionCapBps: sessionCap},
				wire{Type: "session", Session: sid, ExitID: exitID, Relay: relayPeer, RelayTag: relayTag(r.id), Release: coordRelease}, now)
			if chained {
				// Deliberately not the shape of the line below it. There is no exit to
				// name, and printing e.id under an "exit" heading would record a hop as a
				// terminator in the operator's log — the same misattribution §9 keeps out
				// of the session table, arriving by the back door.
				//
				// It DOES carry the capNote (issue #84). It used to omit it by an
				// explicit note that sessionCap was zero here by construction; it no
				// longer is, and a chained line silently missing the cap the session was
				// actually stamped with would be the one place an operator could not see
				// tier shaping working.
				log.Printf("session %s PEER-RELAY (chained): client %s <-> relay %s -> first hop %s(%s); terminating exit not known to this coordinator%s", sid, src, r.addr, e.id, e.country, capNote(sessionCap))
			} else {
				log.Printf("session %s PEER-RELAY: client %s <-> relay %s -> exit %s(%s)%s", sid, src, r.addr, e.id, e.country, capNote(sessionCap))
			}
		} else if e.udp != nil {
			// TURN fallback (issue #17): no peer relay is available, so wire the
			// client straight to the exit (the direct-assignment shape) and tag the
			// reply so it knows. Its transport dials the exit directly; ICE uses a
			// TURN relay candidate only if a direct hole-punch fails — TURN is the
			// last resort, not the default. E2E again terminates at the exit.
			sessions[sid] = &session{client: src, peer: e.udp, exitID: exitID, lastSeen: now}
			// Shaped like the direct path, because it IS the direct path as far as the
			// data plane is concerned: the client reaches the exit itself and the exit
			// terminates the session, so the exit can apply the cap. core's handlerFor
			// deliberately cannot tell the two apart (issue #97) and does not need to.
			pairAndReply(src, m.Nonce, e.udp,
				wire{Type: "assign", Session: sid, SessionCapBps: sessionCap}, // no exitAddr => exit egresses directly
				wire{Type: "session", Session: sid, ExitID: exitID, Relay: relayTURN, Release: coordRelease}, now)
			log.Printf("session %s TURN-FALLBACK: client %s <-> exit %s(%s) (no peer relay available)%s", sid, src, e.id, e.country, capNote(sessionCap))
		} else {
			// Neither a peer relay nor a directly-reachable exit — nothing to pair.
			send(src, wire{Type: "error"})
			return
		}
	case "offer", "answer", "candidate":
		s := sessions[m.Session]
		if s == nil {
			return
		}
		s.lastSeen = now // signaling keeps the rendezvous entry alive; silence lets prune reap it
		// The first frame is what tells a paired session apart from a merely MINTED one
		// (issue #1). It matters only for the peer-relay disposition, which prune
		// exempts from the idle sweep — see session.signaled and prune.
		s.signaled = true
		other := s.peer
		if src.String() == s.peer.String() {
			other = s.client
			// This frame came from the forwarder this coordinator assigned, which is
			// the one thing that proves the assignment was acted on at all (issue
			// #114). Recorded on ARRIVAL, before it is relayed, so a client that has
			// itself gone away does not make a healthy node look silent.
			s.answered = true
		}
		send(other, m)
	case "capacity-report":
		// A client attests what an exit delivered to it, to feed the coordinator-side
		// capacity estimator (issue #158). Fire-and-forget: it touches no registry state
		// and gets no reply — see handleCapacityReport (cmd/coordinator/capacity_feed.go).
		handleCapacityReport(m, src)
	}
}

func prune(now time.Time) {
	for id, r := range relays {
		if now.Sub(r.lastSeen) > ttl {
			delete(relays, id)
		}
	}
	for id, e := range exits {
		if now.Sub(e.lastSeen) > ttl {
			delete(exits, id)
		}
	}
	for id, s := range sessions {
		if s.relayID != "" {
			// Peer-relay sessions (issue #96) see no coordinator signaling once the
			// data plane is up — it flows client<->relay<->exit directly — so their
			// lastSeen freezes at setup and this signaling-silence bound would reap a
			// perfectly healthy session ~sessionTTL after connect, blinding
			// reselectDeadRelays to the relay dying later (issue #105). A peer-relay
			// session's real liveness is its relay's: reselectDeadRelays is its sole
			// reaper, dropping it when that relay goes stale. (A session whose client
			// vanished while its relay stays up therefore lingers until the relay
			// dies; the coordinator has no client-side liveness signal — see ADR-0033.)
			//
			// That exemption applies to a session that was BROUGHT UP, which is what
			// signaled records. One that never saw a single handshake frame was paired
			// and abandoned, and exempting it too is what let a client harvest
			// relay-mode sessions no reaper would ever touch (issue #1): the exits they
			// name stayed excludable forever, where a direct-mode client's aged out in
			// sessionTTL. Reaped on the same idle bound as any other unused session —
			// which for an unsignaled entry is measured from when it was minted, since
			// nothing has refreshed lastSeen since.
			if s.signaled || now.Sub(s.lastSeen) <= sessionTTL {
				continue
			}
		}
		if now.Sub(s.lastSeen) > sessionTTL {
			delete(sessions, id)
		}
	}
	// Per-connect idempotency records expire on their own, shorter window (issue #1).
	pruneMintedConnects(now)
}

// reselectDeadRelays is the coordinator-side liveness check on the peer relay that
// is actually carrying each session (issue #96) — the in-session counterpart to
// connect-time pickRelay. A peer-relay session whose assigned relay has gone stale
// past ttl/2 (the very bound pickRelay uses to judge a relay unpickable), or whose
// relay has re-registered under a new address (a restart of the same id — a
// different incarnation than the one the splice was built on, issue #105), is
// treated as dead under it: the client is nudged to re-establish and the now-defunct
// session is dropped so the nudge fires exactly once.
//
// This is also the sole reaper of peer-relay sessions (issue #105): prune no longer
// expires them on signaling silence, because a healthy peer-relay session sees no
// coordinator signaling once its data plane is up. Tying their liveness to the relay
// rather than to silence is what lets this check still see — and recover — a relay
// that dies minutes into a session, not only one that dies in its first sessionTTL.
//
// The client's re-establish re-drives connect{mode:relay}, and the reselect-or-TURN
// falls out of the existing matchmaker for free — pickRelay skips the dead relay by
// that same staleness (so a fresh live relay is chosen, the dead one excluded) or
// returns nil and the client is wired to the exit over the TURN fallback. Reaping
// the session here is safe: the old data plane is dead, and a re-establish mints a
// fresh session id, so nothing reads the reaped entry.
//
// The nudge is best-effort. A lost datagram is not fatal — the client's own
// transport teardown eventually drives the same reconnect (issue #2) — this just
// bounds recovery to a heartbeat window instead of a TCP timeout when a relay
// black-holes (host powered off / network-partitioned) without closing the splice.
// In the ordinary case where the relay dies cleanly, the client has usually already
// reconnected off its own transport signal by the time this fires; the client
// scopes the nudge to its live session id and ignores a stale one (core/client.go).
func reselectDeadRelays(now time.Time) {
	for sid, s := range sessions {
		if s.relayID == "" {
			continue // direct or TURN-fallback session: no peer relay to monitor
		}
		if r, ok := relays[s.relayID]; ok && now.Sub(r.lastSeen) <= ttl/2 && r.addr.String() == s.peer.String() {
			continue // the same relay incarnation carrying this session is still live
		}
		// Assigned relay is gone or stale — its splice is dead. Signal the client to
		// re-establish (it re-drives connect, landing on a fresh relay or TURN) and
		// retire the session so the sweep does not keep re-nudging a dead path.
		send(s.client, wire{Type: "reselect", Session: sid})
		delete(sessions, sid)
		log.Printf("session %s RELAY-DEAD: assigned relay %s gone/stale — nudged client %s to re-establish", sid, s.relayID, s.client)
	}
}

// reportUnansweredNodes names a forwarder that is being assigned work and silently
// dropping it (issue #114) — the failure every other signal this coordinator has is
// blind to.
//
// The blindness is structural: registration is stable across builds and session
// setup is not, so a node running a diverged binary registers cleanly, re-announces
// every 10s, is never pruned, appears in the signed snapshot, is offered to clients
// and is assigned sessions it never acts on. Liveness, capacity, quota and country
// all keep reporting health, because all of them exercise the half of the protocol
// that did not change. What breaks is only ever visible one layer up: the assignment
// went out and nothing came back.
//
// The predicate is per-SESSION evidence, aggregated per node:
//
//   - answered — the assigned node has spoken on this session. It is healthy, full
//     stop, and one of these is enough to clear the node.
//   - signaled && !answered && quiet for answerGrace — a client tried to bring this
//     session up and the node it was handed to has said nothing back for longer than
//     the client itself was willing to wait. This is the fault.
//   - !signaled — the client never spoke either. NOT counted, and that exclusion is
//     what keeps this quiet: "a client walked away before it tried" is the ordinary,
//     blameless case the issue worried would make this cry wolf, and it is
//     distinguishable rather than merely rare (see session.answered).
//
// A node is reported only when it has at least one unanswered session and NO
// answered one — the issue's "a node whose sessions are ALL unsignalled is serving
// nobody". One client hitting a snag against an otherwise-working node therefore
// says nothing, and a single dropped assign datagram costs at most one line, once,
// until the node answers anything at all.
//
// Deliberately a sweep over LIVE sessions rather than a check at reap time. Two
// reasons: a peer-relayed session that was signaled is exempt from prune's idle
// sweep (see prune) and so would never reach a reap-time check while its relay
// keeps heartbeating, which is precisely the state a diverged relay is in; and a
// live sweep reports the fault while it is still happening rather than sessionTTL
// after the client gave up.
func reportUnansweredNodes(now time.Time) {
	type tally struct {
		answered, unanswered int
		waiting              time.Duration // how long the longest-waiting unanswered session has been quiet
	}
	byNode := map[nodeRef]*tally{}
	for _, s := range sessions {
		ref, ok := assignedNode(s)
		if !ok {
			continue
		}
		t := byNode[ref]
		if t == nil {
			t = &tally{}
			byNode[ref] = t
		}
		switch {
		case s.answered:
			t.answered++
		case s.signaled && now.Sub(s.lastSeen) > answerGrace:
			t.unanswered++
			if quiet := now.Sub(s.lastSeen); quiet > t.waiting {
				t.waiting = quiet
			}
		}
	}
	for ref, t := range byNode {
		h := healthOf(ref)
		if h == nil {
			continue // pruned since this session was minted: there is nobody left to report
		}
		if t.answered > 0 {
			// Serving somebody. Re-arm, so a node that fails, recovers and fails
			// again is reported on the second episode too.
			h.silentWarned = false
			continue
		}
		if t.unanswered == 0 || h.silentWarned {
			continue
		}
		h.silentWarned = true
		log.Printf("WARNING: %s %s was assigned %d session(s) that a client tried to bring up and has answered NONE of them (the longest has been waiting %s). It registers and heartbeats normally, so nothing else here reports it: check it is reachable and running a build compatible with this coordinator — it reports release %s, this coordinator is %s (issue #114)",
			ref.role, ref.id, t.unanswered, t.waiting.Truncate(time.Second), releaseOrUnknown(h.release), coordRelease)
	}
}

// reselectLoop runs prune + reselectDeadRelays on a fixed timer so a peer relay that
// dies mid-session is detected and its client nudged within a heartbeat window,
// without waiting for an incoming packet to drive handle() (issue #96). Pruning here
// too means an idle coordinator (no traffic at all) still expires stale peers and
// sessions, which was previously packet-driven only. Runs for the process lifetime,
// like the TURN/bootstrap background loops; this coordinator has no shutdown path.
//
// reportUnansweredNodes rides this timer rather than handle()'s per-packet prune
// (issue #114): it is a whole-table pass whose answer changes on the scale of tens
// of seconds, so running it per datagram would be pure cost. Last of the three, so
// it sees the table the other two leave behind.
func reselectLoop(ctx context.Context) {
	t := time.NewTicker(reselectInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			mu.Lock()
			sweepTick(time.Now())
			mu.Unlock()
		}
	}
}

// sweepTick is one pass of reselectLoop's timer, split from the loop so a test can
// drive the real sequence — and the real composition — without waiting out a
// reselectInterval. The order is load-bearing: prune first so the two checks below
// it see the table it leaves, and reportUnansweredNodes last so it does not report a
// node about a session reselectDeadRelays is in the middle of retiring.
//
// Callers hold mu.
func sweepTick(now time.Time) {
	prune(now)
	reselectDeadRelays(now)
	reportUnansweredNodes(now)
}

// pickRelay chooses a Bacchus relay node to splice a client<->exit data path
// (issue #17, ADR-0033). It excludes excludeID so a node registered as both a
// relay and the very exit being connected to is never asked to relay to itself —
// a pointless loopback hop that would also collapse the "relay is a distinct
// peer" property the transparency argument rests on. It returns nil when no
// other relay is registered, on which the caller falls back to TURN.
//
// Selection policy — pick a live relay at random. Go randomizes map iteration
// order, so the first eligible entry varies from call to call; "live" means the
// relay was last seen within half the prune TTL (so it is unlikely to have
// silently vanished), and the exit itself is never eligible (excludeID).
//
// The randomness is deliberate — do NOT collapse this into a deterministic
// freshest-first pick. A deterministic winner would let a relay that controls
// its own heartbeat cadence make itself the perpetual choice and so be handed
// every relay-mode client, concentrating the source address + timing metadata a
// relay can observe (the payload stays end-to-end opaque). It would also defeat
// the client's cross-coordinator failover: every coordinator would keep handing
// back the same relay, so a relay that died but has not yet pruned would black-
// hole relay-mode connects instead of a retry landing on a healthy peer. Per-
// call variation spreads sessions, re-rolls on retry, and denies a hostile relay
// a fixed target. A load-aware policy (fewest live sessions) is still a follow-up
// once the relay tier is actually populated (see ADR-0033's consequences).
//
// Declared limits (issue #143, ADR-0040) compose with that as a FILTER and never as
// a sort: an exhausted relay is skipped, and the choice among the survivors stays
// random. Any later capacity-aware policy must keep that shape. Sorting by rating
// and taking the best would rebuild exactly the deterministic winner this comment
// exists to prevent, and would hand it to whichever relay advertised the most
// attractive number — which is worse than the arbitrary winner, not better.
func pickRelay(excludeID string) *relayNode {
	now := time.Now()
	for id, r := range relays {
		if id == excludeID {
			continue
		}
		if now.Sub(r.lastSeen) > ttl/2 {
			continue // stale — likely gone; let prune reap it
		}
		if r.exhausted {
			continue // declared monthly quota spent this cycle (issue #143): its operator is done
		}
		if !meetsServeFloor(r.id, r.speedCap) {
			// Serve floor (issue #145) as a FILTER, not a sort — preserving the random
			// pick this function's doc insists on. OFF in this lane (serveFloor zero), and
			// doubly inert for relays, which earn no measured rating at all until relay
			// attribution exists (design §8.5, issue #159): measuredUsable falls back to
			// the declared cap, so this cannot strand the relay tier.
			continue
		}
		return r
	}
	return nil
}

// validIngressPort reports whether a relay's self-reported onion-forward listener port
// is a port at all (issue #11, ADR-0038 §9 item 3).
//
// Only the PORT of a relay's forwarding ingress is taken from the node — buildSnapshot
// supplies the host from the address this coordinator OBSERVED, so a relay cannot claim
// an ingress in an AS it does not occupy — and this is the one check that half needs.
// A relay reporting 70000, or a negative number, was advertised in the SIGNED directory
// as `observedIP:70000`, an address no client can dial.
//
// It is self-inflicted (a relay reporting nonsense only makes itself undialable) and
// §4 rejects it on dial, so this is hardening rather than a correctness fix. It is worth
// having because the signed directory is the artifact this project asks clients to
// trust: publishing an entry that cannot possibly work spends a client's hop-selection
// attempt and its dial timeout on a node the coordinator could see was unusable when it
// registered.
//
// Out of range means "advertises no ingress" rather than "refuse the register". The
// relay is otherwise perfectly serviceable — it can still splice, still act as a
// mesh-walk courier, still carry a country — and only its relay-ELIGIBILITY (#124's
// field-level gate) depends on a usable port. Refusing the whole registration over one
// malformed advisory field would cost the network a working node.
func validIngressPort(p int) bool { return p >= 1 && p <= 65535 }

// servingCheck applies the min-serving-version fence (issue #36, ADR-0015) to a
// registering node's reported release. ok is false, with a safe-to-log reason
// (protocol/version data only, never anything identifying the node), when the
// node must be fenced. With the fence disabled (the effective floor is the zero
// 0.0.0) it serves everyone, including nodes from before this field existed, so
// enabling the fence is opt-in and backward compatible. With a floor set, a node
// that reports no parseable release, or one below the floor, is fenced — which
// is exactly how an operator forces the fleet onto a new release once the grace
// window has elapsed.
//
// The floor comes from policyServingFloor, which is the ONE place the precedence
// between a loaded policy and the -min-serving-version flag is decided (issue #39,
// ADR-0043). It is read here rather than compared here so there is exactly one
// answer to "what is the fence right now", wherever it is asked.
//
// Serve eligibility is more than the version fence (issue #15): the same gate now
// also applies the policy's measured-throughput floor and its declared-quota floor.
// All three conditions live here because they answer one question — may this node
// join the serve pool — and a node that fails any of them is client-only: it may use
// the service, it just may not serve. nodeID is needed for the capacity condition,
// which is per-node; declaredQuota is the node's own declaration off this register.
//
// The three conditions are exactly the three fields of the signed policy's
// ServeFloor (min_serving_version, min_measured_bps, min_declared_quota_bytes), and
// keeping them together is deliberate: the alternative is an operator having to know
// which of three code paths answers "why is this node not serving".
//
// Order is cheapest-and-most-actionable first. The version fence needs nothing but
// the register; the quota floor needs nothing but the register; the measured floor
// needs a rating that in this build no node has. A node failing several is told about
// the version first, because that is the one it can fix by updating.
func servingCheck(release, nodeID string, declaredQuota capacity.Bytes) (reason string, ok bool) {
	if reason, ok := versionCheck(release); !ok {
		return reason, false
	}
	if reason, ok := meetsDeclaredQuotaFloor(declaredQuota); !ok {
		return reason, false
	}
	return meetsMeasuredFloor(nodeID)
}

// versionCheck is the min-serving-version half of servingCheck, split out so the
// version fence keeps a name of its own now that serve eligibility has more than one
// condition.
func versionCheck(release string) (reason string, ok bool) {
	floor := policyServingFloor()
	if floor == (version.Version{}) {
		return "", true
	}
	nv, err := version.Parse(release)
	if err != nil {
		return fmt.Sprintf("node reports no valid release (%q); minimum serving version is %s — update", release, floor), false
	}
	if !version.ServingAllowed(nv, floor) {
		return fmt.Sprintf("node version %s is below the minimum serving version %s — update to serve", nv, floor), false
	}
	return "", true
}

// coordBuild renders this coordinator's build identity for its startup line (issue
// #114): its release, plus the VCS revision the Go toolchain records in the binary.
//
// The revision is there because the release alone does not identify a build. A
// release ships many commits, so two builds from either end of one report the
// same release and are not the same binary — which is the shape of skew this
// issue was opened about. The revision is what differs, and it costs nothing:
// the toolchain stamps it into any build made from a checkout.
//
// Until issue #128 the reason was blunter than that. Nothing in this repository
// stamped core/version.current — deploy/install.sh and docs/RUNNING.md both built
// with a plain `go build`, and the -ldflags -X hook core/version documents was
// used by nobody — so every binary ever produced here reported the same release
// and the release identified nothing at all. All three build paths stamp it from
// the repository's VERSION file now, which is what makes these two halves
// complementary rather than the revision carrying the line by itself.
//
// It is the coordinator's HALF of the comparison, not the comparison: a node's
// revision is not on the register wire, so pairing this against a node still means
// reading the node's own binary (go version -m). Half is what can be had from inside
// this binary, and it is the half an operator otherwise has to go and fetch.
//
// Absent, and printed as such, for a build made in a git WORKTREE (the toolchain
// records VCS data only from a checkout with a real .git directory) and under
// `go test`. The release is printed either way, so the line degrades to exactly what
// it said before this existed.
//
// The value goes to the log only. It is not put on any wire and not folded into
// coordRelease, which is a wire field that clients parse as semver (ADR-0015).
func coordBuild() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return coordRelease
	}
	return describeBuild(coordRelease, bi.Settings)
}

// describeBuild is coordBuild's rendering half, split out because the reading half
// cannot be exercised from a test: a test binary carries the settings the toolchain
// gave it and there is no way to hand it different ones. Everything about the format
// is decided here, so the format is what a test can pin.
func describeBuild(release string, settings []debug.BuildSetting) string {
	var revision, dirty string
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = ", uncommitted changes"
			}
		}
	}
	if revision == "" {
		return release + " (no build revision recorded — see coordBuild)"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	return fmt.Sprintf("%s (revision %s%s)", release, revision, dirty)
}

// releaseOrUnknown renders a node's self-reported release for the operator log,
// naming the empty case rather than printing a blank (as countryOrUnknown does for
// a country tag). Empty is what a node predating ADR-0015 sends, and — with the
// fence at its default 0.0.0 — such a node serves, so the blank is a state an
// operator really can be looking at.
func releaseOrUnknown(release string) string {
	if release == "" {
		return "unknown"
	}
	return release
}

// noteRelease says what a register reveals about the build a node is running, and
// says it at most once per (node, release) rather than on all 8,640 registers a
// node sends in a day (issue #114).
//
// prior is the node's health record from before this register, nil for a node new
// to the registry. The three cases it separates:
//
//   - New node. The "registered" line has just printed the release, so there is
//     nothing to add but the mismatch warning below.
//   - Same release as last time. The steady state — say nothing at all.
//   - Different release. Said out loud, because this is the ONLY place a rebuild
//     under a running coordinator is visible: the "registered" line fires only for
//     a node not already in the registry, an update restarts a node in about a
//     second, and the entry survives 35s (ttl) — so a staged rollout swaps every
//     binary in the fleet without that line firing once.
//
// The mismatch is a WARNING and never a refusal. Refusing by default would turn one
// silent failure into a fleet-wide outage on any staged rollout; -min-serving-version
// is the fence for operators who want the strict posture, and its 0.0.0 default is
// deliberate (ADR-0015).
//
// Caveat worth knowing before trusting this: it compares RELEASES, not builds.
// Two binaries built from different commits of one release report the same string
// and do not trip this line. That is why reportUnansweredNodes exists rather than
// this being the whole answer to #114, and why the startup line carries a VCS
// revision that the register wire does not.
//
// It could not fire at all until issue #128: nothing stamped core/version.current
// at build time — install.sh and docs/RUNNING.md both built with a plain
// `go build` — so every binary reported the same release. Every build path stamps
// from the repository's VERSION file now. One consequence to expect: an unstamped
// build reports 0.0.0 (core/version.Current), so a node someone built with a bare
// `go build` trips this against any stamped coordinator — correctly, since that is
// exactly a node whose build cannot be identified.
func noteRelease(role, id string, prior *forwarderHealth, release string) {
	if prior != nil {
		if prior.release == release {
			return
		}
		log.Printf("%s %s changed release: %s -> %s", role, id, releaseOrUnknown(prior.release), releaseOrUnknown(release))
	}
	if release == coordRelease {
		return
	}
	log.Printf("WARNING: %s %s reports release %s and this coordinator is %s — a node and a coordinator built from different commits register and heartbeat normally and can still drop every session between them, because registration is stable across builds and session setup is not (issue #114). It is NOT refused: -min-serving-version is the fence for that, and it is unaffected by this line",
		role, id, releaseOrUnknown(release), coordRelease)
}

// nodeRef names one registered forwarder ROLE. The role is part of the key because
// a node that serves both roles registers BOTH under a single id (core/engine.go
// builds each register from the same e.cfg.ID), so relays["n"] and exits["n"] are
// two registrations of one box which are assigned work — and can fail to do it —
// independently of each other.
type nodeRef struct{ role, id string }

// assignedNode names the forwarder this coordinator handed a session to: the peer
// relay on a peer-relayed session, the terminating exit on a direct or TURN-fallback
// one. It reports false for the single shape that names neither — a chained connect
// that found no peer relay and fell through to the TURN fallback, which records no
// exit id by construction (ADR-0042 §9) — and such a session is skipped rather than
// attributed to a node this coordinator did not choose.
func assignedNode(s *session) (nodeRef, bool) {
	if s.relayID != "" {
		return nodeRef{role: "relay", id: s.relayID}, true
	}
	if s.exitID != "" {
		return nodeRef{role: "exit", id: s.exitID}, true
	}
	return nodeRef{}, false
}

// healthOf returns the live health record of the forwarder ref names, or nil if it
// is no longer registered. The role decides which map is consulted — see nodeRef.
func healthOf(ref nodeRef) *forwarderHealth {
	switch ref.role {
	case "relay":
		if r, ok := relays[ref.id]; ok {
			return &r.forwarderHealth
		}
	case "exit":
		if e, ok := exits[ref.id]; ok {
			return &e.forwarderHealth
		}
	}
	return nil
}

// coordAdvertise picks the host:port a client should dial for this
// coordinator's signaling service: advertise if the operator set it,
// otherwise the bind address (fine as long as it isn't a wildcard like
// ":8080" — the operator is expected to set -advertise in that case).
func coordAdvertise(advertise, bindAddr string) string {
	if advertise != "" {
		return advertise
	}
	return bindAddr
}

// liveStore adapts an atomically-swappable *coldstart.MemStore into a
// [coldstart.SecretStore] whose contents can be hot-reloaded (see
// reloadSecretsLoop) without restarting the bootstrap listener.
type liveStore struct {
	ptr *atomic.Pointer[coldstart.MemStore]
}

func (l liveStore) Lookup(secretID string) ([]byte, bool) { return l.ptr.Load().Lookup(secretID) }

// turnConfig holds the real STUN/TURN server's operator-provided settings
// (formerly cmd/turn's flags, folded in here by issue #30).
type turnConfig struct {
	addr     string
	publicIP string
	realm    string
	user     string
	pass     string
}

// startTurnAndBootstrap brings up the real STUN/TURN server (pion/turn) with
// the cold-start bootstrap listener blended onto its same UDP socket and
// port (issue #30): it loads (or generates) the snapshot-signing key, starts
// the secrets-file reload loop and the snapshot sign-and-refresh loop, wraps
// the TURN socket in coldstart.Demux, and hands the wrapped conn to
// turn.NewServer — bootstrap-shaped requests are answered by Demux directly;
// every other packet (ordinary STUN Binding requests, TURN Allocate/Refresh/
// CreatePermission/ChannelBind/data) reaches pion/turn exactly as it would
// on a bare socket. It returns the bound address once setup succeeds;
// everything else runs in background goroutines for the lifetime of the
// process (this coordinator has no graceful-shutdown path today, matching
// the rest of main).
func startTurnAndBootstrap(turnCfg turnConfig, keyPath, secretsPath, advertise string) (string, error) {
	priv, err := loadOrGenerateBootstrapKey(keyPath)
	if err != nil {
		return "", fmt.Errorf("bootstrap: %w", err)
	}

	var store atomic.Pointer[coldstart.MemStore]
	store.Store(coldstart.NewMemStore())

	var snapshot atomic.Pointer[[]byte]
	empty := []byte(nil)
	snapshot.Store(&empty)

	conn, err := net.ListenPacket("udp", turnCfg.addr)
	if err != nil {
		return "", fmt.Errorf("turn: listen %s: %w", turnCfg.addr, err)
	}
	demuxed := coldstart.Demux(conn, liveStore{&store}, func() []byte { return *snapshot.Load() })

	key := turn.GenerateAuthKey(turnCfg.user, turnCfg.realm, turnCfg.pass)
	if _, err := turn.NewServer(turn.ServerConfig{
		Realm: turnCfg.realm,
		AuthHandler: func(username, realm string, src net.Addr) ([]byte, bool) {
			if username == turnCfg.user {
				return key, true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: demuxed,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP(turnCfg.publicIP), // address peers are told to use
				Address:      "0.0.0.0",                     // bind on all interfaces
			},
		}},
	}); err != nil {
		return "", fmt.Errorf("turn: %w", err)
	}

	ctx := context.Background()
	go reloadSecretsLoop(ctx, secretsPath, &store)
	go refreshSnapshotLoop(ctx, priv, advertise, &snapshot)

	log.Printf("bacchus STUN/TURN + bootstrap (UDP) on %s  realm=%s user=%s public-ip=%s, bootstrap advertising %s",
		turnCfg.addr, turnCfg.realm, turnCfg.user, turnCfg.publicIP, advertise)
	return conn.LocalAddr().String(), nil
}

// buildSnapshot takes the registry lock and turns the live exits/relays into
// a coldstart.Snapshot: this coordinator's own signaling address plus every
// currently-registered exit and relay, so a bootstrapping client (or a
// mesh-walk recovery, issue #6) gets a usable set of entry points without a
// separate round trip. Relay entries additionally carry an onion-forward ingress
// and operator tag when known (issue #124), so a client can later assemble a
// multi-hop chain (§2/§4) from the same signed directory.
func buildSnapshot(advertise string) coldstart.Snapshot {
	mu.Lock()
	defer mu.Unlock()
	now := time.Now()
	prune(now)

	entries := []coldstart.Entry{{Role: "coordinator", ID: "coordinator", Addr: advertise}}
	for _, e := range exits {
		if e.exhausted {
			continue // declared monthly quota spent (issue #143); see the relay loop below
		}
		// Operator is carried for exits as well as relays (issue #142). It was
		// relay-only, and that quietly disabled operator-diversity hop selection at the
		// depth most clients run: a chain's head must be exit-role (it is reached by
		// being named in connect{firstHop}), so an unlabeled head was neither recorded
		// nor collided against, and at depth 2 the head is the only peeling hop there
		// is. The operators map is keyed by node id and has never been role-scoped, so
		// this reads a value that was already there.
		// Country ships with the provenance that produced it (issue #3). Without it,
		// three different claims arrived here indistinguishable: a country resolved
		// from an observed address, one taken verbatim from the node's own -country
		// flag, and one resolved from an address this coordinator can see disagrees
		// with the endpoint the exit says it serves traffic from. The signature proves
		// this coordinator said the country; it says nothing about which of the three
		// it was, and ADR-0042 §9 made this artifact the exit-discovery path for
		// chaining — so a chaining client picks its jurisdiction out of exactly this
		// field with no live reply to check it against.
		//
		// # A split-endpoint exit STAYS in the snapshot, and that is a decision
		//
		// The alternative — withholding it — was considered and is worse, because this
		// snapshot is not only a jurisdiction menu. It is also the mesh-walk courier
		// list (issue #31, ADR-0037): the relay and exit entries are the peers a client
		// that has lost every coordinator asks for a fresh directory. Dropping a
		// working courier because of a property of its COUNTRY withdraws recovery
		// capacity at exactly the moment recovery is what the client needs, to fix a
		// problem that has nothing to do with reaching it.
		//
		// It would also put this surface out of step with connect. Without
		// -geoip-required a split-endpoint exit keeps its signaling-derived country and
		// is assignable (ADR-0042 §8) — a directory that hid what connect would hand
		// out is the same class of disagreement §4 forbids in the other direction, and
		// a client would see a country vanish from the directory while the coordinator
		// happily pairs it there.
		//
		// So it ships, labelled, and the consumer decides: Entry.CountryContradicted is
		// the fail-closed test, and core/relaychain.go refuses such an exit as a
		// terminating exit while still using it as a courier. Under -geoip-required the
		// question does not arise — such an exit has no country at all (§8, issue #2)
		// and ships as the country-less exit it is.
		entries = append(entries, coldstart.Entry{Role: "exit", ID: e.id, Country: e.country, CountrySource: e.countrySource, DeclaredCountry: publishedDeclaration(e.declaredCountry), Addr: e.tcpAddr, Operator: operators[e.id]})
	}
	for id, r := range relays {
		if r.exhausted {
			// Its operator's declared monthly quota is spent for this cycle (issue #143).
			// The signed directory is an assignment surface like list and pickRelay: a
			// client selecting from it (ADR-0037 mesh-walk recovery, or an ADR-0038 chain)
			// would pick this node and have its splice cut by the node's own quota
			// enforcement — the "your connection failed" mode that stopping assignment
			// exists to avoid. Note the snapshot's 5-minute TTL against the register's 10s
			// heartbeat means a client can still hold a stale entry briefly; the node's
			// local enforcement is the guarantee, this is the courtesy.
			continue
		}
		// Operator is coordinator-side truth (never a node self-report); "" when
		// unassigned. Ingress is advertised only when the relay reported a listener port,
		// and its host is the coordinator-OBSERVED source IP (r.addr.IP), never a node
		// self-report — a relay therefore cannot claim a forwarding ingress in an AS it
		// does not occupy, which is what lets §4 trust an IP-derived AS (issue #124). The
		// port is the relay's own, since a TCP listener is not observable from a UDP
		// register. A relay that reported no port advertises no ingress and is simply not
		// relay-eligible (Entry.RelayEligible).
		// Country is the coordinator-DERIVED tag (issue #136), so advertising it in
		// the signed directory advertises a fact this coordinator established, not a
		// relay's claim about itself — the same standard Ingress and Operator are held
		// to right below. A relay's country was silently dropped before #136: it was
		// registered and then had nowhere to live.
		// The provenance rides along for a relay too (issue #3). A relay's Addr and
		// Ingress are both built from the observed source IP so they cannot disagree
		// with each other, but its COUNTRY still falls back to the node's own -country
		// hint whenever that address resolves to nothing — which is every node in a
		// deployment with no database staged. A consumer that cannot see the difference
		// is reading a self-report as a coordinator-established fact.
		e := coldstart.Entry{Role: "relay", ID: id, Country: r.country, CountrySource: r.countrySource, DeclaredCountry: publishedDeclaration(r.declaredCountry), Addr: r.addr.String(), Operator: operators[id]}
		if r.ingressPort != 0 {
			e.Ingress = net.JoinHostPort(r.addr.IP.String(), strconv.Itoa(r.ingressPort))
		}
		entries = append(entries, e)
	}
	return coldstart.Snapshot{
		Version:   coldstart.SnapshotVersion,
		IssuedAt:  now,
		ExpiresAt: now.Add(snapshotTTL),
		Entries:   entries,
	}
}

// refreshSnapshotLoop signs a fresh snapshot immediately and then every
// snapshotRefresh, so the registry state served to bootstrapping clients
// never lags more than one interval behind reality.
func refreshSnapshotLoop(ctx context.Context, priv ed25519.PrivateKey, advertise string, current *atomic.Pointer[[]byte]) {
	sign := func() {
		signed, err := coldstart.Sign(priv, buildSnapshot(advertise))
		if err != nil {
			log.Printf("bootstrap: sign snapshot: %v", err)
			return
		}
		current.Store(&signed)
	}
	sign()
	t := time.NewTicker(snapshotRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sign()
		}
	}
}

// reloadSecretsLoop (re)loads the bootstrap secrets file into a fresh
// MemStore and swaps it in atomically, so an operator can issue a new
// per-user secret (cmd/coldstart-issue) without restarting the coordinator.
// A missing file is not an error — it just means nobody can authenticate
// yet — but any other read/parse failure is logged and the previous store
// is kept.
func reloadSecretsLoop(ctx context.Context, path string, current *atomic.Pointer[coldstart.MemStore]) {
	load := func() {
		store, err := coldstart.LoadMemStore(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("bootstrap: reload secrets from %s: %v", path, err)
			}
			return
		}
		current.Store(store)
	}
	load()
	t := time.NewTicker(secretsReload)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			load()
		}
	}
}

// loadOrGenerateBootstrapKey reads the hex-encoded ed25519 seed at path, or
// generates and persists a new keypair if the file doesn't exist yet. The
// public key is logged so an operator can copy it into client
// config/invites — there is no other distribution path for it in this v1
// (see docs/design/bootstrap-protocol.md's open questions).
//
// The create is O_EXCL and the seed is flushed before this returns; bacchus#189
// is both. One coordinator per host makes the race the weakest of the three seed
// writers' — but it costs one flag to close, and read-then-create is a TOCTOU
// wherever it appears: without O_EXCL a second process that also saw no file
// overwrites this one's key with no error. EEXIST refuses rather than
// re-reading, because the key this process holds in memory is not the key on
// disk, and a coordinator signing snapshots under a key that is not the one an
// operator will read back out is the same skew by a longer route. The flush is
// what the log line below makes load-bearing: that pubkey is baked into invites,
// and a power loss before the bytes are durable leaves every invite carrying it
// failing snapshot verification against a regenerated key.
//
// A partial write is deliberately left in place — the malformed-key branch above
// refuses it loudly on the next start, where deleting it would silently mint a
// second signing key and strand every invite already issued.
func loadOrGenerateBootstrapKey(path string) (ed25519.PrivateKey, error) {
	if b, err := os.ReadFile(path); err == nil {
		seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("malformed bootstrap key at %s", path)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read bootstrap key %s: %w", path, err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate bootstrap key: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("bootstrap key %s was created by another process while this one was generating: "+
				"refusing, because the key this process holds is not the key on disk", path)
		}
		return nil, fmt.Errorf("create bootstrap key %s: %w", path, err)
	}
	if _, err := f.WriteString(hex.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return nil, fmt.Errorf("write bootstrap key %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("flush bootstrap key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("close bootstrap key %s: %w", path, err)
	}
	log.Printf("bootstrap: generated new signing key at %s — public key (bake into client config/invites): %s",
		path, hex.EncodeToString(pub))
	return priv, nil
}

// loadOperators reads a JSON object {"<node id>": "<operator tag>"} from path — an
// operator's out-of-band assignment of nodes to operator / vouch subtrees, the same
// operator-managed-file shape as the bootstrap secrets and revocation files. A path
// that does not exist yields an empty map and no error, matching the "a missing file
// means nothing is configured" convention of -admission-revocations; a present but
// unreadable or malformed file is a hard error, since a misconfigured operator map
// would silently erase the diversity signal §4 depends on.
func loadOperators(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read operators file %s: %w", path, err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse operators file %s: %w", path, err)
	}
	return m, nil
}
