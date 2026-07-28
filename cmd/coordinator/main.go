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
// fallback hint for an address that resolves to nothing.
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
	"github.com/bacchus-vpn/bacchus/core/admission"
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
	QuotaState      string                 `json:"quotaState,omitempty"`  // quotaOK | quotaExhausted (issue #143, ADR-0040): whether this forwarder's declared monthly quota — its operator's own ISP data cap — is spent for the current billing cycle. Re-sent on EVERY register (core/engine.go registerLoop) because the handler below replaces the registry entry wholesale, so a state carried once would be forgotten 10s later. One BIT rather than the byte counts, deliberately: matchmaking needs only "may I assign to you", and a per-node monthly usage curve would hand this coordinator — untrusted by standing assumption (ADR-0020, #60) — a linkability signal about a residential operator's household in exchange for nothing. Empty = no declared quota; additive/optional.
	Receipt         *accounting.Receipt    `json:"receipt,omitempty"`     // capacity-report payload (issue #158, ADR-0041): a co-signed usage receipt (ADR-0021) the CLIENT sends to feed the coordinator-side capacity estimator. Carries the client-asserted Saturated bit; bound to the co-signing client by ReportSig. Absent on every other message. A leaf import (core/accounting), like admission — not the transport stack this binary avoids.
	ReportSig       []byte                 `json:"reportSig,omitempty"`   // client signature over the capacity-report receipt + its saturation bit (accounting.SignReport, issue #158): proves the un-co-signed Saturated bit came from the client that co-signed the receipt, so a node that merely holds the receipt cannot forge or flip it.

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

type relayNode struct {
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
	speedCap  uint64
	exhausted bool
	lastSeen  time.Time
	// country is the coordinator-DERIVED country tag (issue #136): resolved from the
	// observed source IP in addr, falling back to the node's self-reported hint only
	// when that resolves nothing. countrySource records which of the two it was, for
	// the operator log. Empty means no country could be established.
	//
	// A relay registers a -country tag exactly as an exit does, but before #136 this
	// struct had no field for it and buildSnapshot never advertised it, so relay
	// country was silently discarded. It is carried now: ADR-0038's hop selection
	// wants to know where a relay is, and #136 covers relays explicitly.
	country       string
	countrySource string
}
type exitNode struct {
	id, tcpAddr string
	udp         *net.UDPAddr // signaling addr (for direct mode)
	// Declared limits (issue #143, ADR-0040); see relayNode. An exhausted exit is
	// withheld from the country aggregate and refused at connect.
	speedCap  uint64
	exhausted bool
	lastSeen  time.Time
	// country / countrySource: coordinator-derived, as for relayNode (issue #136). An
	// exit with no country is unreachable, because a country is the only thing a
	// client can ask for (issue #146) — see exitAssignable.
	country       string
	countrySource string
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
	lastSeen time.Time // last signaling activity; the rendezvous state is reaped sessionTTL after it goes quiet
}

var (
	mu       sync.Mutex
	relays   = map[string]*relayNode{}
	exits    = map[string]*exitNode{}
	sessions = map[string]*session{}
	pc       *net.UDPConn

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

func send(to *net.UDPAddr, m wire) {
	b, _ := json.Marshal(m)
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
	admissionPubKey := flag.String("admission-pubkey", "", "admission authority public key (hex, from cmd/admission-issue). When set, every node (register) and client (list/connect) must present a credential this key signed (issue #42). Empty DISABLES admission — the network serves anyone.")
	admissionRevocations := flag.String("admission-revocations", "secrets/admission-revocations.json", "path to the revoked-credential-serials file (hot-reloaded); a missing file means nothing is revoked")
	deviceRootPubKey := flag.String("device-root-pubkey", "", "offline ROOT public key (hex) that the account service's device-credential chain anchors to (issue #50, ADR-0045). When set, every client connect must additionally present a device credential, the issuer cert it chains through, and an assertion over a challenge this coordinator issued — all verified OFFLINE, so this coordinator never calls the account service. Empty DISABLES the gate and leaves connects gated by -admission-pubkey alone. This is a DIFFERENT credential from -admission-pubkey's: that one is the network's own membership, this one is an entitlement bound to one device, and both are checked. Direction of failure matches -admission-pubkey (unset = off) and is deliberately the opposite of -policy-root-pubkey; see ADR-0045 for why an absent anchor is not sheddable the way a stale policy is.")
	deviceAudienceFlag := flag.String("device-audience", "", "the audience string a device must bind its connect assertion to (issue #50). Defaults to -advertise, which is what a client knows independently because it chose to dial it. Set explicitly only when clients reach this coordinator under a name it does not advertise itself as. An assertion bound to an audience the coordinator merely announced would bind nothing — a hostile pool member would announce someone else's and relay.")
	deviceRevocations := flag.String("device-revocations", "secrets/device-revocations.json", "path to the revoked device-credential and issuer-cert serials file (hot-reloaded); a missing file means nothing is revoked. Separate from -admission-revocations because the two credentials come from different authorities and their serial namespaces are unrelated.")
	operatorsPath := flag.String("operators", "secrets/operators.json", "path to the node->operator-tag assignment file (JSON object {\"nodeID\":\"operatorTag\"}), advertised in the signed directory for operator-diversity hop selection (issue #124, ADR-0038); a missing file means no operator tags")
	geoipDir := flag.String("geoip", "", "path to an unzipped MaxMind GeoLite2-Country-CSV directory, used to derive each node's country from the source address this coordinator OBSERVES it register from (issue #136). Staged out of band and never committed; see docs/RUNNING.md. Empty DISABLES derivation and falls back to each node's self-reported -country tag.")
	geoipRequired := flag.Bool("geoip-required", false, "refuse to fall back to a node's self-reported -country when its observed address does not resolve (issue #136). The hardened posture: no node self-report can reach a client's country choice. Off by default because every node in a local stack registers from loopback, which no database resolves. Requires -geoip.")
	minServingVersion := flag.String("min-serving-version", "0.0.0", "minimum node release (MAJOR.MINOR.PATCH) this coordinator will assign work to; nodes below it are fenced from matchmaking until they update (issue #36, ADR-0015). Raise it past the grace window after a release to pull stragglers up. 0.0.0 disables the fence — every node serves regardless of version.")
	policyRootPubKey := flag.String("policy-root-pubkey", "", "offline ROOT public key (hex) the signed network policy chains to (issue #39, ADR-0043). When set, this coordinator fetches a signed policy bundle and enforces the floors, fences and reserves inside it — numbers it cannot author, because it does not hold the key that signs them. Empty DISABLES signed policy and leaves this coordinator enforcing only its own flags. NOTE the direction of failure flips here: unlike -admission-pubkey and -min-serving-version, which fail OPEN when unset, a coordinator WITH a policy root configured stops assigning new work once its policy goes stale. Coordinators are a pool with client rotation, so one failing closed sheds to its peers.")
	policySource := flag.String("policy-source", "", "where to fetch the signed policy bundle from: an http(s) URL, or a filesystem path an operator stages the bundle at. Required when -policy-root-pubkey is set. Re-fetched every 10s and re-verified from scratch every time, delegation included.")
	policyStatePath := flag.String("policy-state", "secrets/policy-state.json", "path to this coordinator's persistent policy state (issue #39): the last VERIFIED bundle, so a restart does not begin unpoliced, and the highest policy sequence ever accepted, which is what refuses a rollback. The sequence floor cannot be re-derived from signed data, so write access to this file is equivalent to being able to roll this coordinator back one generation — keep it with the other secrets.")
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
		log.Printf("version fence DISABLED (-min-serving-version 0.0.0) — any node version may serve (issue #36); coordinator release %s", coordRelease)
	} else {
		log.Printf("version fence ENABLED — nodes below %s are dropped from matchmaking (issue #36); coordinator release %s", servingFloor, coordRelease)
	}
	v, err := setupAdmission(context.Background(), *admissionPubKey, *admissionRevocations)
	if err != nil {
		log.Fatal(err)
	}
	admissionVerifier = v
	if v == nil {
		log.Printf("WARNING: admission DISABLED (-admission-pubkey not set) — any client or node can join this network (issue #42)")
	} else {
		log.Printf("admission ENABLED — nodes and clients must present a credential signed by the configured authority")
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
	ua, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	pc, err = net.ListenUDP("udp", ua)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("bacchus coordinator v3 (UDP) listening on %s", *addr)

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

	buf := make([]byte, 65535)
	for {
		n, src, err := pc.ReadFromUDP(buf)
		if err != nil {
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
		if !admit(m, src, admission.Role(m.Role), m.ID) {
			return
		}
		// Version fence (issue #36, ADR-0015): a node too old to carry the
		// current transport shape is dropped from matchmaking until it updates —
		// a stale node still advertises the old, now-detectable fingerprint and
		// would burn the users routed through it. Enforced here, at register,
		// because a stale or hostile node cannot be trusted to fence itself.
		if reason, ok := servingCheck(m.Release, m.ID); !ok {
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
		country, countrySrc := deriveCountry(src, m.Country)
		switch m.Role {
		case "relay":
			if _, ok := relays[m.ID]; !ok {
				log.Printf("relay registered: %s (%s) country=%s (%s)", m.ID, src, countryOrUnknown(country), countrySourceLabel(countrySrc))
			}
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
			relays[m.ID] = &relayNode{id: m.ID, addr: src, ingressPort: port, speedCap: m.SpeedCap, exhausted: m.QuotaState == quotaExhausted, lastSeen: now, country: country, countrySource: countrySrc}
		case "exit":
			// An exit, unlike a relay, advertises a data-plane endpoint of its own, so
			// its country is derived against that too: signaling arriving from one
			// country while traffic egresses from another is the jurisdiction
			// misrouting country selection exists to prevent (issue #136, ADR-0042 §8).
			country, countrySrc = deriveExitCountry(src, m.Country, m.Addr)
			if _, ok := exits[m.ID]; !ok {
				log.Printf("exit registered: %s -> %s country=%s (%s)", m.ID, m.Addr, countryOrUnknown(country), countrySourceLabel(countrySrc))
				if countrySrc == countrySplit {
					// Loud, because it is the one case where a client is shown a
					// country this coordinator has NOT tied to the egress path.
					log.Printf("WARNING: exit %s signals from %s but advertises %s — its country tag (%s) describes where it SIGNALS from, not necessarily where traffic egresses; run -geoip-required to refuse this shape (issue #136, ADR-0042 §8)",
						m.ID, src.IP, m.Addr, country)
				}
				if country == countryUnknown {
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
					switch countrySrc {
					case countryNoEndpoint:
						log.Printf("WARNING: exit %s has NO country: its address resolved, but it advertises no data-plane endpoint and -geoip-required is set, so this coordinator cannot tie the resolution to where its traffic egresses. Set -advertise to the address it serves from. It will not be offered to any client (issues #2/#136/#146)", m.ID)
					case countrySplit:
						log.Printf("WARNING: exit %s has NO country: it signals from %s but advertises %s, and -geoip-required refuses a country this coordinator cannot tie to the egress path. It will not be offered to any client (issues #136/#146, ADR-0042 §8)", m.ID, src.IP, m.Addr)
					default:
						log.Printf("WARNING: exit %s has NO country (observed address did not resolve and no usable -country hint) — it will not be offered to any client (issues #136/#146)", m.ID)
					}
				}
			}
			exits[m.ID] = &exitNode{id: m.ID, tcpAddr: m.Addr, udp: src, speedCap: m.SpeedCap, exhausted: m.QuotaState == quotaExhausted, lastSeen: now, country: country, countrySource: countrySrc}
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
			r.lastSeen = now
			r.addr = src
			r.country, r.countrySource = rederiveCountry(src, r.country, r.countrySource)
		}
		if e, ok := exits[m.ID]; ok {
			e.lastSeen = now
			e.udp = src
			// Re-checked against the STORED advertisement: a heartbeat carries none,
			// and an exit whose signaling address moves must not keep an endpoint
			// agreement that was established against the address it has left.
			e.country, e.countrySource = rederiveExitCountry(src, e.tcpAddr, e.country, e.countrySource)
		}
	case "list":
		// Client admission (issue #42): only credentialed clients may enumerate
		// exits, closing the "pose as an ordinary user to enumerate the network"
		// capability in the threat model. No subject binding — a client has no
		// coordinator-known id on this channel, so its credential is bearer.
		if !admit(m, src, admission.RoleClient, "") {
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
		send(src, wire{Type: "countries", Countries: countrySnapshot(now), Release: coordRelease})
	case "challenge":
		// Device-credential challenge (issue #50, ADR-0045). A device cannot prove
		// possession of its credential's key without a nonce THIS coordinator chose,
		// so it asks for one immediately before connecting.
		//
		// Gated by admission like every other client message, so an uncredentialed
		// party cannot spin the challenge store. The nonce is single use and
		// short-lived; see admitDevice.
		if !admit(m, src, admission.RoleClient, "") {
			return
		}
		c := issueDeviceChallenge(src)
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
		// Client admission (issue #42): matchmaking is gated too, so a leaked
		// exit list can't be turned into a live session without a credential.
		if !admit(m, src, admission.RoleClient, "") {
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
			e, refusal = chooseExit(m.Country, excludedExits(src, m.ExcludeSessions), now)
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
				wire{Type: "assign", Session: sid}, // no exitAddr => egress directly
				wire{Type: "session", Session: sid, ExitID: exitID, Release: coordRelease}, now)
			log.Printf("session %s DIRECT: client %s <-> exit %s(%s)", sid, src, e.id, e.country)
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
			pairAndReply(src, m.Nonce, r.addr,
				wire{Type: "assign", Session: sid, ExitAddr: e.tcpAddr},
				wire{Type: "session", Session: sid, ExitID: exitID, Relay: relayPeer, RelayTag: relayTag(r.id), Release: coordRelease}, now)
			if chained {
				// Deliberately not the shape of the line below it. There is no exit to
				// name, and printing e.id under an "exit" heading would record a hop as a
				// terminator in the operator's log — the same misattribution §9 keeps out
				// of the session table, arriving by the back door.
				log.Printf("session %s PEER-RELAY (chained): client %s <-> relay %s -> first hop %s(%s); terminating exit not known to this coordinator", sid, src, r.addr, e.id, e.country)
			} else {
				log.Printf("session %s PEER-RELAY: client %s <-> relay %s -> exit %s(%s)", sid, src, r.addr, e.id, e.country)
			}
		} else if e.udp != nil {
			// TURN fallback (issue #17): no peer relay is available, so wire the
			// client straight to the exit (the direct-assignment shape) and tag the
			// reply so it knows. Its transport dials the exit directly; ICE uses a
			// TURN relay candidate only if a direct hole-punch fails — TURN is the
			// last resort, not the default. E2E again terminates at the exit.
			sessions[sid] = &session{client: src, peer: e.udp, exitID: exitID, lastSeen: now}
			pairAndReply(src, m.Nonce, e.udp,
				wire{Type: "assign", Session: sid}, // no exitAddr => exit egresses directly
				wire{Type: "session", Session: sid, ExitID: exitID, Relay: relayTURN, Release: coordRelease}, now)
			log.Printf("session %s TURN-FALLBACK: client %s <-> exit %s(%s) (no peer relay available)", sid, src, e.id, e.country)
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

// reselectLoop runs prune + reselectDeadRelays on a fixed timer so a peer relay that
// dies mid-session is detected and its client nudged within a heartbeat window,
// without waiting for an incoming packet to drive handle() (issue #96). Pruning here
// too means an idle coordinator (no traffic at all) still expires stale peers and
// sessions, which was previously packet-driven only. Runs for the process lifetime,
// like the TURN/bootstrap background loops; this coordinator has no shutdown path.
func reselectLoop(ctx context.Context) {
	t := time.NewTicker(reselectInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			mu.Lock()
			now := time.Now()
			prune(now)
			reselectDeadRelays(now)
			mu.Unlock()
		}
	}
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
// also applies the policy's measured-throughput floor. Both conditions live here
// because they answer one question — may this node join the serve pool — and a node
// that fails either is client-only: it may use the service, it just may not serve.
// nodeID is needed for the capacity condition, which is per-node.
func servingCheck(release, nodeID string) (reason string, ok bool) {
	if reason, ok := versionCheck(release); !ok {
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
		entries = append(entries, coldstart.Entry{Role: "exit", ID: e.id, Country: e.country, CountrySource: e.countrySource, Addr: e.tcpAddr, Operator: operators[e.id]})
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
		e := coldstart.Entry{Role: "relay", ID: id, Country: r.country, CountrySource: r.countrySource, Addr: r.addr.String(), Operator: operators[id]}
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
	if err := os.WriteFile(path, []byte(hex.EncodeToString(priv.Seed())), 0o600); err != nil {
		return nil, fmt.Errorf("write bootstrap key %s: %w", path, err)
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
