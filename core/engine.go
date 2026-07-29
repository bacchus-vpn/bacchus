package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/capacity"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
	"github.com/bacchus-vpn/bacchus/core/handshake"
	"github.com/bacchus-vpn/bacchus/core/selection"
	"github.com/bacchus-vpn/bacchus/core/version"
	"github.com/flynn/noise"
)

// Roles a node can play. A single node may hold any combination at once (the
// mesh: a user is also a relay/exit).
const (
	RoleClient = "client"
	RoleRelay  = "relay"
	RoleExit   = "exit"
)

// Event kinds emitted through [Config.OnEvent].
const (
	EventInfo      = "info"      // general progress
	EventSession   = "session"   // a session was created/assigned
	EventICE       = "ice"       // an ICE connection-state change
	EventConnected = "connected" // client established a path (Message: "direct"/"relay")
	EventError     = "error"     // a non-fatal error
)

// Event is a status update surfaced by the engine.
type Event struct {
	Kind    string // one of the Event* constants
	Session string // session id, when relevant
	Message string // human-readable line
}

// Config describes a node. The zero value is not valid; at minimum set one
// entry in Coordinators and one in Roles. [New] fills in defaults (an auto ID)
// and validates the combination.
type Config struct {
	// Coordinators is the rendezvous pool: one or more coordinator UDP
	// host:port endpoints (issue #6, ADR-0020). Forwarder roles register with
	// every member; the client rotates across them. A single-entry pool
	// behaves exactly as one coordinator did before the pool existed.
	Coordinators []string
	Roles        []string // any combination of RoleClient, RoleRelay, RoleExit
	ID           string   // node id; auto-generated when empty

	// Client role.
	SocksAddr string // local SOCKS5 listen address

	// ExitID is ACCEPTED AND IGNORED. It named the exit a client wanted; country-only
	// assignment (issue #146, ADR-0042) removed exact-exit pinning for everyone, so a
	// connect names a country (Geo) and the coordinator picks the exit inside it.
	//
	// Kept as a field only so the GUI clients, whose removal of the setting is their
	// own lane's work, still compile. New(  ) emits a loud error event when a client
	// sets it, because a pin that is silently ignored is worse than one that is
	// rejected: the user believes they are egressing through a specific exit and they
	// are not. Remove it, and this field, once no client writes it.
	//
	// Deprecated: has no effect. Use Geo to choose a country.
	ExitID string

	// Exit / relay roles.
	ListenAddr string // exit TCP listen (relay path)
	Advertise  string // exit: host:port that relays dial (required for RoleExit)
	Country    string // exit/relay country tag

	// ExitKeyHex is an exit's X25519 static private key (64 hex chars). It fixes
	// the exit's identity: the node id becomes the matching public key, which
	// clients use to authenticate the exit's end-to-end handshake. When empty a
	// fresh key is generated at startup (a new key means a new id).
	ExitKeyHex string

	// Transport selects the session transport: "webrtc" (default, UDP/DTLS with
	// NAT traversal) or "reality" (TCP :443 with camouflage TLS). Empty means
	// WebRTC. The two fail on different axes. It is the single-transport selector
	// used when TransportPool is empty; when the pool is on, TransportPool[0] is
	// the primary and this is ignored. See core/transport.go and ADR-0008.
	Transport string

	// TransportPool, when non-empty, turns on the client-side transport pool and
	// per-user failover (issue #15): instead of dialing one Transport, the client
	// races the listed transports across the exits the coordinator advertises,
	// validates sustained flow, converges on the path that works for this user's
	// network, and re-selects when it drops. The slice is the preference order —
	// TransportPool[0] is the primary protocol; names are as in Transport
	// ("webrtc", "reality"). Empty preserves the pre-pool single-transport
	// Connect. Only the client role reads it.
	TransportPool []string

	// Geo filters the exits the pool selects among to one country tag (matching
	// ExitInfo.Country) — the geo the user picked. Empty selects across every
	// advertised exit. Meaningful only with TransportPool set.
	Geo string

	// SelectionDir is where the pool persists what it learned — the winning
	// (transport, exit, mode) per network+geo, tried first next time (issue #15).
	// Empty keeps the learning in memory only (forgotten on exit). The file holds
	// nothing user-identifying; see core/selection. Meaningful only with a pool.
	SelectionDir string

	// Reality transport (used when Transport == "reality").
	RealityListen    string // exit: TCP listen address (default ":443")
	RealityAdvertise string // exit: host:port clients dial; defaults to Advertise
	RealitySNI       string // camouflage SNI worn on the outer TLS (default a common host)

	// RealityProbeOrigin is the exit's active-probe response (issue #62): where to
	// reverse-proxy a connection that fails the inner handshake, so a prober sees a
	// real website instead of the tell of an instant close. Empty defaults to the
	// SNI host on :443 (on by default); "off" restores the bare immediate close.
	RealityProbeOrigin string

	// ICE / WebRTC.
	STUNURL    string
	TURNURL    string
	TURNUser   string
	TURNPass   string
	ForceRelay bool // force traffic through TURN (ICE relay policy)

	// DTLSFingerprint selects how the WebRTC DTLS ClientHello is reshaped to
	// avoid pion's static, blockable signature (issue #14): "auto" (default;
	// pick a browser profile per node), "chrome", "firefox", or "off" (pion
	// default — debugging/interop only). See core/dtls_fingerprint.go.
	DTLSFingerprint string

	// ICEmDNS, when true, makes host ICE candidates browser-style .local mDNS
	// names instead of pion's raw private IPs (issue #49, ADR-0022). Off by
	// default: .local candidates do not resolve between peers on different
	// networks (mDNS is link-local), so it is a connectivity trade-off that must
	// be validated against the full-device TUN client and kill-switch before it
	// is turned on. See core/ice_fingerprint.go and docs/design/dtls-fingerprint.md.
	ICEmDNS bool

	// AcctDir turns on the co-signed usage-receipt stub (issue #20, ADR-0021)
	// and sets where receipts are persisted (JSONL, one file per role: an
	// exit's own claims and a client's own copies). Empty disables accounting
	// entirely — no byte counting, no extra streams, no files — which is the
	// default for every caller that predates this field. Direct-mode sessions
	// only: see core/accounting.go's startAccounting doc for why relay-mode
	// is out of scope for this stub.
	AcctDir string

	// AcctIntervalSec is how often (seconds) a session reports a co-signed
	// receipt while AcctDir is set. Zero uses a 60s default; meaningless when
	// AcctDir is empty.
	AcctIntervalSec int

	// Limits is what this node's operator declares it is WILLING to serve (issue
	// #143, ADR-0040): an aggregate speed cap and a monthly traffic quota. Both
	// apply to the exit AND relay roles, because both spend the operator's uplink
	// and their ISP meters both the same way.
	//
	// The zero Limits declares nothing and is exactly today's behaviour — uncapped,
	// unmetered — so this is opt-in and the existing datacenter fleet is unaffected.
	// It exists for the residential volunteer, who cannot safely participate at all
	// without a way to say "this much and no more".
	//
	// Self-reported to the coordinator on every register, and that is safe: a node
	// under-declaring only reduces what it is given (the operator's own prerogative),
	// and a node OVER-declaring gains nothing, because the coordinator binds it with
	// usable = min(declared, measured) and the measured term is not a self-report.
	// See core/capacity's doc for the full trust asymmetry.
	Limits capacity.Limits

	// QuotaStatePath is where the monthly quota counter is checkpointed, so a
	// restart resumes the cycle it was in. Empty keeps it in memory only.
	//
	// Empty is a real hazard rather than merely a lesser mode when Limits.MonthlyQuota
	// is set: an in-memory counter makes `systemctl restart` mint a fresh month, and
	// "never exceeded" then holds only until the next crash. cmd/node defaults it to a
	// real path for that reason; it is empty here only so tests and embedders can opt
	// out deliberately.
	QuotaStatePath string

	// AdmissionCred is this node's admission credential (issue #42), the
	// encoded string minted by cmd/admission-issue and signed by the operator's
	// admission authority. It is attached to every register (relay/exit) and
	// list/connect (client) so an enforcing coordinator admits this node, and an
	// exit additionally presents it end-to-end inside the Noise_NK handshake so
	// the client can verify the exit is admission-authorized (issue #60, below).
	// Empty means "present none": fine against a coordinator with admission
	// disabled, rejected by one that enforces it. The engine does not verify its
	// own credential locally — it is opaque here and only meaningful to the peer
	// that holds the matching public key.
	AdmissionCred string

	// AdmissionPubKey is the admission authority's ed25519 public key (64 hex
	// chars) — the trust anchor a client role uses to verify an exit's admission
	// credential end-to-end (issue #60), rejecting an exit the authority never
	// authorized even when a hostile coordinator advertises it. Empty means the
	// client does not verify exit credentials and accepts any exit it can
	// complete Noise_NK with (fail-open, matching the coordinator when
	// -admission-pubkey is unset, #42); a malformed value is a construction
	// error. It is distributed to clients out of band exactly like the snapshot-
	// signing key — baked into the coldstart invite (core/coldstart) or set
	// directly, the latter overriding the former. Only the client role reads it.
	AdmissionPubKey string

	// AdmissionCRL is a signed, short-lived revocation bundle (issue #69,
	// core/admission.CRL's encoded form) that lets the client reject an exit
	// whose credential was revoked but has not yet naturally expired — closing
	// the gap #60 v1 accepted (offline verification with no revocation oracle).
	// Minted by cmd/admission-issue -crl and distributed exactly like
	// AdmissionPubKey: baked into the coldstart invite alongside the anchor, or
	// set directly here, the latter overriding the former. Empty means the
	// client does not check revocation at all (fail-open, matching an unset
	// AdmissionPubKey); meaningless without AdmissionPubKey also set, since
	// verifying the bundle's own signature needs the anchor — supplying one
	// without the other is a construction error, not a silent no-op. A bundle
	// that fails to parse, fails signature verification, or has already expired
	// is likewise a construction error, so a stale or corrupt bundle can never
	// silently degrade to "nothing is revoked". Only the client role reads it.
	AdmissionCRL string

	// OnEvent, when set, receives status events. When nil the engine logs the
	// same messages via the standard logger.
	OnEvent func(Event)

	// AdmissionCRLPath is a client-side alternative to AdmissionCRL (issue
	// #90): a filesystem path to a signed revocation bundle, re-read on an
	// interval so a long-lived client picks up an operator's newly rotated
	// CRL without a restart — mirroring cmd/coordinator's own revocation-file
	// reload loop. Loaded once synchronously at construction (a bad path,
	// like a bad inline AdmissionCRL, is a construction error) and again
	// every few minutes thereafter by a background loop started in Start; a
	// reload that fails to read, parse, or verify is logged and the
	// previously loaded bundle is kept unchanged. At most one of
	// AdmissionCRL and AdmissionCRLPath may be set. Empty disables reload;
	// only the client role reads it.
	AdmissionCRLPath string

	// AdmissionRequireCRL, when true, turns "an admission anchor is
	// configured (AdmissionPubKey, direct or via a coldstart invite) but no
	// CRL is" from today's fail-open-on-revocation default into a
	// construction error instead (issue #91). Opt-in and off by default: it
	// exists for an operator who wants a hostile or buggy coordinator that
	// strips the CRL from a v3 coldstart invite to be a hard failure the
	// client refuses to start with, rather than a silent downgrade to "not
	// checking revocation." Has no effect without AdmissionPubKey also set —
	// see buildExitVerifier. Only the client role reads it.
	AdmissionRequireCRL bool

	// OnUnderlayDial, when set, is called synchronously on the client dial path
	// the moment a transport has learned the physical host:port it is about to
	// open an underlay connection to — BEFORE that connection is dialed. It
	// exists for a full-device tunnel (clients/windows) whose leak-protection
	// must exclude the underlay's address from the tunnel's own default route
	// (and, under the kill-switch, allow-list it) before the connection is made,
	// so the pool's own underlay never loops into or is blocked by the tunnel it
	// carries. It matters only for a transport whose address is not known ahead
	// of time: WebRTC's is fixed by ForceRelay (the configured TURN server, and
	// already excluded); reality's exit address arrives only in the per-session
	// coordinator answer, so it is surfaced here instead. The handler must make
	// addr tunnel-safe before it returns; it is called once per distinct
	// underlay connection (dedup is the handler's job). Errors are the handler's
	// to absorb — the dial proceeds regardless, matching the fail-open posture of
	// the pre-existing control-plane exclusions (a missed exclusion fails the
	// path, it never leaks). Only the client role invokes it. Appended last so
	// the struct layout stays a stable seam for parallel callers.
	OnUnderlayDial func(addr string)

	// Mesh-walk recovery config (issue #31/#115), client role. When every
	// coordinator this engine was built with goes unreachable — at first connect
	// OR mid-session — a client with these set walks known peer couriers for a
	// fresh coordinator-signed directory instead of failing cold or spinning on a
	// dead pool. MeshPeers is the courier addresses to ask (relay/exit nodes met in
	// a prior session, running -courier-listen); MeshProof is a cached signed
	// snapshot presented as proof of prior contact; MeshPubKey is the coordinator's
	// snapshot-signing key that verifies replies. All three are required together —
	// any missing and recovery is simply off (a client with no couriers fails cold,
	// exactly as before). Mid-session recovery hands the rediscovered coordinators
	// back to the supervisor (the node binary) to rebuild the engine against
	// (ADR-0037); see [Engine.NeedsRecovery]. Appended after OnUnderlayDial to keep
	// the struct tail a stable seam.
	MeshPeers  []string
	MeshProof  []byte
	MeshPubKey ed25519.PublicKey

	// Relay chaining (issue #142, ADR-0038). Appended after the mesh-recovery
	// fields to keep the struct tail a stable seam for parallel callers.

	// RelayHops is how many relay hops a RELAYED path is routed through, so that
	// no single relay sees both this client and its exit. Client role.
	//
	// 0 and 1 both mean today's single hop and are the default: the coordinator
	// assigns one relay which blind-splices ciphertext (ADR-0033), the onion path
	// is not engaged at all, and this field costs exactly nothing. 2 and above opt
	// into a client-assembled onion (core/relaychain.go): the client telescopes
	// Noise_NK layers through hops IT picks from the signed directory, naming each
	// hop's successor only inside the previous hop's encrypted stream. A value above
	// RelayHopsMax is refused at construction rather than clamped — the same
	// silent-downgrade rule the last paragraph below states, applied to the knob
	// itself, and enforced in exactly one place (setupRelayChaining).
	//
	// It applies only once the selection ladder has reached the relay tier —
	// direct paths are unaffected, since there is no relay to chain. Depth is
	// engine config rather than a per-candidate field: every relay candidate in a
	// run uses the same configured depth (ADR-0038 §5).
	//
	// The cost is real and falls on the volunteer mesh: n hops carry n times the
	// bandwidth for one unit of user traffic, and setup pays n+1 sequential
	// handshakes. That is why the default is the cheapest value. Setting it above 1
	// REQUIRES RelayDirectory (there is nothing to select hops from otherwise), and
	// a chain that cannot be built fails the path rather than quietly falling back
	// to one hop — see core/relaychain.go on why a silent downgrade is the one
	// outcome this feature must never produce.
	RelayHops int

	// RelayIngress is the relay role's onion-forward TCP listener (host:port),
	// the address an upstream hop dials to hand this node an onion layer to peel
	// (coldstart.Entry.Ingress, issue #124). Empty — the default — means this node
	// does not serve as an intermediate hop and opens no such port, which is every
	// node in today's fleet.
	//
	// The port is self-reported to the coordinator on register; the coordinator
	// advertises the ingress as its OWN observed source IP joined to that port, so
	// a relay cannot claim an ingress in an AS it does not occupy (see
	// cmd/coordinator's buildSnapshot and Entry.Ingress). Setting it requires
	// RelayDirectory: a hop with no directory would have no way to tell a mesh node
	// from an arbitrary internet host, and forwarding to the latter is precisely
	// what turns a relay into an open proxy — so that combination is a construction
	// error rather than a listener that rejects everything.
	//
	// A middle hop must be publicly reachable (ADR-0038 §4.6): it is reached by a
	// plain outbound dial from the previous hop, not by hole-punching. A NAT'd
	// residential node can still be a chain's FIRST hop (reached by the client's
	// coordinator-brokered rendezvous) or its exit, just not a middle one.
	RelayIngress string

	// RelayDirectory is a coordinator-signed snapshot (coldstart.Sign's wire form,
	// as cached by cmd/coldstart-bootstrap -cache) that both roles read for
	// chaining, verified under MeshPubKey and required to be unexpired:
	//
	//   - a CLIENT selects its hops from the relay-eligible entries in it
	//     (Entry.RelayEligible — a relay that advertises a forwarding ingress),
	//     spreading them across operators; and
	//   - a RELAY serving RelayIngress admits a forward only to an ingress named in
	//     it, which is what keeps a hop from becoming an open internet proxy
	//     (ADR-0038 principle #4).
	//
	// Empty disables chaining on both sides. Unlike MeshProof — a proof of prior
	// contact that is legitimately stale, and verified without an expiry check —
	// this must be LIVE: it names nodes that are supposed to be reachable right now,
	// and hop selection against a long-dead directory just builds chains that fail.
	// It is loaded and verified once at construction, so a bad or expired snapshot
	// is a startup error, never a silent degradation to no chaining. When
	// RelayDirectoryPath is also set, a background loop keeps it fresh thereafter
	// (issue #27); with no path, a restart is still how this initial copy is
	// replaced, exactly as before that issue.
	RelayDirectory []byte

	// RelayDirectoryKey is the coordinator's snapshot-signing key that
	// RelayDirectory is verified under. Empty falls back to MeshPubKey, which is
	// the same key serving a different purpose — so a node that already configured
	// mesh recovery needs no second copy of it.
	//
	// It exists as its own field rather than simply reusing MeshPubKey because
	// chaining and recovery are independent: a client may want hops without
	// couriers, and setting MeshPubKey alone would look like a half-configured
	// mesh-recovery setup to the issue #121 diagnostic and warn about a
	// misconfiguration that is not one.
	RelayDirectoryKey ed25519.PublicKey

	// RelayDirectoryPath is a filesystem path to the same signed snapshot
	// RelayDirectory carries, re-read on an interval so a long-lived node picks
	// up a rotated directory (new hops, an operator's freshly re-signed
	// snapshot) without a restart (issue #27) — the client-side-CRL-reload
	// shape (AdmissionCRLPath, issue #90) applied to chaining, and mirroring
	// cmd/coordinator's own revocation-file reload loop the same way that one
	// does. RelayDirectory itself must still be set (and is what construction
	// verifies) — this only says where to re-read a fresh copy FROM; it names
	// no new source. A reload that fails to read, fails to verify, or is
	// itself expired is logged and the previously loaded directory is kept
	// enforcing unchanged: it must never degrade to "forward to anything" or
	// "no chaining" just because one reload landed on a stale or half-written
	// file. Empty disables reload — a restart is still how the initial copy is
	// replaced, exactly as before this field existed. Read by both roles that
	// read RelayDirectory itself, since either can outlive its snapshot's
	// validity window with uptime.
	RelayDirectoryPath string

	// Client device credential (issue #50/#51, ADR-0045, ADR-0046), client role.
	// Appended after RelayDirectoryPath to keep the struct tail a stable seam.
	//
	// This is a DIFFERENT credential from AdmissionCred - see core/devicecred's
	// package doc - and the engine does not obtain the first one for a device
	// (enrollment, by claim code, is out of this feature's scope). What it does:
	// generate and keep the on-device key that never leaves it, hold whatever
	// credential + issuer cert something else provisioned into DeviceCredDir,
	// present that chain on every connect (core/devicecred_connect.go), and keep
	// it fresh by renewal when DeviceRenew is set.

	// DeviceCredDir is where the on-device keypair and the device credential +
	// issuer cert (core/devicestore) persist across restarts. Empty means both
	// are IN-MEMORY ONLY: a fresh keypair every restart and no credential to
	// present, ever - a client that never touches this field connects exactly as
	// one predating #50 does. Only the client role reads it.
	DeviceCredDir string

	// DeviceRenew, when set, lets a client refresh its device credential before
	// it expires (account-model.md §5) instead of running unrenewed until the
	// coordinator's gate - if the operator has one configured - starts refusing
	// connects with a legible reason. It is called with the device's own public
	// key and a Sign closure scoped to exactly the renewal purpose and whatever
	// audience/challenge the account service's protocol wants; the raw private
	// key is never handed out. Nil (the default) leaves renewal off: the client
	// runs on whatever core/devicestore already holds until it expires.
	//
	// This is a seam rather than a built-in HTTP client on purpose: the account
	// service's renewal endpoint has no specified request shape anywhere yet (see
	// ADR-0046), and the public repository committing to one would bind a
	// contract the private service does not yet own. Only the client role reads
	// it, and only when DeviceCredDir (or an out-of-band Put into its store) has
	// given this device something to renew in the first place.
	DeviceRenew func(ctx context.Context, req DeviceRenewRequest) (cred, issuerCert string, err error)

	// DeviceRenewMargin is how far before its claimed expiry a stored device
	// credential is treated as due for renewal. Zero uses a 6h default -
	// comfortably inside the 24-72h lifetime account-model.md §5 describes.
	// Meaningless without DeviceRenew also set.
	DeviceRenewMargin time.Duration
}

// RelayHopsMax is the hard ceiling on Config.RelayHops (ADR-0038 §6). The client
// bounds its own knob and cannot be coerced past it, because the client — not the
// coordinator — builds the onion and a coordinator never sees or writes the inner
// layers, so it has nowhere to inject an extra hop. ADR-0038 §6 calls that
// "client-clamped", meaning only that the bound is the client's to enforce: what
// enforcement DOES is refuse at construction, never shorten a chain (see
// Config.RelayHops).
//
// Four is well past the point of diminishing anonymity returns for a low-latency
// system: the property multi-hop buys is "no SINGLE relay sees both endpoints,"
// which is already bought at two, with three and four buying margin against a
// partly-colluding path. What grows without limit past that is the volunteer
// bandwidth multiplier and the n+1 sequential handshakes of setup latency.
const RelayHopsMax = 4

// Engine is a running (or runnable) Bacchus node. All state hangs off the
// value; there are no package-level mutable globals. Construct with [New].
type Engine struct {
	cfg       Config
	roles     map[string]bool
	clientOn  bool
	transport Transport

	// Transport pool + per-user failover (issue #15), client role. transportOrder
	// is empty (pool off) unless Config.TransportPool is set, in which case
	// transports holds one built transport per name and store persists what
	// worked. See core/pool.go and core/selection.
	transports     map[string]Transport
	transportOrder []string
	store          *selection.Store

	poolStagger     time.Duration // happy-eyeballs delay before starting the next candidate
	poolParallel    int           // max candidates dialing at once
	listTimeout     time.Duration // budget for fetching the exit list before a selection
	reselectBackoff time.Duration // delay between failover reselection retries

	candCoolMu  sync.Mutex                        // guards candidate health memory
	candCooling map[selection.Candidate]time.Time // candidate -> last failed attempt

	poolMu        sync.Mutex // guards the active pooled session, its exit key, and socksBound
	activeSess    Session    // session new SOCKS connections use; swapped on failover
	activeExitPub []byte     // the active session's exit static key
	socksBound    bool       // the pooled SOCKS listener is bound (bind once, swap under it)

	// Selection seams (issue #15): production wires these to dialAndValidate and
	// poolCountries in newEngine; tests override them to drive the race and failover
	// deterministically with simulated candidates and no real network.
	dialFn      candidateDialer
	countriesFn func(context.Context) ([]CountryInfo, error)

	// Auto-reconnect (issue #2), client single-transport path. When the live
	// session drops, reconnectLoop re-establishes within the same transport —
	// retrying the just-dropped mode first with bounded exponential backoff, then
	// failing over to the other candidate — and swaps the new session under the
	// SOCKS listener without a rebind. Kept deliberately separate from the pool's
	// activeSess: the pool (issue #15) and this default path are mutually
	// exclusive, and separate state keeps each failover mechanism self-contained
	// (the pool fails over across transports; this re-establishes within one).
	rcMu      sync.Mutex          // guards rcSess/rcCtr/rcSid/rcExitPub/rcBound
	rcSess    Session             // session new SOCKS connections tunnel over; swapped on reconnect
	rcCtr     *accounting.Counter // its accounting counter (direct-mode stub, issue #20; nil otherwise)
	rcSid     string              // the active session's coordinator id, so a coordinator relay-dead nudge (issue #96) can be scoped to the live path and a stale one ignored
	rcExitPub []byte              // static key of the exit terminating rcSess. Swapped WITH the session (issue #146): the coordinator now chooses the exit and may choose a different one in the same country on any reconnect, so this cannot be engine-lifetime state
	rcBound   bool                // the single-transport SOCKS listener is bound (bind once, swap under it)

	reconnectBase        time.Duration // first retry delay; exponential backoff base
	reconnectMax         time.Duration // backoff ceiling — no busy-loop, bounds recovery latency
	reconnectHealthy     time.Duration // a session up at least this long is "stable"; a later drop retries fast
	reconnectMaxAttempts int           // 0 = retry until recovered or Stop; >0 = give up after N failed passes

	// Mesh-walk warm recovery beyond first connect (issue #115), client role. When a
	// failover loop (reconnectLoop or the pool's maintainPath) finds every
	// coordinator silent, tryMeshRecovery walks meshPeers for a fresh signed
	// directory; if one names DIFFERENT coordinators it stashes them, closes
	// recoverCh, and the loop stops so the supervisor rebuilds the engine against
	// them (ADR-0037). meshRecoveryAfter is how many consecutive all-silent
	// single-transport passes precede a walk — enough to rule out a brief blip the
	// ordinary backoff already rides out. All read-only after New except the
	// recover* handoff state, which is written once under recoverMu / recoverOnce.
	meshPeers         []string
	meshProof         []byte
	meshPubKey        ed25519.PublicKey
	meshRecoveryAfter int

	recoverOnce   sync.Once     // guards the one-time close of recoverCh
	recoverCh     chan struct{} // closed when a mid-session walk has a fresh directory to rebuild against
	recoverMu     sync.Mutex    // guards recoverCoords/recoverProof
	recoverCoords []string      // the rediscovered coordinators the supervisor rebuilds against
	recoverProof  []byte        // the fresher snapshot to carry as the next proof

	// establishFn brings up one single-transport path (the initial connect and
	// each reconnect), preferring the given mode. Production wires it to establish
	// in newEngine; tests override it to drive backoff and failover deterministically
	// with fake sessions and no coordinator or transport I/O (mirrors dialFn).
	establishFn func(ctx context.Context, prefer string) (connPath, error)

	// exitKey is the exit role's static keypair (id == public key), and also an
	// onion-forwarding relay's (issue #142): a hop is authenticated by the client
	// running Noise_NK against the key the signed directory publishes as its id, so
	// a relay that serves an ingress needs a real, STABLE X25519 identity rather
	// than the opaque random id an ordinary relay carries. See setupRelayChaining
	// on why an unset ExitKeyHex is refused for that combination.
	exitKey noise.DHKey

	// deviceKey is this client's on-device keypair for the account service's
	// entitlement chain (issue #50/#51, core/devicecred_connect.go) — a
	// DIFFERENT identity from exitKey, which authenticates a forwarder role, not
	// a client. Set once in newEngine for the client role (nil for a pure
	// forwarder) and read-only thereafter. Generated fresh, or loaded from
	// Config.DeviceCredDir, by core/devicestore.LoadOrGenerateKey — see there for
	// why a present-but-corrupt key file is a hard construction error rather
	// than a silent regeneration.
	deviceKey ed25519.PrivateKey

	// deviceStore holds the device credential + issuer cert core/devicestore
	// persists across restarts, and is what deviceRenewLoop refreshes. Non-nil
	// whenever the client role is on, even with Config.DeviceCredDir empty (an
	// in-memory store that simply never has anything to present — see
	// presentDeviceCredential); nil for a pure forwarder, which never connects.
	deviceStore *devicestore.Store

	// connectCountry is the country this client asks to egress in (issue #146) —
	// Config.Geo, or the first assignable country when that is unset (resolveCountry).
	// Written once by Connect before any goroutine that reads it starts, and never
	// mutated after, so the reconnect loop reads it without a lock. Settled once
	// deliberately: see resolveCountry on why a busy country must refuse rather than
	// silently reroute the user somewhere they did not choose.
	//
	// There is no engine-lifetime exit key beside it. The client no longer selects an
	// exit, so the static key it authenticates against belongs to the PATH (connPath /
	// rcExitPub / poolExitPub), not to the engine. A CHAINING client is the same shape:
	// it picks its terminating exit per connect out of the signed snapshot, and that
	// key lives in the chainPlan (core/relaychain.go), not here.
	connectCountry string

	// relayDir is the verified, unexpired signed snapshot relay chaining reads
	// (issue #142, ADR-0038): a client picks its hops out of it, a forwarding node
	// admits a splice only to an address in it. Load() == nil means this engine
	// does not chain and does not forward onion layers. Built once in New (a bad
	// or expired directory is a construction error, not a silent loss of
	// chaining) and, when Config.RelayDirectoryPath is set, swapped for a freshly
	// verified one on an interval by reloadRelayDirLoop (issue #27) — the same
	// atomic.Pointer-swap shape cmd/coordinator's reloadRevocationsLoop uses, and
	// each *relayDirectory a Load() can return is itself immutable, so a reader
	// mid-selectHops never observes a directory changing under it.
	relayDir atomic.Pointer[relayDirectory]

	// exitVerifier verifies the admission credential an exit presents in the
	// Noise_NK handshake (issue #60); nil when the client has no admission anchor
	// (fail-open). Built once in New from Config.AdmissionPubKey.
	exitVerifier *admission.Verifier

	// clientCRL backs exitVerifier's revocation oracle (issue #69) and is the
	// mutable half of client-side exit admission: nil exactly when
	// exitVerifier is (no anchor configured). When Config.AdmissionCRLPath is
	// set, reloadCRLLoop swaps a freshly verified bundle into it on an
	// interval (issue #90); otherwise it holds whatever buildExitVerifier
	// loaded once at construction, or nothing at all if neither CRL source
	// was configured (the anchor-only #60 v1 fail-open shape).
	clientCRL *admission.ClientCRL

	// crlReloadInterval is how often reloadCRLLoop re-reads
	// Config.AdmissionCRLPath (issue #90). A field, not a constant, so a test
	// can shrink it; the production default (admissionCRLReloadInterval) is
	// set in newEngine.
	crlReloadInterval time.Duration

	links []*coordLink // coordinator pool, one live UDP link per member (issue #6)

	healthMu  sync.Mutex           // guards unhealthy (client rotation memory)
	unhealthy map[string]time.Time // coordLink.raw -> last failed client attempt

	// Client version policy (issue #36, ADR-0015). A coordinator advertises the
	// network's current release on its client replies; observeNetworkVersion
	// evaluates it against this build. updateReq latches non-empty once a MAJOR
	// gap means this client is too old to participate (force-major), which
	// ListExits/Connect surface as a hard error; a MINOR/PATCH gap is tolerated
	// (skip-minor). lastNetVersion dedupes the evaluation+event per advert.
	updateMu       sync.Mutex
	updateReq      string
	lastNetVersion string

	// Per-mode client connect timeouts. Fields (not constants) so a test can
	// shorten them; production keeps the defaults set in newEngine.
	directTimeout time.Duration
	relayTimeout  time.Duration

	sigMu sync.Mutex
	sigs  map[string]*coordSignaler // per-session signaling inboxes

	sessMu   sync.Mutex
	sessions map[string]*trackedSession // active transport sessions (client + forwarder)

	// Idle-session reaping (issue #3, M4). A forwarder session whose peer vanished
	// without a transport-level close would otherwise sit in sessions forever — its
	// AcceptStream loop blocked, its FDs and goroutines pinned. reapLoop closes any
	// reap-eligible session with no stream I/O for idleTTL, and trackSession's
	// watcher then frees it from the map. Fields, not constants, so a test can
	// shrink them; production defaults are set in newEngine. Client sessions are
	// never reaped — see trackSession's reap argument.
	idleTTL      time.Duration
	reapInterval time.Duration

	// udpIdleTimeout bounds one UDP relay flow's NAT-style association (issue
	// #41): the exit closes its dialed UDP socket and the client-facing E2E
	// stream after this long with no datagram in either direction. The
	// windows client drives teardown first in the common case (it observes
	// its own gVisor-side flow going idle and closes its end, which cascades
	// here); this is the backstop for when that signal never arrives —
	// same rationale as idleTTL/reapInterval above, just for a UDP
	// association instead of a whole forwarder session. A field, not a
	// constant, so a test can shrink it; the production default is set in
	// newEngine.
	udpIdleTimeout time.Duration

	// Accounting (issue #20, ADR-0021): nil/empty when Config.AcctDir is unset.
	acctKey         ed25519.PrivateKey // exit role: stable accounting-signing key
	acctStore       *accounting.Store  // exit role: co-signed receipts this exit collected
	acctClientStore *accounting.Store  // client role: this client's copy of each receipt
	acctMu          sync.Mutex
	acctCounters    map[string]*accounting.Counter // per-session byte counters
	acctSeq         map[string]uint64              // exit role: next interval seq per session

	// Declared limits (issue #143, ADR-0040), forwarder roles. Both are nil and
	// inert when Config.Limits declares nothing, which is every node today — the
	// nil-receiver idiom means meter() needs no branch for the common case.
	//
	// One limiter for the whole node, deliberately: the operator's cap is aggregate
	// (what leaves their house), so every session shares the bucket. Same for the
	// quota — it is one ISP bill, not one per session.
	limiter *capacity.Limiter
	quota   *capacity.Quota

	// limiterCtx is cancelled by Stop. It exists so a data-path reader parked
	// waiting for rate-limiter tokens unblocks at shutdown rather than holding the
	// node open for the length of its wait — at a low declared cap that wait is
	// seconds, not milliseconds.
	//
	// One context for the engine's lifetime, cancelled directly by Stop rather than
	// by a goroutine watching e.stop: a watcher would block on <-e.stop forever if
	// newEngine failed after starting it, since the half-built engine is discarded
	// and nothing ever closes that channel.
	limiterCtx    context.Context
	limiterCancel context.CancelFunc

	mu        sync.Mutex // guards listeners + started
	listeners []net.Listener
	started   bool

	stopOnce sync.Once
	stop     chan struct{} // closed to signal shutdown
	done     chan struct{} // closed once shutdown completes
	wg       sync.WaitGroup
}

// wire is the coordinator signalling envelope shared by every role. Handshake
// payloads (offer/answer SDP, ICE candidates) all travel opaquely in Cand; the
// transport owns their encoding.
//
// Magic/Version/Capabilities/Reason carry the "hello"/"reject" pair (see
// core/handshake, ADR-0016): a node sends hello first, before register/list/
// connect; the coordinator silently proceeds on a match and replies reject
// with Reason on a mismatch.
type wire struct {
	Type string `json:"type"`
	Role string `json:"role,omitempty"`
	ID   string `json:"id,omitempty"`
	// Country on register is this node's self-reported -country tag, a HINT the
	// coordinator consults only when the address it observed resolves to nothing
	// (issue #136). On connect it is the country the USER chose, and it is the entire
	// input to exit selection (issue #146) — it always names where the client wants to
	// EGRESS, i.e. the terminating exit's country, never an intermediate hop's. On a
	// refusal it names the country the refusal is about (issue #147).
	Country  string `json:"country,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Session  string `json:"session,omitempty"`
	ExitAddr string `json:"exitAddr,omitempty"`
	// ExitID is the coordinator's ANSWER, never the client's request (issue #146,
	// ADR-0042): it names the exit the coordinator chose inside the requested country
	// and rides only on the "session" reply. A client cannot send it — there is no
	// exact-exit pinning for anyone, so a connect names a country and nothing else.
	//
	// It is load-bearing, not informational: an exit's id IS its Noise static public
	// key (ADR-0009), so the client cannot bring up the end-to-end channel without it.
	// A "session" reply that omits it is unusable and is treated as a refusal.
	ExitID string `json:"exitId,omitempty"`
	// FirstHop is the one node a client MAY name on a connect, and it is not an exit
	// request: it is the head of a relay chain the client assembled itself (issue
	// #142, ADR-0038), the field ADR-0042 §9 reserved for exactly this. The
	// coordinator pairs the client with that node instead of choosing an exit, and
	// learns nothing about where the path terminates — the real exit is named only
	// inside the onion, which it cannot read.
	//
	// It is sent ONLY on a relay-mode connect — chainFor builds a plan for no other
	// mode, and a coordinator refuses the combination outright
	// (hop-needs-relay-mode) — because outside relay mode the node named would be
	// the one the traffic egresses from, which is the pinning §2 closed.
	//
	// Within relay mode this engine does not reopen pinning: the hop is drawn fresh
	// from a shuffled candidate set on every connect (core/relaychain.go selectHops)
	// and is not the node the traffic egresses from. That holds because THIS client
	// is built that way, not because the wire enforces it — a modified client can
	// name a node and terminate there, and no coordinator can tell. ADR-0042 §9
	// records that residual.
	//
	// Country is omitted alongside it: it means the terminating exit's country and a
	// chaining client resolves its own exit, so the coordinator has nothing to do with
	// it. Set only by a client at RelayHops >= 2; absent otherwise, which keeps an
	// ordinary connect byte-identical to a pre-#142 one.
	FirstHop string `json:"firstHop,omitempty"`
	// Nonce is this client's per-connect idempotency key (issue #1, ADR-0042 §2):
	// one fresh value per pairing REQUEST, repeated identically on every copy sendN
	// puts on the wire. The coordinator assigns the first copy it sees, remembers the
	// answer against (our source address, this nonce), and replays it for the rest.
	//
	// It is what makes one request one assignment. Without it the coordinator drew a
	// fresh randomized exit per COPY, so a single request produced several exits and
	// whichever reply a client kept was the exit it had chosen — country-only
	// assignment (#146) undone by retransmission. Required on a connect: a coordinator
	// refuses one without it (connect-needs-nonce).
	//
	// Minted per attemptWith call rather than per Connect(), because the mode ladder's
	// direct and relay attempts are different requests and must be answered
	// separately. See newConnectNonce.
	Nonce string `json:"nonce,omitempty"`
	// ExcludeSessions names sessions this client was minted whose exits it just failed
	// against, so a retry is not handed the same broken exit (issue #146; ADR-0035's
	// relay dedupe applied to exits). Sessions rather than exit ids so that excluding
	// cannot be turned into pinning-by-complement — see ADR-0042 §7 and the
	// coordinator's excludedExits.
	ExcludeSessions []string `json:"excludeSessions,omitempty"`
	// Countries is the per-country capacity map a client picks from (issue #146),
	// carried on the "countries" reply that replaced the pre-#146 per-exit list. It is
	// aggregate by construction — counts and busy-ness per country, never per node.
	Countries    []wireCountry          `json:"countries,omitempty"`
	SDP          string                 `json:"sdp,omitempty"`
	Cand         json.RawMessage        `json:"cand,omitempty"`
	Magic        string                 `json:"magic,omitempty"`
	Version      int                    `json:"version,omitempty"`
	Capabilities []handshake.Capability `json:"capabilities,omitempty"`
	Reason       string                 `json:"reason,omitempty"`
	Cred         string                 `json:"cred,omitempty"`        // admission credential (issue #42)
	Release      string                 `json:"release,omitempty"`     // product release version, semver (issue #36, ADR-0015): a node stamps it on register so the coordinator can fence stale nodes; the coordinator stamps it on client replies so a client can force-major/skip-minor. Distinct from Version, the wire-shape int (ADR-0016).
	Relay        string                 `json:"relay,omitempty"`       // relay disposition the coordinator stamps on a relay-mode "session" reply (issue #17, ADR-0033): relayPeer when a Bacchus relay node was assigned to splice client<->exit (the preferred data-plane path), relayTURN when none was available and the client instead reaches the exit directly (its ICE relays through the coordinator's TURN only if it can't hole-punch — the fallback). Empty on direct-mode replies and from coordinators predating #17.
	RelayTag     string                 `json:"relayTag,omitempty"`    // stable opaque tag for the assigned peer relay (issue #56, ADR-0035): the client remembers a tag whose transport dial failed this Connect and skips a later pool member that assigns the SAME relay, instead of re-dialing a known-bad splice. Set only on the peer-relay path; empty for direct/TURN-fallback and from coordinators predating #56. Never a routable address — it reveals nothing the client can't already infer from the relay's ICE candidates (ADR-0009).
	SpeedCap     uint64                 `json:"speedCap,omitempty"`    // a forwarder's DECLARED aggregate speed cap in bits/s (issue #143, ADR-0040): what its operator is willing to carry, not what it can. Self-reported on every register, which is safe because the claim is only ever binding downward — the coordinator applies usable = min(declared, measured) and the measured term is NOT a self-report (see core/capacity). Zero/absent = no declared cap; additive/optional, so a node predating #143 omits it and is treated exactly as it is today. Note there is deliberately NO measured-capacity field on this wire in either direction: a node reporting its own capacity would be reporting the one number it profits from inflating.
	QuotaState   string                 `json:"quotaState,omitempty"`  // quotaOK | quotaExhausted (issue #143, ADR-0040): whether this forwarder's declared monthly traffic quota — its operator's own ISP data cap — is spent for the current billing cycle. One BIT, not the byte counts: the coordinator needs only "may I assign to you", and a per-node monthly usage curve would hand a hostile coordinator (ADR-0020, #60) a linkability signal about a residential operator's household for no matchmaking benefit. Empty = no declared quota; additive/optional.
	Receipt      *accounting.Receipt    `json:"receipt,omitempty"`     // capacity-report payload (issue #158): a co-signed usage receipt (ADR-0021) the CLIENT sends to the coordinator to feed the capacity estimator. Not a node self-report — the node cannot move this number (both parties co-sign the throughput, and SignReport binds the client-asserted Saturated bit), which is exactly why it can ride the wire where a self-reported capacity could not. Absent on every other message.
	ReportSig    []byte                 `json:"reportSig,omitempty"`   // client signature over the capacity-report receipt + its saturation bit (accounting.SignReport, issue #158): proves the un-co-signed Saturated bit came from the client that co-signed the receipt.
	IngressPort  int                    `json:"ingressPort,omitempty"` // a relay's onion-forward TCP listener port (issue #124/#142, ADR-0038): the port an upstream hop dials to hand this node a layer to peel. Self-reported on register — a coordinator cannot observe a TCP listener from a UDP register — but only the PORT is trusted: the coordinator advertises the ingress as its OWN observed source IP joined to this port (buildSnapshot), so a relay cannot assert an ingress IP and therefore cannot claim to sit in an AS it does not occupy. Contrast SpeedCap, where a self-report is safe because it only binds downward; here the self-report is exactly what an attacker would profit from, so only the unforgeable half is taken. Zero/absent => this relay advertises no ingress and is not relay-eligible.

	// Connect-time device-credential verification (issue #50/#51, ADR-0045).
	// These four carry the account service's two-tier entitlement chain
	// (core/devicecred), a DIFFERENT credential from Cred above: Cred is the
	// network's own membership (one tier, bearer, operator-anchored), these are
	// an entitlement bound to one device (two tiers, challenge-bound, anchored to
	// a root the operator does not hold). Both are checked on a connect and
	// neither replaces the other. Byte-for-byte the same four fields as
	// cmd/coordinator's wire (that binary does not import this one, by design —
	// see this type's doc); TestDeviceCredWireContract pins both copies so they
	// cannot drift, the same way TestCountryReplyWireContract pins wireCountry.
	//
	// All four are additive/optional: a client with nothing to present sends none
	// of them, connecting exactly as it did before #50 existed — see
	// core/devicecred_connect.go's presentDeviceCredential.
	Challenge    string `json:"challenge,omitempty"`    // standard base64. Client -> coordinator on "challenge": empty (just Cred + Type). Coordinator -> client on the reply: the fresh nonce to sign. Client -> coordinator again on "connect": that same nonce, echoed back so a mismatch is a clear refusal rather than an opaque assertion failure.
	DeviceCred   string `json:"deviceCred,omitempty"`   // this device's credential in its "bacchusd1:" envelope form (core/devicestore), signed by the account service's issuer key.
	IssuerCert   string `json:"issuerCert,omitempty"`   // the issuer cert in its "bacchusi1:" envelope form, signed by the offline root DeviceCred chains through.
	DeviceAssert string `json:"deviceAssert,omitempty"` // standard base64. This device's signature over purpose || audience || challenge (core/devicecred.SignAssertion), proving it holds the key inside DeviceCred for exactly this coordinator and this challenge.
}

// Declared quota dispositions (issue #143, ADR-0040) carried in wire.QuotaState on
// a register. The literals are duplicated in cmd/coordinator/main.go (that binary
// does not import this one, by design — see its wire's doc);
// TestQuotaStateWireContract pins both copies so they cannot drift, the same way
// TestRelayDispositionWireContract pins relayPeer/relayTURN (issue #97).
const (
	quotaOK        = "ok"        // quota unset, or unspent this cycle: assignable
	quotaExhausted = "exhausted" // this cycle's declared quota is spent: do not assign
)

// Relay-mode dispositions (issue #17, ADR-0033) carried in wire.Relay on a
// "session" reply. They tell the client which data-plane path the coordinator
// wired for a relay-mode connect, so it can prefer the Bacchus peer relay and
// surface an accurate connected-via line. The exit terminates the end-to-end
// Noise channel unchanged in both — the disposition is transport plumbing, not
// a change to who the client authenticates.
const (
	relayPeer = "peer" // a Bacchus relay node blind-splices client<->exit (preferred)
	relayTURN = "turn" // no peer relay available: reach the exit directly, TURN-relayed by ICE only if hole-punching fails (fallback)
)

// wireCountry is one entry of the "countries" reply — the whole of what a client
// learns about the network's shape. It mirrors cmd/coordinator's countryInfo
// byte-for-byte (the two binaries deliberately do not import each other, as for
// wire itself); TestCountryReplyWireContract pins both copies so they cannot drift,
// the same way TestQuotaStateWireContract pins the quota literals.
//
// Note what is absent: no exit ids, no addresses, no per-node anything. That is the
// point of #146 rather than an omission — a count is not a network map, and not the
// raw material for a pin.
type wireCountry struct {
	Country   string `json:"country"`
	Exits     int    `json:"exits"`
	Available int    `json:"available"`
	Busy      bool   `json:"busy"`
	PingMs    int    `json:"pingMs,omitempty"`
}

// New validates cfg, applies defaults, and builds the transport. It performs no
// network I/O — call [Engine.Start] for that.
func New(cfg Config) (*Engine, error) {
	// Normalize the pool: trim, drop blanks, dedup while preserving order.
	// Callers may pass endpoints from a comma-split flag or a JSON array, so a
	// stray empty entry shouldn't count toward "at least one coordinator".
	cfg.Coordinators = dedupNonEmpty(cfg.Coordinators)
	if len(cfg.Coordinators) == 0 {
		return nil, errors.New("core: at least one coordinator address required")
	}
	roles := map[string]bool{}
	for _, r := range cfg.Roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		switch r {
		case RoleClient, RoleRelay, RoleExit:
			roles[r] = true
		default:
			return nil, fmt.Errorf("core: unknown role %q", r)
		}
	}
	if len(roles) == 0 {
		return nil, errors.New("core: at least one role required (client, relay, exit)")
	}
	if roles[RoleExit] && cfg.Advertise == "" {
		return nil, errors.New("core: exit role requires Advertise host:port")
	}

	// An exit's identity is its X25519 static key: the node id is the public
	// key, so a client authenticates the exit it selected and a malicious relay
	// cannot impersonate it. This overrides any supplied ID for the exit role.
	//
	// A relay serving as an onion hop (issue #142) needs the same thing for the
	// same reason: the client runs Noise_NK against the key the SIGNED directory
	// publishes as that hop's id, so a hop a hostile coordinator substituted cannot
	// complete the handshake. A relay that is NOT an onion hop keeps its opaque
	// random id, so no relay in today's fleet changes identity.
	var exitKey noise.DHKey
	if roles[RoleExit] || (roles[RoleRelay] && cfg.RelayIngress != "") {
		k, err := exitStaticKey(cfg.ExitKeyHex)
		if err != nil {
			return nil, err
		}
		exitKey = k
		cfg.ID = hex.EncodeToString(k.Public)
	} else if cfg.ID == "" {
		cfg.ID = randID()
	}

	acctKey, acctStore, acctClientStore, err := setupAccounting(cfg, roles, exitKey)
	if err != nil {
		return nil, err
	}

	// The client-side exit-admission anchor (issue #60) and its revocation
	// bundle (issue #69). Built before the engine so a malformed key or CRL is
	// a construction error, not a surprise mid-connect: a client told to
	// verify against an unusable key/bundle must not fall through to trusting
	// every exit.
	exitVerifier, clientCRL, err := buildExitVerifier(cfg.AdmissionPubKey, cfg.AdmissionCRL, cfg.AdmissionCRLPath, cfg.AdmissionRequireCRL, time.Now())
	if err != nil {
		return nil, err
	}

	// Relay chaining (issue #142, ADR-0038). Built before the engine for the same
	// reason as the admission anchor above: a node told to chain, or to forward
	// onion layers, against a directory it cannot verify must fail here rather than
	// discover it mid-connect and quietly stop providing the property its operator
	// asked for.
	relayDir, err := setupRelayChaining(cfg, roles, time.Now())
	if err != nil {
		return nil, err
	}

	// The client's own device identity and credential store (issue #50/#51,
	// core/devicecred_connect.go). Built before the engine for the same reason as
	// the two calls just above: a corrupt on-device key file must fail
	// construction, never fall through to silently minting a fresh identity that
	// strands whatever credential this device already holds.
	deviceKey, deviceStore, err := setupDeviceCredential(cfg, roles)
	if err != nil {
		return nil, err
	}

	eng, err := newEngine(cfg, roles, exitKey)
	if err != nil {
		return nil, err
	}
	eng.acctKey, eng.acctStore, eng.acctClientStore = acctKey, acctStore, acctClientStore
	eng.exitVerifier = exitVerifier
	eng.clientCRL = clientCRL
	eng.relayDir.Store(relayDir)
	eng.deviceKey, eng.deviceStore = deviceKey, deviceStore
	return eng, nil
}

// exitStaticKey builds the exit's static keypair from the configured hex private
// key, or generates a fresh one when none is set.
func exitStaticKey(hexKey string) (noise.DHKey, error) {
	if strings.TrimSpace(hexKey) == "" {
		return generateExitKey()
	}
	priv, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(priv) != 32 {
		return noise.DHKey{}, errors.New("core: ExitKeyHex must be 64 hex chars (a 32-byte X25519 private key)")
	}
	return exitKeyFromSeed(priv)
}

// newEngine assembles the engine value once config and the exit key are settled.
func newEngine(cfg Config, roles map[string]bool, exitKey noise.DHKey) (*Engine, error) {
	e := &Engine{
		cfg:             cfg,
		roles:           roles,
		clientOn:        roles[RoleClient],
		exitKey:         exitKey,
		unhealthy:       map[string]time.Time{},
		directTimeout:   12 * time.Second,
		relayTimeout:    18 * time.Second,
		sigs:            map[string]*coordSignaler{},
		sessions:        map[string]*trackedSession{},
		acctCounters:    map[string]*accounting.Counter{},
		acctSeq:         map[string]uint64{},
		candCooling:     map[selection.Candidate]time.Time{},
		poolStagger:     800 * time.Millisecond,
		poolParallel:    2,
		listTimeout:     8 * time.Second,
		reselectBackoff: 2 * time.Second,
		// Auto-reconnect (issue #2, ADR-0030). reconnectMaxAttempts stays 0
		// (unbounded): the single-transport path retries until it recovers or the
		// engine stops — resilience over self-limiting, the owner's call.
		reconnectBase:    500 * time.Millisecond,
		reconnectMax:     15 * time.Second,
		reconnectHealthy: 5 * time.Second,
		// Mesh-walk warm recovery (issue #115): try a walk after this many
		// consecutive all-silent single-transport reconnect passes. A field, not a
		// constant, so a test can drop it to 1. recoverCh is closed at most once,
		// when a mid-session walk finds a fresher directory to rebuild against.
		meshPeers:         dedupNonEmpty(cfg.MeshPeers),
		meshProof:         cfg.MeshProof,
		meshPubKey:        cfg.MeshPubKey,
		meshRecoveryAfter: 3,
		recoverCh:         make(chan struct{}),
		// Idle-session reaping (issue #3, M4). A forwarder session with no stream
		// I/O for idleTTL is closed as half-open/idle; reapInterval is how often the
		// reaper scans. 5 min is comfortably clear of the over-aggressive expiry that
		// caused the earlier "12s disconnect" — a live-but-quiet session (an idle SSH
		// session, a paused download) survives, while a vanished peer is still freed
		// within idleTTL + one scan.
		idleTTL:      5 * time.Minute,
		reapInterval: 30 * time.Second,
		// UDP relay association idle timeout (issue #41): 45s matches the
		// windows client's own flow-table timeout (clients/windows/tun2socks.go),
		// so in the common case the client's own teardown reaches here well
		// before this backstop would ever fire.
		udpIdleTimeout: 45 * time.Second,
		// Client CRL hot-reload (issue #90); meaningless unless
		// Config.AdmissionCRLPath is set, in which case Start uses it as
		// reloadCRLLoop's ticker interval.
		crlReloadInterval: admissionCRLReloadInterval,
		stop:              make(chan struct{}),
		done:              make(chan struct{}),
	}
	// Diagnose a half-configured mesh-recovery setup once, here, rather than
	// leaving it silently disabled with no signal (issue #121). cmd/node's
	// loadMeshRecovery already fails fast on this for the flag-driven path; a
	// direct core.Config caller has no equivalent guard. The fail-safe itself is
	// unchanged — meshRecoveryConfigured still requires the full combination —
	// this only makes the gap observable.
	if e.meshRecoveryPartial() {
		e.emit(EventInfo, "", "mesh recovery: MeshPeers/MeshProof/MeshPubKey partially set (peers=%d proof=%dB pubkey=%dB, want %d) — all three required together; recovery disabled",
			len(e.meshPeers), len(e.meshProof), len(e.meshPubKey), ed25519.PublicKeySize)
	}

	// A configured exit pin no longer does anything (issue #146, ADR-0042). Say so at
	// full volume rather than letting it be quietly dropped: a user who set this
	// believes their traffic leaves through one specific exit, and silently egressing
	// them somewhere else while their configuration still says otherwise is the one
	// failure this feature exists to prevent. EventError, not EventInfo — this is a
	// setting that is not doing what it says.
	if e.clientOn && cfg.ExitID != "" {
		e.emit(EventError, "", "Config.ExitID (%s) is set but has NO EFFECT: choosing a specific exit was removed (issue #146) — the coordinator picks the exit inside the country you choose. Set Geo to a country code instead", shortID(cfg.ExitID))
	}

	// Declared limits (issue #143, ADR-0040). Both constructors return the inert
	// nil when nothing is declared, so a node that predates this field builds
	// exactly the engine it built before.
	e.limiterCtx, e.limiterCancel = context.WithCancel(context.Background())
	if err := cfg.Limits.Validate(); err != nil {
		return nil, fmt.Errorf("declared limits: %w", err)
	}
	e.limiter = capacity.NewLimiter(cfg.Limits.SpeedCap)
	q, err := capacity.NewQuota(cfg.Limits, cfg.QuotaStatePath, time.Now())
	if err != nil {
		// A quota that cannot be restored must not start: silently serving with a
		// zeroed counter is how an operator discovers their cap on the bill.
		return nil, fmt.Errorf("declared quota: %w", err)
	}
	e.quota = q
	if cfg.Limits.MonthlyQuota != 0 && cfg.QuotaStatePath == "" {
		e.emit(EventInfo, "", "quota: %s declared with no state path — usage will NOT survive a restart", cfg.Limits.MonthlyQuota)
	}

	tr, err := newTransport(cfg, func(kind, msg string) { e.emit(kind, "", "%s", msg) })
	if err != nil {
		return nil, err
	}
	e.transport = e.attachRealitySplice(tr)
	// Build the client-side transport pool and its learned store (issue #15).
	// A no-op when Config.TransportPool is empty: transportOrder stays empty
	// (pool off) and the store is in-memory.
	if err := e.setupPool(cfg); err != nil {
		return nil, err
	}
	e.dialFn = e.dialAndValidate
	e.countriesFn = e.poolCountries
	e.establishFn = e.establish
	return e, nil
}

// ID returns the node id (the one supplied, or the auto-generated one).
func (e *Engine) ID() string { return e.cfg.ID }

// HasRole reports whether the engine plays the given role.
func (e *Engine) HasRole(role string) bool { return e.roles[role] }

// Start dials the coordinator pool and brings up the forwarder roles
// (exit/relay) in the background. It returns once setup is complete; it does
// not block. Client actions ([Engine.ListExits], [Engine.Connect]) are separate
// calls.
//
// If ctx is cancelled the engine stops itself. Start is not safe to call twice.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return errors.New("core: engine already started")
	}
	e.started = true
	e.mu.Unlock()

	if e.poolOn() {
		e.emit(EventInfo, "", "transport pool: %s (per-user failover, issue #15)", strings.Join(e.transportOrder, ", "))
	} else if wt, ok := e.transport.(*webrtcTransport); ok {
		e.emit(EventInfo, "", "transport webrtc, dtls fingerprint: %s", wt.fingerprint)
	} else {
		e.emit(EventInfo, "", "transport %s", e.transport.Name())
	}

	links, err := dialPool(e.cfg.Coordinators, func(addr string, err error) {
		e.emit(EventError, "", "skipping coordinator %q: %v", addr, err)
	})
	if err != nil {
		return err
	}
	e.links = links
	if len(links) > 1 {
		e.emit(EventInfo, "", "coordinator pool: %d members", len(links))
	}

	// A forwarder must be reachable through every pool member, so it greets and
	// registers with all of them up front (see registerLoop). A client instead
	// greets lazily — only the member it rotates to in ListExits/Connect —
	// because touching the whole pool at startup would hand a censor the
	// client's entire fallback set at once. The hello is the versioned
	// handshake (issue #8, ADR-0016): one-shot per member, answered by the
	// coordinator only on a version mismatch, so a silent coordinator is
	// indistinguishable from an agreeing one by design.
	if e.hasForwarderRole() {
		e.broadcast(helloWire())
	}

	// Bind the exit TCP server before returning so bind failures surface here
	// rather than in a background goroutine.
	if e.roles[RoleExit] {
		ln, err := net.Listen("tcp", e.cfg.ListenAddr)
		if err != nil {
			e.closeLinks()
			return fmt.Errorf("core: exit listen: %w", err)
		}
		e.addListener(ln)
		e.wg.Add(1)
		go e.serveExit(ln)
		e.emit(EventInfo, "", "exit %s (%s) advertising %s + direct WebRTC", e.cfg.ID, e.cfg.Country, e.cfg.Advertise)
	}
	if e.roles[RoleRelay] {
		e.emit(EventInfo, "", "relay %s online", e.cfg.ID)
	}

	// A relay that opted into carrying onion layers (issue #142, ADR-0038) binds
	// its forwarding ingress — the address an upstream hop dials to hand it a layer
	// to peel. It runs the SAME accept loop as the exit's ingress, because a hop and
	// an exit differ only in the target the client encrypts to them: exitTerminate
	// splices a "hop:" target onward and egresses a bare one, and refuses to egress
	// at all without the exit role. Bound here so a bind failure surfaces at Start,
	// as the exit's does, rather than in a background goroutine.
	ingressPort := 0
	if e.forwardOn() {
		ln, err := net.Listen("tcp", e.cfg.RelayIngress)
		if err != nil {
			e.closeLinks()
			return fmt.Errorf("core: relay ingress listen: %w", err)
		}
		e.addListener(ln)
		ingressPort = addrPort(ln.Addr())
		e.wg.Add(1)
		go e.serveExit(ln)
		e.emit(EventInfo, "", "relay onion ingress on %s (forwarding to %d known mesh addresses)",
			ln.Addr(), len(e.relayDir.Load().dialable))
	}
	// The client's chain depth, reported once so an operator can see what actually
	// took effect. There is no clamp notice to print: a depth above RelayHopsMax is
	// refused outright by setupRelayChaining rather than quietly reduced, so what an
	// operator configured is what runs or the node did not start.
	if e.clientOn && e.chaining() {
		depth := chainDepth(e.cfg.RelayHops)
		e.emit(EventInfo, "", "relay chaining: %d hops on relayed paths — %d peeling hop(s) chosen per connect from %d directory candidates; DIRECT paths are not offered while chaining",
			depth, depth-1, len(e.relayDir.Load().hops))
	}

	// A forwarder stamps its product release on every register (issue #36,
	// ADR-0015) so a coordinator enforcing a minimum serving version can fence it
	// when it falls behind. Computed once here — the loop re-sends the same regs.
	release := version.Current().String()
	// The declared speed cap (issue #143) is static for the process's life, so it
	// rides the template. The quota's spent/unspent bit is NOT — registerLoop stamps
	// it fresh on every send, because the coordinator's register handler REPLACES
	// its registry entry wholesale, so any field absent from a given register is
	// zeroed for the next 10s.
	speedCap := uint64(e.cfg.Limits.SpeedCap)
	var regs []wire
	if e.roles[RoleExit] {
		regs = append(regs, wire{Type: "register", Role: "exit", ID: e.cfg.ID, Country: e.cfg.Country, Addr: e.cfg.Advertise, Cred: e.cfg.AdmissionCred, Release: release, SpeedCap: speedCap})
	}
	if e.roles[RoleRelay] {
		// IngressPort is this relay's onion-forward listener port (issue #142). The
		// coordinator joins it to the source ip it OBSERVES on this register to form
		// the ingress it advertises, so only the port is ours to state. Zero when this
		// relay serves no ingress, which leaves it simply not relay-eligible as a hop.
		regs = append(regs, wire{Type: "register", Role: "relay", ID: e.cfg.ID, Country: e.cfg.Country, Cred: e.cfg.AdmissionCred, Release: release, SpeedCap: speedCap, IngressPort: ingressPort})
	}

	// One read loop per pool member: a forwarder can be assigned a session by
	// any coordinator it registered with, and a client's rotation reply arrives
	// on whichever member it sent to.
	for _, l := range e.links {
		e.wg.Add(1)
		go e.readLoop(l)
	}
	if len(regs) > 0 {
		e.wg.Add(1)
		go e.registerLoop(regs)
	}

	// Idle-session reaper (issue #3): only a forwarder reaps. A client's single
	// session is owned by its reconnect loop and must not be reaped out from under
	// it, so the loop starts solely for the exit/relay roles.
	if e.hasForwarderRole() {
		e.wg.Add(1)
		go e.reapLoop()
	}

	// Client CRL hot-reload (issue #90): only when a reload path is
	// configured, and only for the client role, since exitVerifier/clientCRL
	// are read solely by the client's exit-connect path.
	if e.clientOn && e.clientCRL != nil && e.cfg.AdmissionCRLPath != "" {
		e.wg.Add(1)
		go e.reloadCRLLoop()
	}

	// Relay-directory hot-reload (issue #27), the same shape as the CRL block
	// just above: only when this engine holds a directory to refresh AND a
	// path to refresh it from — a node given RelayDirectory inline with no
	// RelayDirectoryPath (or that failed to configure chaining/forwarding at
	// all, in which case relayDir.Load() is nil) keeps today's construction-
	// once-and-restart-to-refresh behavior exactly, for either role that
	// reads it (a chaining client or a forwarding relay).
	if e.relayDir.Load() != nil && e.cfg.RelayDirectoryPath != "" {
		e.wg.Add(1)
		go e.reloadRelayDirLoop()
	}

	// Device credential renewal (issue #50/#51, core/devicecred_connect.go), the
	// same shape as the CRL block above: only for the client role, and only when
	// an embedder actually supplied a renewal transport. deviceStore is non-nil
	// whenever clientOn is (see newEngine) even with DeviceCredDir empty, so the
	// real gate here is DeviceRenew — no seam, nothing to call, nothing to loop.
	if e.clientOn && e.deviceStore != nil && e.cfg.DeviceRenew != nil {
		e.wg.Add(1)
		go e.deviceRenewLoop()
	}

	// Watch ctx for cancellation. Not tracked by wg (it calls Stop, which waits
	// on wg, and must not wait on itself).
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				e.Stop()
			case <-e.stop:
			}
		}()
	}
	return nil
}

// Stop tears the engine down: it closes every coordinator link, every
// listener, and every active session, then waits for the background goroutines
// to exit. It is idempotent and safe to call concurrently.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		close(e.stop)
		// Unblock any data-path reader parked on the rate limiter (issue #143), so a
		// session torn down mid-wait does not hold shutdown for the length of that
		// wait. The quota's final checkpoint is deliberately NOT here — it comes after
		// wg.Wait() below, once the data path has actually stopped moving bytes.
		e.limiterCancel()
		e.closeLinks()
		e.mu.Lock()
		lns := e.listeners
		e.mu.Unlock()
		for _, ln := range lns {
			_ = ln.Close()
		}
		// Release transport-owned resources (the reality transport's shared :443
		// listener and its accept loop). The WebRTC transport holds none, so it
		// does not implement close.
		if c, ok := e.transport.(interface{ close() error }); ok {
			_ = c.close()
		}
		e.sessMu.Lock()
		sessions := make([]Session, 0, len(e.sessions))
		for _, ts := range e.sessions {
			sessions = append(sessions, ts.sess)
		}
		e.sessMu.Unlock()
		for _, s := range sessions {
			_ = s.Close()
		}
		e.wg.Wait()
		// Every read loop has exited (they are tracked by wg and their links
		// are now closed), so nothing more will be delivered: closing each
		// member's inbox unblocks any client action still selecting on it,
		// with no risk of a send on a closed channel.
		for _, l := range e.links {
			close(l.msgCh)
		}
		// Persist the declared-quota counter (issue #143). Placed HERE, after wg.Wait()
		// and the session closes above, because only now has the data path stopped
		// moving bytes — flushing before teardown would checkpoint a count that every
		// still-draining session then invalidates, leaving a clean stop losing the same
		// bound as a crash. The periodic checkpoints bound what a CRASH loses; this is
		// what makes a clean stop lose nothing.
		if err := e.quota.Flush(time.Now()); err != nil {
			e.emit(EventError, "", "quota: final checkpoint failed: %v — usage this cycle may not survive a restart", err)
		}
		if e.acctStore != nil {
			_ = e.acctStore.Close()
		}
		if e.acctClientStore != nil {
			_ = e.acctClientStore.Close()
		}
		close(e.done)
	})
}

// Wait blocks until the engine has fully stopped (via [Engine.Stop] or ctx
// cancellation).
func (e *Engine) Wait() { <-e.done }

// Done returns a channel closed when the engine has fully stopped.
func (e *Engine) Done() <-chan struct{} { return e.done }

func (e *Engine) addListener(ln net.Listener) {
	e.mu.Lock()
	e.listeners = append(e.listeners, ln)
	e.mu.Unlock()
}

// broadcast sends m to every pool member. Used for the forwarder's hello and
// registrations, which must reach all coordinators.
func (e *Engine) broadcast(m wire) {
	for _, l := range e.links {
		l.send(m)
	}
}

// closeLinks closes every coordinator UDP link, unblocking each read loop.
func (e *Engine) closeLinks() {
	for _, l := range e.links {
		if l.conn != nil {
			_ = l.conn.Close()
		}
	}
}

// hasForwarderRole reports whether this node forwards traffic (exit or relay),
// as opposed to a client-only node.
func (e *Engine) hasForwarderRole() bool { return e.roles[RoleExit] || e.roles[RoleRelay] }

// helloWire builds this build's version/capability handshake envelope
// (core/handshake, ADR-0016).
func helloWire() wire {
	h := handshake.Local()
	return wire{Type: "hello", Magic: h.Magic, Version: h.Version, Capabilities: h.Capabilities}
}

// greet sends the version/capability hello to a single coordinator. The client
// calls it on the member it is about to use, so it greets only what it actually
// rotates to. One-shot and idempotent — the coordinator answers only on a
// version mismatch — so a repeat on a later rotation is harmless.
func (e *Engine) greet(l *coordLink) { l.send(helloWire()) }

// observeNetworkVersion evaluates the network's current release, as advertised
// by a coordinator on a client reply, against this build (issue #36, ADR-0015).
// A MAJOR gap latches updateReq so ListExits/Connect refuse to proceed
// (force-major); a client merely behind on MINOR/PATCH keeps working and is only
// nudged with an informational note (skip-minor). It dedupes on the exact advert
// string, so a repeated or steady-state version emits its event just once, and
// it never fails the client on an absent or garbled advert — the check only ever
// adds safety, it never invents a reason to stop.
func (e *Engine) observeNetworkVersion(release string) {
	if release == "" {
		return
	}
	e.updateMu.Lock()
	if release == e.lastNetVersion {
		e.updateMu.Unlock()
		return
	}
	e.lastNetVersion = release
	nv, err := version.Parse(release)
	if err != nil {
		e.updateMu.Unlock()
		return
	}
	self := version.Current()
	mustUpdate := version.ClientMustUpdate(self, nv)
	if mustUpdate {
		e.updateReq = fmt.Sprintf("this client is %s but the network requires %s", self, nv)
	}
	e.updateMu.Unlock()

	switch {
	case mustUpdate:
		e.emit(EventError, "", "update required: this client is %s but the network requires %s — a major update is needed to continue", self, nv)
	case self.Compare(nv) < 0:
		e.emit(EventInfo, "", "update available: network is %s, this client is %s (still compatible)", nv, self)
	}
}

// updateRequired reports the force-major error latched by observeNetworkVersion,
// or nil. ListExits/Connect call it after exchanging with a coordinator so a
// client too old for the network stops with a clear, actionable message instead
// of quietly running on a wire protocol the fleet no longer speaks.
func (e *Engine) updateRequired() error {
	e.updateMu.Lock()
	defer e.updateMu.Unlock()
	if e.updateReq != "" {
		return fmt.Errorf("core: %s — a major update is required", e.updateReq)
	}
	return nil
}

func (e *Engine) emit(kind, session, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if e.cfg.OnEvent != nil {
		e.cfg.OnEvent(Event{Kind: kind, Session: session, Message: msg})
		return
	}
	log.Println(msg)
}

// coordSignaler is the engine-side [Signaler]: it sends a transport's frames to
// the coordinator link that owns the session, tagged with the session id, and
// receives the frames the read loops route to it. One exists per active session.
type coordSignaler struct {
	eng  *Engine
	link *coordLink // the pool member that owns this session's rendezvous
	sid  string
	in   chan SignalFrame
}

func (s *coordSignaler) Send(ctx context.Context, f SignalFrame) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eng.stop:
		return errEngineStopped
	default:
	}
	s.link.send(wire{Type: f.Kind, Session: s.sid, Cand: f.Data})
	return nil
}

func (s *coordSignaler) Recv(ctx context.Context) (SignalFrame, error) {
	select {
	case f, ok := <-s.in:
		if !ok {
			return SignalFrame{}, errSessionClosed
		}
		return f, nil
	case <-ctx.Done():
		return SignalFrame{}, ctx.Err()
	case <-s.eng.stop:
		return SignalFrame{}, errEngineStopped
	}
}

// newSignaler registers and returns a signaler for sid, bound to the
// coordinator link that owns the session — a forwarder's assigning member, or
// the client's rotation choice. All of the session's signaling flows over that
// one link.
func (e *Engine) newSignaler(sid string, link *coordLink) *coordSignaler {
	s := &coordSignaler{eng: e, link: link, sid: sid, in: make(chan SignalFrame, 64)}
	e.sigMu.Lock()
	e.sigs[sid] = s
	e.sigMu.Unlock()
	return s
}

// dropSignaler unregisters sid and closes its inbox, so the transport's
// signaling loop unblocks. Idempotent.
func (e *Engine) dropSignaler(sid string) {
	e.sigMu.Lock()
	defer e.sigMu.Unlock()
	if s, ok := e.sigs[sid]; ok {
		delete(e.sigs, sid)
		close(s.in)
	}
}

// routeSignal hands one inbound signaling frame to the session's signaler.
// Delivery is best-effort: a full inbox drops the frame (trickle-ICE tolerates
// loss). The lock is held across the send so it cannot race dropSignaler's
// close of the same channel.
func (e *Engine) routeSignal(m wire) {
	e.sigMu.Lock()
	defer e.sigMu.Unlock()
	s := e.sigs[m.Session]
	if s == nil {
		return
	}
	select {
	case s.in <- SignalFrame{Kind: m.Type, Data: m.Cand}:
	default:
	}
}

// trackedSession is a live transport session plus the bookkeeping the idle
// reaper needs. reap marks forwarder-side (exit/relay) sessions the reaper may
// close once they fall idle; a client's own session sets it false so the reaper
// never tears the client's tunnel down under it. lastNano is the unix-nano time
// of the last observed activity — session accept or stream I/O — written from the
// stream wrappers and read by the reaper, hence atomic.
type trackedSession struct {
	sess     Session
	reap     bool
	lastNano atomic.Int64
}

// touch marks the session active as of now. Called on stream accept and on every
// stream read/write (see activityStream), so a session moving bytes is never
// mistaken for idle even when it opens no new streams.
func (t *trackedSession) touch() { t.lastNano.Store(time.Now().UnixNano()) }

// activityStream wraps a forwarder stream so byte movement in either direction
// refreshes the owning session's last-activity time. Reaping on new-stream events
// alone would close a session carrying one long-lived, busy stream (a large
// download) that opens nothing new, so the reaper's notion of "idle" is "no
// bytes", tracked here.
type activityStream struct {
	Stream
	ts *trackedSession
}

func (a activityStream) Read(p []byte) (int, error) {
	n, err := a.Stream.Read(p)
	if n > 0 {
		a.ts.touch()
	}
	return n, err
}

func (a activityStream) Write(p []byte) (int, error) {
	n, err := a.Stream.Write(p)
	if n > 0 {
		a.ts.touch()
	}
	return n, err
}

// reapStream wraps st so its I/O keeps ts alive under the idle reaper.
func (e *Engine) reapStream(ts *trackedSession, st Stream) Stream {
	return activityStream{Stream: st, ts: ts}
}

// trackSession records s under sid for shutdown cleanup and idle reaping, and
// spawns the watcher that drops the session's signaler and frees it from the map
// once it closes (or the engine stops). reap marks the session eligible for the
// idle reaper (a forwarder passes true; a client passes false). It returns the
// trackedSession so the forwarder can attribute stream activity to it.
func (e *Engine) trackSession(sid string, s Session, reap bool) *trackedSession {
	ts := &trackedSession{sess: s, reap: reap}
	ts.touch()
	e.sessMu.Lock()
	e.sessions[sid] = ts
	e.sessMu.Unlock()
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		select {
		case <-s.Closed():
		case <-e.stop:
			// Stop's own loop collects e.sessions under sessMu and closes each one,
			// but this watcher reacts to the very same close(e.stop) and can win the
			// race to delete sid from e.sessions first — leaving it out of Stop's
			// snapshot, so Stop's loop never calls Close on it at all and the
			// transport session (and its goroutines) leaks past Stop returning. Close
			// here too so the session is torn down regardless of which side wins;
			// Close is idempotent, so a session Stop's loop already closed is a no-op.
			_ = s.Close()
		}
		e.dropSignaler(sid)
		e.dropAcctState(sid)
		e.sessMu.Lock()
		delete(e.sessions, sid)
		e.sessMu.Unlock()
	}()
	return ts
}

// reapLoop periodically closes forwarder sessions gone idle past idleTTL — the
// backstop for a peer that vanished without a transport-level close (issue #3).
// It runs only for a forwarder role (see Start) and exits on Stop. Closing a
// session cascades through its trackSession watcher, which frees it from the map.
func (e *Engine) reapLoop() {
	defer e.wg.Done()
	t := time.NewTicker(e.reapInterval)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case now := <-t.C:
			if n := e.reapIdle(now); n > 0 {
				e.emit(EventInfo, "", "reaped %d idle session(s); %d active", n, e.SessionCount())
			}
		}
	}
}

// reapIdle closes every reap-eligible session with no activity since now-idleTTL
// and returns how many it closed. Dead sessions are collected under the lock and
// closed outside it: Session.Close wakes the trackSession watcher, which takes
// sessMu to delete the entry, so closing under the lock could deadlock.
func (e *Engine) reapIdle(now time.Time) int {
	cutoff := now.Add(-e.idleTTL).UnixNano()
	var dead []Session
	e.sessMu.Lock()
	for _, ts := range e.sessions {
		if ts.reap && ts.lastNano.Load() < cutoff {
			dead = append(dead, ts.sess)
		}
	}
	e.sessMu.Unlock()
	for _, s := range dead {
		_ = s.Close()
	}
	return len(dead)
}

// SessionCount reports the number of live transport sessions (client + forwarder).
// It is cardinality only — no session ids, peers, or destinations — so it is safe
// to surface as an operational metric.
func (e *Engine) SessionCount() int {
	e.sessMu.Lock()
	defer e.sessMu.Unlock()
	return len(e.sessions)
}

// registerLoop re-announces this forwarder's role(s) to every pool member on a
// fixed interval so each coordinator's directory (which expires stale entries)
// keeps listing it. Registering with all members is what lets a client reach
// this node through whichever coordinator it rotates to (ADR-0020) — there is
// no coordinator-to-coordinator replication.
func (e *Engine) registerLoop(regs []wire) {
	defer e.wg.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		// Stamp the volatile fields per send. QuotaState (issue #143) is the only one
		// today, and it MUST be re-stamped rather than baked into regs: a node that
		// exhausts its quota mid-cycle has to stop being assigned work within one
		// heartbeat, and the coordinator replaces its whole registry entry on each
		// register, so a state carried only in the first one would be forgotten.
		qs := e.quotaState(time.Now())
		for _, r := range regs {
			r.QuotaState = qs // r is a copy: mutating it does not touch the template
			e.broadcast(r)
		}
		select {
		case <-e.stop:
			return
		case <-t.C:
		}
	}
}

// quotaState renders this node's declared-quota disposition for the register wire
// (issue #143, ADR-0040). Empty when no quota is declared, which omits the field
// and leaves a coordinator seeing exactly the register a node sent before #143.
//
// One bit, deliberately — see wire.QuotaState for why the byte counts stay home.
func (e *Engine) quotaState(now time.Time) string {
	if e.quota == nil {
		return ""
	}
	if e.quota.Exhausted(now) {
		return quotaExhausted
	}
	return quotaOK
}

// deliver hands a client rendezvous message from member l to that member's
// inbox, unblocking on shutdown so a read loop can never wedge. Per-link
// delivery is what keeps one member's replies out of another member's client
// attempt while the client rotates.
func (e *Engine) deliver(l *coordLink, m wire) {
	select {
	case l.msgCh <- m:
	case <-e.stop:
	}
}

// readLoop is the dispatcher for one pool member l: it reads that coordinator's
// datagrams and routes them to the per-session signalers (offer/answer/
// candidate), the forwarder assignment path (assign — the session's signaling
// then flows back over this same link l), the client rendezvous path
// (session/countries/error/challenge), and the handshake reject path. One
// readLoop runs per link; the shared msgCh is closed by Stop once every readLoop
// has exited, so no single blocked member ends the client's rendezvous.
func (e *Engine) readLoop(l *coordLink) {
	defer e.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, err := l.conn.Read(buf)
		if err != nil {
			return // this member's link was closed (Stop) or errored
		}
		var m wire
		if json.Unmarshal(buf[:n], &m) != nil {
			continue
		}
		switch m.Type {
		case "assign": // forwarder: we are exit/relay for this session
			e.startFwdSession(m, l)
		case sigOffer, sigAnswer, sigCandidate:
			e.routeSignal(m)
		// "challenge" answers a device-credential challenge request
		// (core/devicecred_connect.go, issue #50/#51) and is delivered through the
		// exact same client-rendezvous path as session/countries/error: it is a
		// per-request reply on the same link, awaited the same way (awaitChallenge
		// mirrors awaitSession), and a build with no client role has no business
		// receiving one either.
		case "session", "countries", "error", "challenge":
			if !e.clientOn {
				// A client rendezvous reply arriving at an engine with no client role
				// is a real misconfiguration (or a confused coordinator), and dropping
				// it silently is how it stays invisible.
				l.noteUnroutable(e, m.Type, "this engine has no client role")
				continue
			}
			// A client reply carries the coordinator's advertised network
			// release; check it before delivering so a force-major mismatch is
			// latched by the time ListCountries/Connect inspect it (issue #36).
			e.observeNetworkVersion(m.Release)
			e.deliver(l, m)
		case "reject": // coordinator rejected our hello (ADR-0016) or fenced a stale node (issue #36, ADR-0015)
			e.emit(EventError, "", "coordinator rejected us: %s", m.Reason)
		case "reselect": // coordinator says our assigned peer relay died (issue #96) — re-establish now
			if e.clientOn {
				e.onRelayReselect(m)
			}
		default:
			// An unrecognized type is dropped — there is nothing else to do with it —
			// but never silently. A coordinator that starts speaking a shape this build
			// does not know is exactly the condition that took a whole protocol change
			// to review to notice (issue #146): the reply was well-formed, routed
			// nowhere, and the client reported a timeout as if the coordinator were
			// unreachable. One line here turns that into a diagnosis.
			l.noteUnroutable(e, m.Type, "unrecognized message type")
		}
	}
}

func randID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
