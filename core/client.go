package core

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// CountryInfo is one country the coordinator will assign exits in, and the whole of
// what a client learns about the network's shape (issue #146, ADR-0042).
//
// It replaced a per-exit list, and the replacement is strictly less: the old reply
// enumerated every exit's id, which is both a network map and the raw material for
// pinning. A count is neither. What a client needs in order to CHOOSE is preserved —
// which countries exist, whether each can take a session, roughly how far away it is —
// and nothing beyond that survives.
type CountryInfo struct {
	Country string // ISO-3166-1 alpha-2, canonicalized by the coordinator

	// Exits is how many exits the coordinator knows in this country; Available how
	// many of those it would assign right now. Both matter: Exits alone cannot express
	// "the country exists but is full", which is the state #147 has to say out loud.
	Exits     int
	Available int

	// Busy is Available == 0 — the country is known but nothing in it is assignable.
	// Carried rather than derived so two clients cannot derive it differently.
	Busy bool

	// PingMs is the aggregate round-trip clients have observed to this country; 0
	// means unknown and the UI shows no latency. It is always 0 today — an unfed seam
	// on the coordinator side (see cmd/coordinator's countryInfo.PingMs).
	PingMs int
}

// Assignable reports whether this country can take a session right now. It is the
// predicate a picker should filter on, named once here so the client, the pool ladder
// and any UI cannot each invent their own reading of Busy/Available.
func (c CountryInfo) Assignable() bool { return !c.Busy && c.Available > 0 }

// ListCountries asks the coordinator pool for the countries it will assign exits in,
// rotating across members in health-ranked order so a blocked member is skipped and
// the next is tried. It requires the client role and a started engine; an empty slice
// means a member answered but knows no country with an exit in it.
//
// This replaced ListExits (issue #146): a client picks a COUNTRY and the coordinator
// picks the exit inside it, so enumerating exits is neither offered nor needed. A
// client that must name a concrete exit — the client-assembled onion of #142/ADR-0038
// is the only such case — reads the SIGNED directory instead (core/coldstart), which
// carries exits with their countries and, unlike this reply, is authenticated. See
// ADR-0042 §9.
func (e *Engine) ListCountries(ctx context.Context, timeout time.Duration) ([]CountryInfo, error) {
	if !e.clientOn {
		return nil, errors.New("core: ListCountries requires the client role")
	}
	links := e.orderLinks()
	per := perLinkBudget(timeout, len(links))
	for _, l := range links {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.stop:
			return nil, errors.New("core: engine stopped")
		default:
		}
		e.drainMsgCh(l)
		e.greet(l)
		l.sendN(wire{Type: "list", Cred: e.cfg.AdmissionCred}, 3)
		if countries, ok := e.awaitCountries(ctx, l, per); ok {
			// The reply advertised the network's release; if this client is too
			// old (force-major) surface that rather than a stale country list (#36).
			if err := e.updateRequired(); err != nil {
				return nil, err
			}
			return countries, nil
		}
		e.markUnhealthy(l.raw) // silent within its slice — deprioritize and rotate
	}
	// Every member was silent — none answered. Wrap the recovery sentinel so the
	// pooled path (poolCountries/selectPath) can tell this apart from "answered but no
	// countries" and trigger mesh-walk, exactly as establish does on the direct path
	// (issue #115). errors.Is unwraps to ErrNoCoordinatorReachable; the message stays
	// descriptive for a human reading a -list failure.
	return nil, fmt.Errorf("core: no coordinator answered the country list: %w", ErrNoCoordinatorReachable)
}

// awaitCountries waits for a "countries" reply on member l's inbox within timeout,
// skipping any other buffered message. ok is false on timeout, cancellation, or
// shutdown — the caller treats that as "this member is silent" and rotates.
func (e *Engine) awaitCountries(ctx context.Context, l *coordLink, timeout time.Duration) ([]CountryInfo, bool) {
	deadline := time.After(timeout)
	for {
		select {
		case <-ctx.Done():
			return nil, false
		case <-e.stop:
			return nil, false
		case <-deadline:
			return nil, false
		case m, ok := <-l.msgCh:
			if !ok {
				return nil, false
			}
			if m.Type != "countries" {
				continue
			}
			out := make([]CountryInfo, 0, len(m.Countries))
			for _, c := range m.Countries {
				out = append(out, CountryInfo{
					Country:   c.Country,
					Exits:     c.Exits,
					Available: c.Available,
					Busy:      c.Busy,
					PingMs:    c.PingMs,
				})
			}
			return out, true
		}
	}
}

// pickCountry chooses which country to connect in.
//
// A connect names exactly one country (the coordinator refuses a connect that names
// none), so a client whose user expressed no preference still has to choose. Rather
// than push that into every caller — where three UIs would invent three different
// defaults — the choice is made once, here: prefer the configured country, and
// otherwise take the first assignable one in the coordinator's order, which is
// alphabetical and therefore stable across refreshes.
//
// A configured country is used VERBATIM even when the list says it is busy or absent.
// Substituting a different country for the one the user asked for would silently
// egress them somewhere they did not choose, which for this project is the worst
// available failure; letting the connect be refused with "country-busy" tells them the
// truth and leaves the choice theirs.
func pickCountry(configured string, countries []CountryInfo) (string, error) {
	if configured != "" {
		return configured, nil
	}
	for _, c := range countries {
		if c.Assignable() {
			return c.Country, nil
		}
	}
	if len(countries) == 0 {
		return "", errors.New("core: the coordinator knows no country with an exit in it")
	}
	return "", fmt.Errorf("core: every country the coordinator offers is busy (%d known) — try again shortly or choose one explicitly", len(countries))
}

// connectOutcome is why a single coordinator's connect attempt ended. Ordered
// by how much it tells us about the member being reachable (silent < refused <
// transportFailed), so mergeOutcome can keep the most informative across a
// member's direct and relay attempts.
type connectOutcome int

const (
	connectOK          connectOutcome = iota // a path was established
	coordinatorSilent                        // no reply — the member looks blocked
	coordinatorRefused                       // member replied "error" — up, but wouldn't pair us
	transportFailed                          // member paired us, but the transport never came up
)

// modeDirect and modeRelay are the two single-transport candidate modes the
// client pairs in: a P2P hole-punch to the chosen exit, or a path relayed through
// nodes. They are the wire Mode values and the identity the reconnect driver
// keeps so a drop retries the just-dropped mode before failing over (issue #2).
const (
	modeDirect = "direct"
	modeRelay  = "relay"
)

// connPath is one established single-transport path: the live session, the
// accounting counter feeding it (direct-mode stub only, issue #20; nil for
// relay), and which mode won. The reconnect driver keeps the mode so a drop
// retries the same candidate first, and swaps the session (with its counter and its
// exit key) under the SOCKS listener on recovery.
type connPath struct {
	sess Session
	ctr  *accounting.Counter
	mode string
	sid  string // coordinator session id; tracked so a relay-dead nudge (issue #96) can be scoped to the live path

	// exitID / exitPub name the exit the COORDINATOR assigned this path, read off the
	// session reply (issue #146). They are per-path, not per-engine, and that is the
	// substantive change country-only assignment forces on this file: the client used
	// to configure one exit and hold its key for the engine's lifetime, so a reconnect
	// could reuse it. Now the coordinator chooses, and it may legitimately choose a
	// DIFFERENT exit inside the same country on every reconnect — so the key travels
	// with the path and is swapped into the SOCKS accept path alongside the session.
	// Carrying it per-engine would run clientHandshake against the previous exit's
	// static key after any reselection, which fails as an authentication error and
	// looks like a hostile exit rather than a stale key.
	exitID  string
	exitPub []byte
}

// relayDedup is one single-transport establish pass's memory of peer relays that
// already failed a transport dial (issue #56), keyed by the coordinator's opaque
// relay tag. attemptWith records a tag on dial failure and skips a later pool
// member that re-offers the same tag, so a bad relay assigned by two different
// coordinators costs one failed dial, not two. A nil *relayDedup disables the
// dedupe (the pool path, issue #15, has its own cross-transport failover) — every
// method is nil-safe. An empty tag (direct, TURN-fallback, or a coordinator
// predating #56) never matches and is never recorded.
//
// Only genuine peer relays are deduped: attemptWith gates both seen and fail on the
// relayPeer disposition (issue #111), so a hostile coordinator cannot stamp a tag on
// a non-peer reply to poison a direct/TURN path. That gate — not the coordinator's
// honesty in leaving the tag empty off the peer path — is what enforces the
// invariant here.
type relayDedup struct {
	failed map[string]bool
}

func newRelayDedup() *relayDedup { return &relayDedup{failed: map[string]bool{}} }

// seen reports whether tag was already recorded as failed this pass. A nil
// receiver or empty tag is never seen.
func (d *relayDedup) seen(tag string) bool { return d != nil && tag != "" && d.failed[tag] }

// fail records tag as a failed relay for the rest of this pass. A nil receiver or
// empty tag is a no-op.
func (d *relayDedup) fail(tag string) {
	if d != nil && tag != "" {
		d.failed[tag] = true
	}
}

// Connect establishes a path to the configured exit, starts the local SOCKS5
// server, and keeps that path alive. It rotates across the coordinator pool until
// one member connects: a blocked or refusing member is skipped, and — because a
// coordinator could be poisoned and hand back a dead or hostile relay — a member
// that pairs the client but whose transport then fails is skipped too, in favour
// of a fresh relay assignment from the next member. Once a path is up it returns
// (SOCKS accepting in the background) and reconnectLoop watches the session: when
// it drops (data-channel/ICE teardown, peer gone, network change) the path is
// re-established automatically within the same transport — retrying the current
// path with bounded exponential backoff, then failing over to the next candidate
// — and the fresh session is swapped under the listener with no rebind (issue #2).
// It returns an error only if no member could connect at all. Requires the client
// role; the country comes from Config.Geo, or is chosen from the coordinator's
// country list when that is unset (pickCountry).
//
// The transport pool (issue #15) is a separate path with its own failover across
// transports (connectPooled/maintainPath); this is the default single-transport
// path and owns re-establishing within the one transport.
func (e *Engine) Connect(ctx context.Context) error {
	if !e.clientOn {
		return errors.New("core: Connect requires the client role")
	}
	// Transport pool + per-user failover (issue #15): race transports and modes,
	// validate sustained flow, learn per network.
	if e.poolOn() {
		return e.connectPooled(ctx)
	}
	if err := e.resolveCountry(ctx); err != nil {
		return err
	}

	// Initial connect: the default direct-then-relay order (prefer "" == direct).
	path, err := e.establishFn(ctx, "")
	if err != nil {
		return err
	}
	e.setReconnectSession(path)
	if err := e.serveReconnectSocks(e.cfg.SocksAddr); err != nil {
		// The session is up and tracked, but the SOCKS listener never bound, so
		// nothing will ever use or close it — drop it here rather than leak it until
		// Stop (issue #85). trackSession's watcher then frees it from the map.
		_ = path.sess.Close()
		return err
	}
	// Watch the path and re-establish on drop, swapping the session under the
	// listener. wg-tracked so Stop drains it.
	e.wg.Add(1)
	go e.reconnectLoop(ctx, path)
	return nil
}

// resolveCountry settles, once and before the first connect, which country this
// client asks to egress in.
//
// A connect names exactly one country — the coordinator refuses one that names none
// (refuseNoCountry) — so a client with no configured country must obtain one before it
// can pair at all. Config.Geo is used when set; otherwise the country list is fetched
// and pickCountry takes the first assignable entry.
//
// Settled once rather than re-chosen per attempt, deliberately: re-picking on every
// reconnect would let a momentarily-busy country silently move the user to a different
// jurisdiction mid-session, which is precisely the surprise country selection exists to
// prevent. If the chosen country later goes busy the connect is refused and the user is
// told, rather than quietly rerouted.
func (e *Engine) resolveCountry(ctx context.Context) error {
	if e.cfg.Geo != "" {
		e.connectCountry = e.cfg.Geo
		return nil
	}
	countries, err := e.ListCountries(ctx, e.listTimeout)
	if err != nil {
		return err
	}
	cc, err := pickCountry("", countries)
	if err != nil {
		return err
	}
	e.connectCountry = cc
	e.emit(EventInfo, "", "no country configured — using %s", cc)
	return nil
}

// establish runs one pass of the single-transport connect ladder into the resolved
// country: it rotates the coordinator pool (orderLinks) and, per member,
// attempts the candidate modes in preference order, returning the first path that
// comes up. prefer names the mode to try first — the reconnect driver passes the
// just-dropped mode so the current path is retried before failing over to the
// other candidate; "" is the initial direct-then-relay order. A direct attempt is
// a coordinator-independent P2P hole-punch, so it is offered only once per pass;
// relay is retried on each member because its assignment varies per coordinator.
// It is the default value of e.establishFn (the reconnect seam).
func (e *Engine) establish(ctx context.Context, prefer string) (connPath, error) {
	triedDirect := false
	// Rotation dedupe (issue #56): remember, for this one pass, the opaque tag of
	// any peer relay whose transport dial failed, so a later pool member that
	// assigns the SAME relay is skipped instead of re-dialing a known-bad splice.
	// Scoped to the pass — a fresh reconnect gives a previously-bad relay another
	// chance, since it may have recovered.
	dedup := newRelayDedup()
	// Track whether every failing member was SILENT (network-unreachable) rather
	// than answering-but-unable-to-pair. All-silent is the specific condition that
	// warrants mesh-walk recovery (issue #31): the coordinators can't be reached at
	// all, so a live one must be rediscovered through a peer. A member that answered
	// (refused/relay-failed) means rendezvous itself is fine, so we surface the
	// ordinary error and do not walk.
	allSilent := true
	for _, l := range e.orderLinks() {
		select {
		case <-ctx.Done():
			return connPath{}, ctx.Err()
		case <-e.stop:
			return connPath{}, errEngineStopped
		default:
		}
		// A prior member's reply may already have latched a force-major mismatch;
		// don't keep dialing a network this client can't speak to (issue #36).
		if err := e.updateRequired(); err != nil {
			return connPath{}, err
		}
		e.greet(l)
		modes := e.modeLadder(prefer, !triedDirect)
		if modesHaveDirect(modes) {
			triedDirect = true
		}
		path, outcome := e.connectVia(ctx, l, modes, dedup)
		// This member's session reply is now observed; if it forces a major update,
		// stop before running SOCKS over a doomed wire protocol — closing any
		// session we just brought up.
		if err := e.updateRequired(); err != nil {
			if path.sess != nil {
				_ = path.sess.Close()
			}
			return connPath{}, err
		}
		if outcome == connectOK {
			return path, nil
		}
		// Only a silent member is treated as blocked (deprioritized for the
		// cooldown). A member that answered but couldn't get us connected is still
		// healthy — we simply rotate past it for this attempt.
		if outcome == coordinatorSilent {
			e.markUnhealthy(l.raw)
		} else {
			allSilent = false
		}
	}
	if allSilent {
		return connPath{}, ErrNoCoordinatorReachable
	}
	return connPath{}, errors.New("core: could not connect via any coordinator")
}

// ErrNoCoordinatorReachable is what establish returns when every coordinator in
// the pool was silent — none answered a connect request. It is the trigger for
// mesh-walk recovery (issue #31, design §4.3): rendezvous itself is down, so a live
// coordinator must be rediscovered by asking a known peer for a fresh signed
// snapshot. A failure where some coordinator answered but couldn't pair us returns
// a plain error instead, because walking the mesh would not help.
var ErrNoCoordinatorReachable = errors.New("core: no coordinator reachable")

// MeshWalk performs warm re-bootstrap recovery (issue #31, design §4.3) when every
// coordinator has gone unreachable. Given peer courier addresses learned in a prior
// session (the relay/exit entries of a cached snapshot), a proof of prior contact
// (that cached snapshot's signed bytes), and the coordinator's snapshot-signing
// public key, it asks each peer in turn for a current signed snapshot and returns
// the first one that verifies — a fresh directory the caller can adopt to reconnect
// through and re-cache as its next proof.
//
// A courier is a dispenser, not an author: FetchSnapshot re-verifies every reply
// against pub, so a hostile peer can only serve a stale-but-genuine snapshot or
// nothing — never a forged directory. A peer that is unreachable, is not a courier,
// or has only an expired snapshot is skipped; the walk fails only when no peer
// yields a live, verified snapshot. The caller loops — walk, reconnect, and if the
// rediscovered coordinators are down too, walk again from the fresher peer set —
// until a live path is found or the peers are exhausted.
func (e *Engine) MeshWalk(ctx context.Context, peers []string, proof []byte, pub ed25519.PublicKey) (*coldstart.Result, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("core: mesh-walk requires the coordinator snapshot public key")
	}
	if len(proof) == 0 {
		// Recovery, not cold-start: without a prior signed snapshot there is no proof
		// of prior contact to present, and a courier will (correctly) refuse to serve.
		return nil, errors.New("core: mesh-walk requires a cached snapshot as proof of prior contact")
	}
	peers = dedupNonEmpty(peers)
	if len(peers) == 0 {
		return nil, errors.New("core: mesh-walk has no known peers to ask")
	}

	e.emit(EventInfo, "", "coordinators unreachable — walking %d known peer(s) for a fresh directory", len(peers))
	var lastErr error
	for _, peer := range peers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.stop:
			return nil, errEngineStopped
		default:
		}
		res, err := e.fetchPeerSnapshot(ctx, peer, proof, pub)
		if err != nil {
			e.emit(EventInfo, "", "mesh-walk: peer %s did not yield a directory: %v", peer, err)
			lastErr = err
			continue
		}
		e.emit(EventInfo, "", "mesh-walk: recovered a fresh directory from %s (%d coordinator(s))",
			peer, len(res.Snapshot.AddrsForRole("coordinator")))
		return res, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no peers")
	}
	return nil, fmt.Errorf("core: mesh-walk found no live directory: %w", lastErr)
}

// fetchPeerSnapshot is the per-peer fetch, bounded by the relay timeout so one
// silent peer can't stall the whole walk.
func (e *Engine) fetchPeerSnapshot(ctx context.Context, peer string, proof []byte, pub ed25519.PublicKey) (*coldstart.Result, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, e.relayTimeout)
	defer cancel()
	return coldstart.FetchSnapshot(fetchCtx, peer, proof, pub)
}

// meshRecoveryConfigured reports whether this engine can attempt warm recovery
// (issue #115): it needs peer couriers to ask, a proof of prior contact, and the
// coordinator key to verify replies. A half-configured or absent setup simply
// disables recovery — the client fails cold / keeps retrying as it did before.
func (e *Engine) meshRecoveryConfigured() bool {
	return len(e.meshPeers) > 0 && len(e.meshProof) > 0 && len(e.meshPubKey) == ed25519.PublicKeySize
}

// meshRecoveryPartial reports a half-configured mesh-recovery setup: at least
// one of MeshPeers/MeshProof/MeshPubKey set, but not the full combination
// meshRecoveryConfigured requires (including a present-but-wrong-size
// MeshPubKey). False both when recovery is fully configured and when it is
// simply unconfigured (all three empty) — the latter is not a misconfiguration,
// it's "recovery not requested," and must stay silent. newEngine uses this once
// at construction to diagnose the gap cmd/node's loadMeshRecovery already
// fails fast on, for a direct core.Config caller that has no such guard
// (issue #121).
func (e *Engine) meshRecoveryPartial() bool {
	hasPeers := len(e.meshPeers) > 0
	hasProof := len(e.meshProof) > 0
	hasPubkey := len(e.meshPubKey) > 0
	return (hasPeers || hasProof || hasPubkey) && !e.meshRecoveryConfigured()
}

// tryMeshRecovery is the mid-session escalation shared by both failover loops
// (reconnectLoop's reconnect and the pool's maintainPath) when every coordinator
// this engine knows has gone silent (issue #115). It walks the configured peer
// couriers for a fresh signed directory; if one names coordinators DIFFERENT from
// the current (dead) set, it stashes them and closes recoverCh so the supervisor
// rebuilds the engine against them (ADR-0037), then returns true — the caller stops
// its loop. It returns false — the caller keeps its normal retry — when recovery is
// off, no peer yields a live directory, or the directory only re-lists the same
// still-unreachable coordinators. That last guard is what preserves ADR-0030: a
// transient outage (peers can't help either, or point back at the same addresses)
// never triggers a needless rebuild; only a genuine coordinator move does.
func (e *Engine) tryMeshRecovery(ctx context.Context) bool {
	if !e.meshRecoveryConfigured() {
		return false
	}
	res, err := e.MeshWalk(ctx, e.meshPeers, e.meshProof, e.meshPubKey)
	if err != nil {
		return false
	}
	fresh := res.Snapshot.AddrsForRole("coordinator")
	if len(fresh) == 0 || sameCoordSet(fresh, e.cfg.Coordinators) {
		// A directory with no coordinators, or one naming exactly the set we are
		// already (unsuccessfully) dialing, is no improvement — keep retrying rather
		// than tear the engine down to rebuild against the same dead addresses.
		e.emit(EventInfo, "", "mesh-walk: recovered directory adds no new coordinator — continuing to retry")
		return false
	}
	e.recoverMu.Lock()
	e.recoverCoords = fresh
	e.recoverProof = res.Signed
	e.recoverMu.Unlock()
	e.recoverOnce.Do(func() { close(e.recoverCh) })
	e.emit(EventInfo, "", "mesh-walk: rediscovered %d coordinator(s) mid-session — rebuilding to recover (issue #115)", len(fresh))
	return true
}

// NeedsRecovery is closed once a mid-session mesh-walk has rediscovered a fresh
// coordinator directory and the engine wants the supervisor to rebuild against it
// (issue #115). The node binary selects on it alongside [Engine.Done]; on close it
// reads [Engine.RecoveredDirectory], stops this engine, and builds a new one with
// the rediscovered coordinators. It never fires when mesh recovery is unconfigured.
func (e *Engine) NeedsRecovery() <-chan struct{} { return e.recoverCh }

// RecoveredDirectory returns the coordinators a mid-session mesh-walk rediscovered
// and the fresher snapshot to carry as the next proof, valid once NeedsRecovery has
// fired. The coordinators are the rebuilt engine's Config.Coordinators; the proof is
// its Config.MeshProof.
func (e *Engine) RecoveredDirectory() ([]string, []byte) {
	e.recoverMu.Lock()
	defer e.recoverMu.Unlock()
	return e.recoverCoords, e.recoverProof
}

// sameCoordSet reports whether a and b hold the same coordinator addresses,
// order-independent — so tryMeshRecovery can tell a genuinely moved directory from
// one that merely re-lists the coordinators already known to be down.
func sameCoordSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		if seen[s] == 0 {
			return false
		}
		seen[s]--
	}
	return true
}

// modeLadder is reconnectModes for THIS engine: the same ordering, minus modeDirect
// whenever the client is chaining (issue #142).
//
// A direct path has no relay in it, so there is nothing for an onion to be built on
// — chainFor returns no plan for it and the attempt would come up as an ordinary
// unchained connection. That is a silent downgrade, which is the one outcome
// core/relaychain.go's fail-closed rule exists to forbid: a user who configured a
// path no single node can link, and got a path where one node sees both ends,
// would go on acting on an assurance they no longer have. Since direct is tried
// FIRST in the default order, leaving it in meant a chaining client's very first
// attempt was the unchained one — and, before ADR-0042 §9 moved exit selection off
// the wire, that attempt also put the real exit id on it.
//
// Dropping the tier costs a chaining client the direct path's lower latency and its
// independence from relay availability. That is the price of the property, it is
// stated in -relay-hops' help, and it is why the default depth of 1 leaves the
// ladder exactly as it was.
func (e *Engine) modeLadder(prefer string, allowDirect bool) []string {
	return reconnectModes(prefer, allowDirect && !e.chaining())
}

// reconnectModes orders the candidate modes for one coordinator pass. allowDirect
// (true only on the first member of a pass, and never for a chaining client — see
// modeLadder) offers direct once, since its P2P hole-punch outcome is
// coordinator-independent. prefer == modeRelay retries relay before direct so a
// dropped relay path is re-tried before falling back to direct; any other prefer
// keeps the initial direct-then-relay order.
func reconnectModes(prefer string, allowDirect bool) []string {
	if prefer == modeRelay {
		if allowDirect {
			return []string{modeRelay, modeDirect}
		}
		return []string{modeRelay}
	}
	if allowDirect {
		return []string{modeDirect, modeRelay}
	}
	return []string{modeRelay}
}

func modesHaveDirect(modes []string) bool {
	for _, m := range modes {
		if m == modeDirect {
			return true
		}
	}
	return false
}

// timeoutFor is the per-mode connect budget: a relay handshake (through TURN) gets
// the longer relayTimeout, direct the shorter directTimeout.
func (e *Engine) timeoutFor(mode string) time.Duration {
	if mode == modeRelay {
		return e.relayTimeout
	}
	return e.directTimeout
}

// connectVia attempts each mode in order through member l, returning the first
// established path (its session, winning mode, and — for a direct-disposition
// path — accounting counter) or the merged failure outcome so establish can
// update coordinator health memory. It only merges failures, so connectOK never
// participates. dedup carries the per-pass relay skip-set (issue #56).
func (e *Engine) connectVia(ctx context.Context, l *coordLink, modes []string, dedup *relayDedup) (connPath, connectOutcome) {
	outcome := coordinatorSilent // until a mode shows the member responded
	for i, mode := range modes {
		r := e.attempt(ctx, l, mode, e.timeoutFor(mode), dedup)
		sess, sid, relay, res := r.sess, r.sid, r.relay, r.outcome
		if res == connectOK {
			// A relay-mode request that came back relay:"turn" (issue #97) has no
			// peer relay in the path — the coordinator wired us straight to the exit,
			// and ICE relays through TURN only if a hole-punch fails. That is the
			// DIRECT disposition: the exit terminates the session and holds a session
			// id to attribute bytes to, so it is accounted exactly like a mode:"direct"
			// connect (ADR-0021 — a peer-relay splice, which carries no session id, is
			// the only relayed case left unaccounted). Only relay:"peer" is a genuine
			// relayed data plane.
			if mode == modeDirect || relay == relayTURN {
				e.emit(EventConnected, "", "connected DIRECT to exit %s in %s", shortID(r.exitID), e.connectCountry)
				// The counter is nil (a no-op) when Config.AcctDir is unset, so this
				// stays inert for callers that don't opt in.
				return connPath{sess: sess, ctr: e.startAccounting(sid, sess, l, r.exitPub), mode: mode, sid: sid, exitID: r.exitID, exitPub: r.exitPub}, connectOK
			}
			e.emit(EventConnected, "", "connected via RELAY to exit %s in %s", shortID(r.exitID), e.connectCountry)
			return connPath{sess: sess, mode: mode, sid: sid, exitID: r.exitID, exitPub: r.exitPub}, connectOK
		}
		outcome = mergeOutcome(outcome, res)
		if mode == modeDirect && i+1 < len(modes) {
			e.emit(EventInfo, "", "direct failed -> trying relay…")
		}
	}
	return connPath{}, outcome
}

// mergeOutcome keeps the more informative of two failure outcomes (higher wins,
// per the connectOutcome ordering): a member that paired us then failed the
// transport is more clearly reachable than one that only refused, which in turn
// beats one that stayed silent. connectVia only merges failures, so connectOK
// (the lowest value) never participates.
func mergeOutcome(a, b connectOutcome) connectOutcome {
	if b > a {
		return b
	}
	return a
}

// connectReq is one pairing request: the country to egress in, the mode to pair,
// which of this client's own recent sessions failed so the coordinator avoids their
// exits, and — for a chaining client — the assembled chain whose head it wants to be
// wired to.
//
// country always names where the client wants to EGRESS — the terminating exit's
// country. That is a wire commitment rather than a local convention (ADR-0042 §9),
// and it is why a chained request omits the field rather than repurposing it: on a
// chained path the client resolves its own terminating exit, so there is no country
// for the coordinator to act on, and sending one would hand it the user's egress
// jurisdiction for nothing. See wireCountry.
type connectReq struct {
	country string
	mode    string
	exclude []string // session ids, not exit ids — see wire.ExcludeSessions

	// plan, when non-nil, is a relay chain (issue #142, ADR-0038). It changes what
	// goes out — connect{firstHop} names the chain's first peeling hop instead of
	// asking the coordinator to choose an exit — and it makes the reply's relay
	// disposition load-bearing rather than informational (see the relayPeer and
	// verifyChainDisjoint checks below). A nil plan, which is every path at the
	// default depth, leaves the request byte-identical to what it was.
	plan *chainPlan
}

// wireCountry is the country this request puts on the wire: the requested one
// normally, and NOTHING on a chained request. See the type doc.
func (r connectReq) wireCountry() string {
	if r.plan != nil {
		return ""
	}
	return r.country
}

// attemptResult is one pairing attempt's outcome. The exit fields are the reason this
// is a struct rather than a tuple: the coordinator now CHOOSES the exit, so its id
// arrives with the session and nothing else in the client knows it. A caller that
// forgets to carry it forward runs the end-to-end handshake against the wrong static
// key, which surfaces as an authentication failure rather than as the plumbing mistake
// it is — so the value is placed where it cannot be dropped by omission.
//
// On a CHAINED attempt the exit fields are the client's own choice rather than the
// coordinator's answer, read back out of the plan. They mean the same thing to every
// reader — "the exit this path terminates at" — which is what lets accounting, the
// connected-via line and the pool's learned store stay unaware that chaining exists.
type attemptResult struct {
	sess    Session
	sid     string
	exitID  string // the exit the coordinator assigned (issue #146), or the chain's own (#142)
	exitPub []byte // exitID decoded; validated once here, at the wire boundary
	relay   string // relay disposition (issue #17): relayPeer / relayTURN / ""
	outcome connectOutcome
}

// attempt runs one connection attempt in the given mode (direct/relay) through
// coordinator link l: it asks that member to pair us in the resolved country, then
// dials the transport over the resulting session. dedup is the per-pass relay skip-set
// (issue #56).
func (e *Engine) attempt(ctx context.Context, l *coordLink, mode string, timeout time.Duration, dedup *relayDedup) attemptResult {
	plan, err := e.chainFor(mode, e.connectCountry)
	if err != nil {
		// The user asked for a chained relay path and one could not be assembled. That
		// fails this attempt rather than falling back to an unchained relay: see
		// core/relaychain.go on why a silent downgrade is the one outcome this feature
		// must never produce.
		e.emit(EventError, "", "[relay] chain not built: %v", err)
		return attemptResult{outcome: transportFailed}
	}
	return e.attemptWith(ctx, l, connectReq{country: e.connectCountry, mode: mode, plan: plan}, e.transport, timeout, dedup)
}

// attemptWith is attempt generalized over the request and transport, so the pool
// (issue #15) can pair a chosen country and dial a chosen transport while the
// single-transport Connect keeps using the engine's resolved country and e.transport.
// The pairing, session buffering, and outcome semantics are identical. dedup, when
// non-nil, skips a peer relay this pass already failed on and records a fresh failure
// (issue #56); the pool passes nil (it has its own failover).
func (e *Engine) attemptWith(ctx context.Context, l *coordLink, req connectReq, tr Transport, timeout time.Duration, dedup *relayDedup) attemptResult {
	// Each connect is sent several times against UDP loss, so the coordinator
	// mints one session per copy and we buffer the extra "session" replies. Drop
	// any left over from a prior mode on this member so awaitSession can't pick
	// up a stale session id.
	e.drainMsgCh(l)
	l.sendN(wire{
		Type:            "connect",
		Country:         req.wireCountry(),
		FirstHop:        req.plan.firstHopID(),
		Mode:            req.mode,
		Cred:            e.cfg.AdmissionCred,
		ExcludeSessions: req.exclude,
	}, 3)

	reply, res := e.awaitSession(ctx, l, timeout)
	switch res {
	case pairSilent:
		return attemptResult{outcome: coordinatorSilent}
	case pairRefused:
		// Surface WHY (issue #147). "country-busy" and "no-such-country" are
		// actionable in ways a bare failure is not — one says try again or pick
		// elsewhere, the other says your country is wrong — and discarding the reason
		// here is what left both invisible to logs and to users alike.
		e.emit(EventError, "", "coordinator refused to pair in %s: %s", req.country, refusalText(reply.reason))
		return attemptResult{outcome: coordinatorRefused}
	}
	// Which exit this path terminates at, and its static key.
	//
	// On an ordinary attempt the coordinator's answer is the only source: an exit's id
	// IS its Noise static public key (ADR-0009), and under country-only assignment the
	// client did not choose the exit, so it cannot know the key unless told. Validate
	// at the wire boundary and treat a bad or missing id as a refusal rather than
	// carrying it inward to fail as a confusing handshake error several layers down.
	//
	// On a CHAINED attempt the plan is the only source, and the reply is ignored
	// entirely — not merely preferred. The coordinator was asked to wire a hop and was
	// never told the exit, so it has nothing truthful to say here; reading a key out of
	// its reply would let it redirect a chained path's innermost layer to a node of its
	// choosing, which is the whole attack the chain exists to prevent.
	exitID, exitPub := reply.exitID, []byte(nil)
	if req.plan != nil {
		exitID, exitPub = req.plan.exitID, req.plan.exitPub
	} else {
		var err error
		exitPub, err = hex.DecodeString(exitID)
		if err != nil || len(exitPub) != 32 {
			e.emit(EventError, reply.sid, "coordinator assigned session %s without a usable exit id (%q) — cannot establish the end-to-end channel", reply.sid, reply.exitID)
			return attemptResult{outcome: coordinatorRefused}
		}
	}
	sid := reply.sid
	e.emit(EventSession, sid, "[%s] session: %s (exit %s)", req.mode, sid, shortID(exitID))
	// Surface which data-plane path a relay-mode request actually got (issue #17):
	// the preferred Bacchus peer relay, or the TURN fallback when none was free.
	switch reply.relay {
	case relayPeer:
		e.emit(EventInfo, sid, "[relay] routing through a peer relay")
	case relayTURN:
		e.emit(EventInfo, sid, "[relay] no peer relay available — falling back to TURN")
	}

	// Rotation dedupe (issue #56) applies ONLY to the peer-relay disposition. A
	// coordinator legitimately assigns a distinct, dedup-able relay only on the
	// relayPeer path; a tag on any other disposition is illegitimate. Gate both the
	// skip check and the failure record on relayPeer (issue #111) so a hostile
	// coordinator cannot stamp a tag on a relayTURN reply and make the client skip
	// an otherwise valid direct-over-TURN path — enforcing in code the invariant
	// relayDedup's doc comment (and the wire.RelayTag doc) only asserted. A
	// well-behaved coordinator leaves the tag empty off the peer path, so this
	// changes nothing for it (an empty tag is already a dedupe no-op).
	isPeerRelay := reply.relay == relayPeer

	// A chained path requires a genuine peer relay in front of it, so a TURN
	// fallback fails the attempt instead of being chained (issue #142). On that
	// disposition the coordinator wires us straight to the node we named — which is
	// the chain's first peeling hop — so that hop would see our own address AND, one
	// layer in, the real exit: exactly the linkage the chain was bought to prevent.
	// Failing here lets selection try another member or candidate, whereas building
	// the chain anyway would hand the user an assurance it does not have.
	// This is the same fail-closed rule as the rest of core/relaychain.go: never
	// silently give back a weaker path than the one that was asked for.
	if req.plan != nil && !isPeerRelay {
		e.emit(EventInfo, sid, "[relay] %v", errChainNoTURN)
		return attemptResult{sid: sid, outcome: transportFailed}
	}
	// And it requires that relay to be a DIFFERENT node from every hop it is about to
	// telescope through, or one node holds both ends of the chain. Checked here rather
	// than in chainFor because the relay is not known until the reply arrives.
	if err := verifyChainDisjoint(req.plan, reply.tag); err != nil {
		e.emit(EventInfo, sid, "[relay] %v", err)
		return attemptResult{sid: sid, outcome: transportFailed}
	}

	// If this peer relay already failed a dial this pass, an earlier pool member
	// handed back the SAME relay — skip re-dialing a known-bad splice and rotate on.
	// transportFailed, not silent: the member answered fine, it just re-offered an
	// unlucky relay, so it keeps its health. The session the coordinator just minted
	// is abandoned exactly as any unused pairing is (see ADR-0035 on the resulting
	// orphaned coordinator entry).
	if isPeerRelay && dedup.seen(reply.tag) {
		e.emit(EventInfo, sid, "[relay] skipping a peer relay that already failed this connect")
		return attemptResult{sid: sid, exitID: reply.exitID, outcome: transportFailed}
	}

	sig := e.newSignaler(sid, l)
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sess, err := tr.Dial(dialCtx, sig)
	if err != nil {
		e.dropSignaler(sid)
		e.emit(EventError, sid, "[%s] dial: %v", req.mode, err)
		if isPeerRelay {
			dedup.fail(reply.tag) // remember this relay so a sibling member's re-offer is skipped
		}
		// The sid rides out on the failure too: it is what a retry names in
		// ExcludeSessions so the coordinator does not hand back the same exit.
		return attemptResult{sid: sid, exitID: exitID, outcome: transportFailed}
	}
	// Tag the session with the chain it was paired through, so every end-to-end
	// channel opened over it later telescopes the same hops without any separate
	// bookkeeping to keep in step across a failover (see planOf). A nil plan
	// returns sess itself, unwrapped.
	chained := withChain(sess, req.plan)
	e.trackSession(sid, chained, false) // client's own tunnel: reconnectLoop owns its lifetime, never the reaper
	return attemptResult{sess: chained, sid: sid, exitID: exitID, exitPub: exitPub, relay: reply.relay, outcome: connectOK}
}

// refusalText renders a coordinator refusal reason for a human. The two country
// refusals (issue #147) get a sentence saying what to do about them; anything else —
// including an empty reason from a coordinator that sent a bare error — is shown
// verbatim so an unrecognized reason is never swallowed.
func refusalText(reason string) string {
	switch reason {
	case "country-busy":
		return "country-busy (every exit there is at capacity or out of quota — try again shortly, or choose another country)"
	case "no-such-country":
		return "no-such-country (this coordinator knows no exit in that country — check the country code)"
	case "no-such-hop":
		return "no-such-hop (this coordinator has no exit registered under the node this chain names as its first hop — your signed directory may be stale)"
	case "hop-needs-relay-mode":
		// Not reachable from an honest client — chainFor builds a plan only in relay
		// mode, so this build never names a hop outside it. Rendered anyway: reaching
		// it means the engine is sending a combination it believes it cannot send,
		// and a bare reason string in a log is a poor way to find that out.
		return "hop-needs-relay-mode (a first hop may only be named on a relay-mode connect; this is a client bug, not a network condition)"
	case "":
		return "no reason given"
	default:
		return reason
	}
}

// drainMsgCh discards any buffered replies on member l's inbox so a new attempt
// on it starts clean. It never blocks.
func (e *Engine) drainMsgCh(l *coordLink) {
	for {
		select {
		case <-l.msgCh:
		default:
			return
		}
	}
}

// pairResult is how a coordinator answered a connect request.
type pairResult int

const (
	pairMinted  pairResult = iota // assigned a session id
	pairRefused                   // replied "error"
	pairSilent                    // no reply before the deadline
)

// sessionReply is what a coordinator's answer to a connect carries beyond the session
// id: the exit it ASSIGNED (issue #146), the relay disposition (issue #17 —
// relayPeer/relayTURN, or "" for a direct-mode reply), the opaque rotation-dedupe tag
// for that peer relay (issue #56 — "" when there is no distinct relay to dedupe), and,
// on a refusal, why (issue #147).
type sessionReply struct {
	// exitID names the exit the coordinator chose inside the requested country. It is
	// the one field here without which the connection cannot proceed at all: an exit's
	// id is its Noise static public key (ADR-0009), and under country-only assignment
	// the client has no other way to learn it — it did not choose the exit, so it
	// cannot know the key unless told.
	exitID string
	sid    string
	relay  string
	tag    string
	// reason is the coordinator's refusal reason on an "error" reply (#147:
	// country-busy / no-such-country). Kept rather than discarded because these two
	// are the only refusals the protocol names deliberately, and a refusal a user
	// cannot see is a refusal they cannot act on.
	reason string
}

// awaitSession waits for member l to assign a session id, report an error, or
// fall silent after a connect request. On a mint it returns the session id, the
// assigned exit, and the relay disposition and rotation-dedupe tag the coordinator
// stamped (issues #17/#56); on a refusal it returns the reason.
func (e *Engine) awaitSession(ctx context.Context, l *coordLink, timeout time.Duration) (sessionReply, pairResult) {
	deadline := time.After(timeout)
	for {
		select {
		case <-ctx.Done():
			return sessionReply{}, pairSilent
		case <-e.stop:
			return sessionReply{}, pairSilent
		case <-deadline:
			return sessionReply{}, pairSilent
		case m, ok := <-l.msgCh:
			if !ok {
				return sessionReply{}, pairSilent
			}
			switch m.Type {
			case "session":
				return sessionReply{sid: m.Session, exitID: m.ExitID, relay: m.Relay, tag: m.RelayTag}, pairMinted
			case "error":
				return sessionReply{reason: m.Reason}, pairRefused
			}
		}
	}
}

// perLinkBudget splits an overall list/connect timeout across the pool so
// rotation can give each member a fair slice without blowing the caller's
// deadline. A floor keeps each slice usable when the pool is large; the caller's
// ctx still bounds the total wait.
func perLinkBudget(total time.Duration, n int) time.Duration {
	if n <= 1 {
		return total
	}
	per := total / time.Duration(n)
	if floor := 800 * time.Millisecond; per < floor {
		return floor
	}
	return per
}

// reconnectLoop keeps the single-transport path alive (issue #2). It watches the
// live session and, when it drops (data-channel/ICE teardown, peer gone, network
// change), re-establishes automatically — retrying the just-dropped mode first
// with bounded exponential backoff, then failing over to the other candidate —
// and swaps the fresh session under the SOCKS listener with no rebind. It mirrors
// the pool's maintainPath for the default single-transport path, and exits on
// shutdown or context cancellation (or, when reconnectMaxAttempts is set, once the
// attempt budget is spent). wg-tracked.
//
// Two capped backoff clocks keep it from ever busy-looping. reconnect (below)
// spaces *failed* establish passes while a path stays down. A *flap* guard here
// spaces retries when a path connects then drops almost immediately: a session
// that held for reconnectHealthy is a genuine one-off drop and is retried fast; a
// session that dies at once grows the wait so a connect/drop cycle can't spin.
func (e *Engine) reconnectLoop(ctx context.Context, path connPath) {
	defer e.wg.Done()
	flapDelay := e.reconnectBase
	for {
		upSince := time.Now()
		select {
		case <-path.sess.Closed():
		case <-e.stop:
			return
		case <-ctx.Done():
			return
		}
		if time.Since(upSince) >= e.reconnectHealthy {
			flapDelay = e.reconnectBase // stable run then dropped: recover fast
		} else {
			// Flapping: wait out a growing, capped backoff before retrying so a
			// rapid connect/drop cycle can never become a busy-loop.
			e.emit(EventInfo, "", "path unstable (%s) — waiting %s before retry", strings.ToUpper(path.mode), flapDelay)
			if !e.sleepBackoff(ctx, flapDelay) {
				return
			}
			flapDelay = capDelay(flapDelay*2, e.reconnectMax)
		}
		e.emit(EventError, "", "connection lost (%s) — reconnecting…", strings.ToUpper(path.mode))

		newPath, err := e.reconnect(ctx, path.mode)
		if err != nil {
			if errors.Is(err, errRecovering) {
				// A mid-session mesh-walk found a fresh directory; tryMeshRecovery has
				// signalled the supervisor (NeedsRecovery), which rebuilds the engine
				// against the rediscovered coordinators (issue #115, ADR-0037). Stop this
				// loop cleanly — the path is already down and the handoff is the
				// supervisor's; nothing here should keep dialing the dead pool.
				return
			}
			e.emit(EventError, "", "reconnect abandoned: %v", err)
			return
		}
		e.setReconnectSession(newPath)
		e.emit(EventConnected, "", "reconnected via %s to exit %s in %s", strings.ToUpper(newPath.mode), shortID(newPath.exitID), e.connectCountry)
		path = newPath
	}
}

// errRecovering is the internal signal reconnect returns when a mid-session
// mesh-walk has rediscovered a fresh coordinator directory (issue #115). It is not
// a failure: tryMeshRecovery has already stashed the directory and closed
// NeedsRecovery, so reconnectLoop stops and the supervisor rebuilds the engine
// against it. Distinct from a real reconnect give-up, which surfaces its own error.
var errRecovering = errors.New("core: mid-session mesh-walk recovery in progress")

// reconnect makes repeated establish passes with bounded exponential backoff until
// one succeeds. Each pass retries the just-dropped mode first, then fails over to
// the other candidate (establish). The backoff (base doubling, capped at
// reconnectMax) means a path that stays down is retried without a busy-loop. With
// reconnectMaxAttempts == 0 it retries until the path recovers or the engine stops
// / ctx cancels (the owner's resilience-over-self-limiting choice, ADR-0030); a
// positive budget gives up after that many failed passes.
//
// Mid-session warm recovery (issue #115) rides on top of that retry: when a run of
// passes all come back ErrNoCoordinatorReachable — every coordinator silent, not
// merely a blocked path — it walks known peer couriers for a fresh directory and,
// if one names a genuinely different live coordinator, returns errRecovering so the
// supervisor rebuilds. Crucially this never abandons ADR-0030's retry-forever: a
// walk that finds nothing better leaves the loop retrying exactly as before, so a
// transient outage still self-heals in place without a rebuild.
func (e *Engine) reconnect(ctx context.Context, dropped string) (connPath, error) {
	delay := e.reconnectBase
	silentStreak := 0
	for attempt := 1; ; attempt++ {
		path, err := e.establishFn(ctx, dropped)
		if err == nil {
			return path, nil
		}
		// Count consecutive all-silent passes; a walk after meshRecoveryAfter of them
		// rules out a brief blip. Any non-silent failure (a coordinator answered but
		// couldn't pair) resets the count — rendezvous is up, so mesh-walk wouldn't help.
		if errors.Is(err, ErrNoCoordinatorReachable) && e.meshRecoveryConfigured() {
			silentStreak++
			if silentStreak >= e.meshRecoveryAfter {
				if e.tryMeshRecovery(ctx) {
					return connPath{}, errRecovering
				}
				silentStreak = 0 // pace the next walk another meshRecoveryAfter passes out
			}
		} else {
			silentStreak = 0
		}
		if e.reconnectMaxAttempts > 0 && attempt >= e.reconnectMaxAttempts {
			return connPath{}, fmt.Errorf("core: gave up after %d attempts: %w", attempt, err)
		}
		e.emit(EventInfo, "", "reconnect attempt %d failed (%v) — retrying in %s", attempt, err, delay)
		if !e.sleepBackoff(ctx, delay) {
			return connPath{}, e.stopOrCtxErr(ctx)
		}
		delay = capDelay(delay*2, e.reconnectMax)
	}
}

// sleepBackoff waits d, returning false if the engine stops or ctx is cancelled
// first so the caller aborts the reconnect promptly on shutdown.
func (e *Engine) sleepBackoff(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	case <-e.stop:
		return false
	}
}

// stopOrCtxErr names why a backoff wait was cut short: ctx cancellation if that is
// what fired, otherwise engine shutdown.
func (e *Engine) stopOrCtxErr(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return errEngineStopped
}

// capDelay clamps an exponential backoff step to a ceiling.
func capDelay(d, max time.Duration) time.Duration {
	if d > max {
		return max
	}
	return d
}

// setReconnectSession swaps in the path (its session, accounting counter, coordinator
// session id, and the static key of the exit terminating it) that new SOCKS
// connections tunnel over. The reconnect driver calls it after a successful
// (re)establish so a failover routes new streams over the fresh session with no
// listener rebind. The sid is kept so onRelayReselect can scope a coordinator
// relay-dead nudge to the live path (issue #96).
//
// The exit key is swapped WITH the session, exactly as the pool's setActivePath does.
// It used to be constant here because the client configured one exit for the engine's
// lifetime; under country-only assignment (issue #146) the coordinator picks, and it
// may pick a different exit inside the same country on any reconnect — so a key held
// per-engine would be the previous exit's after the first failover, and every stream
// would fail its end-to-end handshake against a key nobody holds.
func (e *Engine) setReconnectSession(p connPath) {
	e.rcMu.Lock()
	e.rcSess = p.sess
	e.rcCtr = p.ctr
	e.rcSid = p.sid
	e.rcExitPub = p.exitPub
	e.rcMu.Unlock()
}

// onRelayReselect handles a coordinator "reselect" push (issue #96): the peer relay
// splicing this client's single-transport session has died, so re-establish now
// instead of waiting out the dead relay's transport timeout. It closes the active
// session, which fires reconnectLoop's Closed() watch; the reconnect re-drives
// connect, landing on a fresh relay (the dead one now excluded by the coordinator's
// own staleness bound) or the TURN fallback — no manual reconnect.
//
// The nudge is scoped to the live session id: a relay dying cleanly usually breaks
// the client's transport first, so by the time this arrives the client has often
// already reconnected onto a new session, and a nudge for the abandoned one must be
// ignored rather than tear down the healthy path. Its real value is the black-hole
// case (relay host gone without a TCP reset), where the client is still on the dead
// session and its transport would otherwise hang for a multi-minute timeout. A lost
// nudge is not fatal — the client's own teardown drives the same reconnect (issue
// #2). Only the single-transport path has a reconnect session; a pooled client
// (issue #15) has its own failover and leaves rcSess nil, so this no-ops for it.
func (e *Engine) onRelayReselect(m wire) {
	e.rcMu.Lock()
	sess, sid := e.rcSess, e.rcSid
	e.rcMu.Unlock()
	if sess == nil || m.Session == "" || m.Session != sid {
		return // no live single-transport session, or a nudge for a path we already left
	}
	e.emit(EventInfo, sid, "coordinator: assigned peer relay died — re-establishing")
	_ = sess.Close() // idempotent; reconnectLoop re-establishes off the Closed() signal
}

// activeReconnectSession returns the session, its counter, and the static key of the
// exit terminating it, for new SOCKS connections to use right now — read together at
// accept time so a failover swap is picked up without rebinding the listener.
//
// All three are read under one lock hold. Reading the session and the key separately
// would admit a torn pair across a failover — a fresh session tunnelled to the key of
// the exit that just dropped — and the resulting handshake failure would look like a
// hostile exit rather than a race.
func (e *Engine) activeReconnectSession() (Session, *accounting.Counter, []byte) {
	e.rcMu.Lock()
	defer e.rcMu.Unlock()
	return e.rcSess, e.rcCtr, e.rcExitPub
}

// serveReconnectSocks binds the local SOCKS5 listener once and serves it in the
// background, tunnelling each accepted connection over whatever session is active
// at accept time — so the reconnect driver (issue #2) swaps the live session
// underneath on failover without rebinding or dropping the port. Calling it again
// is a no-op (the listener persists across reconnects). It mirrors the pool's
// bindPoolSocks for the single-transport path, kept separate so the two failover
// mechanisms do not share mutable state.
func (e *Engine) serveReconnectSocks(addr string) error {
	e.rcMu.Lock()
	if e.rcBound {
		e.rcMu.Unlock()
		return nil
	}
	e.rcBound = true
	e.rcMu.Unlock()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("core: socks listen: %w", err)
	}
	e.addListener(ln)
	e.emit(EventInfo, "", "SOCKS5 on %s", addr)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-e.stop:
					return
				default:
					continue
				}
			}
			sess, ctr, exitPub := e.activeReconnectSession()
			if sess == nil || len(exitPub) == 0 {
				_ = c.Close()
				continue
			}
			go e.handleSocks(c, sess, exitPub, ctr)
		}
	}()
	return nil
}

var errBadSOCKSAddrType = errors.New("core: unsupported SOCKS5 address type")

// handleSocks serves one local SOCKS5 connection: after the version/method
// negotiation (no-auth only) and the VER/CMD/RSV/ATYP header, it dispatches on
// CMD — CONNECT (handleSocksConnect) or UDP ASSOCIATE (issue #41,
// handleSocksUDPAssociate in core/udprelay.go); anything else gets SOCKS reply
// code 7 ("command not supported"), same as an unrecognized CMD always has.
// Both the single-transport Connect (serveReconnectSocks) and the pool
// (bindPoolSocks) share this one implementation.
func (e *Engine) handleSocks(c net.Conn, sess Session, exitPub []byte, ctr *accounting.Counter) {
	defer c.Close()
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 5 {
		return
	}
	if _, err := io.ReadFull(c, buf[:int(buf[1])]); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	switch buf[1] {
	case 1:
		e.handleSocksConnect(c, buf, sess, exitPub, ctr)
	case 3:
		e.handleSocksUDPAssociate(c, buf, sess, exitPub, ctr)
	default:
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

// readSOCKSAddr reads a SOCKS5 ATYP+DST.ADDR+DST.PORT field (RFC 1928 §4/§5)
// from c into buf (buf[3] must already hold ATYP, as handleSocks left it) and
// returns "host:port". Shared by CONNECT (the address to dial) and UDP
// ASSOCIATE (the client's advertised send-from address, which
// handleSocksUDPAssociate ignores — see its doc comment for why); behavior is
// unchanged from the original inline version in handleSocks this replaces,
// including not checking every inner read's error — the final port read below
// catches a truncated address the same way a truncated port would.
func readSOCKSAddr(c net.Conn, buf []byte) (string, error) {
	var host string
	switch buf[3] {
	case 1:
		io.ReadFull(c, buf[:4])
		host = net.IP(buf[:4]).String()
	case 3:
		io.ReadFull(c, buf[:1])
		l := int(buf[0])
		io.ReadFull(c, buf[:l])
		host = string(buf[:l])
	case 4:
		io.ReadFull(c, buf[:16])
		host = net.IP(buf[:16]).String()
	default:
		return "", errBadSOCKSAddrType
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(buf[:2]))), nil
}

// handleSocksConnect serves one SOCKS5 CONNECT request — buf already holds
// the VER/CMD/RSV/ATYP header handleSocks read. Unchanged from the original
// handleSocks body, just extracted so handleSocks can dispatch on CMD (issue
// #41).
func (e *Engine) handleSocksConnect(c net.Conn, buf []byte, sess Session, exitPub []byte, ctr *accounting.Counter) {
	target, err := readSOCKSAddr(c, buf)
	if err != nil {
		return
	}

	openCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// The transport stream carries a non-revealing label; the destination goes
	// only inside the end-to-end Noise channel, so a relay in the path never
	// learns it.
	st, err := sess.OpenStream(openCtx, e2eLabel)
	if err != nil {
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	// dialE2E is clientHandshake when this path carries no chain, which is every
	// path at the default hop count; when it does carry one it telescopes the hops
	// first and ends in the same clientHandshake call (core/relaychain.go).
	nc, err := e.dialE2E(st, planOf(sess), exitPub, target)
	if err != nil {
		_ = st.Close()
		// A rejected exit credential (issue #60) lands here like any other
		// handshake failure: the stream is dropped, SOCKS reports a general
		// failure, and the reason is surfaced as an event for the user. A chain
		// that failed to build a hop layer surfaces the same way.
		e.emit(EventError, "", "exit rejected: %v", err)
		c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	// Upload (app -> tunnel): watch the tunnel-write side for backpressure — a write
	// that blocks past satBlockThreshold means the client had more to send than the link
	// carried, i.e. demand-saturated, the one bit a capacity sample needs (issue #158,
	// design §5.3). Only the upload direction, where backpressure is unambiguous; the
	// download read is confounded by remote-server speed (see WatchSaturation).
	go func() {
		_, _ = io.Copy(ctr.WatchSaturation(nc, satBlockThreshold), ctr.CountReads(c))
		_ = nc.Close()
	}()
	_, _ = io.Copy(c, ctr.CountReads(nc))
	_ = nc.Close()
}
