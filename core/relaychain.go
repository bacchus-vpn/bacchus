package core

// Client-assembled, onion-layered relay chains (issue #142, ADR-0038).
//
// A chain routes a RELAYED path through several nodes so that no single one of
// them links this client to its exit. It is not a new protocol: a chain is the
// existing client<->exit Noise_NK handshake (core/e2e.go) run once per hop,
// nested. core/e2e.go's noiseConn re-delimits frames from an opaque byte stream,
// so it is itself an io.ReadWriteCloser that another noiseConn can run over —
// which is the whole mechanism. The client stacks layers; each hop peels exactly
// one and splices the rest onward without understanding it.
//
//	layer 1    client <-> H1     target "hop:<H2 dial addr>"
//	  ...
//	layer n-1  client <-> Hn-1   target "hop:<exit dial addr>"
//	innermost  client <-> exit   target = the real destination, exit presents its
//	                             admission credential (#60/#69) — UNCHANGED
//
// # How the chain reaches its first peeling hop
//
// Noise_NK authenticates the responder by a static key the initiator supplies up
// front, so the client can only peel at a hop whose X25519 key it already holds.
// It does not hold the coordinator-assigned relay's: that relay is named to the
// client only by wire.RelayTag, which is deliberately non-routable (issue #56).
// So the assigned relay canNOT be a peeling hop; the client has to name the head
// of its chain itself.
//
// It names it in connect{firstHop} — a request field reserved for exactly this by
// ADR-0042 §9. The coordinator pairs the client with that node instead of choosing
// an exit for it, and the onion begins there. Three things follow, and each is a
// commitment §9 made before this code existed:
//
//   - The coordinator is told a HOP, never the terminating exit. The real exit is
//     named only inside the onion, which the coordinator cannot read.
//   - The session it mints records exitID = "" — the terminating exit is a thing it
//     does not know, and recording the hop there would charge a hop with a
//     terminator's load. A chained session is therefore invisible to exit ranking
//     rather than misattributed (cmd/coordinator/assign.go already skips empty ids).
//   - connect{country} is OMITTED on a chained request. It means "the terminating
//     exit's country" and nothing else (§9), and a chaining client resolves its own
//     exit, so the coordinator has no use for the field — and not sending it keeps
//     the user's egress jurisdiction off the wire entirely.
//
// The client resolves its terminating exit from the SIGNED coldstart snapshot
// (core/coldstart), which carries exits with their countries and is the same
// artifact hop selection already reads. That is what replaced the pre-#146 live
// per-exit list, and it is strictly better than what it replaced: signed, and never
// requested per connect.
//
// # What a chain does and does not hide
//
// For RelayHops = n, n nodes sit between client and exit — the coordinator's
// blind-splicing relay plus n-1 peeling hops:
//
//	client -> R1 (blind splice) -> H1 -> ... -> Hn-1 -> exit
//
//   - R1 sees the client's transport address and H1. Never the exit.
//   - Hi sees Hi-1 and Hi+1. Neither endpoint.
//   - Hn-1 sees Hn-2 (or R1) and the exit. Never the client.
//   - The exit sees Hn-1 and the destination. Never the client — as today.
//
// So at n >= 2 no single node sees both endpoints, PROVIDED R1 is not also one of
// the peeling hops. That proviso is real and is not hand-waving:
//
//   - An HONEST coordinator can collide by accident. pickRelay excludes only the
//     node it paired (the head), so at n >= 3 it may hand back an R1 that is also
//     H2..Hn-1 — and the last hop plus R1 in one node is client-and-exit in one
//     node. verifyChainDisjoint closes this: RelayTag is a published function of the
//     relay's id (relayTagFor), the client holds every hop's id, so it recomputes
//     the tag for each and fails the path on a match.
//   - A HOSTILE coordinator can defeat that check by sending a tag that does not
//     match the relay it actually wired, and nothing client-side can catch it: the
//     client never learns R1's identity by any other route. Against a coordinator
//     actively colluding with a hop, this file's unlinkability property does NOT
//     hold, at any depth. That is a genuine limit, recorded in ADR-0038 §7 and
//     tracked as a child issue; it is not closed here.
//
// At n = 1 (the default) R1 sees both ends, which is today's accepted behaviour,
// not a regression.
//
// It does NOT defend against a global passive adversary who can watch every link
// and correlate timing and volume — the standing limit of low-latency onion
// routing, which Tor shares (ADR-0038 §7). This targets malicious PARTICIPANTS,
// not omniscient OBSERVERS, and claims no traffic-analysis resistance.
//
// # Fail closed, always
//
// Every failure to build or verify the requested chain fails the path. None of
// them falls back to a shorter chain, and a hop count above RelayHopsMax is
// refused at construction rather than quietly clamped. A user who asked for a path
// no single relay can link and silently got a linkable one is worse off than a
// user who got an error, because they would act on an assurance they no longer
// have. That rule is why buildChain returns errors rather than truncated chains,
// why a chaining client's mode ladder drops modeDirect (an unchained path is a
// downgrade even though it leaks nothing), and why a TURN fallback fails the
// attempt. It is the single most important behavioural property in this file.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core/asn"
	"github.com/bacchus-vpn/bacchus/core/capacity"
	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/geoip"
)

// relayDirReloadInterval is the default cadence reloadRelayDirLoop re-reads
// Config.RelayDirectoryPath at (issue #27), mirroring
// admissionCRLReloadInterval's reasoning (core/exit_admission.go) and
// cmd/coordinator's own reloadRevocationsLoop: loadRelayDirectory enforces
// the snapshot's own ExpiresAt on every reload — unlike the mesh-walk
// proof-of-prior-contact check, which is legitimately stale — so this only
// needs to stay comfortably under however often an operator re-signs a
// snapshot, not race any particular TTL.
const relayDirReloadInterval = 5 * time.Minute

// Chain-construction failures. All of them fail the path rather than shortening
// the chain (see the file doc): each names a distinct reason the requested depth
// could not be honoured, so an operator can tell "my directory is too small" from
// "my directory does not list my exit."
var (
	errNoRelayDirectory = errors.New("core: relay chaining needs a signed relay directory (Config.RelayDirectory)")
	errChainTooShort    = errors.New("core: not enough distinct relay hops in the directory for the requested chain depth")
	errChainNoExit      = errors.New("core: the signed directory names no exit to terminate the chain at")
	errChainNoTURN      = errors.New("core: a chained path needs an assigned peer relay; the coordinator offered only the TURN fallback")
	errChainRelayIsHop  = errors.New("core: the assigned peer relay is also a hop in this chain, which would put one node at both ends of it")
	errHopNotInMesh     = errors.New("core: onion forward target is not a node in the signed directory")
	errHopSelfDial      = errors.New("core: onion forward target is this node itself")
	errForwardDisabled  = errors.New("core: this node does not forward onion layers")
	errForwardPeerBusy  = errors.New("core: this hop is already carrying its per-previous-hop limit of forwarded circuits")
	errForwardNodeBusy  = errors.New("core: this hop is already carrying its aggregate limit of forwarded circuits")
)

// relayHop is one node a chain can peel a layer at: its X25519 static key (the
// key the client runs Noise_NK against, so a substituted hop cannot complete the
// handshake) and the address the PREVIOUS hop dials to reach it.
type relayHop struct {
	id       string // hex X25519 public key — the node id (#12/#60)
	pub      []byte // that id decoded; PeerStatic for this hop's layer
	dial     string // host:port the previous hop dials
	operator string // coordinator-signed operator/vouch tag, for diversity (#124)

	// country is the country tag the coordinator published for this node (issue #136,
	// ADR-0042 §1). A chaining client filters terminating-exit candidates by it, which
	// is the whole of how the user's chosen country still means something once the
	// coordinator has stopped choosing the exit.
	//
	// It is NOT unconditionally coordinator-derived, and an earlier version of this
	// comment said it was. It is derived from an observed address when the coordinator
	// has a geo database and that address resolves; otherwise it is the node's own
	// -country claim, which is every node in a deployment with none staged. See
	// countryContradicted.
	country string

	// countryContradicted marks a node whose published country the coordinator itself
	// observed to disagree with where the node says it serves traffic from — signaling
	// arriving from one country while the advertised data-plane endpoint is another
	// (coldstart.CountrySignalingOnly, ADR-0042 §8). chooseChainExit refuses such a
	// node as a TERMINATING exit.
	//
	// It deliberately does not gate a node's use as a peeling HOP. A hop's country is
	// not a jurisdiction the user chose — hop diversity is operator- and AS-based (§4)
	// — so a contradicted country says nothing about a hop's fitness, and dropping it
	// would shrink the candidate set for no gain.
	countryContradicted bool

	// pairable reports whether the COORDINATOR can pair a client directly to this
	// node, i.e. it is registered as an exit with an advertised address. It gates
	// two distinct positions, for two distinct reasons:
	//
	//   - the chain's FIRST peeling hop, because that hop is reached by naming it in
	//     connect{firstHop} and the coordinator can only pair a client to a node it
	//     has as an exit. Middle hops are reached by an outbound dial from the hop
	//     before them and need no coordinator relationship at all.
	//   - the chain's TERMINATING exit, because that is what an exit is.
	//
	// The two must never be the same node — see buildChain.
	pairable bool
}

// relayDirectory is the verified, unexpired signed snapshot both chaining roles
// read: the client picks hops out of it, and a forwarding node admits a splice
// only to an address in it.
//
// Holding the parsed form (rather than re-verifying per connection) is safe
// because it is immutable once built — it is loaded once at construction and
// replaced only by a restart.
type relayDirectory struct {
	hops []relayHop

	// dialable is every address any node in the directory can be reached at. It is
	// the forwarding allow-list: an onion hop splices only to a member of this set,
	// which is what stops a relay from being turned into an open internet proxy
	// (ADR-0038 principle #4). It holds BOTH the forwarding ingress and the
	// advertised address of each entry, because a chain legitimately dials either —
	// an exit-role hop is reached at its advertise address, a relay-only hop at its
	// ingress.
	dialable map[string]bool

	// exitAddr maps an exit's id to the address a hop dials to reach it, so the
	// last layer can tell its hop how to reach the real exit.
	exitAddr map[string]string

	// as resolves a hop's OBSERVED address to the autonomous system announcing it,
	// for selectHops' diversity control (issue #23). It is the table embedded in this
	// binary (asn.Embedded, issue #55), set by loadRelayDirectory. Nil is still a
	// meaningful value — it resolves every hop to unknown, which is what the relaxed
	// rungs of selectHops' ladder exist for — but it is no longer the state a normal
	// build ships in.
	//
	// It is deliberately NOT loaded from the signed snapshot alongside the rest of
	// this struct. The whole point of #23 is that the AS is derived by the party
	// relying on it, from an address the coordinator observed but did not choose; a
	// table the coordinator also shipped would be a tag with extra steps.
	//
	// It stays a field here rather than moving to *Engine now that the distribution
	// mechanism IS picked. Embedding is not configuration — there is nothing for an
	// operator to set, no path, no flag, no fetch — so routing it through the
	// engine's config would add a knob to describe a constant. The consumer is this
	// struct, so the table is attached where this struct is built.
	as asn.Lookup

	// own is every address the directory publishes for THIS node, and it is how a
	// forwarding hop recognizes a target as itself (relayForward's self-dial guard).
	//
	// The directory is the only place that comparison can be made honestly. A hop
	// binds its ingress locally — often on a wildcard, and on whatever the OS handed
	// it when the port is 0 — while the address an upstream dials is the one the
	// COORDINATOR observed and published. Those two strings essentially never match,
	// so a guard written against the local listener would pass every real self-dial.
	own map[string]bool

	// reloadInterval is how often reloadRelayDirLoop re-reads
	// Config.RelayDirectoryPath (issue #27), captured once when the loop starts
	// (time.NewTicker is not re-consulted per tick) rather than a field on
	// *Engine — so a test can shrink it on the *relayDirectory a build produced,
	// exactly as crlReloadInterval lets a test shrink the CRL loop's cadence,
	// with no new Engine field to carry it. Set from relayDirReloadInterval by
	// every loadRelayDirectory call, including each reload's.
	reloadInterval time.Duration
}

// exitsIn returns the directory's exit-role entries in country cc, which is the
// candidate set a chaining client picks its TERMINATING exit from. cc is matched
// canonically (geoip.Canonical) so a directory tag and a user-typed -geo differ
// only by case, never by meaning; an empty cc matches every exit.
//
// This is the reader ADR-0042 §9 says core/ was missing. Removing the live
// per-exit list (#146) left the signed snapshot as the only place a client can
// learn a concrete exit id, and a chaining client needs one — it encrypts its
// innermost layer to that exit's static key, which IS its id (ADR-0009).
//
// An exit whose country the coordinator flagged as CONTRADICTED is not a candidate,
// however well its tag matches (issue #3). This is the same fail-closed rule as the
// rest of this file: a user who asked to egress in one jurisdiction and was handed an
// exit whose tag the coordinator can see describes a different machine has been given a
// weaker path than the one they asked for, and would go on acting on an assurance they
// no longer have. Refusing costs them that exit; accepting costs them the feature's
// entire point. It is scoped to CONTRADICTED rather than to merely unverified — see
// coldstart.Entry.CountryContradicted for why refusing an unverified tag would break
// every deployment with no geo database staged.
func (d *relayDirectory) exitsIn(cc string) []relayHop {
	want := geoip.Canonical(cc)
	var out []relayHop
	for _, h := range d.hops {
		if !h.pairable {
			continue
		}
		if h.countryContradicted {
			continue
		}
		if want != "" && geoip.Canonical(h.country) != want {
			continue
		}
		out = append(out, h)
	}
	return out
}

// contradictedIn counts the exit-role entries in country cc that exitsIn withheld for a
// contradicted country tag. It exists purely for diagnosis: it is read only when no
// candidate survived, so a chaining client can say which of "there are no exits there"
// and "there are exits there and none of them can be trusted to be there" it hit.
func (d *relayDirectory) contradictedIn(cc string) int {
	want := geoip.Canonical(cc)
	n := 0
	for _, h := range d.hops {
		if !h.pairable || !h.countryContradicted {
			continue
		}
		if want != "" && geoip.Canonical(h.country) != want {
			continue
		}
		n++
	}
	return n
}

// embeddedAS is the AS table this binary ships (issue #55, ADR-0044's amendments),
// resolved once and shared by every directory this process builds.
//
// A failure DEGRADES rather than refuses. Returning an error here would mean a
// client that cannot build chains at all, and ADR-0044 §3 already settled that trade
// in the other direction: with no table every hop resolves to unknown, the ladder
// falls through to its operator-only rung, and the client builds exactly the chain it
// built before AS diversity existed — reported as degraded, never silently. That is
// strictly better than not connecting.
//
// Nothing is swallowed by this. The embedded bytes cannot change between build and
// run — they are in the binary's read-only data — so the only way this fails is a
// committed table that never loaded, which is a build fault that
// TestEmbeddedTableLoads catches in CI. What is left here is defence in depth, and
// the degradation it falls back to is itself reported: buildChain emits the
// "no hop resolved" notice, which on a normal build no longer fires.
//
// The untyped nil matters. A nil *asn.Table stored in an asn.Lookup is a non-nil
// interface holding a nil pointer, which works — every Table method is nil-safe — but
// returning a plain nil interface is what asn.OfHostPort's own nil check is written
// against, and keeping the two agreed is cheaper than relying on both.
func embeddedAS() asn.Lookup {
	t, err := asn.Embedded()
	if err != nil {
		return nil
	}
	return t
}

// loadRelayDirectory verifies signed under pub and indexes it for chaining. It
// enforces expiry, unlike the mesh-walk proof-of-prior-contact check
// (coldstart.VerifySigned): a recovery proof is legitimately stale, but a hop
// directory names nodes that are supposed to answer a dial right now, and
// selecting hops out of a long-dead snapshot only builds chains that fail.
//
// A snapshot that does not verify, has expired, or names no usable hop is an
// error rather than an empty directory, so a misconfigured node fails at
// construction instead of silently never chaining.
// selfID is this node's own id, used to recognize its own entry (see
// relayDirectory.own); "" for a pure client, which never forwards and so never
// needs to.
func loadRelayDirectory(signed []byte, pub ed25519.PublicKey, selfID string, now time.Time) (*relayDirectory, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("core: relay chaining needs the coordinator snapshot public key (Config.MeshPubKey)")
	}
	snap, err := coldstart.VerifySigned(pub, signed)
	if err != nil {
		return nil, fmt.Errorf("core: relay directory: %w", err)
	}
	if now.After(snap.ExpiresAt) {
		return nil, fmt.Errorf("core: relay directory: %w", coldstart.ErrSnapshotExpired)
	}

	d := &relayDirectory{
		dialable:       map[string]bool{},
		exitAddr:       map[string]string{},
		own:            map[string]bool{},
		reloadInterval: relayDirReloadInterval,
		as:             embeddedAS(),
	}
	for _, ent := range snap.Entries {
		if selfID != "" && ent.ID == selfID {
			if ent.Addr != "" {
				d.own[ent.Addr] = true
			}
			if ent.Ingress != "" {
				d.own[ent.Ingress] = true
			}
		}
		// Every address any entry can be reached at joins the forwarding allow-list,
		// including a coordinator's — a coordinator is a mesh node, and admitting it
		// leaks nothing a hop could not already learn. What must never join is an
		// address that is not in the signed directory at all.
		if ent.Addr != "" {
			d.dialable[ent.Addr] = true
		}
		if ent.Ingress != "" {
			d.dialable[ent.Ingress] = true
		}
		if ent.Role == "exit" && ent.Addr != "" {
			d.exitAddr[ent.ID] = ent.Addr
		}

		// A peeling hop must have an X25519 id (so the client can run Noise_NK
		// against it) and an address the previous hop can dial. A relay-only node
		// qualifies through Ingress (issue #124); an exit-role node qualifies through
		// its advertise address, and only it can be a chain's first peeling hop.
		pub, err := hex.DecodeString(ent.ID)
		if err != nil || len(pub) != 32 {
			continue // a node id that is not a key cannot be authenticated as a hop
		}
		dial := ent.Ingress
		if dial == "" && ent.Role == "exit" {
			dial = ent.Addr
		}
		if dial == "" {
			continue
		}
		d.hops = append(d.hops, relayHop{
			id: ent.ID, pub: pub, dial: dial,
			operator:            ent.Operator,
			country:             ent.Country,
			countryContradicted: ent.CountryContradicted(),
			pairable:            ent.Role == "exit" && ent.Addr != "",
		})
	}
	if len(d.hops) == 0 {
		return nil, errors.New("core: relay directory names no node usable as a chain hop")
	}
	return d, nil
}

// setupRelayChaining validates a node's chaining configuration and, when it
// chains or forwards, loads the signed directory both sides need. It returns nil
// with no error for every node that does neither, which is every node in today's
// fleet.
//
// Each combination below is a construction error rather than a silent no-op,
// because the failure mode of a silent no-op here is an operator who believes
// they are running a hop or a user who believes they have a chain, and neither
// would find out. A node that will not do what it was configured to do should
// refuse to start and say why.
func setupRelayChaining(cfg Config, roles map[string]bool, now time.Time) (*relayDirectory, error) {
	wantsForward := cfg.RelayIngress != ""
	wantsChain := roles[RoleClient] && cfg.RelayHops >= 2

	// A depth above the ceiling is REFUSED, not clamped. Clamping is the silent
	// downgrade this file exists to forbid: an operator who asked for 6 hops and was
	// given 4 without failing has been handed a weaker path than the one they
	// requested, which is precisely the shape of the mistake the fail-closed rule
	// names. Refusing costs them one edit and tells them the ceiling exists.
	if cfg.RelayHops > RelayHopsMax {
		return nil, fmt.Errorf("core: RelayHops=%d exceeds RelayHopsMax=%d (ADR-0038 §6); ask for a depth in range rather than being silently given a shorter chain", cfg.RelayHops, RelayHopsMax)
	}
	if wantsForward && !roles[RoleRelay] {
		return nil, errors.New("core: RelayIngress serves onion hops and requires the relay role")
	}
	// A hop's id is the key clients authenticate it against, and it is published in a
	// signed directory that is minted periodically and cached by clients. Deriving it
	// from a fresh random keypair every start would rotate that id on every restart,
	// so every client holding a snapshot naming this node would fail its Noise_NK
	// handshake against it until a new snapshot propagated — the node would look
	// intermittently broken rather than misconfigured. An exit is already required to
	// persist its key; a forwarding relay needs the same for the same reason, and
	// nothing about -exit-key's name would tell a relay-only operator that.
	if wantsForward && !roles[RoleExit] && strings.TrimSpace(cfg.ExitKeyHex) == "" {
		return nil, errors.New("core: RelayIngress requires ExitKeyHex — a forwarding hop's node id IS its X25519 public key, and clients authenticate hops against the id published in the signed directory, so an identity regenerated on each restart makes this node unreachable as a hop until a fresh directory propagates")
	}
	if wantsForward && len(cfg.RelayDirectory) == 0 {
		// The listener would accept layers and refuse every one of them, since the
		// directory is what says which next hops are mesh nodes — and forwarding
		// without that check is what turns a relay into an open internet proxy.
		return nil, errors.New("core: RelayIngress requires RelayDirectory — a hop with no signed directory cannot tell a mesh node from an arbitrary internet host")
	}
	if wantsChain && len(cfg.RelayDirectory) == 0 {
		return nil, fmt.Errorf("core: RelayHops=%d: %w", cfg.RelayHops, errNoRelayDirectory)
	}
	if len(cfg.RelayDirectory) == 0 {
		return nil, nil
	}
	key := cfg.RelayDirectoryKey
	if len(key) == 0 {
		key = cfg.MeshPubKey // the same coordinator snapshot-signing key
	}
	return loadRelayDirectory(cfg.RelayDirectory, key, cfg.ID, now)
}

// reloadRelayDirLoop re-reads Config.RelayDirectoryPath on an interval and,
// when it reads, verifies, and is unexpired, swaps it into e.relayDir — so a
// long-lived node picks up an operator's freshly re-signed snapshot (new
// hops, a renewed expiry) without a restart (issue #27), the client-side
// mirror of cmd/coordinator's own reloadRevocationsLoop, and the same shape
// as this engine's own reloadCRLLoop (core/exit_admission.go). Runs only
// when a path is configured and this engine already holds a directory to
// refresh (both checked by the caller, Start). Exits on Stop.
//
// A read, verify, or expiry failure is logged as a non-fatal event and the
// previously loaded directory is kept — the same fail-safe posture as
// reloadCRL and the coordinator's own loop: a transient misread (an operator
// mid-write) or an operator late to re-sign a lapsed snapshot must not
// silently degrade a hop's forwarding allow-list to "nothing" or a client's
// hop selection to "no chaining" (this file's fail-closed rule, at the top),
// and must not take down an otherwise healthy connection either.
func (e *Engine) reloadRelayDirLoop() {
	defer e.wg.Done()
	// The interval is read once, from whichever *relayDirectory was current
	// when this loop started, and then owned by the ticker for the loop's
	// whole life — a later reload's *relayDirectory carries the same default
	// (loadRelayDirectory always sets it), but nothing here re-consults it
	// per tick, matching how time.NewTicker itself works. This is what lets a
	// test shrink the interval (on the *relayDirectory a build produced)
	// with no Engine field of its own — see relayDirectory.reloadInterval.
	interval := relayDirReloadInterval
	if d := e.relayDir.Load(); d != nil && d.reloadInterval > 0 {
		interval = d.reloadInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			e.reloadRelayDir(time.Now())
		}
	}
}

// reloadRelayDir performs a single reload attempt against clock now; split
// out from reloadRelayDirLoop, and parameterized on now rather than reading
// time.Now() itself, so a test can drive it deterministically without a
// ticker (matching reloadCRL). It re-reads Config.RelayDirectoryPath from
// disk and runs it through the exact same loadRelayDirectory this engine's
// construction-time load used — same signature verification, same expiry
// check, same "a node id that is not a key cannot be authenticated as a
// hop" filtering — so a reload can only ever produce a directory exactly as
// strict as New's, never a looser one.
//
// On any failure the PREVIOUS directory is left in place: e.relayDir.Store
// is reached only on the success path, so a failed reload is a pure no-op
// against the live directory, never a partial or empty one — the same
// guarantee construction itself makes (loadRelayDirectory returns an error
// rather than a directory with no usable hop).
func (e *Engine) reloadRelayDir(now time.Time) {
	b, err := os.ReadFile(e.cfg.RelayDirectoryPath)
	if err != nil {
		e.emit(EventError, "", "relay directory: reload from %s: %v", e.cfg.RelayDirectoryPath, err)
		return
	}
	key := e.cfg.RelayDirectoryKey
	if len(key) == 0 {
		key = e.cfg.MeshPubKey
	}
	fresh, err := loadRelayDirectory(b, key, e.cfg.ID, now)
	if err != nil {
		e.emit(EventError, "", "relay directory: reload from %s: %v", e.cfg.RelayDirectoryPath, err)
		return
	}
	e.relayDir.Store(fresh)
	e.emit(EventInfo, "", "relay directory: reloaded from %s (%d hops, %d dialable addresses)", e.cfg.RelayDirectoryPath, len(fresh.hops), len(fresh.dialable))
}

// isSelfAddr reports whether a names this node. It is the self-dial guard's
// question, and the directory answers it (see relayDirectory.own); the configured
// literals are a second chance for a node whose own entry has not yet appeared in
// the snapshot it is holding, which is the ordinary state for the first few minutes
// of a fresh node's life.
func (e *Engine) isSelfAddr(a string) bool {
	if a == "" {
		return false
	}
	if d := e.relayDir.Load(); d != nil && d.own[a] {
		return true
	}
	return a == e.cfg.RelayIngress || (e.cfg.Advertise != "" && a == e.cfg.Advertise)
}

// chainDepth is the configured hop count with the unset/zero case normalized: 0
// and 1 both mean today's single hop.
//
// It does NOT apply the RelayHopsMax ceiling. That is enforced once, at
// construction (setupRelayChaining), as a refusal — because clamping here would be
// the silent downgrade the file doc forbids, and because a bound that is checked in
// one place cannot disagree with itself. ADR-0038 §6 is why a client-side bound is
// meaningful at all: the client assembles its own chain and a coordinator has
// nowhere to inject an extra hop, since it never sees the inner layers.
func chainDepth(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// chaining reports whether this engine builds onion chains as a CLIENT — i.e. the
// configured depth is 2 or more.
//
// It gates the client half of this file only. The relay half is gated separately by
// forwardOn, and the two are independent: a node with RelayHops unset still runs
// setupRelayChaining, loadRelayDirectory, the ingress listener and relayForward if
// its operator opted it in as a hop, and relayForward is that node's entire hot
// path. "Default 1 == today" is a claim about the CLIENT's dial path — dialE2E is a
// single call through to clientHandshake with no plan — not about the file.
func (e *Engine) chaining() bool { return chainDepth(e.cfg.RelayHops) >= 2 }

// chainPlan is one path's assembled chain: the peeling sequence in order, and the
// terminating exit that only the innermost layer names. The client resolves BOTH
// ends itself — the coordinator contributes the blind-splicing relay and nothing
// else.
type chainPlan struct {
	hops []relayHop // H1..Hn-1, in the order they are peeled

	// The terminating exit. exitID never leaves this process: it is here so the
	// client can log and account for where it actually egressed, and putting it on
	// any wire is the one thing this whole file is built to avoid.
	exitID  string
	exitPub []byte // exitID decoded — the innermost layer's PeerStatic
	exitDia string // the address the LAST hop dials to reach the exit
}

// firstHopID is what the client puts in connect{firstHop} to be wired to the head
// of its chain (ADR-0042 §9). On a nil plan it is "" — the field is simply absent,
// and an unchained connect is byte-identical to what it was before this feature.
//
// There is deliberately no fallback to a real exit id here. The predecessor of this
// method took the real exit as an argument and returned it when the plan was nil,
// which meant the single most sensitive value in the design sat one nil-check away
// from the wire. A method that has no exit id to leak cannot leak one.
func (p *chainPlan) firstHopID() string {
	if p == nil || len(p.hops) == 0 {
		return ""
	}
	return p.hops[0].id
}

// chainFor assembles the chain for one connect attempt in the given mode, or
// returns a nil plan when this attempt does not chain — which is every attempt on
// an engine at the default depth.
//
// country is the user's chosen egress country and is used HERE, client-side, to
// pick the terminating exit out of the signed directory (ADR-0042 §9). It is not
// sent on a chained connect; see attemptWith.
//
// mode is expected to be modeRelay: a chaining client's ladder drops modeDirect
// (see reconnectModes), because chaining is defined over the relay tier — the
// coordinator's blind-splicing relay is the node that hides the client from H1.
// The mode check stays as a belt-and-braces guard so that a caller which
// reintroduced a direct tier would get an unchained plan and be caught by the
// modeDirect gate, rather than silently building an onion whose head sees the
// client's own address.
//
// It is called BEFORE the connect is sent, because the chain's first peeling hop is
// what the coordinator is asked to pair us with. The other two halves of the
// decision — that the coordinator gave us a peer relay rather than the TURN
// fallback, and that the relay it gave us is not itself one of our hops — can only
// be checked against the reply, and live in verifyChainDisjoint / attemptWith.
func (e *Engine) chainFor(mode, country string) (*chainPlan, error) {
	if mode != modeRelay || !e.chaining() {
		return nil, nil
	}
	return e.buildChain(chainDepth(e.cfg.RelayHops), country)
}

// buildChain picks a terminating exit in country and the peeling hops that reach
// it, for a depth-n chain.
//
// n counts every node between the client and the exit, and the coordinator's
// blind-splicing relay is one of them, so n-1 hops are chosen here. The exit is
// excluded from the hop candidate set (a chain that doubles back through its own
// exit hides nothing), and no node is used twice.
func (e *Engine) buildChain(n int, country string) (*chainPlan, error) {
	// Loaded ONCE and threaded through the rest of this call (rather than each
	// helper re-reading e.relayDir itself) so one chain build sees a single,
	// self-consistent directory generation even if a reload (issue #27) lands
	// concurrently — every *relayDirectory a Load() can return is independently
	// immutable, so mixing exit/hop choices across two different Loads would be
	// safe (a dial-time Noise_NK handshake still gates everything), but there is
	// no reason to accept even that inconsistency when one Load suffices.
	d := e.relayDir.Load()
	if d == nil {
		return nil, errNoRelayDirectory
	}
	exit, err := e.chooseChainExit(d, country)
	if err != nil {
		return nil, err
	}
	hops, div, err := selectHops(d.hops, n-1, exit.id, d.as)
	if err != nil {
		return nil, err
	}
	// Say so when the chain is weaker than its depth implies. A fallback nobody can
	// see is indistinguishable from the control working, which is the failure mode
	// #23 names — so the degradation is REPORTED, not just permitted.
	//
	// The level splits on whether the table was working. A table that could not keep
	// two hops apart is a real weakening on a real deployment and an operator can act
	// on it (add a hop in another network); nothing resolving AT ALL is the older,
	// blunter condition and stays at Info.
	//
	// That split was drawn (#52) when no build shipped a table and the Info path was
	// the normal case. Since #55 embedded one it is the abnormal case — a normal
	// client resolves its hops — but the level is deliberately unchanged. What
	// reaches Info now is a chain of hops NONE of which the table places: addresses
	// in unrouted or documentation space, which is every local smoke stack and every
	// developer box. Promoting that to Error would cry wolf exactly where it did
	// before, just for a different reason.
	if div.degraded() {
		kind := EventError
		if div.resolved == 0 {
			kind = EventInfo
		}
		e.emit(kind, "", "relay chain (%d hops): %s", n, div.describe())
	}
	return &chainPlan{
		hops:    hops,
		exitID:  exit.id,
		exitPub: exit.pub,
		exitDia: d.exitAddr[exit.id],
	}, nil
}

// chooseChainExit picks the chain's terminating exit at random from the signed
// directory's exits in country.
//
// Random, not "best": a chaining client picks its own exit, so a deterministic rule
// would give every client running this build the same answer for a given country
// and directory — reintroducing, client-side, precisely the stable exit preference
// ADR-0042 §2 removed from the wire. It would also concentrate load on whichever
// node the rule happened to favour, with no coordinator able to move it, since a
// chained session is invisible to exit ranking (§9).
//
// The address is read from exitAddr rather than from the candidate's dial field: a
// terminating exit must be reached where it terminates end-to-end channels (its
// advertised address), not at a forwarding ingress it might also publish.
func (e *Engine) chooseChainExit(d *relayDirectory, country string) (relayHop, error) {
	cand := d.exitsIn(country)
	// An exit whose advertised address the directory does not carry cannot be
	// reached by the last hop, so it is not a candidate however well it matches.
	usable := cand[:0:0]
	for _, h := range cand {
		if d.exitAddr[h.id] != "" {
			usable = append(usable, h)
		}
	}
	if len(usable) == 0 {
		// Name the withheld ones. "No exit in NL" when the directory plainly lists
		// exits in NL is the kind of failure an operator chases in the wrong place for
		// an afternoon; the actual condition — this coordinator published a country for
		// those exits that it can see disagrees with where they serve traffic from — is
		// both diagnosable and actionable, and it is not the user's fault.
		if n := d.contradictedIn(country); n > 0 {
			return relayHop{}, fmt.Errorf("%w: none usable in %q (%d exit(s) there carry a country the coordinator itself flagged as describing where they SIGNAL from, not where they egress, and cannot be trusted to choose a jurisdiction — issue #3, ADR-0042 §8)",
				errChainNoExit, country, n)
		}
		return relayHop{}, fmt.Errorf("%w: none in %q", errChainNoExit, country)
	}
	i, err := randIndex(len(usable))
	if err != nil {
		return relayHop{}, err
	}
	return usable[i], nil
}

// selectHops chooses want distinct hops from cand, excluding the chain's own
// exit, spreading them across operators, and ordering them randomly.
//
// Operator diversity is the anti-correlation control (ADR-0038 §6): controlling
// the FIRST and LAST hop of a chain re-links client to exit, so two hops of one
// chain must not sit in the same operator's vouch subtree. The tag is
// coordinator-signed and not a node self-report (#124), which is what makes it
// worth anything — a node asked to state its own operator would simply lie.
//
// # Exactly how far it goes, which is less far than "enforced"
//
// It constrains a PAIR of hops, so it does nothing at depth 2, where there is one
// peeling hop and nothing for it to differ from. It first bites at depth 3.
//
// It constrains only hops the coordinator has an operator assignment for.
// operators[id] is "" for every node absent from the coordinator's curated
// operators file, and an empty tag is never treated as a collision — two unlabeled
// hops may freely share an operator. On a deployment with no operators file the
// control is therefore INERT, not merely weak. That is a deliberate choice over the
// alternative, which is refusing to build chains on a network nobody has curated.
//
// And it is not the load-bearing signal even when it does apply. Real network
// diversity is AS diversity, and an AS number is deliberately absent from the
// signed directory because neither a node nor a coordinator can be trusted to
// assert one (the ADR-0038 #124 amendment says so explicitly).
//
// # AS diversity, which IS the load-bearing signal (issue #23)
//
// Each hop's AS is derived here, from the OBSERVED address the directory carries for
// it, against an independent table the coordinator did not supply (core/asn). That
// address is the coordinator's own observation joined to a self-reported PORT — a
// node cannot assert the host half, so it cannot claim to sit in an AS it does not
// occupy (cmd/coordinator's buildSnapshot, coldstart.Entry.Ingress). Deriving rather
// than reading is the whole of #23: a signed AS tag would be free for a Sybil
// operator to fabricate, and an address is not, because the address has to actually
// route or the hop is simply unreachable.
//
// Two hops of one chain must not sit in one AS, for the same first-and-last-hop
// correlation reason operator diversity exists — but this catches the case operator
// diversity structurally cannot: one operator spread across several UNLABELED
// directory entries, which is precisely what a Sybil looks like.
//
// # The unknown AS is pooled, never treated as diverse
//
// A hop whose address the table cannot place (no table staged, an address absent
// from it, or a loopback/RFC1918 address no AS announces) is ACCEPTED but CONTRIBUTES
// NO DIVERSITY, which is two rules working together:
//
//   - It cannot satisfy a diversity pass. Only a hop with a resolved, unused AS
//     can, so a resolvable candidate is always preferred while one exists and an
//     attacker gains nothing by occupying address space the table does not cover.
//   - Unresolved hops share ONE bucket, so two of them collide with each other
//     rather than counting as two ASes.
//
// It is still placeable by the relaxed passes, which is what makes this
// accept-but-do-not-count rather than reject — and any chain leaning on one is
// reported as degraded, because "these hops are in different networks" is precisely
// the claim that has not been established about it.
//
// This is the opposite of how the operator tag above treats an empty value, and the
// asymmetry is deliberate rather than an inconsistency. An absent operator tag means
// the COORDINATOR has not curated a file — an administrative gap that applies to
// honest and hostile nodes alike, and one no attacker chooses. An unresolvable
// address is different in kind: the attacker picks the address. Counting unknown as
// diverse would therefore hand a Sybil operator a whole chain's worth of free
// diversity for the cost of using address space the table does not cover, inverting
// the exact control it is feeding. Pooling costs an honest node in unmapped space
// the chance to sit beside another such node; that is the cheaper mistake, and it is
// the one this makes.
//
// It also lands the no-table case where it belongs. With no table every hop is
// unknown, so every hop collides, so the ladder below falls through to its relaxed
// pass and produces exactly the chain this function produced before #23 — degraded
// through the documented, REPORTED path rather than by accident. See hopDiversity.
//
// # The ladder, and why the two constraints degrade independently
//
// Four passes rather than the two operator diversity used alone — the honest lattice
// of two constraints that can each hold or not, ordered by which is worth more:
//
//  0. AS-distinct AND operator-distinct — the chain worth having.
//  1. AS-distinct only.
//  2. operator-distinct only.
//  3. neither.
//
// Passes 1 and 2 are both needed, and collapsing either into "strict, then relaxed"
// breaks something real. Without pass 1, a directory that can supply AS diversity
// but not operator diversity gives up BOTH — sacrificing the load-bearing control to
// satisfy the advisory one. Without pass 2, the no-table case is worse than useless:
// every hop pools into unknown, so no pass demanding AS distinctness can place
// anything, and the fill would fall straight through to unconstrained — silently
// switching OFF the operator diversity that has been running since #124. Adding a
// control must not remove one, so the ladder keeps a rung where operator diversity
// stands alone.
//
// The order between them is the ranking, and it is the one #23 states: AS diversity
// is load-bearing and operator diversity is advisory, so operator is dropped first
// (pass 1) and AS last (pass 2).
//
// The first hop gets one extra constraint: it must be pairable (exit-registered),
// because it is reached by being named in connect{firstHop}.
func selectHops(cand []relayHop, want int, excludeID string, lookup asn.Lookup) ([]relayHop, hopDiversity, error) {
	if want <= 0 {
		return nil, hopDiversity{}, nil
	}
	pool := make([]relayHop, 0, len(cand))
	for _, h := range cand {
		if h.id != excludeID {
			pool = append(pool, h)
		}
	}
	if err := shuffleHops(pool); err != nil {
		return nil, hopDiversity{}, err
	}

	// The head is chosen FIRST, on its own, because it carries a constraint no
	// other position does: it must be pairable. Folding that into the general fill
	// below would make selection order-dependent — a shuffle that happened to put
	// non-pairable candidates first would skip them while the chain was empty and
	// never reconsider them, silently costing operator diversity that the directory
	// could in fact supply.
	out := make([]relayHop, 0, want)
	usedOp := map[string]bool{}
	usedID := map[string]bool{}
	usedAS := map[string]bool{}
	var div hopDiversity
	take := func(h relayHop) {
		key, resolved := hopASKey(h, lookup)
		// The collision is recorded where it HAPPENS rather than inferred from which
		// pass placed the hop, so the report describes the chain that was built and
		// not the route the loop took to build it.
		if usedAS[key] {
			div.asRepeated = true
		}
		if h.operator != "" && usedOp[h.operator] {
			div.opRepeated = true
		}
		if resolved {
			div.resolved++
		} else {
			div.unresolved++
		}
		out = append(out, h)
		usedID[h.id] = true
		usedAS[key] = true
		if h.operator != "" {
			usedOp[h.operator] = true
		}
	}
	for _, h := range pool {
		if h.pairable {
			take(h)
			break
		}
	}
	if len(out) == 0 {
		return nil, hopDiversity{}, fmt.Errorf("%w: no directory entry can head a chain (the head must be one the coordinator can pair a client to)", errChainTooShort)
	}

	// Then fill the rest down the ladder documented above: the best chain the
	// directory can supply, dropping the advisory constraint before the load-bearing
	// one, and allowing a repeat rather than refusing to connect. A repeated AS is a
	// weaker chain, but it still hides the exit from the coordinator and from every
	// node that operator does not run; in a small mesh, refusing outright would be
	// the worse trade. Every outcome is reachable, so none is silently assumed — and
	// the one that was reached is returned, not discarded.
	for pass := 0; pass < 4 && len(out) < want; pass++ {
		needAS := pass == 0 || pass == 1
		needOp := pass == 0 || pass == 2
		for _, h := range pool {
			if len(out) == want {
				break
			}
			if usedID[h.id] {
				continue
			}
			if needAS {
				// An unresolved hop can never SATISFY a diversity pass — "does not
				// count toward diversity" is the whole decision, and a hop the table
				// could not place contributes no diversity to count. It stays
				// available to the relaxed passes below, which is what makes it
				// accepted-but-not-counted rather than rejected outright.
				key, resolved := hopASKey(h, lookup)
				if !resolved || usedAS[key] {
					continue
				}
			}
			if needOp && h.operator != "" && usedOp[h.operator] {
				continue
			}
			take(h)
		}
	}
	if len(out) < want {
		return nil, hopDiversity{}, fmt.Errorf("%w: need %d, found %d", errChainTooShort, want, len(out))
	}
	return out, div, nil
}

// unknownASKey is the single bucket every hop the table cannot place falls into.
//
// One shared value, so two unresolved hops collide with each other — see selectHops
// on why unknown must never read as diverse. It is not a valid asn.AS rendering
// (those are always "AS" followed by digits), so it can never collide with a
// resolved answer.
const unknownASKey = "?"

// hopASKey is the diversity bucket a hop falls in, and whether the table actually
// placed it.
//
// The address is the hop's dial address, which is where the directory says this hop
// RECEIVES traffic — a relay's coordinator-observed ingress, or an exit's advertised
// address. That is the right input and not merely the available one: correlation
// risk is a property of the network a hop's traffic actually crosses, so the address
// upstream dials is exactly the address whose AS matters.
func hopASKey(h relayHop, lookup asn.Lookup) (string, bool) {
	if a, ok := asn.OfHostPort(lookup, h.dial); ok {
		return a.String(), true
	}
	return unknownASKey, false
}

// hopDiversity is what selectHops ACHIEVED, as opposed to what it was asked for.
//
// It exists because a degraded chain and a strong one are otherwise the same value —
// a []relayHop of the right length — and a security control that can quietly stop
// applying while its caller reports success is not a control. Operator diversity has
// degraded silently this way since it was written; #23 does not extend that to the
// signal it calls load-bearing. buildChain reports it.
//
// Every field describes the chain that was returned, so the zero value means "asked
// for nothing, achieved nothing" and is only correct for want <= 0.
type hopDiversity struct {
	// asRepeated: two hops share an AS bucket — either one resolved AS, or the
	// pooled unknown. The chain was built anyway; this is the fallback being taken.
	asRepeated bool

	// opRepeated: two hops share a coordinator-assigned operator tag.
	opRepeated bool

	// resolved and unresolved count the chosen hops the table could and could not
	// place. resolved == 0 on a non-empty chain is worth telling apart from a table
	// that failed on one address: since #55 embedded a table in every client, the
	// first means these hops are all in space no AS announces — a local stack on
	// loopback, or documentation addresses — while the second is one hop an operator
	// can go and look at.
	resolved, unresolved int
}

// degraded reports whether this chain's AS diversity is something the client can
// actually vouch for, which is the condition worth saying out loud.
//
// An unplaced hop counts as degraded even when no bucket visibly repeated: the
// control's claim is "these hops are in different networks", and about a hop the
// table could not place, that claim has not been established. Reporting only literal
// collisions would let a chain whose diversity is merely UNKNOWN read as one whose
// diversity is known-good, which is the same silent overstatement the whole card is
// about.
//
// A repeated operator alone is not degradation here: that control is advisory, it is
// inert on any deployment with no operators file, and reporting it would fire
// constantly while saying nothing about the load-bearing signal.
func (d hopDiversity) degraded() bool { return d.asRepeated || d.unresolved > 0 }

// describe renders the degradation for an operator or a user reading the event log.
// Empty when nothing was given up.
//
// The three cases are three different people's problems, so they do not share a
// sentence: nothing resolving is the distribution decision nobody has taken
// (ADR-0044), a partial resolution is an address an operator can look at, and a
// clean collision is a directory too small to spread this chain.
func (d hopDiversity) describe() string {
	if !d.degraded() {
		return ""
	}
	if d.resolved == 0 {
		return fmt.Sprintf("AS diversity is NOT being enforced: no hop resolved to an autonomous system (no table is loaded, or none of these addresses is in it), so all %d hop(s) are treated as ONE network (issue #23, ADR-0044). The chain is what it was before AS diversity existed — operator diversity only", d.unresolved)
	}
	if d.unresolved > 0 {
		return fmt.Sprintf("AS diversity RELAXED: %d hop(s) resolved, but %d could not be placed in any autonomous system and count as ONE network, so two hops of this chain may share one", d.resolved, d.unresolved)
	}
	return fmt.Sprintf("AS diversity RELAXED: the directory could not supply %d hops in distinct autonomous systems, so two hops of this chain share one network — weaker against first-and-last-hop correlation than the depth suggests", d.resolved)
}

// shuffleHops randomizes hop order with a crypto/rand Fisher-Yates. A fresh
// random chain per connect denies a Sybil a fixed target and spreads observation,
// the same reasoning that keeps the coordinator's own pickRelay random
// (ADR-0033); a predictable order would let an adversary who learns one chain
// predict the next. Chains are never persisted for the same reason (ADR-0038 §5).
func shuffleHops(h []relayHop) error {
	for i := len(h) - 1; i > 0; i-- {
		k, err := randIndex(i + 1)
		if err != nil {
			return fmt.Errorf("core: chain hop shuffle: %w", err)
		}
		h[i], h[k] = h[k], h[i]
	}
	return nil
}

// randIndex returns a uniform index in [0, n) from crypto/rand. Every choice this
// file makes about a path — hop order, which exit terminates it — goes through it,
// so none of them can be predicted by an adversary who has seen previous chains
// (ADR-0038 §5: chains are never persisted, for the same reason).
func randIndex(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("core: chain: no candidates to choose from")
	}
	j, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("core: chain random choice: %w", err)
	}
	return int(j.Int64()), nil
}

// relayTagFor recomputes the coordinator's opaque peer-relay tag (issue #56) for a
// node id the client already holds.
//
// The derivation is duplicated from cmd/coordinator's relayTag rather than
// imported, exactly as the wire literals are (see wire's doc: the two binaries
// deliberately do not import each other). TestRelayTagWireContract pins the two
// copies together so they cannot drift, the same way TestQuotaStateWireContract
// pins the quota literals.
//
// The tag is one-way, so it cannot be turned back into a node id — which is the
// property #56 wanted. It is not, however, unguessable FORWARD: a client that
// already knows a specific node's id can compute that node's tag and compare. That
// asymmetry is what verifyChainDisjoint uses, and it costs #56 nothing, because a
// client can only test ids it already has.
func relayTagFor(id string) string {
	sum := sha256.Sum256(append([]byte("bacchus-relay-tag\x00"), id...))
	return hex.EncodeToString(sum[:8])
}

// verifyChainDisjoint fails a chained attempt whose assigned peer relay is also one
// of the chain's own peeling hops.
//
// R1 sees the client's address; the LAST hop sees the exit. One node in both roles
// is one node holding both ends of the path, which is the single property the chain
// was built to deny. An honest coordinator can produce this by accident: pickRelay
// excludes only the node it paired the client to — the head — so at depth 3 and
// above any later hop is a legitimate relay candidate and may be handed straight
// back. Every hop is checked, not just the head, because it is the LAST hop that
// makes the collision fatal.
//
// # What this does not do
//
// The tag is the coordinator's own statement about which relay it assigned. A
// HOSTILE coordinator that wants the collision simply reports a different tag, or
// none, and this check passes; the client has no other way to learn R1's identity,
// so there is nothing left to compare. Against a coordinator colluding with a hop
// the chain's unlinkability does not hold at any depth, and this function does not
// change that — it closes the accident, not the attack. See the file doc and
// ADR-0038 §7.
func verifyChainDisjoint(plan *chainPlan, relayTag string) error {
	if plan == nil || relayTag == "" {
		return nil
	}
	for i, h := range plan.hops {
		if relayTagFor(h.id) == relayTag {
			return fmt.Errorf("%w: hop %d/%d (%s)", errChainRelayIsHop, i+1, len(plan.hops), shortID(h.id))
		}
	}
	return nil
}

// addrPort is the port a listener actually bound, so a relay advertises the port
// it is really on rather than the one it was configured with. The two differ
// whenever RelayIngress names port 0 — an OS-assigned port, which is how tests
// bind and how an operator asks for any free port.
func addrPort(a net.Addr) int {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.Port
	}
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// chainedSession is an established session tagged with the chain that was used to
// pair it. The plan has to travel with the session because it is chosen per
// connect (hops are random and never persisted, ADR-0038 §5) and because its head
// determined which node the coordinator wired us to — so it cannot be recomputed
// later from the candidate alone.
//
// Carrying it here rather than in another return value keeps both failover
// mechanisms and the whole SOCKS path unchanged: they already move Sessions
// around, and the embedded interface forwards every method, so a chained session
// is a Session everywhere that does not specifically ask.
type chainedSession struct {
	Session
	plan *chainPlan
}

// withChain tags sess with plan, or returns sess untouched when there is no chain
// — so the unchained path allocates nothing and stays the exact value it was.
func withChain(sess Session, plan *chainPlan) Session {
	if plan == nil {
		return sess
	}
	return &chainedSession{Session: sess, plan: plan}
}

// planOf recovers the chain a session was paired with, or nil for an ordinary
// unchained session (every session today). Read at the point an end-to-end
// channel is opened, so a failover that swaps the session underneath a listener
// also swaps the chain, with no separate bookkeeping to keep in step.
func planOf(sess Session) *chainPlan {
	if cs, ok := sess.(*chainedSession); ok {
		return cs.plan
	}
	return nil
}

// ---------- client side: the telescoping dial ----------

// dialE2E opens the end-to-end channel to the exit over raw. It is the single
// seam every client-side data path goes through, so chaining applies uniformly to
// SOCKS CONNECT, UDP ASSOCIATE, and the pool's sustained-flow probe rather than
// to whichever one was wired first.
//
// With no plan — which is every path today, and every direct-tier path always —
// it IS clientHandshake, called with the same arguments as before. That identity
// is why "default 1 == today" holds by construction rather than by test: at depth
// 1 there is no plan, and this function is a single call through.
func (e *Engine) dialE2E(raw io.ReadWriteCloser, plan *chainPlan, exitPub []byte, target string) (*noiseConn, error) {
	if plan == nil || len(plan.hops) == 0 {
		return clientHandshake(raw, exitPub, target, e.exitVerifyFunc(exitPub))
	}
	return e.dialChain(raw, plan, target)
}

// dialChain telescopes the onion (ADR-0038 §4.1). Each layer is built THROUGH the
// previous one, so hop i's handshake and target travel as opaque ciphertext to
// every hop before it — which is what keeps a hop from learning anything past its
// own successor.
//
// The innermost handshake is the unedited clientHandshake call, with the same
// exitVerifyFunc every unchained path uses, passed the same thing every unchained
// path passes it: the static key of the exit THIS handshake is against. That is the
// whole of the #60/#69 argument — the exit-admission credential is verified over a
// channel that terminates at the exit, and the layers around it are outside that
// channel, so the check is bit-identical whether it crossed 0, 1, or n hops.
//
// Handing it plan.exitPub is load-bearing rather than cosmetic. A nil key
// hex-encodes to "", which admission.accept reads as a BEARER credential and skips
// the subject-binding check for entirely: signature, window, role and revocation
// would all still be checked, but "this credential belongs to the exit I am
// actually talking to" — the #60 property — would not be. The plan is the only
// place a chained path holds that key.
//
// Layers are verified outermost-first, so a bad hop fails before the client
// tunnels anything through it, and the exit's admission check is last and still
// gates sending the real destination.
//
// Each hop layer now carries the same kind of check the exit layer already did
// (issue #26): hopVerifyFunc verifies the hop's own admission credential
// against Config.RelayAdmissionPubKey, bound to that hop's key exactly as the
// exit check is bound to plan.exitPub. The verifier is built once, before the
// loop, and reused for every hop in the chain — they share one anchor — so a
// malformed RelayAdmissionPubKey fails here rather than partway through a
// chain already half-dialed. An empty RelayAdmissionPubKey yields a nil
// callback (fail-open), independent of whether an exit anchor is set; see
// Config.RelayAdmissionPubKey's doc for why the two are deliberately separate
// gates rather than one implying the other.
//
// A hop whose credential fails this check — revoked, expired, wrong role,
// wrong subject, or simply absent — fails the WHOLE chain. Verification runs as
// part of completing that hop's own clientHandshake, so its error propagates
// through exactly the same path a substituted hop's failed Noise handshake
// already takes below, with no special case added for it. De-selecting just the
// bad hop and retrying with another was the alternative the issue named, and it
// was set aside here: it would need candidate-exclusion state that lives in
// hop SELECTION, above this function, whereas fail-closed needs nothing new and
// already matches how every other verification failure in dialChain behaves.
func (e *Engine) dialChain(raw io.ReadWriteCloser, plan *chainPlan, target string) (*noiseConn, error) {
	// Built once and shared across every hop below rather than per-hop: all of
	// them are checked against the same anchor, and building it here means a
	// malformed anchor is reported before hop 1 is ever dialed.
	hv, err := buildRelayVerifier(e.cfg.RelayAdmissionPubKey, e.clientCRL)
	if err != nil {
		return nil, fmt.Errorf("core: chain: %w", err)
	}

	cur := raw
	for i, h := range plan.hops {
		// Each hop is told only where to send the next layer: the hop after it, or —
		// for the last one — the exit. It is never told the destination, the client,
		// or anything else about the path.
		next := plan.exitDia
		if i+1 < len(plan.hops) {
			next = plan.hops[i+1].dial
		}
		// A hop is authenticated by holding the X25519 key the client selected from
		// the SIGNED directory — a substituted hop cannot do that, and its handshake
		// simply fails below, independent of hopVerifyFunc's admission check (issue
		// #26): the key check says "this is the hop I meant to dial", the credential
		// check says "and it was admitted for the relay role".
		// Sniff the stream this layer is dialed OVER, which is the previous hop's
		// channel: a refusal found here was sealed by hop i-1 (see refusalSniffer),
		// so it is reported against that hop and not against the one whose handshake
		// happened to be in flight when it arrived.
		sn := newRefusalSniffer(cur)
		nc, err := clientHandshake(sn, h.pub, hopTargetPrefix+next, hopVerifyFunc(hv, h.pub))
		if err != nil {
			if cur != raw {
				_ = cur.Close()
			}
			if i > 0 {
				if reason, ok := sn.refusal(); ok {
					prev := plan.hops[i-1]
					return nil, fmt.Errorf("core: chain hop %d/%d: %w", i, len(plan.hops), &hopRefusedError{hop: shortID(prev.id), reason: reason})
				}
			}
			return nil, fmt.Errorf("core: chain hop %d/%d (%s): %w", i+1, len(plan.hops), shortID(h.id), err)
		}
		cur = nc
	}
	// The innermost layer: unchanged, and deliberately so — except that it is the
	// layer the LAST hop's refusal surfaces on, since that hop's channel is what
	// this one is dialed over.
	sn := newRefusalSniffer(cur)
	nc, err := clientHandshake(sn, plan.exitPub, target, e.exitVerifyFunc(plan.exitPub))
	if err != nil {
		if cur != raw {
			_ = cur.Close()
		}
		if len(plan.hops) > 0 {
			if reason, ok := sn.refusal(); ok {
				last := plan.hops[len(plan.hops)-1]
				return nil, fmt.Errorf("core: chain hop %d/%d: %w", len(plan.hops), len(plan.hops), &hopRefusedError{hop: shortID(last.id), reason: reason})
			}
		}
		return nil, fmt.Errorf("core: chain exit layer: %w", err)
	}
	return nc, nil
}

// ---------- a hop's refusal, said out loud to the client ----------

// A hop that declines to forward has to tell somebody, and the fail-closed rule
// (ADR-0038, "Fail closed — the rule that governs every failure in the feature")
// already settles the CONSEQUENCE: the path fails and selection moves on, never a
// silent fall back to a shorter chain. What it does not settle is whether the
// client can tell a deliberate refusal from a hop that is simply dead, and before
// issue #25 it could not: both arrived as the same handshake failure on the next
// layer. That conflation is worth removing, because the two want opposite
// responses — a dead hop should be dropped from the client's candidates, while a
// saturated one is a fine hop the client should come back to.
//
// # The channel this travels on already exists, and it is the right one
//
// A hop shares a Noise_NK channel with the CLIENT, not with its neighbours: the
// telescoped construction means layer i is negotiated end-to-end between the
// client and hop i, and every hop before it only splices that ciphertext (see this
// file's header diagram). So a hop can seal a refusal to the client directly. The
// result is authenticated (only the holder of the key the client picked out of the
// SIGNED directory can produce it), confidential to every other hop in the path,
// and — the property that matters most here — it carries NO new information to
// anyone. It travels client<->hop only, on a channel that already exists, and the
// only party who learns anything is the client, about a hop it selected itself.
//
// This is exactly why the refusal is a message and not a field. A field in the
// onion layer would be read by every hop; this is read by one endpoint.
//
// # Every deliberate refusal carries it, and that is load-bearing
//
// The signal's meaning is "a hop decided", so its ABSENCE has to mean "no hop
// decided" — i.e. the path broke. If only the new occupancy refusals were
// signalled, silence would still mean either "dead hop" or "refused for one of the
// older reasons", and the client would have gained nothing it can act on. So every
// return in relayForward that is a decision emits one.
const (
	// hopRefusedMagic prefixes a refusal body. A real msg2 at this position is a
	// 32-byte X25519 ephemeral followed by an AEAD tag, so a fixed prefix this long
	// cannot be produced by one except with probability 2^-160.
	hopRefusedMagic = "\x00bacchus-hop-refused\x00"
	// maxHopRefusalReason bounds the reason token, so the client's sniff buffer is a
	// small constant rather than something an upstream can grow.
	maxHopRefusalReason = 32
)

// Refusal reasons. They are short stable tokens rather than the error text,
// because they cross a version boundary — an old client reads a new hop's refusal
// — and because the operator-facing wording should be free to change without
// changing what the client parses.
const (
	refusedNodeBusy      = "node-busy"
	refusedPeerBusy      = "peer-busy"
	refusedNotInMesh     = "not-in-mesh"
	refusedSelfTarget    = "self-target"
	refusedForwardingOff = "forwarding-off"
)

// hopRefusalMeaning renders a reason token for the human reading the client's
// "[relay] chain not built:" line. An unknown token is reported verbatim rather
// than swallowed: a newer hop may name a reason this build predates, and "the hop
// said something I do not know" is still strictly better than silence.
var hopRefusalMeaning = map[string]string{
	refusedNodeBusy:      "the hop is at its aggregate forwarded-circuit limit",
	refusedPeerBusy:      "the hop is at its per-previous-hop forwarded-circuit limit",
	refusedNotInMesh:     "the hop does not have the next node in its signed directory (its directory and yours have drifted)",
	refusedSelfTarget:    "the hop was asked to forward to itself",
	refusedForwardingOff: "the hop does not forward onion layers",
}

// hopRefusedError is a hop's own sealed statement that it declined the forward,
// as opposed to any failure that merely LOOKS like one from outside.
type hopRefusedError struct {
	hop    string // short id of the refusing hop
	reason string
}

func (e *hopRefusedError) Error() string {
	meaning, ok := hopRefusalMeaning[e.reason]
	if !ok {
		meaning = "reason not known to this build"
	}
	return fmt.Sprintf("hop %s refused to forward (%s): %s — the hop is reachable and answered; it is not down", e.hop, e.reason, meaning)
}

// hopRefusalFrame builds the bytes a refusing hop writes into its client channel.
//
// It is length-prefixed the same way noiseConn frames its own messages, because
// that is the position in the byte stream it occupies: the client is reading the
// NEXT hop's handshake through this hop, so what it finds here has to be shaped
// like the frame it was expecting or it cannot be parsed at all. The hop writes
// the framing itself rather than getting it from noiseConn.Write, which seals and
// frames at the layer BELOW this one.
func hopRefusalFrame(reason string) []byte {
	if len(reason) > maxHopRefusalReason {
		reason = reason[:maxHopRefusalReason]
	}
	body := hopRefusedMagic + reason
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[:2], uint16(len(body)))
	copy(out[2:], body)
	return out
}

// parseHopRefusal recovers a reason from bytes read where a handshake reply was
// expected, or reports that these were not a refusal.
func parseHopRefusal(b []byte) (string, bool) {
	if len(b) < 2 {
		return "", false
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if n < len(hopRefusedMagic) || len(b) < 2+n {
		return "", false
	}
	body := b[2 : 2+n]
	if string(body[:len(hopRefusedMagic)]) != hopRefusedMagic {
		return "", false
	}
	return string(body[len(hopRefusedMagic):]), true
}

// signalHopRefused seals a refusal to the client on the hop's own channel, then
// leaves the caller to close as it would have anyway. Best-effort by construction:
// if the write fails the client sees the ordinary broken path, which is where it
// was before this existed.
//
// nil-safe, because relayForward's earliest refusals are reachable before there is
// a channel to speak on (and are driven that way by test).
func signalHopRefused(nc *noiseConn, reason string) {
	if nc == nil || nc.enc == nil {
		return
	}
	_, _ = nc.Write(hopRefusalFrame(reason))
}

// refusalSniffer wraps the stream one layer is dialed over and keeps a copy of the
// first few bytes read through it, so that when a handshake fails the caller can
// ask whether what arrived was a refusal rather than a broken hop.
//
// This lives here, not in clientHandshake, on purpose: only a CHAINED dial can
// receive a hop refusal — a direct client<->exit connect has no hop to refuse —
// so the generic handshake has no business growing a branch for it. The cost is
// one length check per read once the buffer is full, and the buffer is a fixed
// small constant, so nothing here scales with traffic.
type refusalSniffer struct {
	io.ReadWriteCloser
	buf []byte
}

func newRefusalSniffer(rw io.ReadWriteCloser) *refusalSniffer {
	return &refusalSniffer{ReadWriteCloser: rw, buf: make([]byte, 0, 2+len(hopRefusedMagic)+maxHopRefusalReason)}
}

func (s *refusalSniffer) Read(p []byte) (int, error) {
	n, err := s.ReadWriteCloser.Read(p)
	if n > 0 && len(s.buf) < cap(s.buf) {
		s.buf = append(s.buf, p[:min(n, cap(s.buf)-len(s.buf))]...)
	}
	return n, err
}

// refusal reports the reason a hop gave, if the bytes read through this sniffer
// began with one.
func (s *refusalSniffer) refusal() (string, bool) { return parseHopRefusal(s.buf) }

// ---------- relay side: bounding what one previous hop can occupy ----------

// Default forwarding occupancy caps (issue #25, ADR-0038 §6). They apply to any
// node that opted into forwarding at all, because a cap that ships off bounds
// nothing and forwarding is ALREADY opt-in — RelayIngress is the switch, and an
// operator who threw it did not thereby ask to be unbounded.
//
// The numbers are deliberately generous rather than tuned. Hop selection is
// random over the signed directory, so the honest load one previous hop sends a
// given next hop is its own client count divided by the directory size; a
// per-peer ceiling of 32 concurrent circuits is far above that for any directory
// worth chaining through, while still being ~8x below the aggregate, so no single
// neighbour can take the node. An operator whose node is bigger or smaller than
// that guess overrides both (-relay-forward-max-per-peer, -relay-forward-max-total).
const (
	defaultForwardMaxPerPeer = 32
	defaultForwardMaxTotal   = 256
)

// forwardLimits bounds what an intermediate hop will carry: concurrent forwarded
// circuits per PREVIOUS HOP and in aggregate, plus an optional per-previous-hop
// byte pace. It is the "rate-limit per previous hop and in aggregate" ADR-0038 §6
// called for and #142 shipped without.
//
// # Why the previous hop is the key
//
// It is the only key there is. An intermediate hop cannot see the client — that is
// the entire point of the onion — so it cannot key on the party actually
// responsible for a circuit. What it can see is the TCP peer that dialed its
// ingress, which is the previous hop. ADR-0038 §6 states this and it is a
// constraint, not a design choice.
//
// It has a consequence worth naming rather than discovering later: a hop's budget
// is shared by everything arriving through the same neighbour. An attacker that
// routes through a busy honest hop spends that hop's budget and degrades the
// honest circuits behind it. What the key DOES buy is containment — that attacker
// cannot spend any OTHER neighbour's budget, and cannot take the node, because the
// per-peer ceiling is a fraction of the aggregate. Bounding the blast radius to one
// neighbour is the most this key can do, and it is worth having.
//
// # Shed, do not queue
//
// A circuit that would exceed either cap is REFUSED, not parked. Queueing a
// forward would convert an occupancy bound into a latency bound and leave the node
// holding exactly the state the cap exists to deny it. The client's answer to a
// refusal is to build its chain somewhere else, which is a thing it can do
// immediately and this node cannot do for it.
//
// Bytes are the other way round: once a circuit is admitted its bytes are PACED,
// not dropped. That is not an inconsistency, it is the same rule applied to the
// resource that is actually scarce at each layer. A circuit is admission — you
// either take the state or you do not. A byte is throughput — cutting a splice
// mid-copy destroys a circuit that was already admitted and paid for, to save
// bandwidth that pacing reclaims anyway. ADR-0027 makes the same call for the
// reality splice and ADR-0040's aggregate limiter already paces every forwarded
// byte on this path; this adds the per-peer share of it that was missing.
type forwardLimits struct {
	maxPerPeer int
	maxTotal   int
	peerRate   capacity.Rate // per-previous-hop byte pace; 0 is unpaced

	mu        sync.Mutex
	total     int
	saturated bool // aggregate cap reached; drives the edge-triggered log
	refused   uint64
	peers     map[string]*forwardPeer
}

// forwardPeer is one previous hop's live occupancy. It exists only while that peer
// has at least one circuit up, which is what keeps the map bounded by maxTotal
// rather than by the number of source addresses an attacker can dial from — an
// attacker-keyed map that outlived its entries would be its own memory DoS.
type forwardPeer struct {
	circuits  int
	pace      *capacity.Limiter // nil (inert) when peerRate is 0
	saturated bool
	refused   uint64
}

func newForwardLimits(perPeer, total int, peerRate capacity.Rate) *forwardLimits {
	if perPeer <= 0 {
		perPeer = defaultForwardMaxPerPeer
	}
	if total <= 0 {
		total = defaultForwardMaxTotal
	}
	// A per-peer ceiling above the aggregate is not a configuration, it is a typo
	// that silently disables the per-peer cap: the aggregate would always bind
	// first and one neighbour could hold every slot on the node. Clamp rather than
	// refuse, because the caps are a safety net an operator should not be able to
	// turn into a footgun by fat-fingering one of two numbers.
	if perPeer > total {
		perPeer = total
	}
	return &forwardLimits{
		maxPerPeer: perPeer,
		maxTotal:   total,
		peerRate:   peerRate,
		peers:      map[string]*forwardPeer{},
	}
}

// acquire takes one forwarding slot for peer, or reports why it will not.
//
// The aggregate is checked FIRST so that a node at its total refuses uniformly
// rather than depending on which neighbour happened to ask; a per-peer refusal
// then always means "you specifically are over your share", which is the
// distinction an operator reading the log needs.
//
// On success it returns the peer's byte pacer and a release that must be called
// when the circuit ends. On refusal, first reports whether this begins a
// saturation episode — the edge the operator log is triggered on.
func (f *forwardLimits) acquire(peer string) (pace *capacity.Limiter, release func() (uint64, bool), first bool, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.total >= f.maxTotal {
		first = !f.saturated
		f.saturated = true
		f.refused++
		return nil, nil, first, errForwardNodeBusy
	}
	p := f.peers[peer]
	if p == nil {
		p = &forwardPeer{pace: capacity.NewLimiter(f.peerRate)}
		f.peers[peer] = p
	}
	if p.circuits >= f.maxPerPeer {
		first = !p.saturated
		p.saturated = true
		p.refused++
		// Do not leave a zero-circuit entry behind for a peer that only ever got
		// refused: that would be the unbounded attacker-keyed map this type avoids.
		// Reachable only with maxPerPeer <= 0, which newForwardLimits does not build.
		if p.circuits == 0 {
			delete(f.peers, peer)
		}
		return nil, nil, first, errForwardPeerBusy
	}
	p.circuits++
	f.total++
	return p.pace, func() (uint64, bool) { return f.release(peer) }, false, nil
}

// release returns one slot, and reports the size of the saturation episode it just
// ended, if it ended one. A release always drops the holder below both caps, so it
// is the only place an episode can end.
func (f *forwardLimits) release(peer string) (refused uint64, ended bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.total > 0 {
		f.total--
	}
	if f.saturated {
		refused, ended = f.refused, true
		f.saturated, f.refused = false, 0
	}
	if p := f.peers[peer]; p != nil {
		p.circuits--
		if p.saturated {
			// A peer episode and an aggregate episode can end on the same release. Report
			// the sum rather than one of them: the operator's question is "how many
			// forwards did I turn away", and attributing it is what the edge line did.
			refused, ended = refused+p.refused, true
			p.saturated, p.refused = false, 0
		}
		if p.circuits <= 0 {
			delete(f.peers, peer)
		}
	}
	return refused, ended
}

// counts reports live occupancy for peer and in aggregate. Tests read it; nothing
// on the data path does.
func (f *forwardLimits) counts(peer string) (perPeer, total int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p := f.peers[peer]; p != nil {
		perPeer = p.circuits
	}
	return perPeer, f.total
}

// forwardPeerKey is the previous hop's identity for accounting, and it is the
// source IP WITHOUT the port. A peer dials a fresh ephemeral port for every
// circuit it hands us, so keying on host:port would give every circuit its own
// bucket and cap nothing at all — the single mistake that would make this whole
// type inert while still passing a naive test.
//
// An empty key is returned for a channel with no addressable remote, and that is a
// key like any other: everything unaddressable shares one budget, which is the
// conservative direction. In practice a forward always arrives on the TCP ingress
// listener and always has one.
//
// It takes the channel rather than the stream underneath so the nil case is handled
// once, here. relayForward is reachable with a nil channel — its earliest refusals
// return before there is one, and a test drives it that way — and a peer key is the
// first thing past those refusals that would touch it.
func forwardPeerKey(nc *noiseConn) string {
	if nc == nil {
		return ""
	}
	ra, ok := nc.raw.(interface{ RemoteAddr() net.Addr })
	if !ok || ra == nil {
		return ""
	}
	addr := ra.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// ---------- relay side: peel one layer, splice the rest ----------

// forwardOn reports whether this node accepts onion layers, i.e. an operator
// opted it in with RelayIngress and gave it a directory to bound its forwarding
// with. Both are required: see relayForward on why the directory is not optional.
func (e *Engine) forwardOn() bool {
	return e.cfg.RelayIngress != "" && e.relayDir.Load() != nil
}

// relayForward is the intermediate-hop egress: this node has already run the
// Noise responder and read a "hop:" target, so it dials the next hop and splices
// the inner ciphertext. It is the generalization of the exit's own terminate
// behaviour, pointed at another Bacchus node instead of the internet.
//
// It peels EXACTLY one layer. The bytes it decrypts from its own layer are the
// next hop's handshake and traffic, which it forwards without being able to read:
// those are encrypted to a key it does not hold. So this node learns its two
// neighbours and nothing else — not the client, not the exit, not the
// destination, not the content.
//
// # Why the directory check is not optional
//
// next is attacker-chosen: it arrives from whoever completed the handshake, and
// completing the handshake requires nothing but this node's public key, which is
// in the directory. A node that dialed any next it was handed would be an open
// TCP proxy — anyone could point it at any host and port on the internet and use
// this operator's address as their egress. That is exactly the relay/exit safety
// line the mesh rests on (ADR-0038 principle #4: a relay forwards ciphertext and
// never egresses under its operator's ip), so the target is admitted only if it is
// an address of a node in the coordinator-SIGNED directory, and a node with no
// directory forwards nothing at all.
//
// # Why it refuses to dial itself
//
// This node's own Addr and Ingress are in the directory it checks against, so
// "hop:<my own ingress>" passes the allow-list. Serving it would splice this node
// to itself, and since the layer inside is still addressed to this node's key it
// would be peeled again and forwarded again: one attacker socket becomes two, then
// four. That is the cheap half of the amplification work tracked in #25; the caps
// below are the other half, and forwardLimits' doc says what they bound and why a
// ring needed no hop counter to bound it.
//
// # Why it refuses when it is full
//
// A forwarded circuit costs this node a socket, a goroutine pair and a share of an
// uplink its operator pays for, for as long as the client keeps it up — and until
// issue #25 there was no bound on how many of them one neighbour could hold.
// forwardLimits supplies the bound (ADR-0038 §6); every refusal here is sealed
// back to the client so it can tell a full hop from a dead one.
//
// Both directions are metered (e.meter), because a forwarded byte spends this
// operator's uplink exactly as an exit's does and their ISP bills it the same way
// — the rule core/forwarder.go's meter doc states for every unbounded-volume path.
// The per-peer pace sits INSIDE that: e.meter is the operator's whole declared
// cap (ADR-0040), and pace is the share of it this one neighbour may take.
func (e *Engine) relayForward(nc *noiseConn, next string) {
	if !e.forwardOn() {
		signalHopRefused(nc, refusedForwardingOff)
		return
	}
	if e.isSelfAddr(next) {
		signalHopRefused(nc, refusedSelfTarget)
		e.emit(EventError, "", "onion: refusing to forward to %s: %v", next, errHopSelfDial)
		return
	}
	if !e.relayDir.Load().dialable[next] {
		// Not an operational fault to stay quiet about: either a hop's directory has
		// drifted from the client's, or someone is probing this node as an open proxy.
		// The operator wants to see both, and the line names only an address this node
		// was offered — never a client, which it cannot see anyway.
		signalHopRefused(nc, refusedNotInMesh)
		e.emit(EventError, "", "onion: refusing to forward to %s: %v", next, errHopNotInMesh)
		return
	}
	// Occupancy is taken BEFORE the dial, so a refused circuit costs this node no
	// outbound connection, and AFTER the two checks above, so a target that was
	// never going to be served does not spend a slot it would immediately return.
	peer := forwardPeerKey(nc)
	pace, release, first, err := e.forwardLimits.acquire(peer)
	if err != nil {
		reason := refusedPeerBusy
		if errors.Is(err, errForwardNodeBusy) {
			reason = refusedNodeBusy
		}
		signalHopRefused(nc, reason)
		if first {
			e.emitForwardRefusal(peer, err)
		}
		return
	}
	defer func() {
		if refused, ended := release(); ended {
			e.emit(EventInfo, "", "onion: forwarding for %s is back under its limits after turning away %d circuit(s)", peerLabel(peer), refused)
		}
	}()
	up, err := net.DialTimeout("tcp", next, 10*time.Second)
	if err != nil {
		e.emit(EventError, "", "onion: dial next hop %s: %v", next, err)
		return
	}
	defer up.Close()
	go func() { _, _ = io.Copy(up, e.meter(pace.LimitReads(e.limiterCtx, nc))); _ = up.Close() }()
	_, _ = io.Copy(nc, e.meter(pace.LimitReads(e.limiterCtx, up)))
}

// emitForwardRefusal reports a cap refusal to the operator on the EDGE — the first
// refusal of an episode — and reports the episode's size when it ends (see
// forwardLimits.release). Logging every refusal instead would hand an attacker a
// log amplifier: they choose the refusal rate, and a node that is already declining
// work should not be spending more per declined circuit than per served one.
//
// The line names the previous hop's address, which is a mesh node this operator is
// already peered with, and never a client — an intermediate hop cannot see one.
func (e *Engine) emitForwardRefusal(peer string, err error) {
	e.emit(EventError, "", "onion: refusing forwards from %s: %v (further refusals in this episode are counted, not logged)", peerLabel(peer), err)
}

// peerLabel names a previous hop for an operator-facing line. The empty key is the
// one forwardPeerKey returns for a conn with no addressable remote, and it reads as
// nothing at all in a log line, so it gets words instead.
func peerLabel(peer string) string {
	if peer == "" {
		return "an unaddressable peer"
	}
	return peer
}
