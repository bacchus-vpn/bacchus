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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

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
	hops, err := selectHops(d.hops, n-1, exit.id)
	if err != nil {
		return nil, err
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
// assert one (the ADR-0038 #124 amendment says so explicitly). Deriving each hop's
// AS from its OBSERVED ip against an independent routing table, client-side, is the
// child issue this leaves open; until it lands, one operator spread across several
// unlabeled entries is not detected here.
//
// The first hop gets one extra constraint: it must be pairable (exit-registered),
// because it is reached by being named in connect{firstHop}.
func selectHops(cand []relayHop, want int, excludeID string) ([]relayHop, error) {
	if want <= 0 {
		return nil, nil
	}
	pool := make([]relayHop, 0, len(cand))
	for _, h := range cand {
		if h.id != excludeID {
			pool = append(pool, h)
		}
	}
	if err := shuffleHops(pool); err != nil {
		return nil, err
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
	take := func(h relayHop) {
		out = append(out, h)
		usedID[h.id] = true
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
		return nil, fmt.Errorf("%w: no directory entry can head a chain (the head must be one the coordinator can pair a client to)", errChainTooShort)
	}

	// Then fill the rest: operator-distinct first, and only if the directory cannot
	// supply enough of those, allow an operator to repeat rather than refuse to
	// connect. A repeated operator is a weaker chain, but it still hides the exit
	// from the coordinator and from every node that operator does not run; in a
	// small mesh, refusing outright would be the worse trade. Both outcomes are
	// reachable, so neither is silently assumed.
	for pass := 0; pass < 2 && len(out) < want; pass++ {
		for _, h := range pool {
			if len(out) == want {
				break
			}
			if usedID[h.id] {
				continue
			}
			if pass == 0 && h.operator != "" && usedOp[h.operator] {
				continue
			}
			take(h)
		}
	}
	if len(out) < want {
		return nil, fmt.Errorf("%w: need %d, found %d", errChainTooShort, want, len(out))
	}
	return out, nil
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
func (e *Engine) dialChain(raw io.ReadWriteCloser, plan *chainPlan, target string) (*noiseConn, error) {
	cur := raw
	for i, h := range plan.hops {
		// Each hop is told only where to send the next layer: the hop after it, or —
		// for the last one — the exit. It is never told the destination, the client,
		// or anything else about the path.
		next := plan.exitDia
		if i+1 < len(plan.hops) {
			next = plan.hops[i+1].dial
		}
		// verifyExit is nil for a relay hop: a hop is authenticated by holding the
		// X25519 key the client selected from the SIGNED directory, which a
		// substituted hop cannot do — its handshake simply fails here. Verifying a
		// relay-ROLE admission credential on top of that is the deferred follow-up
		// (ADR-0038 §4.3); the seam is already on the wire, since every responder
		// presents its credential in msg2.
		nc, err := clientHandshake(cur, h.pub, hopTargetPrefix+next, nil)
		if err != nil {
			if cur != raw {
				_ = cur.Close()
			}
			return nil, fmt.Errorf("core: chain hop %d/%d (%s): %w", i+1, len(plan.hops), shortID(h.id), err)
		}
		cur = nc
	}
	// The innermost layer: unchanged, and deliberately so.
	nc, err := clientHandshake(cur, plan.exitPub, target, e.exitVerifyFunc(plan.exitPub))
	if err != nil {
		if cur != raw {
			_ = cur.Close()
		}
		return nil, fmt.Errorf("core: chain exit layer: %w", err)
	}
	return nc, nil
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
// four. Refusing a self-target is the cheap half of the amplification work tracked
// in #174 — it does not bound a ring of three nodes pointed at each other, which
// needs a hop counter or a rate limit, and is why that issue stays open.
//
// Both directions are metered (e.meter), because a forwarded byte spends this
// operator's uplink exactly as an exit's does and their ISP bills it the same way
// — the rule core/forwarder.go's meter doc states for every unbounded-volume path.
func (e *Engine) relayForward(nc *noiseConn, next string) {
	if !e.forwardOn() {
		return
	}
	if e.isSelfAddr(next) {
		e.emit(EventError, "", "onion: refusing to forward to %s: %v", next, errHopSelfDial)
		return
	}
	if !e.relayDir.Load().dialable[next] {
		// Not an operational fault to stay quiet about: either a hop's directory has
		// drifted from the client's, or someone is probing this node as an open proxy.
		// The operator wants to see both, and the line names only an address this node
		// was offered — never a client, which it cannot see anyway.
		e.emit(EventError, "", "onion: refusing to forward to %s: %v", next, errHopNotInMesh)
		return
	}
	up, err := net.DialTimeout("tcp", next, 10*time.Second)
	if err != nil {
		e.emit(EventError, "", "onion: dial next hop %s: %v", next, err)
		return
	}
	defer up.Close()
	go func() { _, _ = io.Copy(up, e.meter(nc)); _ = up.Close() }()
	_, _ = io.Copy(nc, e.meter(up))
}
