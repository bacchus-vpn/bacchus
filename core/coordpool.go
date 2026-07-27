package core

// Coordinator pool (issue #6, ADR-0020): an engine can be configured with
// several coordinator endpoints instead of one. A single enumerable coordinator
// IP is a blockable rendezvous chokepoint, so signaling must survive one member
// being blocked.
//
// The pool is used asymmetrically by role:
//
//   - Forwarder roles (relay/exit) register with EVERY pool member — each
//     coordinator's directory is populated directly by the nodes that dial it,
//     so there is no coordinator-to-coordinator replication to build or trust.
//     A session assigned by member M signals its handshake back through M
//     (the link the assignment arrived on).
//   - The client role rotates: it tries members in shuffled order, skipping
//     ones recently marked unhealthy, so a blocked coordinator doesn't stall a
//     connect attempt as long as another member is reachable.

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

// coordCooldown is how long a coordinator that failed a client attempt is
// deprioritized for. It is still tried if every pool member is cooling down —
// a slow retry beats a client that refuses to connect at all.
const coordCooldown = 30 * time.Second

// coordLink is one live UDP connection to a single coordinator pool member.
// Sends are serialized per link (each link is written from the register loop,
// the client rotation, and every session's signaler concurrently). Client
// rendezvous replies (session/exits/error) from this member land in its own
// msgCh, so a slow member can never leak a reply into another member's client
// attempt — the whole reason the client can rotate cleanly.
type coordLink struct {
	raw    string // as configured, e.g. "1.2.3.4:8080"
	conn   *net.UDPConn
	sendMu sync.Mutex
	msgCh  chan wire // this member's client rendezvous replies

	// unroutable remembers which message types this member has already been
	// reported for, so readLoop's "never drop silently" rule (see its default
	// branch) costs one line per distinct type per member rather than one line per
	// datagram. Without the memo a coordinator emitting an unknown type at any rate
	// — or a hostile one doing it deliberately — turns the log into a flood, and a
	// flooded log is as good as a silent one.
	unroutableMu sync.Mutex
	unroutable   map[string]bool
}

// noteUnroutable reports, once per distinct message type, that a reply from this
// member was received and could not be routed anywhere. why names the reason.
//
// This exists because the failure it catches is invisible by construction: a
// well-formed reply that no case matches is indistinguishable, from the caller's
// side, from a coordinator that never answered — which is how a client reports
// "no coordinator reachable" about a healthy one and, worse, triggers mesh-walk
// recovery against it (issue #115's trigger is that same silence).
func (l *coordLink) noteUnroutable(e *Engine, msgType, why string) {
	l.unroutableMu.Lock()
	if l.unroutable == nil {
		l.unroutable = map[string]bool{}
	}
	first := !l.unroutable[msgType]
	l.unroutable[msgType] = true
	l.unroutableMu.Unlock()
	if !first {
		return
	}
	shown := msgType
	if shown == "" {
		shown = "(none)"
	}
	e.emit(EventError, "", "coordinator %s sent a %q message this build cannot route (%s) — it is being dropped; this client and that coordinator may be running incompatible protocol versions",
		l.raw, shown, why)
}

func (l *coordLink) send(m wire) {
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	b, _ := json.Marshal(m)
	if l.conn != nil {
		_, _ = l.conn.Write(b)
	}
}

// sendN sends m n times, spaced out, to ride over UDP loss on the rendezvous
// path (the coordinator dedupes; see cmd/coordinator).
func (l *coordLink) sendN(m wire, n int) {
	for i := 0; i < n; i++ {
		l.send(m)
		time.Sleep(60 * time.Millisecond)
	}
}

// dialPool resolves and dials every endpoint in addrs, returning one coordLink
// per usable member. A member that can't be resolved or dialed is reported via
// onSkip and left out rather than failing the whole node — a single typo in a
// pool shouldn't ground a client that has other reachable members. It is an
// error only when *no* member is usable.
//
// Dialing a UDP socket sends nothing on the wire (it only fixes the remote
// address), so dialing the whole pool up front reveals nothing to a censor;
// only an actual send does, and the client controls those through rotation.
func dialPool(addrs []string, onSkip func(addr string, err error)) ([]*coordLink, error) {
	links := make([]*coordLink, 0, len(addrs))
	for _, a := range addrs {
		ua, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			onSkip(a, err)
			continue
		}
		conn, err := net.DialUDP("udp", nil, ua)
		if err != nil {
			onSkip(a, err)
			continue
		}
		links = append(links, &coordLink{raw: a, conn: conn, msgCh: make(chan wire, 128)})
	}
	if len(links) == 0 {
		return nil, fmt.Errorf("core: no usable coordinator in pool %v", addrs)
	}
	return links, nil
}

// dedupNonEmpty trims each entry, drops blanks, and removes duplicates while
// preserving first-seen order. Used to normalize a configured coordinator pool
// that may arrive from a comma-split flag or a JSON array with stray gaps.
func dedupNonEmpty(in []string) []string {
	seen := make(map[string]bool, len(in))
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ---------- client-side rotation + health memory ----------

func (e *Engine) markUnhealthy(raw string) {
	e.healthMu.Lock()
	defer e.healthMu.Unlock()
	e.unhealthy[raw] = time.Now()
}

// unhealthySnapshot returns a copy of the health map so ranking can read a
// consistent view without holding the lock across the rest of orderLinks.
func (e *Engine) unhealthySnapshot() map[string]time.Time {
	e.healthMu.Lock()
	defer e.healthMu.Unlock()
	out := make(map[string]time.Time, len(e.unhealthy))
	for k, v := range e.unhealthy {
		out[k] = v
	}
	return out
}

// rankCoordinators orders addrs healthy-first: entries marked unhealthy within
// cooldown sink to the end but are still present (a member that recovers keeps
// getting retried). Pure and deterministic given now, so it is unit-testable
// without real time or network I/O; randomization happens separately in
// orderLinks.
func rankCoordinators(addrs []string, unhealthy map[string]time.Time, now time.Time, cooldown time.Duration) []string {
	healthy := make([]string, 0, len(addrs))
	cooling := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if t, bad := unhealthy[a]; bad && now.Sub(t) < cooldown {
			cooling = append(cooling, a)
		} else {
			healthy = append(healthy, a)
		}
	}
	return append(healthy, cooling...)
}

// orderLinks returns the pool in client rotation order for a fresh attempt:
// shuffled (so load spreads and no single member is always tried first), then
// ranked healthy-first using current health memory.
func (e *Engine) orderLinks() []*coordLink {
	byAddr := make(map[string]*coordLink, len(e.links))
	addrs := make([]string, len(e.links))
	for i, l := range e.links {
		addrs[i] = l.raw
		byAddr[l.raw] = l
	}
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
	ranked := rankCoordinators(addrs, e.unhealthySnapshot(), time.Now(), coordCooldown)
	out := make([]*coordLink, len(ranked))
	for i, a := range ranked {
		out[i] = byAddr[a]
	}
	return out
}
