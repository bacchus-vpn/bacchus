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
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// coordCooldown is how long a coordinator that failed a client attempt is
// deprioritized for. It is still tried if every pool member is cooling down —
// a slow retry beats a client that refuses to connect at all.
const coordCooldown = 30 * time.Second

// safePathMTU is the path MTU every rendezvous datagram is sized to fit, and it
// is 1280 rather than Ethernet's 1500 for two independent reasons that happen to
// give the same number (issue #183, ADR-0057):
//
//   - It is the IPv6 minimum link MTU (RFC 8200 §5), which every IPv6 path is
//     required to carry. A path that has fallen back to it is still a working
//     path, so a datagram that does not fit is this client's problem and nobody
//     else's.
//   - It is Tailscale's default tunnel MTU, and the same order as WireGuard's
//     common 1420 and the ~1400 carrier paths clamp to. Bacchus is a
//     censorship-resistant VPN: running INSIDE another tunnel is not an exotic
//     deployment, it is the deployment of the users most likely to need it.
//
// 1500 is a bet on the path. 1280 is the floor the path is allowed to have.
const safePathMTU = 1280

// maxRendezvousPayload is the largest UDP payload that fits safePathMTU: the MTU
// less a 40-byte IPv6 header and an 8-byte UDP header. IPv4 leaves more room (20
// bytes of header at minimum, so 1252), so sizing to the IPv6 arithmetic covers
// both — which is the point, since a client does not choose which one its path is.
//
// It does NOT account for IPv6 extension headers or for an outer encapsulation
// this client cannot see. What it buys is that the datagram fits a path that is
// merely at the floor, not that it fits every conceivable path; the send-error
// reporting below is what covers the rest, because no constant can.
const maxRendezvousPayload = safePathMTU - 40 - 8

// coordLink is one live UDP connection to a single coordinator pool member.
// Sends are serialized per link (each link is written from the register loop,
// the client rotation, and every session's signaler concurrently). Client
// rendezvous replies (session/exits/error) from this member land in its own
// msgCh, so a slow member can never leak a reply into another member's client
// attempt — the whole reason the client can rotate cleanly.
type coordLink struct {
	raw  string // as configured, e.g. "1.2.3.4:8080"
	conn *net.UDPConn
	// shaped is this link's message transport when it speaks the shaped rendezvous
	// hop — an ICE connectivity check and then DTLS on the same 5-tuple (issue #175
	// slice 2, ADR-0062) — and nil when it is the cleartext link this has always
	// been. A client's links are shaped; a pure forwarder's are not yet. See
	// core/rendezvous_client.go and Engine.Start.
	//
	// It wraps conn rather than replacing it: the socket stays CONNECTED, because
	// ADR-0057 §4 reads a dead peer's ICMP port-unreachable off the next write, and
	// that is the one signal separating an unreachable coordinator from a silent one.
	shaped *shapedLink
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

	// unroutableN counts EVERY reply from this member that could not be routed,
	// including the ones the memo above suppresses from the log. The memo bounds
	// reporting; this is the control-flow signal, and the two are deliberately
	// separate — a member whose second unroutable reply went unlogged has still
	// answered, and a caller that read the memo would conclude it had not (issue #5).
	//
	// Atomic rather than mutex-guarded because a client leg samples it around a wait
	// while readLoop writes it from its own goroutine; there is nothing to keep
	// consistent with anything else, only a monotonic count to compare against a
	// snapshot.
	unroutableN atomic.Uint64

	// sendNotes memoizes the send-side diagnostics below, keyed by cause and message
	// type, for the reason unroutable is memoized: a condition that recurs per
	// datagram — and every one of these does, because sendN puts three copies of each
	// connect on the wire and the client retries — turns the log into a flood, and a
	// flooded log is as good as a silent one.
	sendNotesMu sync.Mutex
	sendNotes   map[string]bool

	// tooLargeN counts datagrams this link's socket refused FOR THEIR SIZE, including
	// the ones the memo above suppresses from the log. Same split as unroutableN and
	// the same reason: the memo bounds reporting, this is the control-flow signal a
	// waiting leg reads, and conflating them would make a second refused connect look
	// exactly like a coordinator that stayed silent (issue #183).
	//
	// SIZE specifically, and not "any write error", which is the trap here. A
	// connected UDP socket surfaces the ICMP port-unreachable from a dead coordinator
	// as ECONNREFUSED on the NEXT write — so a member that is genuinely unreachable
	// fails the write too, and counting that here would reclassify the one condition
	// ErrNoCoordinatorReachable exists to name. EMSGSIZE is the only write error that
	// says something about this host rather than about the peer, and it is the only
	// one that changes what the client concludes. Every other write failure is still
	// LOGGED (see noteSendFailed) and still reads as silence, exactly as before.
	tooLargeN atomic.Uint64

	// handshakeN counts datagrams this link could not send because the shaped
	// rendezvous handshake did not complete (ADR-0062), including the ones the memo
	// suppresses from the log. Same split as tooLargeN and the same reason.
	//
	// Unlike tooLargeN it does NOT change what the client concludes, and that
	// distinction is the point. A member this client cannot handshake with IS
	// unreachable, so ErrNoCoordinatorReachable is the right answer and rotation is
	// the right recovery; what this changes is only WHEN the leg gives up. Waiting
	// out a deadline for a reply to a datagram that was never sent buys nothing, and
	// with no cleartext fallback that is now a whole leg's budget spent on a member
	// already known to be unusable.
	handshakeN atomic.Uint64
}

// handshakeMark snapshots the failed-handshake count so a caller can tell whether
// THIS attempt drew one, exactly as unroutableMark and tooLargeMark do.
func (l *coordLink) handshakeMark() uint64 { return l.handshakeN.Load() }

// handshakeFailed reports whether the shaped rendezvous handshake with this member
// failed since the caller took `before` from [coordLink.handshakeMark].
func (l *coordLink) handshakeFailed(before uint64) bool {
	return l.handshakeN.Load() > before
}

// answeredUnroutably reports whether this member produced a reply readLoop could not
// route since the caller took `before` from [coordLink.unroutableMark].
//
// This is what turns "answered in a language we do not speak" into something a call
// site can act on. Before it, such a reply was a log line and nothing else: the leg
// waiting on the member simply timed out, reported it as silent, and — since silence is
// the mesh-walk trigger (issue #115) — a client walked the mesh looking for a live
// coordinator while the configured one was up and answering throughout. A version
// problem and a reachability problem want different recovery, and the first step is
// being able to tell them apart at the point that decides.
func (l *coordLink) answeredUnroutably(before uint64) bool {
	return l.unroutableN.Load() > before
}

// unroutableMark snapshots the unroutable count so a caller can tell whether THIS
// attempt drew one. A running total would conflate an attempt against a member that has
// misbehaved before with one that is misbehaving now.
func (l *coordLink) unroutableMark() uint64 { return l.unroutableN.Load() }

// noteUnroutable reports, once per distinct message type, that a reply from this
// member was received and could not be routed anywhere. why names the reason.
//
// This exists because the failure it catches is invisible by construction: a
// well-formed reply that no case matches is indistinguishable, from the caller's
// side, from a coordinator that never answered — which is how a client reports
// "no coordinator reachable" about a healthy one and, worse, triggers mesh-walk
// recovery against it (issue #115's trigger is that same silence).
func (l *coordLink) noteUnroutable(e *Engine, msgType, why string) {
	// Counted before the memo, and every time. The memo below suppresses repeat
	// LOGGING; suppressing the count as well would mean a member's second unroutable
	// reply looked, to the leg waiting on it, exactly like silence.
	l.unroutableN.Add(1)
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

// tooLargeMark snapshots the refused-for-size count so a caller can tell whether THIS
// attempt drew one, exactly as unroutableMark does for the receive side.
func (l *coordLink) tooLargeMark() uint64 { return l.tooLargeN.Load() }

// refusedForSize reports whether a datagram this link was asked to send was refused
// for its size since the caller took `before` from [coordLink.tooLargeMark].
//
// It is the send-side twin of answeredUnroutably, and it exists for the same reason:
// without it, a request that never left the host is indistinguishable at the waiting
// leg from a coordinator that never answered — so a definitive LOCAL fault is
// reported as "no coordinator reachable", which is the mesh-walk trigger (issue #31)
// and the sentence a user on a censored network will believe and report. Rediscovering
// coordinator addresses cannot help a datagram that does not fit the path, and walking
// the mesh to find that out costs the user a working diagnosis (issue #183).
func (l *coordLink) refusedForSize(before uint64) bool {
	return l.tooLargeN.Load() > before
}

// noteOnce reports whether this is the first time (cause, msgType) has been seen on
// this link, latching it either way. Callers use it to bound a per-datagram condition
// to one line per member per kind.
func (l *coordLink) noteOnce(cause, msgType string) bool {
	l.sendNotesMu.Lock()
	defer l.sendNotesMu.Unlock()
	if l.sendNotes == nil {
		l.sendNotes = map[string]bool{}
	}
	k := cause + "/" + msgType
	first := !l.sendNotes[k]
	l.sendNotes[k] = true
	return first
}

// isMessageTooLong reports whether err is the kernel refusing a datagram for its
// size — EMSGSIZE, the same error `ping -M do` prints as "Message too long".
//
// It checks two errnos on purpose. On Unix the socket layer returns
// syscall.EMSGSIZE and errors.Is finds it through net.OpError and os.SyscallError.
// On Windows it returns WSAEMSGSIZE (10040), and syscall.EMSGSIZE on that platform
// is one of the "invented values to support what package os expects"
// (syscall/zerrors_windows.go) — a number no socket ever produces — so matching only
// the named constant would silently never fire on half of the platforms 1.0 ships
// to. The public syscall package does not export WSAEMSGSIZE (only the unimportable
// internal/syscall/windows does), so the number is written out here rather than
// named. On Unix, errno 10040 is not a value any socket returns either, so the extra
// comparison is inert rather than merely harmless.
func isMessageTooLong(err error) bool {
	const wsaEMsgSize = syscall.Errno(10040) // Windows: WSAEMSGSIZE
	return errors.Is(err, syscall.EMSGSIZE) || errors.Is(err, wsaEMsgSize)
}

// noteSendFailed reports, once per distinct message type, that a datagram this link
// was asked to send never left the host — and, when the reason was its SIZE, counts
// it every time so a waiting leg can act on it.
//
// The two halves are deliberately not the same set:
//
//   - Logging covers every write error, because "we never sent it" is worth a line
//     whatever the reason, and before #183 there was no line at all.
//   - Counting covers EMSGSIZE only. A connected UDP socket reports a dead peer's
//     ICMP port-unreachable as ECONNREFUSED on the next write, so every genuinely
//     unreachable coordinator fails a write too — counting those would turn the
//     condition ErrNoCoordinatorReachable is FOR into a size complaint. See tooLargeN.
//
// EMSGSIZE gets its own sentence because it is a COMPLETE diagnosis: the kernel has
// said the datagram is too big for the path, the size is known here, and the safe
// floor is a constant a few lines up. Everything a user needs to understand the
// failure is in hand at this point — which is why discarding it (issue #183: `_, _ =
// l.conn.Write(b)`) turned a one-line answer into a two-hour misdiagnosis that
// pointed at the coordinator.
func (l *coordLink) noteSendFailed(e *Engine, msgType string, size int, err error) {
	tooLarge := isMessageTooLong(err)
	if tooLarge {
		// Counted before the memo and every time, for the reason noteUnroutable gives:
		// suppressing the count as well would make the second refusal look like silence
		// to the leg waiting on it.
		l.tooLargeN.Add(1)
	}
	cause := "send-failed"
	if tooLarge {
		cause = "too-large"
	}
	if !l.noteOnce(cause, msgType) {
		return
	}
	if tooLarge {
		e.emit(EventError, "", "the %d-byte %q datagram for coordinator %s is too large for this network path and was NOT sent (the local network stack refused it): the path's MTU is below %d bytes. This is a local path limit, not a blocked or unreachable coordinator. Bacchus sizes rendezvous to fit a %d-byte path (%d bytes of payload); a path below that is usually another VPN or tunnel wrapping this one",
			size, msgType, l.raw, size+28, safePathMTU, maxRendezvousPayload)
		return
	}
	e.emit(EventError, "", "the %d-byte %q datagram for coordinator %s could not be sent and was dropped locally: %v",
		size, msgType, l.raw, err)
}

// noteOversize warns, once per distinct message type, that a datagram this build
// produced exceeds maxRendezvousPayload — whether or not this particular path
// happened to carry it.
//
// This is the half that does not need a small path to fire. #183 shipped because
// loopback's MTU is 65536, so every unit test, both PR CI runs and the wave's
// combination build carried a 1453-byte connect without complaint and stayed green;
// the defect was found by a person on real hardware two days later. A size check at
// the point of send costs one comparison, needs no network at all, and would have
// said so on the developer's own machine the moment the datagram grew.
func (l *coordLink) noteOversize(e *Engine, msgType string, size int) {
	if !l.noteOnce("oversize", msgType) {
		return
	}
	shaped := ""
	if l.shaped != nil {
		shaped = fmt.Sprintf(" (%d of which is the DTLS record this hop now travels inside — issue #175)", dtlsRecordOverhead)
	}
	e.emit(EventError, "", "this build's %q datagram for coordinator %s is %d bytes, over the %d-byte payload that fits a %d-byte path%s — it will be delivered on an ordinary Ethernet path and refused on any path at the IPv6 minimum MTU (another VPN, a tunnel, or a clamped mobile link). See issue #183",
		msgType, l.raw, size, l.budget(), safePathMTU, shaped)
}

// budget is the largest payload this link may put on the wire: the plain rendezvous
// budget on a cleartext link, and 37 bytes less on a shaped one, because on that one
// every message travels inside a DTLS record (ADR-0059 §3, ADR-0062).
//
// A link reports against the budget it actually speaks rather than against the
// larger of the two. The 37 bytes are not a rounding error against a datagram that
// failed on a real path at 1453 bytes and has ~500 to spare only because issue #206
// moved the issuer cert.
func (l *coordLink) budget() int {
	if l.shaped != nil {
		return maxShapedRendezvousPayload
	}
	return maxRendezvousPayload
}

// shape gives this link the shaped rendezvous transport (ADR-0062). Called by
// Engine.Start for a client's links, before any read loop or send runs, so nothing
// ever observes a link change shape underneath it.
func (l *coordLink) shape() {
	if l.conn != nil {
		l.shaped = newShapedLink(l.conn)
	}
}

// write puts one datagram on this link in whichever shape it speaks. On a shaped
// link this is where the handshake happens, on the first send and not before: see
// shapedLink on why establishment is lazy.
func (l *coordLink) write(b []byte) (int, error) {
	if l.shaped != nil {
		return l.shaped.Write(b)
	}
	return l.conn.Write(b)
}

// read returns the next message from this member, decrypted when the link is shaped.
func (l *coordLink) read(b []byte) (int, error) {
	if l.shaped != nil {
		return l.shaped.Read(b)
	}
	return l.conn.Read(b)
}

// close tears the link down: the transport first, then the socket, because closing
// the socket is what ends the shaped link's reader goroutine.
func (l *coordLink) close() {
	if l.shaped != nil {
		_ = l.shaped.Close()
	}
	if l.conn != nil {
		_ = l.conn.Close()
	}
}

// noteUnshapedReplies reports, once per member, that this coordinator answered in
// neither shape a shaped link speaks.
//
// It exists because ADR-0062 removed the fallback: a coordinator that does not speak
// the shaped hop is unreachable to this client, exactly as a blocked one is, and the
// difference between the two is invisible from a timeout. That is issue #5's lesson
// applied to a condition #5 could not have — a well-formed reply nobody can read is
// the same non-event as silence, and the client walks the mesh looking for a live
// coordinator while a healthy one answers throughout.
func (l *coordLink) noteUnshapedReplies(e *Engine, n int) {
	if n == 0 || !l.noteOnce("unshaped", "") {
		return
	}
	e.emit(EventError, "", "coordinator %s answered in cleartext, which this build does not accept at this hop: the rendezvous handshake is DTLS-shaped and there is deliberately no fallback to plaintext (issue #175, ADR-0062). This member is being treated as unreachable and the client will rotate to another; if it is one of ours, it is running with -rendezvous-dtls=false or on a build predating the shaped hop",
		l.raw)
}

// noteHandshakeFailed reports, once per member, that the shaped rendezvous handshake
// did not complete.
//
// Same discipline as noteSendFailed (issue #183) and the same reason: without it the
// condition presents to the waiting leg as an unexplained timeout, which is the
// mesh-walk trigger and the sentence a user on a censored network will believe. It
// does NOT change what the client concludes — a member it cannot handshake with IS
// unreachable, so ErrNoCoordinatorReachable is the right answer and rotation is the
// right recovery. What it changes is whether anyone can tell why.
func (l *coordLink) noteHandshakeFailed(e *Engine, msgType string, err error) {
	// Counted before the memo and every time, for noteUnroutable's reason:
	// suppressing the count as well would make the second refusal look like silence
	// to the leg waiting on it.
	l.handshakeN.Add(1)
	if !l.noteOnce("handshake", msgType) {
		return
	}
	e.emit(EventError, "", "the shaped rendezvous handshake with coordinator %s did not complete (%v), so the %q datagram was not sent. This client speaks DTLS at this hop and has no cleartext fallback by design (issue #175, ADR-0062): a censor dropping the handshake and a coordinator that never learned it are the same silence, and answering that silence with plaintext would send exactly what the shape exists to hide. Rotating to another pool member",
		l.raw, err, msgType)
}

func (l *coordLink) send(e *Engine, m wire) {
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	b, _ := json.Marshal(m)
	if len(b) > l.budget() {
		l.noteOversize(e, m.Type, len(b))
	}
	if l.conn == nil {
		return
	}
	// A shaped link may have been answered in a shape it does not speak since the
	// last send; report it here, where an engine is in hand, rather than from the
	// goroutine that owns the socket.
	if l.shaped != nil {
		l.noteUnshapedReplies(e, l.shaped.unshapedReplies())
	}
	// The whole reason this is not `_, _ = l.conn.Write(b)` — see noteSendFailed
	// and issue #183. A write error here is a local, definitive fact about a datagram
	// that never reached the network; dropping it leaves the client to infer, from
	// the silence that follows, that the coordinator is unreachable.
	if _, err := l.write(b); err != nil {
		// On a shaped link, a failure with NO live association is the handshake — one
		// diagnosis rather than two, and the signal a leg reads to stop waiting for a
		// reply to a request that was never sent. A failure WITH one is an ordinary
		// send failure and is reported as such, which keeps "this member never
		// answered the handshake" from being said about a member that did. A size
		// refusal goes to noteSendFailed either way, because EMSGSIZE is the one
		// error that changes what the client concludes and the counting lives there.
		if l.shaped != nil && !l.shaped.live() && !isMessageTooLong(err) && !errors.Is(err, net.ErrClosed) {
			l.noteHandshakeFailed(e, m.Type, err)
			return
		}
		l.noteSendFailed(e, m.Type, len(b), err)
	}
}

// sendN sends m n times, spaced out, to ride over UDP loss on the rendezvous
// path (the coordinator dedupes; see cmd/coordinator).
func (l *coordLink) sendN(e *Engine, m wire, n int) {
	for i := 0; i < n; i++ {
		l.send(e, m)
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
