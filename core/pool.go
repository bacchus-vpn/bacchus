package core

// Transport pool + per-user failover (issue #15). The client carries several
// candidate paths — a transport, an exit, and a mode (core/selection.Candidate)
// — and discovers which actually works from *this* user's network, right now.
// Russian blocking is per-operator, regionally fragmented, and time-varying, so
// no single path is "the" answer; coverage is the union, chosen per user.
//
// Three ideas from the field, realized here:
//
//   - "Connected" is not "working" (validateSession): a soft-block completes the
//     handshake then freezes the flow, so a candidate wins only after it
//     round-trips real bytes past that threshold (core/pool_probe.go).
//   - Racing is noisy (raceLadder): candidates start staggered, a few in flight,
//     not a simultaneous blast — happy-eyeballs, so the common case touches one
//     path and the rest never start.
//   - Learn per network (core/selection.Store): the winning combination is
//     remembered on the device and tried first next time.
//
// The ladder ordering (which candidate before which) lives in core/selection;
// this file drives it — dialing, validating, racing, committing, and re-racing
// when the committed path drops — behind a stable local SOCKS listener whose
// active session is swapped underneath it on failover.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"

	"github.com/bacchus-vpn/bacchus/core/selection"
)

// candCooldown is how long a candidate that failed to connect or validate is
// deprioritized within its ladder tier. Like coordCooldown it never removes a
// candidate — a path that recovers keeps getting retried — it only sinks it.
const candCooldown = 30 * time.Second

// poolOn reports whether this engine selects across a transport pool (issue #15)
// rather than dialing the single Config.Transport. Set when Config.TransportPool
// is non-empty; an empty pool preserves the exact pre-pool Connect path.
func (e *Engine) poolOn() bool { return len(e.transportOrder) > 0 }

// setupPool builds the pool's transports and opens its learned store. It is
// called once from newEngine. When Config.TransportPool is empty the pool is
// off — transportOrder stays empty — but the store is still opened (in memory
// when SelectionDir is unset) so ResetSelection is always safe to call. Each
// pool name is validated by building it, so a typo is a construction error, not
// a mid-connect surprise.
func (e *Engine) setupPool(cfg Config) error {
	store, err := selection.Open(selectionPath(cfg.SelectionDir))
	if err != nil {
		return err
	}
	e.store = store

	order := dedupNonEmpty(cfg.TransportPool)
	if len(order) == 0 {
		return nil // pool off
	}
	e.transports = make(map[string]Transport, len(order))
	for _, name := range order {
		tr, err := newNamedTransport(name, cfg, func(kind, msg string) { e.emit(kind, "", "%s", msg) })
		if err != nil {
			return fmt.Errorf("core: transport pool: %w", err)
		}
		// A pooled reality transport splices too, so it needs the same #163 metering the
		// single-transport path gets (Engine.attachRealitySplice); a no-op for webrtc.
		e.transports[name] = e.attachRealitySplice(tr)
	}
	e.transportOrder = order
	return nil
}

// newNamedTransport builds the transport named by name, independent of
// cfg.Transport, so the pool can hold several at once. Names are validated by
// newTransport's switch.
func newNamedTransport(name string, cfg Config, onEvent func(kind, msg string)) (Transport, error) {
	c := cfg
	c.Transport = name
	return newTransport(c, onEvent)
}

// selectionPath is where the learned store persists, or "" (in-memory) when no
// directory is configured.
func selectionPath(dir string) string {
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "selection.json")
}

// ResetSelection forgets everything the transport pool learned on this device
// (issue #15) — the per-network+geo winning paths — so path discovery starts
// fresh. It is what the user's "reset" control calls. Safe any time; a no-op
// before the store is built.
func (e *Engine) ResetSelection() error {
	if e.store == nil {
		return nil
	}
	return e.store.Reset()
}

// ---------- candidate health memory (mirrors the coordinator's) ----------

func (e *Engine) markCandidateCooling(c selection.Candidate) {
	e.candCoolMu.Lock()
	defer e.candCoolMu.Unlock()
	e.candCooling[c] = time.Now()
}

// candidateCooling reports whether c failed within the cooldown, so Ladder sinks
// it to the back of its tier. Read under the lock so it never races a mark.
func (e *Engine) candidateCooling(c selection.Candidate) bool {
	e.candCoolMu.Lock()
	defer e.candCoolMu.Unlock()
	t, bad := e.candCooling[c]
	return bad && time.Since(t) < candCooldown
}

// ---------- selection: fetch exits, build the ladder, race it ----------

// dialedPath is one validated candidate: the live session, the exit the coordinator
// actually assigned inside the candidate's country, and the measured round-trip.
//
// exitID is here because it is an OUTPUT of dialing, not an input to it (issue #146).
// The candidate names a country; which exit inside it the client gets is the
// coordinator's answer, arrives on the session reply, and is the exit's Noise static
// key — so it has to travel back out with the session or the caller cannot open a
// single stream over it.
type dialedPath struct {
	sess    Session
	exitID  string
	exitPub []byte
	rtt     time.Duration
}

// candidateDialer brings up and validates one candidate, returning the live
// path, or an error if it never came up or failed sustained-flow validation. It is a
// field of the race so tests can drive raceLadder with simulated blocked/working
// candidates and no real network.
type candidateDialer func(ctx context.Context, c selection.Candidate) (dialedPath, error)

// selectPath fetches the current exits, builds the priority ladder for this
// network+geo (learned winner first), and races it to a validated session. It
// returns the winning session, the candidate that won, and its round-trip. It
// refuses to select at all once a force-major version mismatch is latched
// (issue #79) — checked both before and after the exits fetch, since that
// fetch is often what observes the mismatch in the first place.
func (e *Engine) selectPath(ctx context.Context) (dialedPath, selection.Candidate, error) {
	// A prior round may already have latched a force-major mismatch; don't keep
	// re-selecting on a network this client can no longer speak to (mirrors
	// Connect's identical guard in client.go).
	if err := e.updateRequired(); err != nil {
		return dialedPath{}, selection.Candidate{}, err
	}
	countries, err := e.countriesFn(ctx)
	if err != nil {
		// poolCountries has already classified this: a force-major mismatch observed
		// during the fetch (issue #79), or ErrNoCoordinatorReachable when every
		// coordinator was silent (issue #115). Either way it is more actionable than
		// a generic empty-list error, so surface it verbatim — connectPooled returns
		// it, and maintainPath keys mesh-walk recovery on the sentinel.
		return dialedPath{}, selection.Candidate{}, err
	}
	if len(countries) == 0 {
		// A coordinator answered but offers no country with an exit in it.
		// (Force-major and all-silent are returned as errors above.)
		return dialedPath{}, selection.Candidate{}, errors.New("core: the coordinator offers no country to select from")
	}
	net := selection.NetworkKey()
	geo := e.cfg.Geo
	now := time.Now()

	sel := make([]selection.Country, 0, len(countries))
	for _, c := range countries {
		sel = append(sel, selection.Country{
			Code:      c.Country,
			Available: c.Available,
			Busy:      c.Busy,
			RTT:       e.store.RTT(net, c.Country, now),
		})
	}
	var learned *selection.Candidate
	if c, ok := e.store.Best(net, geo, now); ok {
		learned = &c
	}
	ladder := e.chainableLadder(selection.Ladder(selection.LadderInput{
		Geo:        geo,
		Countries:  sel,
		Transports: e.transportOrder,
		Learned:    learned,
		Cooling:    e.candidateCooling,
	}))
	if len(ladder) == 0 {
		return dialedPath{}, selection.Candidate{}, fmt.Errorf("core: no candidates for geo %q (%d country(ies) offered, all busy or out of scope)", geo, len(countries))
	}

	path, winner, err := e.raceLadder(ctx, ladder, e.dialFn)
	if err != nil {
		return dialedPath{}, selection.Candidate{}, err
	}
	// Remember the winner so it is tried first next time on this network+geo.
	// Floor the stored round-trip at 1ms: a validated path always has a *known*
	// ping, so a genuinely sub-millisecond one is never recorded as 0, which the
	// ranking reads as "unmeasured".
	rttMs := path.rtt.Milliseconds()
	if rttMs < 1 {
		rttMs = 1
	}
	// The winning EXIT is deliberately not persisted (issue #146): the client cannot
	// ask for it next time, so recording it would be a per-device history of the exits
	// a user has been through in exchange for nothing selection could act on.
	if err := e.store.Put(selection.Record{
		Net: net, Geo: geo, Country: winner.Country,
		Tr: winner.Transport, Mode: winner.Mode,
		RTTms: rttMs, At: now,
	}); err != nil {
		e.emit(EventError, "", "selection: persist winner: %v", err)
	}
	return path, winner, nil
}

// poolCountries returns the countries to select among and, instead of a silent empty
// list, two errors the caller must act on:
//
//   - the latched force-major version mismatch (issue #79): this build can no longer
//     speak the network's wire protocol, so every candidate is withheld and the
//     mismatch surfaced rather than letting a client dial a cutover it can't speak; and
//   - ErrNoCoordinatorReachable when every coordinator was silent (issue #115):
//     pairing a session needs a coordinator, so nothing can be reached — surface the
//     sentinel so the pool triggers mesh-walk recovery instead of failing cold or
//     spinning on a dead directory.
//
// Force-major takes precedence over the all-silent sentinel: a client too old for the
// network must stop with the update message, not chase a fresh directory it still
// couldn't speak to.
//
// # The Config.ExitID fallback is gone
//
// This used to fall back to a configured exit when a coordinator answered with an
// empty directory — the one case a manual pin still helped, since it could be paired
// through that live coordinator. Country-only assignment (issue #146) removes it,
// necessarily rather than by choice: a connect names a country, the coordinator picks
// the exit, and a coordinator that offers no country will refuse every country a
// client could name (refuseNoCountry). There is no longer a request a pin could be
// turned into, so an empty list is simply an empty network and is reported as one.
func (e *Engine) poolCountries(ctx context.Context) ([]CountryInfo, error) {
	countries, err := e.ListCountries(ctx, e.listTimeout)
	if err == nil && len(countries) > 0 {
		return countries, nil
	}
	if ferr := e.updateRequired(); ferr != nil {
		return nil, ferr
	}
	if errors.Is(err, ErrNoCoordinatorReachable) {
		return nil, ErrNoCoordinatorReachable
	}
	return nil, nil
}

// raceLadder runs the ladder as a staggered (happy-eyeballs) race: it starts the
// top candidate, and every poolStagger — or immediately when a candidate fails —
// starts the next, up to poolParallel in flight. The first candidate to return a
// validated session wins; the rest are cancelled and any session they raced to
// completion after the win is closed. This keeps the common case to a single
// path while still failing over fast when the top candidate is blocked.
func (e *Engine) raceLadder(ctx context.Context, ladder []selection.Candidate, dial candidateDialer) (dialedPath, selection.Candidate, error) {
	if len(ladder) == 0 {
		return dialedPath{}, selection.Candidate{}, errors.New("core: empty candidate ladder")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	resc := make(chan raceResult, len(ladder))
	launched, received := 0, 0
	launch := func() {
		c := ladder[launched]
		launched++
		go func() {
			path, err := dial(ctx, c)
			resc <- raceResult{c: c, path: path, err: err}
		}()
	}

	launch()
	stagger := time.NewTimer(e.poolStagger)
	defer stagger.Stop()
	inflight := func() int { return launched - received }

	for {
		select {
		case <-ctx.Done():
			return dialedPath{}, selection.Candidate{}, ctx.Err()
		case <-e.stop:
			return dialedPath{}, selection.Candidate{}, errEngineStopped
		case <-stagger.C:
			if launched < len(ladder) && inflight() < e.poolParallel {
				launch()
			}
			stagger.Reset(e.poolStagger)
		case r := <-resc:
			received++
			if r.err == nil && r.path.sess != nil {
				e.drainLosers(resc, launched-received) // close any sessions still racing
				return r.path, r.c, nil
			}
			e.markCandidateCooling(r.c)
			if launched < len(ladder) {
				launch()
				stagger.Reset(e.poolStagger)
			} else if inflight() == 0 {
				return dialedPath{}, selection.Candidate{}, errors.New("core: no candidate in the pool connected")
			}
		}
	}
}

// raceResult is one candidate's outcome in raceLadder, named so drainLosers can
// take the same channel element type.
type raceResult struct {
	c    selection.Candidate
	path dialedPath
	err  error
}

// drainLosers waits for the still-racing candidates to return (ctx is already
// cancelled, so they fail fast) and closes any session that came up anyway, so a
// loser that finished its handshake just after the winner isn't leaked.
func (e *Engine) drainLosers(resc <-chan raceResult, remaining int) {
	if remaining <= 0 {
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for i := 0; i < remaining; i++ {
			select {
			case r := <-resc:
				if r.path.sess != nil {
					_ = r.path.sess.Close()
				}
			case <-e.stop:
				return
			}
		}
	}()
}

// countryAttempts is how many exits inside one candidate's country the pool will try
// before failing that candidate.
//
// It exists because a candidate no longer names an exit (issue #146). The pre-#146
// ladder held one entry per (transport, EXIT), so a broken exit cost one entry and the
// race moved to the next exit on the same transport. A country-scoped candidate
// collapses all of those into one, so without a retry here a single unhealthy exit
// would condemn its whole transport for that country — a real loss of coverage that
// nothing else in the ladder makes up.
//
// Two, not more: each attempt spends a full pair-and-validate budget serially inside
// one racer, so a larger number trades the responsiveness the staggered race exists to
// provide for diminishing returns. Two covers the common case (one bad exit) while
// leaving the cross-transport failover to do what it is for.
const countryAttempts = 2

// dialAndValidate is the real candidateDialer: pair an exit in the candidate's country
// through a coordinator (rotating the pool as Connect does), dial the candidate's
// transport, then validate sustained flow before declaring it usable. Pairing failures
// rotate coordinators; a dialed-but-frozen path is retried once against a DIFFERENT
// exit in the same country before the candidate fails and the race moves on.
//
// The exit is discovered here rather than chosen: attemptWith returns whichever exit
// the coordinator assigned, and its id is the static key every stream over this session
// authenticates against — so it travels back out in the dialedPath.
func (e *Engine) dialAndValidate(ctx context.Context, c selection.Candidate) (dialedPath, error) {
	tr := e.transports[c.Transport]
	if tr == nil {
		return dialedPath{}, fmt.Errorf("core: no transport %q in pool", c.Transport)
	}
	timeout := e.directTimeout
	if c.Mode == selection.ModeRelay {
		timeout = e.relayTimeout
	}
	// Sessions whose exits failed validation this pass. Named to the coordinator on
	// the retry so it does not hand back the exit we just proved is not carrying
	// traffic — sessions rather than exit ids, see wire.ExcludeSessions.
	var exclude []string
	var lastErr error
	for attempt := 0; attempt < countryAttempts; attempt++ {
		// A relay-tier candidate on a chaining client carries an onion (issue #142),
		// assembled before pairing because its first peeling hop is the node the
		// coordinator is asked to wire us to. Rebuilt on each attempt rather than once
		// per candidate, because a fresh plan is the only thing that can move a chained
		// path off an exit that did not carry traffic: the client picked that exit
		// itself, so ExcludeSessions — which asks the coordinator to avoid an exit IT
		// chose — has nothing to act on. A chain that cannot be built fails the
		// candidate rather than quietly connecting unchained; the race moves on.
		plan, err := e.chainFor(c.Mode, c.Country)
		if err != nil {
			return dialedPath{}, fmt.Errorf("core: candidate chain not built: %w", err)
		}
		r, err := e.pairInCountry(ctx, c, tr, timeout, exclude, plan)
		if err != nil {
			if lastErr != nil {
				// A first attempt already failed validation; report that rather than
				// "could not be paired", which describes the retry and not the fault.
				return dialedPath{}, lastErr
			}
			return dialedPath{}, err
		}
		rtt, verr := e.validateSession(ctx, r.sess, r.exitPub, timeout)
		if verr == nil {
			return dialedPath{sess: r.sess, exitID: r.exitID, exitPub: r.exitPub, rtt: rtt}, nil
		}
		_ = r.sess.Close() // frozen/blocked path — trackSession cleans up on close
		lastErr = fmt.Errorf("core: candidate failed validation: %w", verr)
		if r.sid != "" {
			exclude = append(exclude, r.sid)
		}
		if attempt+1 < countryAttempts {
			e.emit(EventInfo, "", "exit %s in %s did not carry traffic — asking for another", shortID(r.exitID), c.Country)
		}
	}
	return dialedPath{}, lastErr
}

// chainableLadder drops every direct-mode candidate when the client is chaining
// (issue #142), which is the pool's half of the same rule modeLadder applies to the
// single-transport ladder: a direct candidate cannot carry an onion, so racing one
// would mean a chaining client's fastest path is the unchained one — a silent
// downgrade of exactly the property the user configured. See modeLadder.
//
// The result can legitimately be empty, on a client whose transports offer no relay
// tier at all. selectPath already treats an empty ladder as "no candidates", which
// says the right thing: this client cannot connect the way it was configured to.
func (e *Engine) chainableLadder(l []selection.Candidate) []selection.Candidate {
	if !e.chaining() {
		return l
	}
	out := l[:0:0]
	for _, c := range l {
		if c.Mode != selection.ModeDirect {
			out = append(out, c)
		}
	}
	return out
}

// pairInCountry asks each coordinator in turn to pair a session in c's country,
// returning the first that comes up. exclude names this client's own just-failed
// sessions so the coordinator avoids their exits. plan, when non-nil, makes the
// request name the chain's first hop instead of a country (issue #142).
func (e *Engine) pairInCountry(ctx context.Context, c selection.Candidate, tr Transport, timeout time.Duration, exclude []string, plan *chainPlan) (attemptResult, error) {
	for _, l := range e.orderLinks() {
		select {
		case <-ctx.Done():
			return attemptResult{}, ctx.Err()
		case <-e.stop:
			return attemptResult{}, errEngineStopped
		default:
		}
		e.greet(l)
		// nil dedupe: the pool has its own cross-transport failover (issue #15), so
		// it does not use the single-transport rotation skip-set (issue #56).
		r := e.attemptWith(ctx, l, connectReq{country: c.Country, mode: c.Mode, exclude: exclude, plan: plan}, tr, timeout, nil)
		if r.outcome == connectOK {
			return r, nil
		}
		if r.outcome == coordinatorSilent {
			e.markUnhealthy(l.raw)
		}
	}
	return attemptResult{}, errors.New("core: candidate could not be paired")
}

// validateSession proves a freshly dialed session sustains flow before the pool
// commits to it (issue #15, trap #1). It opens an ordinary end-to-end stream to
// the exit, runs the probe (push ~32 KB, read it back), and returns the
// round-trip. The probe stream is closed on return; the session stays up for
// real traffic. The stream is force-closed if ctx elapses, unblocking the read.
func (e *Engine) validateSession(ctx context.Context, sess Session, exitPub []byte, timeout time.Duration) (time.Duration, error) {
	openCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	st, err := sess.OpenStream(openCtx, e2eLabel)
	if err != nil {
		return 0, err
	}
	// noiseConn/Stream carry no deadline of their own, so bound the probe by
	// closing the stream when openCtx fires; that unblocks runProbe's read.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-openCtx.Done():
			_ = st.Close()
		case <-done:
		}
	}()

	// Probe over the SAME chain the real traffic will use (issue #142), not over a
	// shortcut to the exit: the point of sustained-flow validation is that the path
	// the pool is about to commit to actually carries bytes, and on a chained path
	// that includes every hop. A probe that skipped the hops could pass while the
	// chain itself was dead.
	nc, err := e.dialE2E(st, planOf(sess), exitPub, probeSentinel)
	if err != nil {
		_ = st.Close()
		return 0, err
	}
	rtt, err := runProbe(nc)
	_ = nc.Close() // closes only the probe stream, not the session
	if err != nil {
		return 0, err
	}
	return rtt, nil
}

// ---------- connection manager: commit + maintain across failover ----------

// connectPooled selects a validated path, binds the local SOCKS listener over
// it, and maintains it — re-selecting a *different* candidate when the active
// path drops (the #15 acceptance). It returns once SOCKS is listening; the
// maintain loop runs in the background. It returns an error without dialing
// anything if a force-major version mismatch is already latched (issue #79).
func (e *Engine) connectPooled(ctx context.Context) error {
	path, winner, err := e.selectPath(ctx)
	if err != nil {
		return err
	}
	e.setActivePath(path)
	e.emit(EventConnected, "", "connected via %s to exit %s in %s [%s] (rtt %dms)",
		winner.Transport, shortID(path.exitID), winner.Country, winner.Mode, path.rtt.Milliseconds())

	if err := e.bindPoolSocks(e.cfg.SocksAddr); err != nil {
		// The path was already committed above; without this, activeSess would
		// dangle on a session nothing maintains, and SOCKS connections would race
		// against a listener that never bound.
		e.clearActivePath()
		_ = path.sess.Close()
		return err
	}
	e.wg.Add(1)
	go e.maintainPath(ctx, path.sess, winner)
	return nil
}

// maintainPath watches the committed session and, when it drops (peer gone,
// transport failure, or a block that killed the flow), marks that candidate
// cooling and re-selects — swapping the new session in under the same SOCKS
// listener. It exits on shutdown or when no candidate can be found.
//
// Leak-safety on failover: the re-selected candidate may be a *different*
// transport/exit than the one that dropped, and for reality that means a
// different, not-yet-excluded underlay address — re-dialled here while a
// full-device tunnel's default route is already live. That re-dial does not
// race the tunnel because the address is surfaced (Config.OnUnderlayDial) and
// excluded from inside the transport's own dial path, before its underlay
// connection is opened (core/transport_reality.go's dialInner), not after this
// loop commits the new session. So maintainPath never needs to know the
// underlay address itself; it only has to re-run selection, and each candidate
// makes its own underlay tunnel-safe as it dials. See issue #109 / ADR-0028.
func (e *Engine) maintainPath(ctx context.Context, sess Session, current selection.Candidate) {
	defer e.wg.Done()
	for {
		select {
		case <-sess.Closed():
		case <-e.stop:
			return
		case <-ctx.Done():
			return
		}
		e.markCandidateCooling(current)
		e.emit(EventInfo, "", "active path (%s) dropped — reselecting…", current.Transport)

		newPath, winner, err := e.reselect(ctx)
		if err != nil {
			// If reselection kept coming back all-silent — every coordinator
			// unreachable, not just the candidates blocked — try warm recovery before
			// giving up: walk known peers for a fresh directory and, if one names a
			// live coordinator, hand it to the supervisor to rebuild against (issue
			// #115, ADR-0037). tryMeshRecovery returns false for any other failure or
			// when recovery finds nothing better, leaving the existing give-up intact.
			if errors.Is(err, ErrNoCoordinatorReachable) && e.tryMeshRecovery(ctx) {
				return
			}
			e.emit(EventError, "", "reselect gave up: %v", err)
			return
		}
		e.setActivePath(newPath)
		e.emit(EventConnected, "", "reconnected via %s to exit %s in %s [%s] (rtt %dms)",
			winner.Transport, shortID(newPath.exitID), winner.Country, winner.Mode, newPath.rtt.Milliseconds())
		sess, current = newPath.sess, winner
	}
}

// reselectRetries bounds how many times reselect re-runs selection after the
// active path drops before giving up. A transient blip that briefly blocks every
// candidate (often the same event that killed the active path) must not
// permanently end failover — so we retry a few times with a backoff first.
const reselectRetries = 4

// reselect runs selectPath with a bounded backoff retry. It returns the first
// validated path, or the last error once the retries are exhausted; it aborts
// promptly on shutdown or context cancellation between attempts.
func (e *Engine) reselect(ctx context.Context) (dialedPath, selection.Candidate, error) {
	var err error
	for attempt := 0; attempt < reselectRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(e.reselectBackoff):
			case <-ctx.Done():
				return dialedPath{}, selection.Candidate{}, ctx.Err()
			case <-e.stop:
				return dialedPath{}, selection.Candidate{}, errEngineStopped
			}
		}
		var path dialedPath
		var winner selection.Candidate
		if path, winner, err = e.selectPath(ctx); err == nil {
			return path, winner, nil
		}
		e.emit(EventInfo, "", "reselect attempt %d/%d failed: %v", attempt+1, reselectRetries, err)
	}
	return dialedPath{}, selection.Candidate{}, err
}

// setActivePath swaps in the session and the static key of the exit terminating it,
// for new SOCKS connections to use. The key comes from the dialed path rather than
// from the candidate (issue #146): the candidate names a country, and which exit
// inside it the coordinator assigned is known only once the session reply arrives —
// so a failover to a different exit routes its end-to-end handshake to the right one.
func (e *Engine) setActivePath(p dialedPath) {
	e.poolMu.Lock()
	e.activeSess = p.sess
	e.activeExitPub = p.exitPub
	e.poolMu.Unlock()
}

// clearActivePath resets the active pooled session to empty. It is used when a
// path was set by setActivePath but the connect attempt could not be completed
// (bindPoolSocks failed after the path committed), so the engine's state never
// claims an active path that nothing is maintaining and that has already been
// closed.
func (e *Engine) clearActivePath() {
	e.poolMu.Lock()
	e.activeSess = nil
	e.activeExitPub = nil
	e.poolMu.Unlock()
}

func (e *Engine) activePath() (Session, []byte) {
	e.poolMu.Lock()
	defer e.poolMu.Unlock()
	return e.activeSess, e.activeExitPub
}

// bindPoolSocks binds the local SOCKS5 listener once and serves it, tunnelling
// each accepted connection over whatever session is active at accept time — so a
// failover swaps the path underneath without rebinding or dropping the listener.
// Calling it again after a successful bind is a no-op (the listener persists
// across reselections). socksBound is latched only once Listen actually
// succeeds — poolMu is held continuously across the attempt (Listen is a fast
// syscall with no callback into user code, so this is safe) rather than
// released and reacquired, so two concurrent callers can never both dial
// Listen on the same address, and a failed attempt leaves socksBound false so
// a later call retries instead of silently no-op'ing forever.
func (e *Engine) bindPoolSocks(addr string) error {
	e.poolMu.Lock()
	if e.socksBound {
		e.poolMu.Unlock()
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		e.poolMu.Unlock()
		return fmt.Errorf("core: socks listen: %w", err)
	}
	e.socksBound = true
	e.poolMu.Unlock()

	e.addListener(ln)
	e.emit(EventInfo, "", "SOCKS5 on %s (pool)", addr)
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
			sess, pub := e.activePath()
			if sess == nil {
				_ = c.Close()
				continue
			}
			go e.handleSocks(c, sess, pub, nil)
		}
	}()
	return nil
}

// shortID abbreviates an exit id (a 64-hex key) for human-facing event lines.
func shortID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
