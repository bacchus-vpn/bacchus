package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core/capacity"
	"github.com/bacchus-vpn/bacchus/core/policy"
	"github.com/bacchus-vpn/bacchus/core/version"
)

// Signed network policy (issue #39, ADR-0043). This is the enforcing half of the
// arrangement whose signing half lives outside this repository: the coordinator
// applies floors, fences and reserves that arrive inside bytes signed by a key it
// does not have and cannot obtain.
//
// The property is that this coordinator ENFORCES policy it cannot AUTHOR. A
// compromised coordinator can refuse to serve, or lie about capacity, but it
// cannot lower the serve floor to admit Sybils or loosen any other tunable — those
// numbers are signed data, not constants it chose.
//
// # Why it fails closed
//
// Past exp + grace the coordinator stops assigning new work. Established sessions
// are untouched. See policyAllowsAssignment for exactly what that covers and why
// it needs no teardown and no timer.
//
// The direction is the opposite of -admission-pubkey and -min-serving-version,
// which fail OPEN when unset, and the asymmetry is deliberate rather than an
// inconsistency: it follows from whether the failure is SHEDDABLE. Coordinators
// are a pool with client rotation, so one failing closed sheds to its peers rather
// than darkening the network. The admission gate and the version fence are single
// points with nothing to shed to.
//
// A coordinator that has never loaded a policy is in the same state as one whose
// policy went stale. Running unpoliced is not a supported mode: it is what the
// whole mechanism exists to prevent, and "keep enforcing the last policy forever"
// would mean this coordinator had authored policy by OMISSION — pinning the
// network at the most permissive generation it ever held, with no signature
// violated anywhere.

const (
	// policyRefresh is how often the bundle is re-fetched, matching the directory
	// snapshot's cadence. The document is re-verified from scratch on every tick —
	// including its delegation, which is never cached as "already valid" — so a
	// revoked delegation or a passed deadline takes effect within one interval.
	policyRefresh = 10 * time.Second

	// policyFetchTimeout bounds a single fetch. It is well inside policyRefresh so a
	// hung source cannot stall the refresh loop into skipping ticks.
	policyFetchTimeout = 5 * time.Second

	// policyBackoffMax caps the retry interval after repeated fetch failures. The
	// backoff exists to stop a coordinator hammering a source that is down, but it is
	// capped well below any realistic grace window: a policy that is about to go
	// stale must still get frequent chances to be refreshed, so the backoff must
	// never be the reason a coordinator failed closed.
	policyBackoffMax = 2 * time.Minute
)

// policyGate holds the coordinator's current enforcement state. It is read on
// every register and every connect, and replaced wholesale by the refresh loop.
//
// A single mutex rather than an atomic pointer because the readers already run
// under the protocol handler's lock and the write rate is one per refresh; the
// simpler thing that is obviously correct wins over the faster thing that needs an
// argument.
type policyGate struct {
	mu sync.RWMutex

	// configured records whether a policy root was supplied at all. When false the
	// whole mechanism is off and every gate below is inert — that is the pre-policy
	// status quo, and it is how this lands without changing the behaviour of a
	// deployment that has not adopted policy yet.
	configured bool

	// held is the last successfully verified policy, and ok whether there is one.
	held policy.Policy
	ok   bool
}

var policyState policyGate

// policyEnabled reports whether signed policy is configured on this coordinator.
// With no root supplied nothing below enforces anything.
func policyEnabled() bool {
	policyState.mu.RLock()
	defer policyState.mu.RUnlock()
	return policyState.configured
}

// currentPolicy returns the held policy, if one is being enforced.
func currentPolicy() (policy.Policy, bool) {
	policyState.mu.RLock()
	defer policyState.mu.RUnlock()
	return policyState.held, policyState.ok
}

// installPolicy installs a freshly verified policy.
func installPolicy(p policy.Policy) {
	policyState.mu.Lock()
	defer policyState.mu.Unlock()
	policyState.held, policyState.ok = p, true
}

// clearPolicy releases the held policy once it is past its deadline. The
// coordinator is then unpoliced and fails closed.
//
// This is the step that makes "cannot author" true over time rather than at one
// instant. A coordinator that simply stopped refreshing, keeping its last policy
// indefinitely, would have pinned the network at the most permissive generation it
// ever held — authoring policy by omission.
func clearPolicy() {
	policyState.mu.Lock()
	defer policyState.mu.Unlock()
	policyState.held, policyState.ok = policy.Policy{}, false
}

// policyAllowsAssignment reports whether this coordinator may assign NEW work.
//
// What it gates, concretely:
//
//   - register: a node is not added to the serve pool. It is not advertised, so it
//     draws no new sessions.
//   - connect: no new session is matched.
//
// What it deliberately does NOT touch: established sessions, heartbeats, and
// capacity reports. Matchmaking and live sessions are decoupled here, so a drain
// needs no teardown and no timer — existing sessions simply run to their natural
// end while nothing new is handed out. That is the same soft-drain shape the
// version fence already has.
//
// With no policy configured this is always true: a deployment that has not adopted
// signed policy behaves exactly as it did before this landed.
func policyAllowsAssignment() bool {
	policyState.mu.RLock()
	defer policyState.mu.RUnlock()
	if !policyState.configured {
		return true
	}
	return policyState.ok
}

// policyServingFloor is the SINGLE place the min-serving-version precedence is
// decided: a loaded policy's floor wins over the -min-serving-version flag, and
// the flag is the pre-policy default that applies until one is loaded.
//
// It is written as explicit code rather than left to fall out of read order
// because two sources of truth for one fence is exactly the kind of thing that
// gets discovered during an incident, at the point where someone is trying to work
// out why a node they just fenced is still serving.
//
// A policy whose min_serving_version is unparseable cannot occur: the string is
// validated at verification (stricter than version.Parse), so anything held here
// parses. The error branch therefore falls back to the flag rather than inventing
// a fence, and says so.
func policyServingFloor() version.Version {
	p, ok := currentPolicy()
	if !ok {
		return servingFloor
	}
	f, err := version.Parse(p.ServeFloor.MinServingVersion)
	if err != nil {
		log.Printf("policy: min_serving_version %q in seq %d does not parse (%v) — falling back to the -min-serving-version flag %s; this should be impossible, since the value is validated at verification",
			p.ServeFloor.MinServingVersion, p.Seq, err, servingFloor)
		return servingFloor
	}
	return f
}

// policyMeasuredFloor is the serve-eligibility floor on measured throughput
// (issue #15), read from the held policy.
//
// There is deliberately NO constant default. A floor with a fallback constant is a
// floor the coordinator AUTHORED, which is precisely the property signed policy
// exists to deny: with no policy loaded the answer is zero — no floor — and the
// pre-policy status quo applies. That is not a hole, because a coordinator with
// policy configured and none loaded is already refusing to assign anything at all
// (policyAllowsAssignment), and one with policy unconfigured never had a floor to
// begin with.
func policyMeasuredFloor() capacity.Rate {
	p, ok := currentPolicy()
	if !ok {
		return 0
	}
	return capacity.Rate(p.ServeFloor.MinMeasuredBps)
}

// meetsMeasuredFloor reports whether a node clears the policy's measured-throughput
// floor, with a safe-to-log reason when it does not.
//
// It reads the TRUSTED rating, never Measured. The untrusted estimator clamps to
// Ceiling by construction, so a node's untrusted rating says nothing about whether
// it clears a floor above that ceiling — applying the floor to it would fence every
// measured node in the fleet while admitting every unmeasured one, inverting the
// incentive to be measured. See capacity.NodeRating.TrustedRating.
//
// A node with no trusted rating is therefore NOT fenced. An unmeasured node is not a
// slow node (design §5.3), and neither is one whose only evidence is ceiling-bounded.
// With the trusted stream unfed, as it is in this build, that is every node — so this
// gate is live machinery that currently withholds nobody, and starts biting the
// moment the account service feeds the trusted stream, with no change here.
func meetsMeasuredFloor(nodeID string) (reason string, ok bool) {
	floor := policyMeasuredFloor()
	if floor == 0 {
		return "", true
	}
	if ratings == nil {
		return "", true
	}
	measured, rated := ratings.TrustedRating(nodeID)
	if !rated {
		return "", true
	}
	if measured < floor {
		return fmt.Sprintf("measured throughput %s is below the serve floor %s — this node may still use the service, it just cannot serve", measured, floor), false
	}
	return "", true
}

// policySource fetches the raw bundle bytes. The two implementations are an HTTP
// endpoint and a local file an operator stages; both are just "bytes that must
// then verify", because nothing about the transport is trusted.
type policySource interface {
	fetch(ctx context.Context) ([]byte, error)
	String() string
}

type httpPolicySource struct {
	url    string
	client *http.Client
}

func (s httpPolicySource) String() string { return s.url }

func (s httpPolicySource) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("policy source returned %s", resp.Status)
	}
	// Bounded so a hostile or broken source cannot exhaust memory. A bundle is two
	// signed blobs and is kilobytes; a megabyte is generous by three orders of
	// magnitude.
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

type filePolicySource struct{ path string }

func (s filePolicySource) String() string { return s.path }

func (s filePolicySource) fetch(context.Context) ([]byte, error) { return os.ReadFile(s.path) }

// newPolicySource picks a source from the operator's -policy-source value: an
// http(s) URL, or otherwise a filesystem path. A path is the shape every other
// trust artifact this coordinator loads already has (bootstrap secrets, the
// revocation list, the operator map), so an operator who pulls the bundle with
// their existing tooling does not need this process to speak HTTP at all.
func newPolicySource(s string) policySource {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return httpPolicySource{url: s, client: &http.Client{Timeout: policyFetchTimeout}}
	}
	return filePolicySource{path: s}
}

// startPolicy configures signed-policy enforcement and launches the refresh loop.
// An empty rootHex disables the whole mechanism and leaves the coordinator in its
// pre-policy behaviour, which is why this is opt-in rather than a hard requirement
// to boot.
//
// It returns an error only for a misconfiguration an operator must fix (an
// unusable root key, a source that was not supplied). A source that is merely
// unreachable right now is not a startup failure: the cache may still carry a
// usable policy, and the refresh loop will keep trying.
func startPolicy(ctx context.Context, rootHex, source, statePath string) error {
	if rootHex == "" {
		log.Printf("signed policy DISABLED (-policy-root-pubkey unset) — this coordinator enforces only its own flags and constants (issue #39)")
		return nil
	}
	rootPub, err := hex.DecodeString(strings.TrimSpace(rootHex))
	if err != nil {
		return fmt.Errorf("-policy-root-pubkey: %w", err)
	}
	if len(rootPub) != ed25519.PublicKeySize {
		return fmt.Errorf("-policy-root-pubkey: want a %d-byte ed25519 key, got %d bytes", ed25519.PublicKeySize, len(rootPub))
	}
	if source == "" {
		return errors.New("-policy-source is required when -policy-root-pubkey is set: a root with nothing to verify would fail closed forever")
	}

	// Revocation is not wired yet: the delegation's own window bounds the exposure
	// until the signed short-TTL CRL the format specifies is distributed, which is a
	// follow-up (ADR-0043). The verifier takes the predicate and the tests exercise
	// it, so feeding it later is a wiring change rather than a verifier change.
	v, err := policy.NewVerifier(rootPub, nil)
	if err != nil {
		return fmt.Errorf("policy verifier: %w", err)
	}

	policyState.mu.Lock()
	policyState.configured = true
	policyState.mu.Unlock()

	cache := policy.NewCache(statePath)
	src := newPolicySource(source)

	log.Printf("signed policy ENABLED — enforcing signed floors from %s, state in %s; past exp+grace this coordinator STOPS assigning new work (issue #39, ADR-0043)", src, cache.Path())

	// Load the cache before the first fetch, so a restart does not begin unpoliced
	// while waiting on the network. The bytes are re-verified against the current
	// clock and the configured root — a file on disk is as untrusted as the network.
	minSeq, cached, ok, err := cache.Load(v, time.Now())
	if err != nil {
		log.Printf("policy: cached state unusable (%v) — starting from the recorded sequence floor %d and fetching; this coordinator assigns no new work until a policy verifies", err, minSeq)
	}
	if ok {
		installPolicy(cached)
		log.Printf("policy: restored seq %d from cache, valid until %s (grace to %s)", cached.Seq, cached.Expires.UTC(), cached.Deadline().UTC())
	} else {
		log.Printf("policy: no usable cached policy — this coordinator assigns NO new work until one verifies (fail closed, issue #39)")
	}

	go refreshPolicyLoop(ctx, v, cache, src, minSeq)
	return nil
}

// refreshPolicyLoop re-fetches and re-verifies the bundle forever.
//
// minSeq starts at the persisted floor and only ever ratchets up. Persisting it is
// what stops a rollback across a restart: a genuinely signed, correctly delegated,
// unexpired document from an older generation passes every cryptographic check
// there is, so the floor is the only thing that refuses it.
func refreshPolicyLoop(ctx context.Context, v *policy.Verifier, cache *policy.Cache, src policySource, minSeq uint64) {
	fails := 0
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		if refreshPolicyOnce(ctx, v, cache, src, &minSeq, time.Now()) {
			fails = 0
		} else {
			fails++
		}
		t.Reset(policyBackoffFor(fails))
	}
}

// policyBackoffFor is the refresh interval after n consecutive failures: the
// normal cadence while healthy, then a doubling backoff capped at policyBackoffMax
// so a source that is down is not hammered.
//
// The cap matters more than the growth. A coordinator approaching its deadline
// must keep getting frequent chances to refresh, so the backoff must never be the
// reason it failed closed.
func policyBackoffFor(fails int) time.Duration {
	if fails <= 0 {
		return policyRefresh
	}
	d := policyRefresh
	for i := 0; i < fails && d < policyBackoffMax; i++ {
		d *= 2
	}
	return min(d, policyBackoffMax)
}

// refreshPolicyOnce performs one fetch-verify-install cycle and reports whether it
// succeeded. It also ages out a held policy that has passed its deadline, which
// must happen whether or not the fetch worked — otherwise a source that simply
// stopped answering would leave this coordinator enforcing a stale generation
// forever, which is the omission the expiry rule exists to close.
//
// now is passed in rather than read here so tests drive a fixed clock — the frozen
// conformance bundle is only live around its own instant, and a success path that
// could only be exercised on the right calendar day would not be exercised at all.
func refreshPolicyOnce(ctx context.Context, v *policy.Verifier, cache *policy.Cache, src policySource, minSeq *uint64, now time.Time) bool {
	// Age out first. A held policy past exp + grace stops being enforced even if
	// everything else in this function fails.
	if held, ok := currentPolicy(); ok && !now.Before(held.Deadline()) {
		clearPolicy()
		log.Printf("policy: seq %d is STALE (exp %s + grace %s elapsed) — this coordinator now assigns NO new work: no new sessions, no new serve-pool entries. Established sessions are untouched. Sign and publish a new generation (issue #39, ADR-0043)",
			held.Seq, held.Expires.UTC(), held.Grace)
	}

	fetchCtx, cancel := context.WithTimeout(ctx, policyFetchTimeout)
	defer cancel()
	raw, err := src.fetch(fetchCtx)
	if err != nil {
		// A failed fetch is NOT a stale policy. Whatever is held keeps being enforced
		// until its own deadline actually passes, which the age-out above applies.
		log.Printf("policy: fetch from %s failed: %v (still enforcing what is held, if anything)", src, err)
		return false
	}

	bundle, err := policy.ParseBundle(raw)
	if err != nil {
		log.Printf("policy: bundle from %s is malformed: %v (refusing to replace what is held)", src, err)
		return false
	}

	p, err := v.Verify(bundle, now, *minSeq)
	if err != nil {
		// Refusing to REPLACE a good policy with one that fails verification is the
		// point: a hostile upstream must not be able to unload a working policy by
		// serving a bad one.
		log.Printf("policy: bundle from %s failed verification: %v (refusing to replace what is held)", src, err)
		return false
	}

	prev, had := currentPolicy()
	installPolicy(p)

	if p.Seq > *minSeq {
		*minSeq = p.Seq
	}
	if err := cache.Store(raw, *minSeq); err != nil {
		// The policy is verified and is being enforced; only the restart cache and the
		// persisted floor failed to update. That is a real problem — an unpersisted
		// floor is a rollback window across the next restart — so it is loud, but it is
		// not a reason to refuse a policy that verified.
		log.Printf("policy: WARNING seq %d verified and is being enforced, but persisting it to %s failed: %v — the sequence floor will not survive a restart, which leaves this coordinator open to a rollback", p.Seq, cache.Path(), err)
	}

	switch {
	case !had:
		log.Printf("policy: seq %d loaded — serve floor %d bps / %d bytes, min serving version %s, valid until %s (grace to %s)",
			p.Seq, p.ServeFloor.MinMeasuredBps, p.ServeFloor.MinDeclaredQuotaBytes,
			p.ServeFloor.MinServingVersion, p.Expires.UTC(), p.Deadline().UTC())
	case p.Seq != prev.Seq:
		log.Printf("policy: seq %d -> %d — serve floor %d bps / %d bytes, min serving version %s, valid until %s (grace to %s)",
			prev.Seq, p.Seq, p.ServeFloor.MinMeasuredBps, p.ServeFloor.MinDeclaredQuotaBytes,
			p.ServeFloor.MinServingVersion, p.Expires.UTC(), p.Deadline().UTC())
	}

	// Running on grace is logged on EVERY refresh, not once on entry. The operator
	// has missed a re-sign, the window closes into a hard stop with no further
	// warning, and this line is the only notice they get — so it repeats for as long
	// as the condition holds rather than scrolling away once.
	if !p.Fresh(now) {
		log.Printf("policy: WARNING running on GRACE — seq %d expired at %s and is enforceable only until %s (%s left). Past that this coordinator STOPS assigning new work. Sign and publish a new generation now (issue #39, ADR-0043)",
			p.Seq, p.Expires.UTC(), p.Deadline().UTC(), p.Deadline().Sub(now).Truncate(time.Second))
	}
	return true
}
