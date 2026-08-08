package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/revocation"
)

// Signed revocation bundles from the untrusted hop past bacchus-payment's
// revocation-sync (issue #199, ADR-0017, ADR-0063). This is the coordinator's
// half of the arrangement whose signing half lives outside this repository:
// -device-revocations and -admission-revocations already let this coordinator
// hot-reload a plain revoked-serials FILE, trusted because it is this
// coordinator's own disk; ADR-0017 rules the hop that CARRIES those bytes from
// the account-service host to that disk untrusted, and signs the two lists
// under the offline root instead, so a coordinator can verify them without
// trusting whoever staged them.
//
// # Copied from -policy-root-pubkey / -policy-source, in full
//
// This mirrors cmd/coordinator/policy.go's fetch-verify-cache mechanism
// (startPolicy / refreshPolicyLoop / refreshPolicyOnce / core/policy.Cache),
// not merely its fetch loop — see core/revocation's package doc for the wire
// format this ports and ADR-0017 decision 5 for why the cache piece
// specifically is load-bearing rather than optional. What is deliberately NOT
// copied is policyGate's fail-closed drain: a revocations document carries no
// activation window (core/revocation's doc.go), so there is nothing here to
// age out, and — unlike signed policy — an unconfigured or unverified signed
// source never blocks matchmaking. It only ever ADDS to what
// -device-revocations / -admission-revocations already enforce.
//
// # Two independent instances, one shared root
//
// device and admission are separate namespaces with separate sources, separate
// on-disk state, and separate rollback floors — matching how the two plain-file
// flags and their reload loops are already independent. What they share is the
// root public key and, consequently, one *revocation.Verifier: ADR-0017
// decision 2's ceremony mints ONE role for both lists, so there is exactly one
// key whose authority this coordinator ever checks here.
//
// # Additive, never a replacement
//
// An operator who has not configured -revocations-root-pubkey — the state this
// binary ships in, and the state it stays in until the ceremony (bacchus-
// payment#79, the owner's) has run — sees no behaviour change at all:
// -device-revocations / -admission-revocations keep working exactly as today.
// Once configured, the new source is a SECOND way to populate the identical
// in-memory list (reloadRevocationsLoop's atomic.Pointer[admission.RevocationList]),
// active only for a namespace whose own gate is actually enabled — see
// startRevocationsNamespace. Both writers race to the same pointer by design;
// whichever last verified wins, which is what lets an operator run the plain
// file and the signed source side by side during a migration and simply stop
// maintaining the file once they trust the signed path.
const (
	// revocationsRefresh is how often a signed bundle is re-fetched and
	// re-verified from scratch, mirroring policyRefresh exactly. The value is
	// not free to pick: ADR-0017 decision 3 corrects the worst-case propagation
	// figure to "revocation-sync's own interval plus whatever interval the
	// coordinator's fetch-and-verify loop uses" and recommends this loop mirror
	// policyRefresh (10s) BECAUSE that is the number that makes the corrected
	// figure ~70s — revocation-sync's unchanged 60s tick plus this 10s one, one
	// hop rather than two. 10s here is therefore not a default carried over by
	// habit; it is the specific value the ~70s claim depends on.
	revocationsRefresh = 10 * time.Second

	// revocationsFetchTimeout bounds a single fetch, well inside
	// revocationsRefresh so a hung source cannot stall the loop into skipping
	// ticks. Mirrors policyFetchTimeout.
	revocationsFetchTimeout = 5 * time.Second

	// revocationsBackoffMax caps the retry interval after repeated fetch
	// failures, mirroring policyBackoffMax. The cap matters more than the
	// growth: an operator relying on the signed source must keep getting
	// frequent chances to pick up a genuine revocation, so the backoff must
	// never be the reason a stale bundle sits unrefreshed for long.
	revocationsBackoffMax = 2 * time.Minute
)

// revocationsNamespaceConfig names one of the two independent instances
// startRevocations wires up. label is used only in log lines and flag-name
// error messages (device, admission), never on the wire.
type revocationsNamespaceConfig struct {
	label  string
	source string
	state  string
	// target is the SAME atomic.Pointer[admission.RevocationList]
	// reloadRevocationsLoop already populates for this namespace (returned by
	// setupDeviceCred / setupAdmission) — nil exactly when that namespace's own
	// gate is disabled, in which case there is nothing to install into and
	// nothing that would ever read it.
	target *atomic.Pointer[admission.RevocationList]
}

// startRevocations configures signed-revocations verification for both
// namespaces and launches their refresh loops. An empty rootHex disables the
// whole mechanism and leaves the coordinator in its pre-#199 behaviour, which
// is why this is opt-in rather than a hard requirement to boot — the same
// posture startPolicy takes for -policy-root-pubkey.
//
// It returns an error only for a misconfiguration an operator must fix (an
// unusable root key, a namespace whose gate is enabled but whose source was
// not supplied). A source that is merely unreachable right now is not a
// startup failure: the cache may still carry a usable bundle, and the refresh
// loop keeps trying.
func startRevocations(ctx context.Context, rootHex string, namespaces ...revocationsNamespaceConfig) error {
	if rootHex == "" {
		log.Printf("signed revocations DISABLED (-revocations-root-pubkey unset) — -device-revocations and -admission-revocations remain the only source for both lists (issue #199, ADR-0017); this is the state every coordinator is in until the signing ceremony has run")
		return nil
	}
	rootPub, err := hex.DecodeString(strings.TrimSpace(rootHex))
	if err != nil {
		return fmt.Errorf("-revocations-root-pubkey: %w", err)
	}
	if len(rootPub) != ed25519.PublicKeySize {
		return fmt.Errorf("-revocations-root-pubkey: want a %d-byte ed25519 key, got %d bytes", ed25519.PublicKeySize, len(rootPub))
	}

	// Revocation of the DELEGATION itself (as opposed to the serials the
	// document it authorizes carries) is not wired yet — mirroring
	// startPolicy's identical, identically-reasoned choice: the delegation's
	// own window bounds the exposure until a signed short-TTL CRL for this hop
	// exists, which is a follow-up rather than something this card invents.
	v, err := revocation.NewVerifier(rootPub, nil)
	if err != nil {
		return fmt.Errorf("revocations verifier: %w", err)
	}

	for _, ns := range namespaces {
		if err := startRevocationsNamespace(ctx, ns, v); err != nil {
			return err
		}
	}
	return nil
}

// startRevocationsNamespace configures and starts one namespace's
// fetch-verify-cache loop.
//
// A namespace whose gate is disabled (ns.target == nil — the device-credential
// gate off, or admission off) is skipped with a warning rather than an error:
// -revocations-root-pubkey is a per-coordinator, per-mechanism switch, and it
// is entirely legal for an operator to have staged the signed source ahead of
// turning the corresponding gate on. There is nothing to install into and
// nothing that would ever consult it, so starting a loop here would be a
// goroutine that verifies bundles for an audience of nobody.
//
// A namespace whose gate IS enabled but whose source is empty is a hard error:
// a root with nothing to verify would fail closed forever, and a coordinator
// that came up looking configured while silently never fetching anything is
// the exact confusion startPolicy's identical check exists to prevent.
func startRevocationsNamespace(ctx context.Context, ns revocationsNamespaceConfig, v *revocation.Verifier) error {
	if ns.target == nil {
		log.Printf("signed revocations(%s): -revocations-root-pubkey is set, but the %s gate is not configured — there is no verifier that would ever consult this list, so the signed source for %s is not started (issue #199)", ns.label, ns.label, ns.label)
		return nil
	}
	if ns.source == "" {
		return fmt.Errorf("-%s-revocations-source is required when -revocations-root-pubkey is set: a root with nothing to verify would fail closed forever", ns.label)
	}

	cache := revocation.NewCache(ns.state)
	src := newPolicySource(ns.source)

	log.Printf("signed revocations(%s) ENABLED — fetching from %s every %s, state in %s; additive to -%s-revocations, which keeps working unchanged (issue #199, ADR-0017, ADR-0063)",
		ns.label, src, revocationsRefresh, cache.Path(), ns.label)

	state := &revocationsLoopState{}

	// Load the cache before the first fetch, so a restart does not begin
	// holding only whatever the untrusted hop happens to be serving at that
	// exact instant (ADR-0017 decision 5, the un-revoke item this card closes).
	// The bytes are re-verified against the current clock and the configured
	// root — a file on disk is as untrusted as the network.
	minAsOf, cached, ok, err := cache.Load(v, time.Now())
	state.minAsOf = minAsOf
	if err != nil {
		log.Printf("revocations(%s): cached state unusable (%v) — starting from the recorded floor %s and fetching; until a bundle verifies, this namespace's enforced list is whatever -%s-revocations already loaded, if anything", ns.label, err, minAsOf.UTC(), ns.label)
	}
	if ok {
		installRevocationsDoc(ns.target, cached)
		state.had, state.lastAsOf = true, cached.AsOf
		log.Printf("revocations(%s): restored as_of %s from cache (%d serial(s)) before the first fetch", ns.label, cached.AsOf.UTC(), len(cached.Revoked))
	} else {
		log.Printf("revocations(%s): no usable cached signed bundle — this namespace's enforced list is whatever -%s-revocations already loaded (or nothing) until a signed bundle verifies", ns.label, ns.label)
	}

	go refreshRevocationsLoop(ctx, ns.label, v, cache, src, state, ns.target)
	return nil
}

// revocationsLoopState is the per-namespace mutable state
// refreshRevocationsLoop carries between ticks: the persisted rollback floor,
// plus just enough to log only on CHANGE — mirroring refreshPolicyOnce's
// "case !had / case p.Seq != prev.Seq" discipline rather than logging every
// successful tick at a 10s cadence, which would be pure noise in steady state
// (a healthy, unchanged upstream re-verifies the SAME as_of every tick by
// construction — see core/revocation.Verifier.Verify's rollback comment).
type revocationsLoopState struct {
	minAsOf  time.Time
	had      bool
	lastAsOf time.Time
}

// refreshRevocationsLoop re-fetches and re-verifies one namespace's bundle
// forever, mirroring refreshPolicyLoop.
func refreshRevocationsLoop(ctx context.Context, label string, v *revocation.Verifier, cache *revocation.Cache, src policySource, state *revocationsLoopState, target *atomic.Pointer[admission.RevocationList]) {
	fails := 0
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		if refreshRevocationsOnce(ctx, label, v, cache, src, state, time.Now(), target) {
			fails = 0
		} else {
			fails++
		}
		t.Reset(revocationsBackoffFor(fails))
	}
}

// revocationsBackoffFor is the refresh interval after n consecutive failures,
// mirroring policyBackoffFor exactly.
func revocationsBackoffFor(fails int) time.Duration {
	if fails <= 0 {
		return revocationsRefresh
	}
	d := revocationsRefresh
	for i := 0; i < fails && d < revocationsBackoffMax; i++ {
		d *= 2
	}
	return min(d, revocationsBackoffMax)
}

// refreshRevocationsOnce performs one fetch-verify-install cycle for one
// namespace and reports whether it succeeded.
//
// Unlike refreshPolicyOnce there is no age-out step: a revocations document
// carries no window of its own to age out of (core/revocation's doc.go), so
// there is no "stale" state analogous to a policy past exp+grace. A failed or
// unreachable source simply leaves whatever is currently installed — the
// signed bundle if one has ever verified, or whatever -device-revocations /
// -admission-revocations most recently loaded — enforced unchanged, exactly
// like a failed plain-file reload already does.
//
// now is passed in rather than read here so tests drive a fixed clock — the
// frozen conformance bundle is only live around its own instant.
func refreshRevocationsOnce(ctx context.Context, label string, v *revocation.Verifier, cache *revocation.Cache, src policySource, state *revocationsLoopState, now time.Time, target *atomic.Pointer[admission.RevocationList]) bool {
	fetchCtx, cancel := context.WithTimeout(ctx, revocationsFetchTimeout)
	defer cancel()
	raw, err := src.fetch(fetchCtx)
	if err != nil {
		// A failed fetch is not a reason to change anything that is enforced —
		// whatever is currently installed (signed or plain) stays installed.
		log.Printf("revocations(%s): fetch from %s failed: %v (still enforcing whatever is already held)", label, src, err)
		return false
	}

	bundle, err := revocation.ParseBundle(raw)
	if err != nil {
		log.Printf("revocations(%s): bundle from %s is malformed: %v (refusing to replace what is held)", label, src, err)
		return false
	}

	d, err := v.Verify(bundle, now, state.minAsOf)
	if err != nil {
		// Refusing to REPLACE a good list with one that fails verification is
		// the point (ADR-0017 decision 4): an untrusted hop must not be able to
		// un-revoke a serial by serving a bundle that fails, whether by
		// accident or by design.
		log.Printf("revocations(%s): bundle from %s failed verification: %v (refusing to replace what is held)", label, src, err)
		return false
	}

	installRevocationsDoc(target, d)

	if d.AsOf.After(state.minAsOf) {
		state.minAsOf = d.AsOf
	}
	if err := cache.Store(raw, state.minAsOf); err != nil {
		// The list is verified and is being enforced; only the restart cache and
		// the persisted floor failed to update. That is a real problem — an
		// unpersisted floor is a rollback window across the next restart — so it
		// is loud, but it is not a reason to refuse a bundle that verified.
		log.Printf("revocations(%s): WARNING as_of %s verified and is now enforced, but persisting it to %s failed: %v — the rollback floor will not survive a restart, which leaves this coordinator open to a rollback", label, d.AsOf.UTC(), cache.Path(), err)
	}

	switch {
	case !state.had:
		log.Printf("revocations(%s): as_of %s loaded — %d serial(s) now enforced from the signed source (issue #199, ADR-0017)", label, d.AsOf.UTC(), len(d.Revoked))
	case !d.AsOf.Equal(state.lastAsOf):
		log.Printf("revocations(%s): as_of %s -> %s — %d serial(s) now enforced from the signed source", label, state.lastAsOf.UTC(), d.AsOf.UTC(), len(d.Revoked))
	}
	state.had, state.lastAsOf = true, d.AsOf

	return true
}

// installRevocationsDoc builds a fresh admission.RevocationList from a
// verified document's serials and swaps it into target — the same
// "build fresh, then atomically swap" shape reloadRevocationsLoop already uses
// for the plain-file path, so the two sources can never leave a torn or
// partially-applied list visible to a concurrent Revoked() read.
func installRevocationsDoc(target *atomic.Pointer[admission.RevocationList], d revocation.Doc) {
	rl := admission.NewRevocationList()
	for _, serial := range d.Revoked {
		rl.Revoke(serial)
	}
	target.Store(rl)
}
