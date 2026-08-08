package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// Connect-time device-credential verification (issue #50, ADR-0045).
//
// This is the coordinator's half of the account service's two-tier PKI: the
// offline root signs an issuer cert, the issuer key signs a short-lived device
// credential, and the device proves possession of that credential's key against a
// challenge this coordinator chose. All of it is verified OFFLINE — this
// coordinator never calls the account service, so matchmaking keeps working when
// that service is unreachable and leaks nothing to it when it is not.
//
// # It does not replace admission
//
// admissionVerifier gates who may be on the NETWORK at all: one tier, bearer,
// anchored to the operator's admission key, carrying node/client roles. This gates
// whether a client holds a live ENTITLEMENT: two tiers, challenge-bound, anchored
// to a root the operator does not hold. A connect passes admission first and this
// second, and neither can express the other's question. See ADR-0045.
//
// # Which way it fails
//
// With no root configured the gate is DISABLED and connects proceed on admission
// alone, the same direction as -admission-pubkey and -min-serving-version and the
// OPPOSITE of signed policy (issue #39), which stops assigning work once it goes
// stale.
//
// The direction follows from whether the failure is SHEDDABLE, which is the same
// test ADR-0043 applied and not the same answer. A coordinator whose policy went
// stale sheds to its peers, because a client rotates to another pool member and
// that member's policy is fine. An unconfigured trust anchor is not a condition a
// client can rotate away from: every coordinator in the pool reads the same
// configuration posture, so failing closed on it would darken every connect
// everywhere at once, with nothing to shed to and no signed deadline anyone
// authored. A stale policy is an operator's own signed expiry arriving; an absent
// anchor is a feature that was never switched on.
//
// What does NOT differ: once a root IS configured, a failed verification refuses
// that connect outright. There is no fallback, no soft mode and no cached admit.
// The open direction covers "not configured", never "configured and failing".

// deviceVerifier verifies presented device-credential chains, or is nil when
// -device-root-pubkey was not set, which DISABLES the gate. It is set once in main
// before the read loop starts and is read-only thereafter, so handle() needs no
// lock for it; the revocation list it closes over is the only part that changes,
// and that is swapped atomically by reloadRevocationsLoop.
var deviceVerifier *devicecred.Verifier

// deviceAudience is the identity a device must have bound its assertion to. It
// defaults to this coordinator's advertised address, because that is something a
// client knows INDEPENDENTLY — it chose to dial it — which is the whole point.
//
// An audience the coordinator announced in its own challenge reply would bind
// nothing: a hostile pool member would simply announce an honest coordinator's
// audience, relay the challenge, and present the collected chain as its own. The
// binding only works while the client already knows who it meant to talk to.
var deviceAudience string

const (
	// deviceChallengeLen is the size of the nonce this coordinator issues. Well
	// above devicecred.MinChallenge: the floor is what a verifier refuses to go
	// below, not a target.
	deviceChallengeLen = 32

	// deviceChallengeTTL bounds how long an issued challenge stays usable. It has to
	// cover a client signing and a round trip over lossy UDP, and nothing more — the
	// window is exactly how long a captured challenge is worth anything.
	deviceChallengeTTL = 2 * time.Minute

	// maxPendingChallenges caps the challenge store. UDP source addresses are
	// SPOOFABLE, so anything keyed on them is fillable by an attacker who never
	// completes a handshake. The cap plus expiry sweeping is what keeps that a
	// bounded nuisance rather than memory exhaustion; see issueDeviceChallenge for
	// what happens at the cap.
	maxPendingChallenges = 65536

	// challengeSweep is how often expired entries are swept even without new
	// traffic, so a burst of pending challenges does not stay resident until the
	// next request happens to arrive.
	challengeSweep = 30 * time.Second

	// maxStashedIssuerCert bounds the issuer-cert envelope this coordinator will
	// hold beside a nonce (issue #206). A real one is 362 bytes and its size is
	// fixed by its contents — a version, a serial, a 32-byte issuer key, two
	// timestamps, a TTL cap and a 64-byte signature — so this is roughly three
	// times what the artifact can be, not a guess at a range.
	//
	// It is belt and braces behind stashIssuerCert's real gate, which is that the
	// ROOT signed the thing. The bound is what keeps a malformed value cheap in the
	// window between arriving and being refused, on a map keyed by a spoofable UDP
	// source: without it the read path accepts 64 KiB, and maxPendingChallenges
	// would bound gigabytes rather than megabytes.
	maxStashedIssuerCert = 1024
)

// pendingChallenge is one issued nonce.
//
// spentBy records the connect nonce (issue #1's per-REQUEST idempotency key) that
// spent it, empty until it is spent. That binding is what separates the two things
// a repeated connect can be: core's sendN puts three copies of one request on the
// wire against UDP loss, and those copies must all be answered, while a second
// request re-presenting a spent challenge is a replay and must not be.
//
// The connect nonce identifies the REQUEST rather than the datagram, so "same
// nonce" is exactly "same request" — which makes it the right thing to bind to and
// saves keeping a second, parallel notion of sameness next to the one that already
// exists.
//
// cred is the admission credential this source presented on the "challenge" that
// minted the nonce, held so the connect that answers it does not have to carry a
// second copy (issue #183, ADR-0057). See challengeStore.stashCred for what may
// reach this field and why the raw string is kept rather than the decoded result.
//
// issuerCert is the same move for the issuer cert, which the connect no longer
// carries AT ALL (issue #206, ADR-0062). Its gate is a different authority — see
// stashIssuerCert — and the raw envelope is kept for stashCred's reason: the
// connect re-runs the whole verification against the clock and revocation list at
// connect time, so a cert revoked inside the challenge's two-minute TTL is still
// refused.
type pendingChallenge struct {
	value      []byte
	expires    time.Time
	spentBy    string
	spent      bool
	cred       string
	issuerCert string
}

// challengeStore holds the nonces this coordinator has issued and not yet seen
// spent, together with the admission credential each was issued against. A nonce
// answers exactly one REQUEST: spend binds it to the connect nonce that first
// presented it, so the retransmitted copies of that connect are answered and a
// second request re-presenting it is not. Without that binding a captured connect
// could be replayed at the same coordinator for as long as the challenge lived, and
// the challenge would be bounding the damage rather than preventing it.
//
// # Memory
//
// The credential raises what one entry costs from a 32-byte nonce to that plus a
// few hundred bytes of credential, so maxPendingChallenges now bounds roughly 30 MB
// rather than roughly 7. That is affordable because of what it takes to fill: an
// entry is created only from the "challenge" handler, which admission gates like
// every other client message, and stashCred stores nothing that was not VERIFIED
// against the anchored authority. A spoofing attacker with no credential can still
// fill the store — UDP sources are spoofable and that was always true — but every
// entry they create holds an empty string.
type challengeStore struct {
	mu      sync.Mutex
	entries map[string]pendingChallenge
	// capacity bounds the map; zero means maxPendingChallenges. It is a field so a
	// test can fill the store without minting 65536 entries.
	capacity int
	// lastSweep rate-limits the at-capacity sweep. Sweeping is O(entries), so doing
	// it per request under a flood would make the flood quadratic in its own volume
	// — an attacker's spoofed packets paying for each other's scans. The background
	// ticker is the unconditional reclaim; this is only the opportunistic one.
	lastSweep time.Time
	// atCapacity latches the first refusal so the log records the condition once
	// rather than once per spoofed packet.
	atCapacity bool
}

var challenges = &challengeStore{entries: map[string]pendingChallenge{}}

// atCapacitySweep is the minimum gap between opportunistic sweeps once the store
// is full.
const atCapacitySweep = time.Second

func (s *challengeStore) cap() int {
	if s.capacity > 0 {
		return s.capacity
	}
	return maxPendingChallenges
}

// sweepLocked drops expired entries. The caller holds mu.
func (s *challengeStore) sweepLocked(now time.Time) {
	for k, e := range s.entries {
		if !now.Before(e.expires) {
			delete(s.entries, k)
		}
	}
}

// issue mints a fresh challenge for key and stores it alongside cred and
// issuerCert, replacing any challenge already outstanding for that key — a client
// that asks twice is retrying, and honouring only the newest keeps one client from
// holding several live nonces. Both stashed values are replaced with the nonce for
// the same reason: they are the ones that came with the request being honoured.
//
// It returns nil when the store is at capacity after sweeping, which is a refusal
// to issue rather than an eviction of someone else's live challenge: evicting
// would let a spoofing attacker knock honest clients out of the store, turning a
// memory bound into a denial of service against exactly the traffic it protects.
func (s *challengeStore) issue(key, cred, issuerCert string, now time.Time) []byte {
	v := make([]byte, deviceChallengeLen)
	if _, err := rand.Read(v); err != nil {
		log.Printf("device credential: cannot generate a challenge: %v", err)
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// The common path does no scanning at all: replacing an outstanding entry, or
	// adding one while there is headroom, is O(1). Expired entries are reclaimed by
	// sweepChallengesLoop on its ticker.
	if _, held := s.entries[key]; !held && len(s.entries) >= s.cap() {
		// At capacity, expired entries are the only headroom there is — but sweeping
		// costs a full scan, so it is rate-limited. Without that, a flood large
		// enough to fill the store would make every subsequent spoofed packet pay for
		// a scan of every other one.
		if now.Sub(s.lastSweep) >= atCapacitySweep {
			s.lastSweep = now
			s.sweepLocked(now)
		}
		if len(s.entries) >= s.cap() {
			if !s.atCapacity {
				s.atCapacity = true
				log.Printf("WARNING: device credential: %d challenges outstanding — refusing to issue more until they expire (issue #50). UDP sources are spoofable, so this is reachable without any real client", s.cap())
			}
			return nil
		}
	}
	s.atCapacity = false
	s.entries[key] = pendingChallenge{value: v, expires: now.Add(deviceChallengeTTL), cred: cred, issuerCert: issuerCert}
	return v
}

// stashedCred returns the admission credential held for key, or "" when there is no
// live entry. It does not spend, drop or otherwise disturb the challenge: this is a
// read, and the nonce still has its own single-use life to lead.
func (s *challengeStore) stashedCred(key string, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok || !now.Before(e.expires) {
		return ""
	}
	return e.cred
}

// stashedIssuerCert returns the issuer cert held for key, or "" when there is no
// live entry. A read, like stashedCred: it disturbs nothing.
func (s *challengeStore) stashedIssuerCert(key string, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok || !now.Before(e.expires) {
		return ""
	}
	return e.issuerCert
}

// spend returns the outstanding challenge for key, binding it to the connect nonce
// that spent it. A missing or expired entry returns nil, and so does a spent entry
// re-presented by any request other than the one that spent it.
//
// The effect is that a challenge answers exactly one REQUEST — retransmitted as
// often as UDP loss demands — rather than exactly one datagram. Binding to the
// datagram would refuse copies two and three of every honest connect; binding to
// nothing would let a captured connect be replayed for the nonce's whole lifetime.
func (s *challengeStore) spend(key, nonce string, now time.Time) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok || !now.Before(e.expires) {
		return nil
	}
	if e.spent {
		// Only the request that spent it may re-present it. An empty nonce can never
		// match, so a caller that lost its nonce cannot re-enter this path either.
		if e.spentBy == "" || nonce == "" || e.spentBy != nonce {
			return nil
		}
		return e.value
	}
	e.spent, e.spentBy = true, nonce
	s.entries[key] = e
	return e.value
}

// drop removes a challenge outright. It is what a FAILED verification does, so a
// rejected attempt cannot be retried against a nonce that is still live — a
// captured chain gets one attempt, not one attempt per copy it can send.
func (s *challengeStore) drop(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
}

func (s *challengeStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// sweepChallengesLoop drops expired challenges on a timer, so pending entries do
// not stay resident purely because no new request arrived to trigger a sweep.
func sweepChallengesLoop(ctx context.Context) {
	t := time.NewTicker(challengeSweep)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			challenges.mu.Lock()
			challenges.sweepLocked(time.Now())
			challenges.mu.Unlock()
		}
	}
}

// setupDeviceCred builds the connect-time verifier from the operator's configured
// ROOT public key and starts the revocation reload and challenge sweep loops.
//
// An empty rootPubHex DISABLES the gate and returns a nil verifier (the caller
// warns). A malformed key is a hard error: a coordinator told to enforce
// entitlement with an unusable anchor must not fall through to admitting
// everyone — that is the one shape where "fails open" would be a silent hole
// rather than a decision.
//
// audience defaults to this coordinator's advertised address when the operator did
// not set one explicitly. An empty audience with the gate ENABLED is refused: it
// would verify perfectly well and bind nothing, which is the failure mode that
// looks exactly like success.
//
// The fourth return value is the device-namespace revocation list this function
// builds and keeps reloadRevocationsLoop pointed at — nil exactly when the
// device-credential gate is disabled, the same case in which no reload loop
// starts at all. See setupAdmission's identical return value for why: it lets a
// caller point the signed-revocations fetch loop (issue #199, ADR-0017,
// ADR-0063) at the SAME in-memory list, additively, and there is nothing for it
// to populate — and nobody to read it — while this gate is off.
func setupDeviceCred(ctx context.Context, rootPubHex, audience, advertised, revocationsPath string) (*devicecred.Verifier, string, *atomic.Pointer[admission.RevocationList], error) {
	if rootPubHex == "" {
		return nil, "", nil, nil
	}
	pub, err := hex.DecodeString(rootPubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, "", nil, fmt.Errorf("device credential: bad -device-root-pubkey: want %d hex-encoded bytes", ed25519.PublicKeySize)
	}

	if audience == "" {
		audience = advertised
	}
	if audience == "" {
		return nil, "", nil, fmt.Errorf("device credential: -device-root-pubkey is set but this coordinator has no audience — set -advertise (or -device-audience) to the identity clients dial it by, or an assertion would be bound to nothing")
	}

	revocations := new(atomic.Pointer[admission.RevocationList])
	revocations.Store(admission.NewRevocationList())
	go reloadRevocationsLoop(ctx, revocationsPath, revocations)
	go sweepChallengesLoop(ctx)

	v, err := devicecred.NewVerifier(ed25519.PublicKey(pub), func(serial string) bool {
		return revocations.Load().Revoked(serial)
	})
	if err != nil {
		return nil, "", nil, fmt.Errorf("device credential: %w", err)
	}
	return v, audience, revocations, nil
}

// challengeKey identifies whoever a challenge was issued to. It is the full source
// address, so a challenge issued to one address cannot be spent from another.
//
// This is a binding, not an authentication: UDP sources are spoofable, and an
// attacker who can both spoof a source AND observe the reply to it has the
// challenge anyway. What it does buy is that a BLIND attacker cannot spend a
// challenge issued to someone else, and combined with single-use consumption it
// keeps one client's nonce from being usable by another.
func challengeKey(src *net.UDPAddr) string { return src.String() }

// issueDeviceChallenge mints a fresh nonce for src and returns it base64-encoded,
// or "" when the gate is disabled or the store is at capacity. cred and issuerCert
// are what the "challenge" carried, stashed for the connect that will answer this
// nonce (issues #183 and #206) — see stashCred and stashIssuerCert for what is
// actually kept, which is not the same test in the two cases.
func issueDeviceChallenge(src *net.UDPAddr, cred, issuerCert string) string {
	if deviceVerifier == nil {
		return ""
	}
	v := challenges.issue(challengeKey(src), stashCred(cred), stashIssuerCert(issuerCert), time.Now())
	if v == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(v)
}

// stashCred is what may be kept from a "challenge" request: the credential when this
// coordinator VERIFIED it, and nothing at all otherwise.
//
// The gate is admissionVerifier rather than the value being non-empty, and that is
// the whole security argument for the stash. main.go's "challenge" handler runs
// admit() before reaching issueDeviceChallenge, so with an authority anchored, a
// credential that gets this far is one this coordinator has checked against it. With
// NO authority anchored, admit() admits everyone and m.Cred is an unverified,
// unbounded, attacker-chosen string — so nothing is kept, and nothing needs to be:
// the connect that follows is admitted on the same absent gate.
//
// Belt and braces on top of that: an entry can only exist while the DEVICE gate is
// enabled (issueDeviceChallenge returns early otherwise), and a connect that reads
// from the stash must still pass admitDevice, which requires an assertion signed
// over the nonce this coordinator issued to this source. A blind spoofer cannot see
// the reply, so cannot produce one, so cannot spend a stashed credential — the
// stash never widens what a connect can get away with, it only saves it 400 bytes.
func stashCred(cred string) string {
	if admissionVerifier == nil {
		return ""
	}
	return cred
}

// stashIssuerCert is what may be kept from a "challenge"'s issuer cert: the envelope
// when the anchored ROOT signed it and it is live, and nothing at all otherwise
// (issue #206, ADR-0062).
//
// # Why the gate is not stashCred's gate, which the card asked for
//
// #206 says the stash should keep "only what it verified, and only under the same
// condition the existing stash uses." The first half holds and the second does not,
// and the difference matters enough to be worth stating rather than quietly getting
// right. stashCred's condition is `admissionVerifier != nil`, because ADMISSION is
// what verified the credential it keeps — main.go's "challenge" handler runs admit()
// before reaching here. Applying that same condition to the issuer cert would refuse
// to stash on any deployment running the device-credential gate (#50) with admission
// (#42) switched OFF: the nonce is issued, the client therefore leaves the cert off
// its connect, the stash is empty, and admitDevice sees no cert and refuses EVERY
// connect. That is the exact shape of the correction ADR-0057 §2 had to make to its
// own ruling — the failure is total rather than degraded, and it is an ordinary
// configuration rather than an edge case.
//
// The right condition is the authority that can actually speak for this artifact.
// An issuer cert is signed by the offline root, which is the one thing a coordinator
// running this gate is guaranteed to hold — an entry can only exist while
// deviceVerifier is non-nil (issueDeviceChallenge returns before this on a disabled
// gate). So the cert is verified HERE, on arrival, and only a cert the root signed
// and has not revoked is kept.
//
// This is strictly stronger than the credential stash rather than a relaxation of
// it, and it is stronger for a structural reason: an issuer cert is verifiable
// STANDALONE, while an admission credential's bearer is checked by the gate one
// layer up and a device credential means nothing without the assertion that binds it
// to a nonce. Nothing unverified is stored either way.
//
// The raw envelope is kept rather than the parsed cert, for stashCred's reason: the
// connect re-runs the full descent (Verifier.Verify) against the clock and the
// revocation list AS OF THE CONNECT, so a cert revoked inside the challenge's
// two-minute TTL is still refused. This check is what may be held, not what is
// admitted.
func stashIssuerCert(issuerCert string) string {
	if deviceVerifier == nil || issuerCert == "" || len(issuerCert) > maxStashedIssuerCert {
		return ""
	}
	signed, err := devicecred.DecodeIssuerCert(issuerCert)
	if err != nil {
		return ""
	}
	if _, err := deviceVerifier.VerifyIssuerCert(signed, time.Now()); err != nil {
		// Not logged. This is reachable from any source that can send a datagram, and
		// one line per malformed cert is how a log becomes as good as no log at all.
		// The connect that follows is refused by admitDevice, which DOES log, once,
		// with the reason — and that is the refusal an operator needs to see.
		return ""
	}
	return issuerCert
}

// admissionCredFor is the admission credential a connect from src should be judged
// on: the one it carried, or — when it carried none — the one the "challenge" that
// minted this source's outstanding nonce carried (issue #183, ADR-0057).
//
// The client sends only one copy, and which message it rides is decided by whether
// the challenge exchange completed (core's connectAdmissionCred). This is the other
// half of that: a coordinator has to accept a connect whose credential arrived a
// round trip earlier, and it has to do so without loosening anything, which is why
// the stash is read-only here and why nothing unverified ever reaches it.
//
// A connect that carries its own wins outright and is not compared with the stash.
// Two different credentials from one source across one exchange is not a case worth
// adjudicating — verifying what was sent is both the simpler rule and the one that
// cannot be gamed by the stash.
func admissionCredFor(m wire, src *net.UDPAddr) string {
	if m.Cred != "" {
		return m.Cred
	}
	return challenges.stashedCred(challengeKey(src), time.Now())
}

// issuerCertFor is the issuer cert a connect from src should be verified against:
// the one it carried, or — when it carried none, which is every connect a current
// client sends — the one the "challenge" that minted this source's outstanding nonce
// carried (issue #206, ADR-0062).
//
// admissionCredFor's twin, and deliberately the same shape down to the tie-break: a
// connect that carries its own wins outright and is not compared against the stash.
// The two differ only in which message the client CHOOSES to put the field on. The
// admission credential is conditional — it rides the connect whenever no challenge
// was answered — so both branches here are live. The issuer cert moved outright, so
// the first branch exists for a client that predates #206 and for nothing else; it
// is what makes that client keep working against this coordinator, which is the half
// of compatibility a coordinator can actually provide.
func issuerCertFor(m wire, src *net.UDPAddr) string {
	if m.IssuerCert != "" {
		return m.IssuerCert
	}
	return challenges.stashedIssuerCert(challengeKey(src), time.Now())
}

// admitDevice reports whether a connect may proceed on its device credential.
//
// When the gate is disabled (nil verifier) everything is admitted, preserving the
// pre-#50 behavior. Otherwise the presented chain is verified offline against the
// anchored root, bound to this coordinator's audience and to the exact challenge
// this coordinator issued to this source and has not yet seen spent.
//
// On refusal it replies to src with a reject naming the reason and returns false,
// on which the caller stops handling m — no session is minted and no exit is
// assigned. Every devicecred error names a protocol fact only, never key material
// and nothing account-scoped, so it is safe to send and to log.
//
// The challenge is consumed whether or not verification succeeds. A failed attempt
// burns the nonce and the client must ask for a fresh one, so a captured chain
// cannot be retried against a challenge that is still outstanding.
func admitDevice(m wire, src *net.UDPAddr) bool {
	if deviceVerifier == nil {
		return true
	}

	key := challengeKey(src)

	// A refusal drops the challenge, so a rejected attempt cannot be retried against
	// a nonce that is still live. The successful path deliberately leaves the entry
	// in place, bound to this request's nonce, so the retransmitted copies of this
	// same connect are answered rather than refused.
	reject := func(reason string) bool {
		challenges.drop(key)
		log.Printf("device credential: reject connect from %s: %s", src, reason)
		send(src, wire{Type: "reject", Reason: reason})
		return false
	}

	issued := challenges.spend(key, m.Nonce, time.Now())
	if issued == nil {
		return reject("no outstanding device-credential challenge for this address — request one with a \"challenge\" message immediately before connecting")
	}

	// The client echoes the challenge it signed. Comparing it to the one actually
	// issued turns a mismatch into a clear refusal here rather than an opaque
	// assertion failure below — and the comparison is constant-time out of habit
	// rather than need, so the pattern stays right if this is ever copied somewhere
	// the value is secret.
	echoed, err := base64.StdEncoding.DecodeString(m.Challenge)
	if err != nil || subtle.ConstantTimeCompare(echoed, issued) != 1 {
		return reject("device assertion does not answer the challenge this coordinator issued")
	}

	assertion, err := base64.StdEncoding.DecodeString(m.DeviceAssert)
	if err != nil {
		return reject(devicecred.ErrMalformed.Error())
	}
	p, err := devicecred.ParsePresentation(m.DeviceCred, m.IssuerCert, assertion)
	if err != nil {
		return reject(err.Error())
	}

	cred, err := deviceVerifier.Verify(p, time.Now(), deviceAudience, issued)
	if err != nil {
		return reject(err.Error())
	}

	// Nothing account-scoped is logged: the serial names the credential for
	// revocation and the epoch is a generation counter, and neither identifies an
	// account. The device public key is deliberately NOT logged — it is stable
	// across renewals, so logging it would build exactly the linkage the credential
	// format works to avoid handing a coordinator.
	log.Printf("device credential: admit connect from %s (serial %s, epoch %d)", src, cred.Serial, cred.Epoch)
	return true
}
