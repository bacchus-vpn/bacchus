// The signed cold-start directory, on the desktop client (bacchus#193,
// ADR-0061; ADR-0016 decision 4 in bacchus-payment is what asks for it).
//
// # What this closes
//
// Every address this client dials was, until now, a static string in one JSON
// file: the coordinator pool, and the account service beside it. Nothing could
// tell it that any of them had moved. That is not a hypothetical gap — the
// account service runs on anonymously rented infrastructure and its address WILL
// change, and because a device renews the moment it enters its renewal margin,
// an unplanned move takes the first devices offline about six hours later rather
// than at the forty-two-hour renewal period. A moved COORDINATOR is worse: it
// takes the client offline immediately.
//
// core/coldstart has carried the answer since old #18 and no client had
// adopted it. A coordinator signs a directory of entry points with a validity
// window; a client authenticated by a per-user secret fetches it over a
// STUN-shaped exchange on the coordinator's TURN port, verifies the signature,
// and reads addresses out of it by ROLE. This file is that adoption.
//
// # The three tiers, and why an expired snapshot is not one of them
//
// AcquireDirectory answers from the freshest thing it has: a snapshot already
// held in memory, then the on-disk cache, then the network. Every tier is
// signature-checked against the key inside THIS config's invite, and every tier
// must be unexpired.
//
// Refusing an expired snapshot is the rule, and it costs something real: the
// coordinator's snapshotTTL is five minutes, so a cached directory is usable for
// a rapid reconnect and almost never at the next day's launch. That is the right
// trade. The whole value of this artifact is that it says where things are NOW,
// and a client that adopted a stale one would replace a possibly-current
// configured address with a certainly-old directory address — pointing itself
// away from the seed it was installed with, on the strength of a document that
// has expired. The fallback is never "nothing": it is the configured list, which
// is exactly what this client used before it could do any of this.
//
// # What is deliberately NOT here
//
// Mesh-walk recovery (old #31) is the other half of coldstart and stays out.
// It fetches a directory from a PEER when every coordinator is unreachable, and
// its peers are nodes running a courier listener on a separate -courier-listen
// address that the snapshot does not carry — so the relay and exit entries of a
// snapshot are not, in this deployment, addresses a walk could ask. The signed
// bytes are cached here regardless, because they are the proof of prior contact
// such a walk would have to present, and having it on disk is what makes that a
// later wiring job rather than a later protocol job.
package appstate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// directoryTimeout bounds one cold-start fetch. It matches coldstart's own
// default (its defaultTimeout) rather than choosing a new number, and it is
// deliberately short: this runs at the FRONT of a connect, before the coordinator
// is dialled, so on a network where the bootstrap port is blocked but signaling
// is not, it is pure added latency on every connect. The in-memory and on-disk
// tiers are what keep it off the repeat path.
const directoryTimeout = 5 * time.Second

// Directory roles, as they appear in coldstart.Entry.Role. Spelled here rather
// than imported because coldstart carries them as literals too (see
// Entry.RelayEligible) — this is the consuming end of one wire vocabulary, and
// the pairing is asserted by a test rather than shared through a constant that
// package does not export.
const (
	roleCoordinator = "coordinator"
	roleAccount     = "account"
)

// Directory is a verified, unexpired snapshot this client has adopted, or the
// zero value when it holds none — which is the ordinary state of a client with
// no invite, and of one whose fetch failed.
//
// Signed is the wire form exactly as it arrived, which is what SaveCache stores
// and what any later mesh-walk would present as proof of prior contact. Its
// presence is what Held reports: a Snapshot with no Signed beside it was never
// checked against anything.
type Directory struct {
	Snapshot coldstart.Snapshot
	Signed   []byte
}

// Held reports whether this Directory carries a verified snapshot.
func (d Directory) Held() bool { return len(d.Signed) > 0 }

// Expired reports whether the snapshot's own validity window has closed. Read
// with a live clock at the point of USE rather than trusted from the moment of
// verification: a directory held in memory across a long session goes stale
// where it sits, and the tier that would refuse it is the one being skipped.
func (d Directory) Expired(now time.Time) bool {
	return !d.Held() || now.After(d.Snapshot.ExpiresAt)
}

// Coordinators is the signaling addresses this directory names.
func (d Directory) Coordinators() []string {
	if !d.Held() {
		return nil
	}
	return d.Snapshot.AddrsForRole(roleCoordinator)
}

// AccountServiceURLs is the account service base URLs this directory names.
func (d Directory) AccountServiceURLs() []string {
	if !d.Held() {
		return nil
	}
	return d.Snapshot.AddrsForRole(roleAccount)
}

// ErrNoInvite is what decodeInvite reports when the config names none. It is not
// a failure — it is the pre-bacchus#193 client, which is a supported deployment
// and the one every existing install is running.
var errNoInvite = errors.New("no invite configured")

// decodeInvite parses Config.Invite, or reports errNoInvite when it is empty.
//
// A malformed invite is an ERROR rather than a shrug, and the caller turns it
// into a refused connect naming the field. Ignoring it would leave a user whose
// invite lost a character in the worst state available: a client that looks
// configured to follow a moved address, silently does not, and gives no sign
// until the day an address actually moves and it goes offline for a reason
// nothing on screen connects to what they typed.
func (c Config) decodeInvite() (coldstart.Invite, error) {
	s := strings.TrimSpace(c.Invite)
	if s == "" {
		return coldstart.Invite{}, errNoInvite
	}
	inv, err := coldstart.DecodeInvite(s)
	if err != nil {
		return coldstart.Invite{}, fmt.Errorf("the \"invite\" in this client's config file could not be read (%w) — paste the whole bacchus1: string exactly as it was given to you, or remove the key to go back to the addresses in this file", err)
	}
	return inv, nil
}

// AcquireDirectory returns a verified, unexpired directory for cfg, or the zero
// Directory when there is none to be had.
//
// held is what the caller already has in memory (the zero Directory on a first
// call). It is returned untouched when it is still live, so a connect that
// follows a country refresh — or a reconnect a minute after a disconnect — costs
// no file read and no round trip.
//
// The error return is for a MISCONFIGURATION only: an invite that cannot be
// read. Everything else that can go wrong here — no cache, a corrupt cache, an
// unreachable coordinator, a snapshot that fails its signature — returns the
// zero Directory and no error, because every one of those means "carry on with
// what was configured", which is a complete way to run this client. They are
// logged, because a client that silently stopped following the directory would
// be indistinguishable from one that never had an invite.
func AcquireDirectory(ctx context.Context, cfg Config, held Directory, logf func(string, ...any)) (Directory, error) {
	log := func(format string, args ...any) {
		if logf != nil {
			logf(format, args...)
		}
	}
	inv, err := cfg.decodeInvite()
	if errors.Is(err, errNoInvite) {
		// No invite: this client is exactly what it was before bacchus#193. Any
		// snapshot held from a previous config is dropped with it, so removing
		// the invite really does return the client to its configured addresses.
		return Directory{}, nil
	}
	if err != nil {
		return Directory{}, err
	}

	// The in-memory tier, and it is re-checked against THIS invite rather than
	// trusted because this process fetched it. An operator handing a user a
	// replacement invite is the one gesture that changes which coordinator this
	// client believes, and without this the snapshot fetched under the old one
	// would go on answering for the rest of its validity window — a live client
	// still following a directory it is no longer entitled to read. The check is
	// one ed25519 verification per connect against bytes already in memory.
	if !held.Expired(time.Now()) {
		if _, verr := coldstart.VerifySigned(inv.PublicKey, held.Signed); verr == nil {
			return held, nil
		}
		log("directory: the directory held in memory does not verify against the configured invite — re-fetching")
	}

	cachePath := DefaultDirectoryCachePath()
	if d, ok := loadCachedDirectory(cachePath, inv, log); ok {
		return d, nil
	}

	fetchCtx, cancel := context.WithTimeout(ctx, directoryTimeout)
	defer cancel()
	res, err := coldstart.Bootstrap(fetchCtx, inv.Coordinator, inv.SecretID, inv.Secret, inv.PublicKey)
	if err != nil {
		// Includes a coordinator that answered but did not authenticate this
		// secret (coldstart.ErrNotAuthenticated), which is what a revoked or
		// mistyped invite looks like from here and is deliberately
		// indistinguishable from "not a bootstrap endpoint" on the wire.
		log("directory: could not fetch the signed directory from %s: %v — using the addresses in this client's config", inv.Coordinator, err)
		return Directory{}, nil
	}
	// Bootstrap verifies the signature AND the validity window before it
	// returns, so there is nothing further to check here.
	d := Directory{Snapshot: res.Snapshot, Signed: res.Signed}
	if cachePath != "" {
		if err := saveDirectoryCache(cachePath, res.Signed); err != nil {
			// A cache that could not be written costs a round trip next time and
			// nothing else, so it is worth a line and not worth a failed connect.
			log("directory: fetched a fresh directory but could not cache it at %s: %v", cachePath, err)
		}
	}
	log("directory: fetched a signed directory naming %d coordinator(s) and %d account service address(es), valid for %s",
		len(d.Coordinators()), len(d.AccountServiceURLs()), RoughDuration(time.Until(d.Snapshot.ExpiresAt)))
	return d, nil
}

// saveDirectoryCache writes the signed snapshot, creating the parent directory
// if it is missing.
//
// The MkdirAll is not decoration. coldstart.SaveCache stages its temporary file
// in the TARGET'S OWN directory — it has to, because os.Rename is atomic only
// within one filesystem — so a missing parent fails the STAGING rather than the
// rename, with an errno about a temporary file the caller never named. The
// parent here is `<config dir>/Bacchus/`, and on a machine where this client has
// never saved a config, nothing has created it. That is issue #118's failure
// wearing a third face; SaveConfig carries the same MkdirAll for the same
// reason, and coldstart's own doc says it deliberately does not create parents
// because its other caller's missing secrets directory should be an error.
//
// 0700 because the file is this client's own cache under the same directory that
// holds a 0600 config with a TURN password and an exit identity key in it.
func saveDirectoryCache(path string, signed []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return coldstart.SaveCache(path, signed)
}

// loadCachedDirectory reads and verifies the on-disk snapshot, reporting whether
// it produced one worth adopting.
//
// It verifies against THIS invite's public key, which is what makes swapping the
// invite safe: a cache left behind by a previous operator's invite fails the
// signature check and is passed over, rather than being adopted because it
// happens to be sitting at the path this build reads. That is the
// "wrong-coordinator snapshot" case, and it needs no separate machinery — a
// snapshot signed by a key this client does not hold is exactly a snapshot that
// does not verify.
//
// Every failure is normal rather than exceptional: a missing file is a client
// that has never fetched, and a corrupt or expired one is a client that has not
// fetched recently. A missing file is not even logged; the rest are, once, at
// the point where the fetch that replaces them is about to happen.
func loadCachedDirectory(path string, inv coldstart.Invite, log func(string, ...any)) (Directory, bool) {
	if path == "" {
		return Directory{}, false
	}
	signed, err := coldstart.LoadCache(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log("directory: could not read the cached directory at %s: %v — fetching a fresh one", path, err)
		}
		return Directory{}, false
	}
	snap, err := coldstart.Verify(inv.PublicKey, signed)
	if err != nil {
		log("directory: the cached directory at %s was not adopted (%v) — fetching a fresh one", path, err)
		return Directory{}, false
	}
	return Directory{Snapshot: snap, Signed: signed}, true
}

// EffectiveCoordinators is the coordinator pool a connect should use: the
// directory's addresses first, then the configured ones it did not name, with
// blanks and duplicates dropped.
//
// It UNIONS where EffectiveAccountServiceURLs replaces, and the asymmetry is a
// property of the producer rather than a hedge. cmd/coordinator's buildSnapshot
// puts exactly ONE coordinator entry in a snapshot — its own advertised address
// — because a coordinator has no knowledge of its peers to publish. So "the
// directory's list wins" applied literally to this role would narrow a client
// configured with three coordinators down to the single one that happened to
// sign the directory it fetched, deleting the operator's own redundancy through
// a change made on the client. The account service's list has no such limit: one
// flag states the whole of it, so what it publishes is a complete answer.
//
// What the directory therefore contributes here is PRECEDENCE, not membership.
// A coordinator that moved is named by the directory and dialled first; the
// configured addresses stay behind it, where core's own pool ranking
// (core/coordpool.go, healthy-first with a cooldown) costs a dead one a single
// attempt.
func EffectiveCoordinators(fromDirectory, configured []string) []string {
	return mergeAddrs(fromDirectory, configured)
}

// EffectiveAccountServiceURLs is the account service address list a connect
// should use: the directory's, when it names any, and the configured one
// otherwise.
//
// The directory REPLACES rather than merges, which is ADR-0016 decision 4 taken
// literally — "the directory's list wins; the configured list is the seed" — and
// it is the only reading that does the job. The configured address is precisely
// the one that goes stale, so keeping it would leave every client permanently
// re-trying the address the operator moved away from; and a coordinator states
// this list in full (one repeatable flag), so what arrives is a complete answer
// rather than one member of a set.
//
// A directory that names NO account service falls back to the configured list
// rather than to nothing. That is what lets this ship to a fleet whose
// coordinators have not been given the flag yet, and it is the difference
// between an upgrade and an outage.
func EffectiveAccountServiceURLs(fromDirectory, configured []string) []string {
	if d := mergeAddrs(fromDirectory, nil); len(d) > 0 {
		return d
	}
	return mergeAddrs(configured, nil)
}

// mergeAddrs concatenates two address lists in order, trimming each entry and
// dropping blanks and repeats. Order is preference order, so the first mention
// of an address is the one that survives.
func mergeAddrs(first, second []string) []string {
	out := make([]string, 0, len(first)+len(second))
	seen := map[string]bool{}
	for _, list := range [][]string{first, second} {
		for _, a := range list {
			a = strings.TrimSpace(a)
			if a == "" || seen[a] {
				continue
			}
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}
