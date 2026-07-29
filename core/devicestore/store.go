package devicestore

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// record is the on-disk shape of a Store: the two envelope strings exactly as
// received, never re-marshaled from parsed fields. devicecred's own doc is
// explicit about why — a verifier checks the signature over the bytes as
// received, and anything that round-trips a signed body through a re-encode
// risks disagreeing with the signer over whitespace or field order it was never
// supposed to have to agree on. Storage inherits that discipline even though it
// never verifies anything itself: it is the one place a client's own credential
// exists between being received and being presented, and re-marshaling it here
// would be the exact bug devicecred's doc warns a VERIFIER against, just moved
// one step earlier.
type record struct {
	Cred       string `json:"cred"`
	IssuerCert string `json:"issuerCert"`
}

// Store holds one device's credential + issuer cert (core/devicecred's
// "bacchusd1:"/"bacchusi1:" envelope strings) across restarts. It persists to a
// single JSON file and is safe for concurrent use.
//
// The zero value is not usable; construct with Open. path == "" is a fully
// working in-memory store that persists nothing — what a test, or an embedder
// with its own storage story, uses.
type Store struct {
	mu         sync.Mutex
	path       string
	cred       string
	issuerCert string
}

// Open loads the store persisted at path, or returns an empty one if the file is
// missing, unreadable, or corrupt.
//
// This is deliberately the selection.Store posture (soft-fail to empty), not the
// device key's (hard-fail on a present-but-broken file). Losing this file loses
// a renewable, hours-long entitlement, not an identity — the coordinator's gate
// (if enabled) refuses the next connect with a legible reason, and renewal or
// re-enrollment gets a fresh one. Losing the KEY silently would instead orphan
// that entitlement invisibly, which is the harm LoadOrGenerateKey refuses to
// risk. A damaged credential cache must never be why a client cannot even try to
// connect.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return s, nil
	}
	var rec record
	if json.Unmarshal(b, &rec) != nil {
		return s, nil
	}
	s.cred, s.issuerCert = rec.Cred, rec.IssuerCert
	return s, nil
}

// Get returns the stored credential and issuer cert. ok is false when either is
// missing — a partial pair (e.g. a cert with no credential) is not presentable,
// so it is reported the same as having neither.
func (s *Store) Get() (cred, issuerCert string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cred == "" || s.issuerCert == "" {
		return "", "", false
	}
	return s.cred, s.issuerCert, true
}

// Put replaces the stored credential and issuer cert and persists them —
// enrollment's or renewal's result, or an explicit clear when both are "". It
// stores exactly the bytes given; see the record doc on why nothing here
// decodes or re-encodes them.
func (s *Store) Put(cred, issuerCert string) error {
	s.mu.Lock()
	s.cred, s.issuerCert = cred, issuerCert
	path := s.path
	rec := record{Cred: cred, IssuerCert: issuerCert}
	s.mu.Unlock()
	if path == "" {
		return nil
	}
	return save(path, rec)
}

func save(path string, rec record) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// expiryBody is the subset of devicecred.DeviceCredential's JSON shape Expiry
// reads. It is its own type, not devicecred.DeviceCredential, deliberately: a
// caller reaching for the real type would be one field access away from
// treating this read as trustworthy, which is exactly what the Expiry doc below
// says it is not.
type expiryBody struct {
	NotAfter time.Time `json:"exp"`
}

// Expiry reads the NotAfter a stored device credential CLAIMS, without checking
// any signature.
//
// This is the one function in this package that looks inside a credential
// instead of treating it as an opaque string, and it is safe only because
// nothing here relies on it for a trust decision. The coordinator is the only
// party that ever admits or refuses on this chain's contents, and it re-derives
// NotAfter itself from a signature-verified body (core/devicecred.Verify) — this
// device already knows its own credential is genuine, having presumably just
// received it from the account service, so re-verifying a signature against
// itself would prove nothing. What Expiry is FOR is scheduling: deciding when to
// attempt a renewal, which is a liveness question, not a security one. Getting
// it wrong either wastes a renewal attempt slightly early or leaves one slightly
// late for the coordinator to refuse legibly — never a wrong admission.
//
// ok is false on any decode failure, which a caller should treat the same as
// "already due" — failing toward renewing is always the safe direction here.
func Expiry(encodedCred string) (time.Time, bool) {
	signed, err := devicecred.DecodeDeviceCredential(encodedCred)
	if err != nil || len(signed) <= ed25519.SignatureSize {
		return time.Time{}, false
	}
	body := signed[:len(signed)-ed25519.SignatureSize]
	var eb expiryBody
	if json.Unmarshal(body, &eb) != nil || eb.NotAfter.IsZero() {
		return time.Time{}, false
	}
	return eb.NotAfter, true
}

// NeedsRenewal reports whether the stored credential should be renewed now: its
// claimed expiry (see Expiry) is unknown, or is within margin of now.
//
// margin should be generous relative to how often a caller intends to check —
// credentials in this system live 24-72h (account-model.md §5), so checking
// every few minutes against a margin measured in hours gives many attempts
// before a renewal is genuinely urgent, and a transient failure of the account
// service costs nothing but a retry at the next check.
func NeedsRenewal(encodedCred string, now time.Time, margin time.Duration) bool {
	exp, ok := Expiry(encodedCred)
	if !ok {
		return true
	}
	return !now.Add(margin).Before(exp)
}
