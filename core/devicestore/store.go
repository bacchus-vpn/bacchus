package devicestore

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// Credential is everything one issuing response gives a device, and everything
// one Put writes: the device credential, the issuer cert it chains to, and the
// admission credential minted beside them.
//
// The three travel together because the account service issues them together,
// over the SAME validity window, from one call. A caller that wrote them in
// separate steps could persist a fresh credential against a stale companion —
// which is not a theoretical hazard here: it is the shape this store had until
// bacchus#166, when the admission credential had no slot at all and a renewal
// silently left network membership on the expiring copy while the entitlement
// went forward.
type Credential struct {
	// Device is the "bacchusd1:" envelope, verbatim — this device's entitlement,
	// signed by the account service's issuer key, presented on every connect to
	// answer a coordinator's device gate.
	Device string
	// IssuerCert is the "bacchusi1:" envelope Device chains to, signed by the
	// offline root.
	IssuerCert string
	// Admission is the "bacchusc1:" envelope: this device's admission credential,
	// the thing an admission-enforcing coordinator checks before it will speak to
	// this node at all. A DIFFERENT credential under a DIFFERENT authority from
	// the two above — see core/devicecred's package doc — carried here because
	// the account service mints it in the same response over the same window, so
	// storing it anywhere else would mean two writes and two expiries to keep in
	// step.
	//
	// EMPTY IS A REAL DEPLOYMENT, NOT AN ERROR. A service configured with no
	// admission key mints none, and an operator running a coordinator with
	// admission disabled needs none. Empty here means exactly what an empty
	// core.Config.AdmissionCred means: present none.
	Admission string
}

// Presentable reports whether this credential can answer a coordinator's device
// gate: both the credential and the cert it chains to are held. A partial pair
// (a cert with no credential) is not presentable, so it is reported the same as
// having neither.
//
// Admission is deliberately not part of the question. It answers a different
// gate under a different authority, and a deployment that mints none is not a
// deployment whose devices hold half a credential.
func (c Credential) Presentable() bool {
	return c.Device != "" && c.IssuerCert != ""
}

// record is the on-disk shape of a Store: the envelope strings exactly as
// received, never re-marshaled from parsed fields. devicecred's own doc is
// explicit about why — a verifier checks the signature over the bytes as
// received, and anything that round-trips a signed body through a re-encode
// risks disagreeing with the signer over whitespace or field order it was never
// supposed to have to agree on. Storage inherits that discipline even though it
// never verifies anything itself: it is the one place a client's own credential
// exists between being received and being presented, and re-marshaling it here
// would be the exact bug devicecred's doc warns a VERIFIER against, just moved
// one step earlier.
//
// The two original keys keep their names, so a file written before bacchus#166
// loads unchanged; "admission" is additive and omitted when empty.
type record struct {
	Cred       string `json:"cred"`
	IssuerCert string `json:"issuerCert"`
	Admission  string `json:"admission,omitempty"`
}

// Store holds one device's credential, issuer cert and admission credential
// (core/devicecred's "bacchusd1:"/"bacchusi1:" and core/admission's
// "bacchusc1:" envelope strings) across restarts. It persists to a single JSON
// file and is safe for concurrent use.
//
// The zero value is not usable; construct with Open. path == "" is a fully
// working in-memory store that persists nothing — what a test, or an embedder
// with its own storage story, uses.
type Store struct {
	mu   sync.Mutex
	path string
	cred Credential
}

// Open loads the store persisted at path, or returns an empty one if the file is
// missing, unreadable, or corrupt. A file written before the admission
// credential joined the record loads with an empty Admission, and a device
// enrolled in that window has its separate admission file adopted once — see
// legacyAdmissionFileName.
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
	s.cred = Credential{Device: rec.Cred, IssuerCert: rec.IssuerCert, Admission: rec.Admission}
	if s.cred.Admission == "" {
		s.cred.Admission = adoptLegacyAdmission(filepath.Dir(path))
	}
	return s, nil
}

// legacyAdmissionFileName is where core/accountclient kept the admission
// credential for the two days between bacchus#163 and bacchus#166: a file of its
// own beside this one, because this store held exactly two strings and none of
// them was that one.
//
// It is read here, once, so a device enrolled in that window does not silently
// lose its network membership the first time it starts on a build that keeps all
// three together. Nothing writes it any more, and the next Put folds the value
// into the JSON, so a directory needs adopting at most once. Delete this and
// adoptLegacyAdmission when no such directory can plausibly remain — no release
// ever carried the separate file, so the population is the machines that ran
// bacchus#163's end-to-end work.
const legacyAdmissionFileName = "admission.cred"

// adoptLegacyAdmission reads a pre-bacchus#166 admission file from dir, or
// returns "" when there is none.
//
// Soft-fails to empty on every failure, matching Open itself: this is a
// short-lived, reissuable grant, and a damaged copy of it must never be the
// reason a client cannot even try to connect. The single-line check is the same
// one the file's writer applied — the envelope form contains no whitespace, so
// anything multi-line here was half-written by something that crashed.
func adoptLegacyAdmission(dir string) string {
	if dir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, legacyAdmissionFileName))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if s == "" || strings.ContainsAny(s, "\r\n") {
		return ""
	}
	return s
}

// Get returns everything this device holds. ok is Credential.Presentable — false
// when the device credential or the issuer cert is missing, whatever the
// admission credential says, since those two are the pair a connect presents.
func (s *Store) Get() (Credential, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cred, s.cred.Presentable()
}

// Put replaces everything this device holds and persists it — enrollment's or
// renewal's result, or an explicit clear when the zero value is given. It stores
// exactly the bytes given; see the record doc on why nothing here decodes or
// re-encodes them.
//
// All three go in one call, and there is deliberately no way to write one of
// them alone. They are issued together over one window (see Credential), so a
// per-field setter would exist only to create the state this store's whole shape
// is arranged to make unrepresentable: a fresh credential persisted against a
// stale companion. A caller refreshing two of the three carries the third
// through — core's renewal path does exactly that when a response omits the
// admission credential.
func (s *Store) Put(c Credential) error {
	s.mu.Lock()
	s.cred = c
	path := s.path
	rec := record{Cred: c.Device, IssuerCert: c.IssuerCert, Admission: c.Admission}
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
