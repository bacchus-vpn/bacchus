// Package accounting implements the v1 metering stub (old #20): a client
// and an exit each sign a claim of "N bytes over interval T" so that neither
// side can unilaterally inflate the count a receipt records. This proves the
// accounting hook is buildable; it is deliberately not fraud-proof. Co-signing
// stops one side from inventing a number the other never agreed to, but it
// does not stop a volunteer colluding with a fake client -- that is a v2
// problem (staking/slashing, collusion resistance). No payout, no crypto
// wallets, no tokens live here.
//
// The package has no dependency on the rest of core -- it operates on any
// io.Reader/io.Writer -- exactly like core/handshake stays independent of the
// transport stack it eventually gets layered onto.
package accounting

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// acctKeyDomain separates the exit's accounting-signing key from its X25519
// Noise identity key (see AcctKeyFromSeed): reusing one keypair for both
// Diffie-Hellman and signing is a well-known cross-protocol footgun, so the
// two are independently derived from the same seed instead of sharing raw
// key material.
const acctKeyDomain = "bacchus-accounting-v1"

// ErrMismatch means the client's locally observed byte count did not match
// the exit's claim for an interval, so no receipt could be produced. This is
// expected, not exceptional: it is exactly the case co-signing exists to
// catch, and the stub's response is to skip that interval's receipt rather
// than paper over the disagreement (see Reconcile).
var ErrMismatch = errors.New("accounting: client and exit byte counts do not agree")

// Receipt is a co-signed statement that the exit identified by ExitID served
// Bytes bytes to some client during interval Seq (of nominal length
// IntervalSec seconds) within SessionID. It verifies only if both the exit's
// and the client's accounting keys signed it (see Verify) -- proof that
// neither side produced it alone.
//
// ExitAcctPub is not itself proven to belong to ExitID beyond having arrived
// over a connection already authenticated as ExitID by the Noise_NK handshake
// in core/e2e.go (trust-on-first-use within that connection); ClientAcctPub is
// a fresh keypair the client generates per session, not a persistent
// identity, so receipts from different sessions cannot be linked to the same
// client. Both are stub-appropriate simplifications, not load-bearing
// security properties -- see the package doc.
type Receipt struct {
	SessionID     string            `json:"sessionId"`
	Seq           uint64            `json:"seq"`
	IntervalSec   uint32            `json:"intervalSec"`
	Bytes         uint64            `json:"bytes"`
	ExitID        string            `json:"exitId"`
	ExitAcctPub   ed25519.PublicKey `json:"exitAcctPub"`
	ClientAcctPub ed25519.PublicKey `json:"clientAcctPub"`
	ExitSig       []byte            `json:"exitSig"`
	ClientSig     []byte            `json:"clientSig"`

	// Saturated is the client's assertion that it was demand-saturated during this
	// interval — it wanted to move more than the link delivered (design §5.3). It is
	// the ONE datum a capacity sample needs that the byte count does not carry, and
	// the one part of a receipt that is NOT co-signed: the exit cannot verify "I wanted
	// more", so it is deliberately absent from canonical() and unprotected by the
	// co-signature (old #158, an ADR-0021 amendment; the weakness is §8.2). It is
	// instead bound to the co-signing client by SignReport when a capacity-report
	// carries this receipt to the coordinator, so a NODE holding the receipt cannot
	// forge or flip it. omitempty keeps a receipt from a peer that never sets it, and
	// every receipt predating old #158, byte-for-byte unchanged on disk and on the wire.
	Saturated bool `json:"saturated,omitempty"`
}

// Verify reports an error unless both ExitSig and ClientSig are valid
// signatures, by ExitAcctPub and ClientAcctPub respectively, over r's claim
// fields. A tampered Bytes (or any other claim field) invalidates both
// signatures at once, since they cover the same canonical encoding.
func (r Receipt) Verify() error {
	if len(r.ExitAcctPub) != ed25519.PublicKeySize {
		return errors.New("accounting: malformed exit accounting key")
	}
	if len(r.ClientAcctPub) != ed25519.PublicKeySize {
		return errors.New("accounting: malformed client accounting key")
	}
	c := r.canonical()
	if !ed25519.Verify(r.ExitAcctPub, c, r.ExitSig) {
		return errors.New("accounting: invalid exit signature")
	}
	if !ed25519.Verify(r.ClientAcctPub, c, r.ClientSig) {
		return errors.New("accounting: invalid client signature")
	}
	return nil
}

func (r Receipt) canonical() []byte {
	return canonical(r.SessionID, r.Seq, r.IntervalSec, r.Bytes, r.ExitID)
}

// canonical builds the fixed-order, length-prefixed byte encoding both sides
// sign. It is independent of the wire (JSON) encoding on purpose: a signature
// must cover something that cannot shift meaning under a future struct-tag or
// field-order change, so this never delegates to encoding/json.
//
// Neither accounting pubkey is included: each side signs only the claim it
// can itself attest to (session, interval, exit id, byte count). Folding a
// peer's pubkey into what you sign would add nothing here, since a Receipt is
// always stored and verified as one bundle -- see Verify -- and it would
// force an ordering dependency (the exit would need the client's pubkey
// before it could sign its own claim, but the client does not reveal one
// until it has already seen -- and checked -- the exit's claim).
func canonical(sessionID string, seq uint64, intervalSec uint32, bytesN uint64, exitID string) []byte {
	b := make([]byte, 0, len(sessionID)+len(exitID)+24)
	b = appendString(b, sessionID)
	b = binary.BigEndian.AppendUint64(b, seq)
	b = binary.BigEndian.AppendUint32(b, intervalSec)
	b = binary.BigEndian.AppendUint64(b, bytesN)
	b = appendString(b, exitID)
	return b
}

func appendString(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// capacityReportDomain separates a capacity-report signature (old #158) from the
// receipt co-signature. Both cover the receipt's claim bytes; a distinct domain tag
// (and the appended saturation byte) means the client's receipt ClientSig can never be
// replayed as a report signature, nor vice versa.
const capacityReportDomain = "bacchus-capacity-report\x00"

// reportCanonical is the exact byte string a client signs to attest a receipt's
// saturation bit to the coordinator. It is the receipt's own co-signed claim (session,
// seq, interval, bytes, exit) plus the one bit the exit could not co-sign — Saturated —
// under a domain tag. Binding the bit to the receipt's identity is what stops it being
// lifted onto a different receipt; signing it with the client key is what stops a node
// that merely holds the receipt from forging or flipping it (design §5.3/§8.2).
func reportCanonical(r Receipt) []byte {
	c := r.canonical()
	b := make([]byte, 0, len(capacityReportDomain)+len(c)+1)
	b = append(b, capacityReportDomain...)
	b = append(b, c...)
	var sat byte
	if r.Saturated {
		sat = 1
	}
	return append(b, sat)
}

// SignReport produces the client's signature over a receipt and its saturation bit,
// for the capacity-report that carries the receipt to the coordinator (old #158, an
// ADR-0021 amendment). It is a SECOND signature, separate from the receipt's
// co-signature: the co-signature proves the throughput both parties agreed to, this
// proves WHO asserted the (un-co-signable) saturation bit.
//
// key must be the client's accounting key — the private half of r.ClientAcctPub, the
// same key that produced r.ClientSig. A node holding the finished receipt has
// r.ClientAcctPub and r.ClientSig but NOT this private key, so it cannot produce a
// valid report for a saturation bit it chose.
func SignReport(key ed25519.PrivateKey, r Receipt) []byte {
	return ed25519.Sign(key, reportCanonical(r))
}

// VerifyReport checks a capacity-report signature against the receipt's client
// accounting key, so a coordinator accepts a saturation bit only from the client that
// co-signed the receipt (old #158). It does NOT re-check the co-signature — call
// Receipt.Verify for that. The two are separate proofs: Verify covers the throughput,
// this covers the saturation bit riding beside it.
func VerifyReport(r Receipt, sig []byte) error {
	if len(r.ClientAcctPub) != ed25519.PublicKeySize {
		return errors.New("accounting: malformed client accounting key")
	}
	if !ed25519.Verify(r.ClientAcctPub, reportCanonical(r), sig) {
		return errors.New("accounting: invalid capacity-report signature")
	}
	return nil
}

// AcctKeyFromSeed derives an exit's stable Ed25519 accounting-signing key from
// its X25519 Noise identity private key (core.Config.ExitKeyHex). It hashes
// the seed with a domain tag rather than reusing the raw scalar, so the two
// keys are cryptographically independent even though both are stable across
// restarts of the same exit. A client's accounting key is not derived this
// way -- it is a fresh ed25519.GenerateKey per session, since a client has no
// stable identity to derive from (nor should it: v1's Noise_NK pattern keeps
// the client anonymous to the exit, and giving it a stable accounting
// identity would undo that).
func AcctKeyFromSeed(x25519Priv []byte) (ed25519.PrivateKey, error) {
	if len(x25519Priv) != 32 {
		return nil, errors.New("accounting: seed must be a 32-byte private key")
	}
	h := sha256.Sum256(append([]byte(acctKeyDomain+":"), x25519Priv...))
	return ed25519.NewKeyFromSeed(h[:]), nil
}

// claimMsg is the exit's first message: a signed claim for one interval.
type claimMsg struct {
	SessionID   string `json:"sessionId"`
	Seq         uint64 `json:"seq"`
	IntervalSec uint32 `json:"intervalSec"`
	Bytes       uint64 `json:"bytes"`
	ExitID      string `json:"exitId"`
	ExitAcctPub []byte `json:"exitAcctPub"`
	ExitSig     []byte `json:"exitSig"`
}

// ackMsg is the client's reply: a cosignature on acceptance, or a rejection
// carrying its own count (the cross-check hook the issue asks for -- a place
// a future sampling/audit feature can read from).
type ackMsg struct {
	OK            bool   `json:"ok"`
	ClientAcctPub []byte `json:"clientAcctPub,omitempty"`
	ClientSig     []byte `json:"clientSig,omitempty"`
	LocalBytes    uint64 `json:"localBytes,omitempty"`
}

// ExitPropose runs the exit side of one accounting interval over rw -- an
// already-authenticated, encrypted channel to a specific client (in practice
// the noiseConn core/e2e.go hands back once it recognizes the accounting
// sentinel target; this package has no transport opinion of its own, it only
// needs an io.Reader/io.Writer). It signs bytesN as the exit's claim for
// (sessionID, seq) and returns the completed, verified receipt once the
// client cosigns, or an error -- wrapping ErrMismatch -- if the client
// rejects the claim.
func ExitPropose(rw io.ReadWriter, key ed25519.PrivateKey, exitID, sessionID string, seq uint64, intervalSec uint32, bytesN uint64) (Receipt, error) {
	exitPub := key.Public().(ed25519.PublicKey)
	c := canonical(sessionID, seq, intervalSec, bytesN, exitID)
	sig := ed25519.Sign(key, c)

	claim := claimMsg{
		SessionID: sessionID, Seq: seq, IntervalSec: intervalSec, Bytes: bytesN,
		ExitID: exitID, ExitAcctPub: exitPub, ExitSig: sig,
	}
	if err := json.NewEncoder(rw).Encode(claim); err != nil {
		return Receipt{}, fmt.Errorf("accounting: send claim: %w", err)
	}

	var ack ackMsg
	if err := json.NewDecoder(rw).Decode(&ack); err != nil {
		return Receipt{}, fmt.Errorf("accounting: read ack: %w", err)
	}
	if !ack.OK {
		return Receipt{}, fmt.Errorf("%w: exit counted %d, client counted %d", ErrMismatch, bytesN, ack.LocalBytes)
	}

	r := Receipt{
		SessionID: sessionID, Seq: seq, IntervalSec: intervalSec, Bytes: bytesN,
		ExitID: exitID, ExitAcctPub: exitPub, ExitSig: sig,
		ClientAcctPub: ack.ClientAcctPub, ClientSig: ack.ClientSig,
	}
	if err := r.Verify(); err != nil {
		return Receipt{}, fmt.Errorf("accounting: client cosigned but receipt does not verify: %w", err)
	}
	return r, nil
}

// ClientCosign runs the client side of one accounting interval over rw: it
// reads the exit's claim, checks it against localBytes (the client's own
// count for the same interval) via Reconcile, and either cosigns and returns
// the completed receipt, or rejects -- replying with localBytes for the
// exit's cross-check -- and returns an error wrapping ErrMismatch. key is the
// client's accounting keypair; a fresh one per session is enough for this
// stub (see AcctKeyFromSeed's doc for why the client does not derive a stable
// one).
func ClientCosign(rw io.ReadWriter, key ed25519.PrivateKey, localBytes uint64) (Receipt, error) {
	var claim claimMsg
	if err := json.NewDecoder(rw).Decode(&claim); err != nil {
		return Receipt{}, fmt.Errorf("accounting: read claim: %w", err)
	}

	c := canonical(claim.SessionID, claim.Seq, claim.IntervalSec, claim.Bytes, claim.ExitID)
	if len(claim.ExitAcctPub) != ed25519.PublicKeySize || !ed25519.Verify(claim.ExitAcctPub, c, claim.ExitSig) {
		_ = json.NewEncoder(rw).Encode(ackMsg{OK: false, LocalBytes: localBytes})
		return Receipt{}, errors.New("accounting: exit claim has an invalid signature")
	}

	if !Reconcile(localBytes, claim.Bytes) {
		_ = json.NewEncoder(rw).Encode(ackMsg{OK: false, LocalBytes: localBytes})
		return Receipt{}, fmt.Errorf("%w: exit counted %d, client counted %d", ErrMismatch, claim.Bytes, localBytes)
	}

	clientPub := key.Public().(ed25519.PublicKey)
	clientSig := ed25519.Sign(key, c)
	ack := ackMsg{OK: true, ClientAcctPub: clientPub, ClientSig: clientSig}
	if err := json.NewEncoder(rw).Encode(ack); err != nil {
		return Receipt{}, fmt.Errorf("accounting: send ack: %w", err)
	}

	r := Receipt{
		SessionID: claim.SessionID, Seq: claim.Seq, IntervalSec: claim.IntervalSec, Bytes: claim.Bytes,
		ExitID: claim.ExitID, ExitAcctPub: claim.ExitAcctPub, ExitSig: claim.ExitSig,
		ClientAcctPub: clientPub, ClientSig: clientSig,
	}
	return r, r.Verify()
}

// Reconcile is the stub's entire anti-fraud policy: whether the client should
// cosign the exit's claimed byte count for one interval. Co-signing only
// stops *unilateral* inflation if the client actually checks the claim
// against what it saw itself -- a client that signs whatever the exit sends
// defeats the whole point (old #20: "best-effort proof, not trustless
// accounting").
//
// The default is exact match: client and exit are counting the same wire
// bytes on the same stream, so the honest case agrees. On a mismatch, that
// interval's receipt is simply skipped -- best-effort, the next interval gets
// another chance -- rather than silently smoothed over by a tolerance window.
// A tolerance (or an asymmetric rule, e.g. reject only if claimed >
// localBytes, since an exit under-claiming only shortchanges its own future
// payout rather than defrauding the client) is the natural next refinement,
// but picking a number here needs real mismatch-rate data this stub is what
// produces -- not the other way around.
func Reconcile(localBytes, claimed uint64) bool {
	return localBytes == claimed
}

// Counter is a cumulative byte count, safe for concurrent use by the
// goroutines copying each direction of a session's streams. The nil *Counter
// is valid and inert (Add/CountReads/Load/Delta are all no-ops), so callers
// can pass nil when accounting is disabled without a branch at every call
// site.
type Counter struct {
	total atomic.Uint64
	last  atomic.Uint64

	// saturated records whether the client was demand-saturated during the current
	// interval — it had more to move than the link carried (design §5.3), the one bit a
	// capacity sample needs that the byte count cannot supply. It is set by
	// WatchSaturation on the client's upload path and read-and-cleared by TakeSaturated
	// once per interval, exactly as Delta partitions the byte count. Only the client
	// role touches it (the exit cannot verify "I wanted more", §8.2), so it is inert on
	// an exit's counter.
	saturated atomic.Bool
}

// Add adds n to the cumulative count.
func (c *Counter) Add(n uint64) {
	if c == nil {
		return
	}
	c.total.Add(n)
}

// CountReads wraps r so every byte successfully read through it is added to
// c. Counting on read, rather than write, is enough because every call site
// in core copies with io.Copy(dst, src) -- wrapping the source counts each
// byte exactly once.
func (c *Counter) CountReads(r io.Reader) io.Reader {
	if c == nil {
		return r
	}
	return &countingReader{r: r, c: c}
}

type countingReader struct {
	r io.Reader
	c *Counter
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.c.Add(uint64(n))
	}
	return n, err
}

// Load returns the cumulative count so far.
func (c *Counter) Load() uint64 {
	if c == nil {
		return 0
	}
	return c.total.Load()
}

// Delta returns the count added since the previous Delta call (or since
// creation) and advances the baseline, so repeated calls partition the stream
// into the non-overlapping intervals a Receipt reports.
func (c *Counter) Delta() uint64 {
	if c == nil {
		return 0
	}
	now := c.total.Load()
	prev := c.last.Swap(now)
	return now - prev
}

// TakeSaturated reports whether the interval just closing was demand-saturated and
// clears the flag for the next one, partitioning saturation into the same
// non-overlapping intervals Delta partitions the byte count into (old #158). The
// client reads it once per accounting interval and stamps the result onto the receipt's
// Saturated bit. Nil-safe (an unmetered client reports unsaturated).
func (c *Counter) TakeSaturated() bool {
	if c == nil {
		return false
	}
	return c.saturated.Swap(false)
}

// WatchSaturation wraps the client's tunnel-write side so that a single write which
// blocks for at least d — the tunnel applying backpressure while the application still
// had bytes to send — marks the current interval saturated (old #158, design §5.3).
//
// It watches the UPLOAD direction only, and that is deliberate: a blocked write to the
// tunnel is UNAMBIGUOUS evidence the client wanted to move more than the node's link
// carried. The download direction is not — a slow tunnel READ could be the node
// throttling OR the remote server simply being slow, and blaming the node for the
// latter would defame it — so it is left to a follow-up (old #160, design §8.2/§9.4). The
// bit therefore UNDER-reports saturation, which errs toward under-rating a node, the
// direction the design prefers (over-rating hurts users now; under-rating only wastes
// capacity, design §6.3). d is a parameter, not a constant, so the caller owns the
// backpressure threshold and a test can drive it deterministically. Nil-safe.
func (c *Counter) WatchSaturation(w io.Writer, d time.Duration) io.Writer {
	if c == nil {
		return w
	}
	return &satWriter{w: w, c: c, threshold: d}
}

// satWriter marks c saturated when a write blocks past threshold. It intentionally does
// NOT implement io.ReaderFrom, so io.Copy calls Write in bounded chunks and each chunk's
// block time is observed, rather than handing the whole stream to an optimized ReadFrom
// that would hide per-write backpressure.
type satWriter struct {
	w         io.Writer
	c         *Counter
	threshold time.Duration
	clock     func() time.Time // nil => time.Now; injectable for deterministic tests
}

func (s *satWriter) now() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

func (s *satWriter) Write(p []byte) (int, error) {
	start := s.now()
	n, err := s.w.Write(p)
	if s.now().Sub(start) >= s.threshold {
		s.c.saturated.Store(true)
	}
	return n, err
}

// Store appends co-signed receipts to a JSONL file and can reload them. It is
// safe for concurrent use. Persistence is deliberately this simple: the
// wider stack is Go binaries + systemd with no database yet, and a receipt
// history is exactly the kind of small, append-only record a flat file suits.
type Store struct {
	mu sync.Mutex
	f  *os.File
}

// OpenStore opens (creating if needed) the JSONL file at path for appending.
func OpenStore(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("accounting: create store dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("accounting: open store: %w", err)
	}
	return &Store{f: f}, nil
}

// Append persists r as one more line, flushed to disk before returning.
func (s *Store) Append(r Receipt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("accounting: marshal receipt: %w", err)
	}
	b = append(b, '\n')
	if _, err := s.f.Write(b); err != nil {
		return fmt.Errorf("accounting: write receipt: %w", err)
	}
	return s.f.Sync()
}

// Close closes the underlying file.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// LoadReceipts reads every receipt persisted at path. A missing file is not
// an error -- it reads as no receipts yet.
func LoadReceipts(path string) ([]Receipt, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("accounting: open store: %w", err)
	}
	defer f.Close()

	var out []Receipt
	dec := json.NewDecoder(f)
	for dec.More() {
		var r Receipt
		if err := dec.Decode(&r); err != nil {
			return nil, fmt.Errorf("accounting: decode receipt: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}
