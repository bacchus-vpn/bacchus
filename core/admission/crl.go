package admission

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// CRL is a short-lived, signed bundle of revoked credential serials (issue
// #69): the piece that lets a client reject a revoked-but-unexpired exit
// credential without a live connection to the coordinator's own hot-reloaded
// RevocationList. That list is a plain local file the coordinator trusts
// because it reads its own disk; a CRL instead travels to the client over the
// network, possibly via the same hostile coordinator #60/ADR-0026 already
// assumes may lie, so — like a Credential — it is signed by the admission
// root and verified against the anchor the client already holds, trustworthy
// independent of whatever relayed it.
type CRL struct {
	Version   int       `json:"v"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`     // short TTL by design — bounds how stale a cached bundle may be trusted
	Serials   []string  `json:"revoked"` // revoked credential serials; field name distinct from the Revoked method below
}

// CRLVersion is the wire/format version of a CRL's signed body. Bump on any
// breaking change to the field set; ParseCRL rejects anything else.
const CRLVersion = 1

// Sentinel errors mirror Credential's: every one names only protocol facts,
// never key material, so all are safe to log.
var (
	ErrCRLMalformed          = errors.New("admission: malformed CRL")
	ErrCRLBadSignature       = errors.New("admission: CRL signature invalid")
	ErrCRLUnsupportedVersion = errors.New("admission: unsupported CRL version")
	ErrCRLExpired            = errors.New("admission: CRL expired")
)

// crlSignedLen is the fixed ed25519 signature size; SignCRL appends exactly
// this many bytes and ParseCRL splits them off the end, matching Credential.
const crlSignedLen = ed25519.SignatureSize

// crlPrefix tags the string form so a CRL is self-describing, distinct from a
// credential ("bacchusc1:") or a coldstart invite ("bacchus1:").
const crlPrefix = "bacchusr1:"

// SignCRL signs revoked as a bundle valid [now, now+ttl), for
// cmd/admission-issue to hand an operator for distribution alongside the
// admission anchor. Serials are sorted first for a deterministic, diff-
// friendly signed body (mirrors RevocationList.SaveFile).
func SignCRL(priv ed25519.PrivateKey, revoked []string, now time.Time, ttl time.Duration) (string, error) {
	sorted := append([]string(nil), revoked...)
	sort.Strings(sorted)
	c := CRL{
		Version:   CRLVersion,
		IssuedAt:  now.UTC(),
		ExpiresAt: now.Add(ttl).UTC(),
		Serials:   sorted,
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("admission: marshal CRL: %w", err)
	}
	sig := ed25519.Sign(priv, body)
	return crlPrefix + base64.RawURLEncoding.EncodeToString(append(body, sig...)), nil
}

// ParseCRL decodes encoded and checks its signature and format version
// against pub, without checking expiry. Exposed for a caller that needs the
// raw fields regardless of freshness (a diagnostic tool); VerifyCRL is what
// a verifier should use.
func ParseCRL(pub ed25519.PublicKey, encoded string) (CRL, error) {
	encoded = strings.TrimSpace(encoded)
	if !strings.HasPrefix(encoded, crlPrefix) {
		return CRL{}, fmt.Errorf("%w: missing %q prefix", ErrCRLMalformed, crlPrefix)
	}
	if len(pub) != ed25519.PublicKeySize {
		return CRL{}, fmt.Errorf("%w: bad public key length", ErrCRLMalformed)
	}
	signed, err := base64.RawURLEncoding.DecodeString(encoded[len(crlPrefix):])
	if err != nil {
		return CRL{}, fmt.Errorf("%w: %v", ErrCRLMalformed, err)
	}
	if len(signed) <= crlSignedLen {
		return CRL{}, ErrCRLMalformed
	}
	body := signed[:len(signed)-crlSignedLen]
	sig := signed[len(signed)-crlSignedLen:]
	if !ed25519.Verify(pub, body, sig) {
		return CRL{}, ErrCRLBadSignature
	}
	var c CRL
	if err := json.Unmarshal(body, &c); err != nil {
		return CRL{}, fmt.Errorf("%w: %v", ErrCRLMalformed, err)
	}
	if c.Version != CRLVersion {
		return CRL{}, fmt.Errorf("%w: %d", ErrCRLUnsupportedVersion, c.Version)
	}
	return c, nil
}

// VerifyCRL parses encoded and additionally checks it has not expired as of
// now. now is passed in rather than read here so tests use a fixed clock,
// matching Verifier.Verify.
func VerifyCRL(pub ed25519.PublicKey, encoded string, now time.Time) (CRL, error) {
	c, err := ParseCRL(pub, encoded)
	if err != nil {
		return CRL{}, err
	}
	if !now.Before(c.ExpiresAt) {
		return CRL{}, ErrCRLExpired
	}
	return c, nil
}

// Revoked reports whether serial appears in the bundle. A linear scan is
// fine: per its name, a CRL is short.
func (c CRL) Revoked(serial string) bool {
	for _, s := range c.Serials {
		if s == serial {
			return true
		}
	}
	return false
}

// ClientCRL holds a client's currently trusted revocation bundle behind an
// atomically swappable pointer, so a background reload (issue #90) can
// install a freshly verified bundle without a Verifier's concurrent Revoked
// reads ever observing a torn or partial update — the same "swap, don't
// mutate" shape as the coordinator's own RevocationList reload. The zero
// value is not usable; construct with NewClientCRL.
type ClientCRL struct {
	pub ed25519.PublicKey
	cur atomic.Pointer[CRL]
}

// NewClientCRL returns a ClientCRL that verifies every future Set call
// against pub. It starts with no bundle loaded — Revoked reports false for
// every serial, matching Verifier's nil-oracle default — until the first
// successful Set.
func NewClientCRL(pub ed25519.PublicKey) *ClientCRL {
	return &ClientCRL{pub: pub}
}

// Set parses and verifies encoded against the anchor c was built with —
// signature, format version, and expiry, exactly as VerifyCRL — and, only on
// success, atomically swaps it in as the active bundle. now is passed in so
// callers/tests control the clock. On failure the previously active bundle,
// if any, is left unchanged: a transient bad reload (a half-written file, an
// operator late to rotate a lapsed bundle) must not silently un-revoke
// everything or degrade to fail-open.
func (c *ClientCRL) Set(encoded string, now time.Time) error {
	crl, err := VerifyCRL(c.pub, encoded, now)
	if err != nil {
		return err
	}
	c.cur.Store(&crl)
	return nil
}

// Revoked reports whether serial appears in the currently active bundle, or
// false when none has ever loaded successfully. Safe for concurrent use with
// Set; pass it directly as a Verifier's revoked oracle.
func (c *ClientCRL) Revoked(serial string) bool {
	p := c.cur.Load()
	return p != nil && p.Revoked(serial)
}
