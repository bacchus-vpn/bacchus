package coldstart

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// SecretIDLen and SecretLen size the per-user credential (design doc §4.4):
// knowing an address is worthless without holding the secret, so a harvested
// endpoint is inert to anyone who doesn't have it. SecretID doubles as the
// STUN USERNAME (hex, so it's plain ASCII on the wire); Secret is the
// MESSAGE-INTEGRITY HMAC key.
const (
	SecretIDLen = 8
	SecretLen   = 32
)

// GenerateSecret mints a fresh random per-user secretID + secret, for an
// operator to hand a new user (issue #18 §4.2.2's "signed invite bundle").
func GenerateSecret() (secretID string, secret []byte, err error) {
	id := make([]byte, SecretIDLen)
	if _, err := rand.Read(id); err != nil {
		return "", nil, fmt.Errorf("coldstart: generate secret id: %w", err)
	}
	s := make([]byte, SecretLen)
	if _, err := rand.Read(s); err != nil {
		return "", nil, fmt.Errorf("coldstart: generate secret: %w", err)
	}
	return hex.EncodeToString(id), s, nil
}

// Invite is everything a fresh client needs for cold-start (design doc
// §4.2.2: a signed invite/QR carrying a per-recipient secret). It is not
// itself signed — a per-recipient secret only becomes useful once it
// authenticates a fetch to a coordinator that already knows it, so there is
// nothing here for a censor harvesting the invite text to forge; the
// invite's integrity is the out-of-band channel it travels over (messenger,
// in-person QR), per the design's threat model.
type Invite struct {
	Coordinator string // UDP host:port
	SecretID    string // hex, len 2*SecretIDLen
	Secret      []byte // len SecretLen
	PublicKey   ed25519.PublicKey

	// AdmissionKey is the admission authority's public key (issue #60), the
	// anchor a client verifies an exit's admission credential against. It is
	// optional: an operator who distributes the anchor out of band (or runs no
	// admission) leaves it nil and a v1 invite is minted; supplying it selects
	// the v2 invite that carries it. Distributing it here — the same trusted,
	// out-of-band channel that already carries PublicKey — is what lets a client
	// bootstrapped purely from an invite verify exits with no extra setup.
	AdmissionKey ed25519.PublicKey

	// CRL is a signed revocation bundle (issue #69), the encoded string form of
	// a core/admission.CRL, distributed alongside the admission anchor so a
	// client bootstrapped purely from an invite can reject a revoked exit
	// credential with no extra setup. Opaque here — coldstart only carries the
	// bytes; core/admission owns their meaning and signature. Optional, and
	// only representable alongside AdmissionKey (a v3 invite): a CRL is
	// unverifiable without the anchor it is signed against.
	CRL []byte
}

var errInviteFormat = errors.New("coldstart: malformed invite")

// Invite wire versions. The version byte doubles as the presence flag for the
// optional admission anchor (issue #60) and revocation bundle (issue #69): v1
// has neither, v2 adds the anchor before the coordinator address, v3 adds the
// length-prefixed CRL after the anchor — so there is never an ambiguous
// all-zero/empty slot on the wire. Decode accepts all three; Encode picks the
// version from what inv carries.
const (
	inviteV1 = byte(1)
	inviteV2 = byte(2)
	inviteV3 = byte(3)
)

// crlLenPrefixSize is the width of the length prefix a v3 invite puts ahead of
// the CRL bytes, since — unlike the fixed-width fields before it — a CRL's
// size varies and it is not the last field on the wire.
const crlLenPrefixSize = 2

// maxCRLLen bounds a CRL to what crlLenPrefixSize (a uint16) can address.
// "Short" is the entire point of a CRL (see core/admission.CRL), so this is
// generous headroom, not a real-world target.
const maxCRLLen = 1<<16 - 1

// EncodeInvite packs inv into a compact, copy-pasteable / QR-able string. The
// version emitted is v3 when inv carries a CRL (issue #69), v2 when it carries
// only an admission anchor (issue #60), v1 otherwise, so an operator using
// neither produces exactly the old bytes. A CRL without an anchor is rejected:
// the recipient would have no key to verify it against.
func EncodeInvite(inv Invite) (string, error) {
	id, err := hex.DecodeString(inv.SecretID)
	if err != nil || len(id) != SecretIDLen {
		return "", fmt.Errorf("%w: bad secret id", errInviteFormat)
	}
	if len(inv.Secret) != SecretLen {
		return "", fmt.Errorf("%w: bad secret length", errInviteFormat)
	}
	if len(inv.PublicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: bad public key length", errInviteFormat)
	}
	if len(inv.CRL) != 0 && len(inv.AdmissionKey) == 0 {
		return "", fmt.Errorf("%w: a CRL requires an admission anchor", errInviteFormat)
	}
	version, admissionKey := inviteV1, []byte(nil)
	if len(inv.AdmissionKey) != 0 {
		if len(inv.AdmissionKey) != ed25519.PublicKeySize {
			return "", fmt.Errorf("%w: bad admission key length", errInviteFormat)
		}
		version, admissionKey = inviteV2, inv.AdmissionKey
	}
	var crl []byte
	if len(inv.CRL) != 0 {
		if len(inv.CRL) > maxCRLLen {
			return "", fmt.Errorf("%w: CRL too large", errInviteFormat)
		}
		version, crl = inviteV3, inv.CRL
	}
	buf := make([]byte, 0, 1+SecretIDLen+SecretLen+ed25519.PublicKeySize+len(admissionKey)+crlLenPrefixSize+len(crl)+len(inv.Coordinator))
	buf = append(buf, version)
	buf = append(buf, id...)
	buf = append(buf, inv.Secret...)
	buf = append(buf, inv.PublicKey...)
	buf = append(buf, admissionKey...) // present only in v2+ (nil in v1)
	if version == inviteV3 {
		var lenBuf [crlLenPrefixSize]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(crl)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, crl...)
	}
	buf = append(buf, []byte(inv.Coordinator)...)
	return "bacchus1:" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// DecodeInvite reverses [EncodeInvite], accepting v1 (neither), v2 (issue
// #60, admission anchor only), and v3 (issue #69, anchor + CRL) invites. A v1
// invite decodes with a nil AdmissionKey and CRL; a v2 invite with a nil CRL.
func DecodeInvite(s string) (Invite, error) {
	const prefix = "bacchus1:"
	if len(s) <= len(prefix) || s[:len(prefix)] != prefix {
		return Invite{}, fmt.Errorf("%w: missing prefix", errInviteFormat)
	}
	buf, err := base64.RawURLEncoding.DecodeString(s[len(prefix):])
	if err != nil {
		return Invite{}, fmt.Errorf("%w: %v", errInviteFormat, err)
	}
	if len(buf) == 0 {
		return Invite{}, fmt.Errorf("%w: empty", errInviteFormat)
	}
	var admissionLen int
	var hasCRL bool
	switch buf[0] {
	case inviteV1:
		admissionLen = 0
	case inviteV2:
		admissionLen = ed25519.PublicKeySize
	case inviteV3:
		admissionLen = ed25519.PublicKeySize
		hasCRL = true
	default:
		return Invite{}, fmt.Errorf("%w: unsupported version %d", errInviteFormat, buf[0])
	}
	off := 1
	if off+SecretIDLen+SecretLen+ed25519.PublicKeySize+admissionLen > len(buf) {
		return Invite{}, fmt.Errorf("%w: bad length", errInviteFormat)
	}
	id := buf[off : off+SecretIDLen]
	off += SecretIDLen
	secret := append([]byte(nil), buf[off:off+SecretLen]...)
	off += SecretLen
	pub := ed25519.PublicKey(append([]byte(nil), buf[off:off+ed25519.PublicKeySize]...))
	off += ed25519.PublicKeySize
	var admissionKey ed25519.PublicKey
	if admissionLen > 0 {
		admissionKey = ed25519.PublicKey(append([]byte(nil), buf[off:off+admissionLen]...))
		off += admissionLen
	}
	var crl []byte
	if hasCRL {
		if off+crlLenPrefixSize > len(buf) {
			return Invite{}, fmt.Errorf("%w: truncated CRL length", errInviteFormat)
		}
		crlLen := int(binary.BigEndian.Uint16(buf[off : off+crlLenPrefixSize]))
		off += crlLenPrefixSize
		if off+crlLen > len(buf) {
			return Invite{}, fmt.Errorf("%w: truncated CRL", errInviteFormat)
		}
		crl = append([]byte(nil), buf[off:off+crlLen]...)
		off += crlLen
	}
	// Require at least one address byte beyond everything fixed/length-prefixed
	// above, which also makes an empty coordinator address unrepresentable —
	// true for every version, since none of them make Coordinator optional.
	if off >= len(buf) {
		return Invite{}, fmt.Errorf("%w: bad length", errInviteFormat)
	}
	return Invite{
		Coordinator:  string(buf[off:]),
		SecretID:     hex.EncodeToString(id),
		Secret:       secret,
		PublicKey:    pub,
		AdmissionKey: admissionKey,
		CRL:          crl,
	}, nil
}
