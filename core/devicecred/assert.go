package devicecred

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
)

// Purpose is the context a device signature is made in. It is the first thing
// covered by the signature and every verifier accepts exactly one Purpose, so a
// signature made for one context is cryptographically useless in another.
//
// This matters because a device key signs in several places and one of them talks
// to a party that is not trusted with the account. A coordinator is trusted to run
// matchmaking and nothing more, and it CHOOSES the connect challenge. If a device
// signed a bare challenge, a hostile coordinator could hand over bytes that are
// really an approval body, collect the device's signature over them, and enroll a
// device it controls onto the victim's account. The Purpose tag is what makes that
// impossible rather than merely unlikely.
//
// Only the purposes this repository actually uses are declared. The account
// service's own purposes (renewal, sibling approval, enrollment) are verified
// there, by it, and a coordinator has no business holding a verifier for them.
type Purpose string

// PurposeConnect is a device proving possession to a coordinator on the connect
// path. It is the one purpose verified in this repository.
const PurposeConnect Purpose = "bacchus/assert-connect/v1"

// MinChallenge is the smallest challenge an assertion may cover.
//
// An assertion's entire value is that it cannot be replayed, and that rests on the
// challenge being unpredictable; 16 bytes of randomness makes a repeat
// implausible. It is enforced on BOTH sides — a verifier must not accept a weak
// challenge, and a device must not sign one — because the coordinator picks the
// connect challenge and is not trusted to pick it well. A device that signed
// whatever short or fixed value it was handed would be handing out a reusable
// token.
const MinChallenge = 16

// assertionMessage builds the bytes an assertion covers:
//
//	purpose || 0x00 || len(audience) || audience || len(challenge) || challenge
//
// Both variable-length fields are length-prefixed so the framing is unambiguous.
// Plain concatenation would not be: audience "ab" + challenge "c" and audience "a"
// + challenge "bc" produce identical bytes, which would let a signature made for
// one verifier be re-read as one made for another.
//
// The AUDIENCE binds an assertion to the party that demanded it. Bacchus runs a
// pool of coordinators rather than one, so without it a hostile pool member could
// take a challenge issued by an honest coordinator, relay it to a device, collect
// the signature, and present the device's whole chain as its own — spending
// someone else's entitlement and defeating the only thing the challenge exists to
// stop.
//
// The CHALLENGE binds it to one connect. Without it, an assertion captured once is
// an entitlement forever.
func assertionMessage(p Purpose, audience string, challenge []byte) []byte {
	msg := make([]byte, 0, len(p)+1+4+len(audience)+4+len(challenge))
	msg = append(msg, p...)
	msg = append(msg, 0x00)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(audience)))
	msg = append(msg, audience...)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(challenge)))
	return append(msg, challenge...)
}

// SignAssertion proves possession of the device private key for exactly one
// purpose, audience and challenge. audience names the party that issued the
// challenge — a coordinator's identity on connect — and challenge is that party's
// fresh random nonce.
//
// This is the device-side half, and it lives next to the verifier because the two
// only mean anything as a pair: the client that ships in this repository must
// produce these exact bytes, and a divergence between signer and verifier is not
// something either side can detect alone.
func SignAssertion(priv ed25519.PrivateKey, p Purpose, audience string, challenge []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: bad private key length", ErrMalformed)
	}
	if len(challenge) < MinChallenge {
		return nil, fmt.Errorf("%w: challenge is %d bytes, need at least %d", ErrBadAssertion, len(challenge), MinChallenge)
	}
	return ed25519.Sign(priv, assertionMessage(p, audience, challenge)), nil
}

// VerifyAssertion checks a signature produced by SignAssertion.
//
// It returns ErrBadAssertion for every failure. A wrong key, a wrong purpose, a
// wrong audience and a wrong challenge are deliberately indistinguishable to the
// caller, because none of them is a distinction a rejected peer should be able to
// probe for — a verifier that reported which part was wrong would be an oracle for
// finding a part that is right.
func VerifyAssertion(pub ed25519.PublicKey, p Purpose, audience string, challenge, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: bad public key length", ErrMalformed)
	}
	if len(challenge) < MinChallenge {
		return fmt.Errorf("%w: challenge is %d bytes, need at least %d", ErrBadAssertion, len(challenge), MinChallenge)
	}
	if !ed25519.Verify(pub, assertionMessage(p, audience, challenge), sig) {
		return ErrBadAssertion
	}
	return nil
}
