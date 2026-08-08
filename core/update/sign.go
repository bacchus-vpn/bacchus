package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/bacchus-vpn/bacchus/core/delegation"
)

// Sign renders m and returns the signed manifest, body || sig, under the update
// manifest's domain tag.
//
// It is the authoring half, used by cmd/release-sign on an air-gapped machine and
// by this package's own tests. It lives beside Verify rather than only in the tool
// for the reason core/delegation gives about its framing: a second implementation
// of tag || 0x00 || body is exactly the thing that drifts, and a signer that
// disagrees with the verifier by one byte produces a release the whole fleet
// refuses — discoverable only after the ceremony that signed it.
//
// # It refuses UNKNOWN FIELDS, and Verify does not
//
// The manifest is re-marshaled here from a validated struct and then decoded
// STRICTLY back, so a field the struct does not know cannot be signed. That
// asymmetry with Verify is deliberate and is core/policy's: refusing at the signer
// catches an operator's typo — a `sha_256` where `sha256` was meant would sign a
// manifest with a zero digest — before it is signed, while refusing at the
// verifier would mean any additive field bricked every peer that had not shipped
// yet.
//
// Validate runs first, so a manifest that could never be applied is never signed.
// That is the last place a mistake is free.
func Sign(priv ed25519.PrivateKey, m Manifest) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("update: sign: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("update: marshal manifest: %w", err)
	}
	if err := checkNoUnknownFields(body); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, signingMessage(delegation.TagUpdateManifest, body))
	return append(body, sig...), nil
}

// SignBody signs manifest bytes that were authored elsewhere, verbatim.
//
// This is the path that matters on the air-gapped machine: ADR-0052 §6 step 3 has
// the manifest AUTHORED offline and step 4 signs it, and the bytes that get signed
// must be the bytes the operator read. Re-marshaling them through a struct would
// put this code between what was reviewed and what was signed.
//
// It still parses and validates a copy before signing, so an unreadable or invalid
// manifest cannot be signed by accident — but what it signs is body, untouched.
func SignBody(priv ed25519.PrivateKey, body []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("update: sign: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if err := checkNoUnknownFields(body); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, signingMessage(delegation.TagUpdateManifest, body))
	return append(append([]byte(nil), body...), sig...), nil
}

// checkNoUnknownFields refuses a manifest body carrying a field this build does
// not know. See Sign's doc comment for why this is a signer-side rule only.
func checkNoUnknownFields(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var probe Manifest
	if err := dec.Decode(&probe); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return nil
}

// signingMessage builds the domain-separated bytes a signature covers: tag ||
// 0x00 || body, exactly as core/delegation.OpenSigned checks them. The 0x00
// separator cannot occur in a tag, so no body can be crafted to make one tag's
// message equal another's.
//
// It is duplicated from core/delegation because that package exports the OPENING
// half and not the signing half — deliberately, since a public coordinator that
// could mint delegations would defeat the whole arrangement. What is reproduced
// here signs manifests only, and it is pinned against the verifier in
// TestSignedManifestOpensUnderTheDelegationFraming: if the two ever disagree, that
// test fails rather than a release does.
func signingMessage(tag string, body []byte) []byte {
	msg := make([]byte, 0, len(tag)+1+len(body))
	msg = append(msg, tag...)
	msg = append(msg, 0x00)
	return append(msg, body...)
}
