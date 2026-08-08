package revocation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Version is the format version of the signed document. Checked EXACTLY, so a
// coordinator built against this format refuses a newer one rather than reading
// the subset it recognises.
const Version = 1

// Sentinel errors. Every one names a protocol fact only — never key material,
// never anything account-scoped — so all are safe to log and safe to report to
// whoever handed over the bundle. Mirrors bacchus-payment/internal/revocation's
// vocabulary so the frozen conformance vectors' expect_error tokens map onto a
// single, shared meaning on both sides of the wire.
var (
	ErrMalformed          = errors.New("revocation: malformed document")
	ErrUnsupportedVersion = errors.New("revocation: unsupported version")
	ErrRollback           = errors.New("revocation: as_of went backwards")
)

// Doc is the signed document: one namespace's revoked-serial list plus the
// ordering field that makes a replay of an older, still-validly-signed document
// refusable. See verify.go's Verify for what AsOf does and does not defend
// against.
//
// The marshaled form is the signed body, and verification is always over the
// bytes as received rather than a re-marshal, so JSON field order and whitespace
// are not part of the contract. The json tag names, the domain tag
// (delegation.TagRevocationsDoc) and Version are.
//
// Deliberately absent, against policy.Policy's shape: Issued/Expires/Grace. A
// revocation list has no operator-chosen activation window — a coordinator wants
// the freshest list it can verify, full stop — so there is nothing to attach one
// to; see ADR-0017 decision 2 and doc.go.
type Doc struct {
	Version int       `json:"v"`
	AsOf    time.Time `json:"as_of"`
	Revoked []string  `json:"revoked"`
}

// Bundle is what a coordinator fetches for one namespace: the signed document and
// the delegation cert authorizing the key that signed it.
//
// Both members are verified independently against the root, so the wrapper
// itself is not signed and does not need to be — tampering with it can only
// produce a bundle that fails, the same property policy.Bundle has.
type Bundle struct {
	// Revocations is the signed document, body || sig, signed by the operational
	// revocations signer. Named after its content, the way policy.Bundle's field
	// is tagged "policy" rather than a generic "doc".
	Revocations []byte `json:"revocations"`
	// Cert is the signed delegation cert, body || sig, signed by the offline
	// root, with role "revocations".
	Cert []byte `json:"cert"`
}

// ParseBundle decodes the fetch format: a JSON object with two standard-base64
// members. A bundle missing either member is refused here rather than producing
// a confusing signature failure later. Mirrors policy.ParseBundle exactly.
func ParseBundle(data []byte) (Bundle, error) {
	var b Bundle
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("%w: bundle: %v", ErrMalformed, err)
	}
	if len(b.Revocations) == 0 || len(b.Cert) == 0 {
		return Bundle{}, fmt.Errorf("%w: bundle is missing the revocations document or the delegation cert", ErrMalformed)
	}
	return b, nil
}
