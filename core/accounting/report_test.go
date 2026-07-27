package accounting

import (
	"crypto/ed25519"
	"testing"
)

// The capacity-report signature (issue #158) binds a receipt's client-asserted
// saturation bit to the client key that co-signed the receipt, so a node holding the
// finished receipt can neither forge a report nor flip the bit. These tests pin that.

// signedReceipt builds a fully co-signed receipt for the given saturation bit, plus the
// client key so a test can (or cannot) produce a report signature with it.
func signedReceipt(t *testing.T, saturated bool) (Receipt, ed25519.PrivateKey) {
	t.Helper()
	exitKey, clientKey := genKey(t), genKey(t)
	c := canonical("sess-1", 3, 60, 1_000_000, "exit-1")
	r := Receipt{
		SessionID: "sess-1", Seq: 3, IntervalSec: 60, Bytes: 1_000_000, ExitID: "exit-1",
		ExitAcctPub:   exitKey.Public().(ed25519.PublicKey),
		ClientAcctPub: clientKey.Public().(ed25519.PublicKey),
		ExitSig:       ed25519.Sign(exitKey, c),
		ClientSig:     ed25519.Sign(clientKey, c),
		Saturated:     saturated,
	}
	if err := r.Verify(); err != nil {
		t.Fatalf("setup: receipt does not verify: %v", err)
	}
	return r, clientKey
}

// TestSignVerifyReportRoundTrip: a report signed by the receipt's client key verifies,
// for both saturation values.
func TestSignVerifyReportRoundTrip(t *testing.T) {
	for _, sat := range []bool{true, false} {
		r, clientKey := signedReceipt(t, sat)
		sig := SignReport(clientKey, r)
		if err := VerifyReport(r, sig); err != nil {
			t.Fatalf("saturated=%v: a report signed by the client key must verify: %v", sat, err)
		}
	}
}

// TestVerifyReportRejectsFlippedSaturation is the load-bearing property: the saturation
// bit is bound by the signature, so flipping it after signing invalidates the report. A
// node that holds the receipt cannot present the client's report with the bit changed.
func TestVerifyReportRejectsFlippedSaturation(t *testing.T) {
	r, clientKey := signedReceipt(t, true)
	sig := SignReport(clientKey, r) // signs saturated=true

	r.Saturated = false // a node flips the bit it does not control
	if err := VerifyReport(r, sig); err == nil {
		t.Fatal("a report verified after its saturation bit was flipped; the bit is not bound by the signature")
	}
}

// TestVerifyReportRejectsForeignKey: only the client that co-signed can produce a valid
// report. A node has the receipt (and thus ClientAcctPub) but not the client's PRIVATE
// key, so a report it signs with any other key is rejected.
func TestVerifyReportRejectsForeignKey(t *testing.T) {
	r, _ := signedReceipt(t, true)
	nodeKey := genKey(t) // a key the node controls, not the client's
	sig := SignReport(nodeKey, r)
	if err := VerifyReport(r, sig); err == nil {
		t.Fatal("a report signed by a key other than the receipt's client key verified; a node could forge attestations")
	}
}

// TestVerifyReportRejectsTamperedReceipt: the report binds to the receipt's identity, so
// changing a co-signed claim field (here Bytes, the throughput) after signing the report
// invalidates it — the saturation attestation cannot be lifted onto a different receipt.
func TestVerifyReportRejectsTamperedReceipt(t *testing.T) {
	r, clientKey := signedReceipt(t, true)
	sig := SignReport(clientKey, r)

	r.Bytes = 9_000_000 // claim a bigger transfer under the same report signature
	if err := VerifyReport(r, sig); err == nil {
		t.Fatal("a report verified after the receipt's byte count was changed; the report is not bound to the receipt claim")
	}
}

// TestReportSignatureIsDistinctFromCosignature: the report signature is a SEPARATE proof
// from the receipt's co-signature — the receipt's own ClientSig is not a valid report
// signature, so the two cannot be substituted for one another.
func TestReportSignatureIsDistinctFromCosignature(t *testing.T) {
	r, _ := signedReceipt(t, true)
	if err := VerifyReport(r, r.ClientSig); err == nil {
		t.Fatal("the receipt's co-signature verified as a capacity-report signature; the two proofs are not separated")
	}
}
