// The one-shot that lets something off-box bind a usage receipt to this machine
// (issue #271).
//
// A receipt proves that two parties co-signed a byte count. It proves nothing
// about WHO they were: core/accounting's canonical encoding covers no public key,
// so Receipt.Verify checks both signatures against the two keys the receipt hands
// it, and two fresh keypairs plus any exit id produce a receipt that verifies.
// Whatever pays per node therefore needs an out-of-band pairing of node id to
// accounting public key, checked before the signatures are — and the key half of
// that pairing is a domain-separated hash of this node's X25519 PRIVATE scalar, so
// it appears in no snapshot, no admission credential and no log line. Until this
// flag existed it could only be read out of a running process.
//
// # The output is field names, not prose
//
// Three lines of "field: value", where the field names are the ones the operator's
// roster file uses, so transcription is mechanical rather than interpretive:
//
//	id: <64 lowercase hex>       — what a receipt's exitId carries
//	acct_pub: <base64>           — the accounting public key, in the encoding a
//	                               roster's acct_pub field is read in
//	acct_pub_hex: <64 hex>       — the same 32 bytes in hex, for eyeballing and
//	                               for every other key this project prints
//
// The two encodings of one key are deliberate and the base64 one is deliberately
// named for the field it belongs in. An ed25519.PublicKey is a []byte, so a roster
// row's acct_pub is base64 — a hex string pasted there decodes to 48 bytes and is
// refused on length, which is loud but is an hour of somebody's evening. See
// ADR-0075.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/bacchus-vpn/bacchus/core"
)

// printAcctIdentity writes this exit's node id and accounting public key to w.
//
// It takes the exit key as a string rather than reading the flag itself so the
// whole behaviour, refusals included, is testable without running a process — and
// it writes to an io.Writer for the same reason.
//
// The empty check is here as well as in core.ExitAcctIdentity, and that is not
// belt-and-braces: core cannot name a flag (it is reached from clients/fyne too,
// where there is none), and an operator who typed one flag and is told a Go field
// is unset has not been helped. core's refusal is what protects every other
// caller.
func printAcctIdentity(w io.Writer, exitKeyHex string) error {
	if strings.TrimSpace(exitKeyHex) == "" {
		return errors.New("-print-acct-pubkey requires -exit-key (the 64-hex X25519 private key this node serves under). " +
			"Without one a node generates a fresh identity on every start, so there is no stable id or accounting " +
			"key to publish — and printing the generated one would look exactly like printing a usable one")
	}
	id, pub, err := core.ExitAcctIdentity(exitKeyHex)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "id: %s\n", id)
	fmt.Fprintf(w, "acct_pub: %s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Fprintf(w, "acct_pub_hex: %s\n", hex.EncodeToString(pub))
	return nil
}
