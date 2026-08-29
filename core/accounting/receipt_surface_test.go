// What a receipt carries, enumerated (bacchus-payment#98, claim 2).
//
// A receipt leaves the client, is journalled by the exit, and the exit's journal is
// what reaches the account-service host at payout. Everything on it is therefore
// disclosed to the one party the account model works to keep from building a per-user
// profile, and the payout model's claim that receipts "carry no user identity" is a
// claim about this struct's field list and about the lifetime of each field's value.
//
// Two of those fields are keys and one is a session id, so the claim survives on a
// lifetime argument rather than on absence: ClientAcctPub is fresh per session
// (Engine.startAccounting, pinned by core/accounting_client_key_test.go), SessionID
// is per session by construction, ExitID names the exit rather than the user, and
// Bytes and Seq are numbers. Nothing here outlives one session on the client side.
//
// That argument is only as good as the field list it was made about, which is what
// this file pins. A field added later would be covered by no existing test and by no
// sentence in any doc — it would simply start appearing in journals.

package accounting

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// receiptJSONFields is every key a Receipt marshals to, with what makes each safe to
// put in front of the account service. Adding a key here is a deliberate act; the
// test below makes it one.
var receiptJSONFields = map[string]string{
	"sessionId":     "per session by construction — the coordinator mints it for one pairing",
	"seq":           "the interval counter within one session",
	"intervalSec":   "the nominal interval length, a configuration value",
	"bytes":         "a byte count",
	"exitId":        "the EXIT's identity (its X25519 public key), not the user's",
	"exitAcctPub":   "the exit's stable accounting key — stable on purpose, since an exit is the party being paid",
	"clientAcctPub": "the client's accounting key, FRESH PER SESSION — this is the field the whole claim turns on",
	"exitSig":       "a signature over the canonical claim",
	"clientSig":     "a signature over the canonical claim",
	"saturated":     "one bit of client-asserted demand saturation",
}

// TestReceiptCarriesNoFieldThatOutlivesASession pins the disclosure surface: exactly
// these fields reach the account-service host, and no others.
//
// It marshals a fully populated receipt — Saturated set, so omitempty cannot hide a
// field from the comparison — and compares the object's key set against the list
// above. A new field fails here, and the failure asks the one question that matters
// about it: is its value the same in two different sessions?
func TestReceiptCarriesNoFieldThatOutlivesASession(t *testing.T) {
	r := Receipt{
		SessionID:     "session-surface",
		Seq:           7,
		IntervalSec:   60,
		Bytes:         4096,
		ExitID:        "exit-surface",
		ExitAcctPub:   genPub(t),
		ClientAcctPub: genPub(t),
		ExitSig:       []byte("exit signature"),
		ClientSig:     []byte("client signature"),
		Saturated:     true,
	}

	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	var added, missing []string
	for k := range obj {
		if _, ok := receiptJSONFields[k]; !ok {
			added = append(added, k)
		}
	}
	for k := range receiptJSONFields {
		if _, ok := obj[k]; !ok {
			missing = append(missing, k)
		}
	}
	sort.Strings(added)
	sort.Strings(missing)

	if len(added) > 0 {
		t.Errorf("a receipt now carries %s.\n\n"+
			"Every field on a receipt is disclosed to the account-service host, which journals them at "+
			"payout. The payout model says receipts \"carry no user identity\", and that claim rests "+
			"entirely on nothing here having a value that is the same in two different sessions "+
			"(bacchus-payment#98 claim 2).\n\n"+
			"So: is this field's value stable across a user's sessions? If yes, it links them, and the "+
			"claim and the public privacy statement are what have to change. If no, add it to "+
			"receiptJSONFields with the reason, the way every field there is annotated.",
			strings.Join(added, ", "))
	}
	if len(missing) > 0 {
		t.Errorf("receiptJSONFields names %s, which a receipt no longer carries; the list is stale and "+
			"the check above is weaker than it looks", strings.Join(missing, ", "))
	}

	// Non-vacuity. An empty or near-empty object would make both loops above agree
	// about almost nothing while reporting success.
	if len(obj) != len(receiptJSONFields) {
		t.Fatalf("receipt marshalled to %d fields against %d expected — the comparison above did not "+
			"actually run over the whole struct", len(obj), len(receiptJSONFields))
	}
}

// TestReceiptCanonicalCoversNoKey restates, as a test, the fact ExitAcctIdentity's
// doc in core depends on and that claim 2 needs kept separate from it: the co-signed
// canonical covers the CLAIM and no public key.
//
// It is why verification is not attribution — two fresh keypairs produce a receipt
// that verifies perfectly — and it is also why the client's key can be rotated every
// session at no cost to the co-signature. The privacy property and the attribution
// property are the same design fact seen from two sides, so a change to canonical()
// would move both at once, and this is the cheaper of the two places to notice.
func TestReceiptCanonicalCoversNoKey(t *testing.T) {
	base := Receipt{
		SessionID: "session-canonical", Seq: 1, IntervalSec: 60, Bytes: 4096, ExitID: "exit-canonical",
		ExitAcctPub: genPub(t), ClientAcctPub: genPub(t),
	}
	other := base
	other.ExitAcctPub, other.ClientAcctPub = genPub(t), genPub(t)

	if string(base.canonical()) != string(other.canonical()) {
		t.Fatal("the canonical encoding changed when only the two accounting public keys changed, so it " +
			"now covers a key. That makes the client's key part of what is signed, and a per-session key " +
			"is only free to rotate because it is not (bacchus-payment#98 claim 2)")
	}
}

// genPub returns a fresh ed25519 public key.
func genPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub
}
