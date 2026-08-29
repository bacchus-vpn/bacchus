// What ExitAcctIdentity claims, measured against a receipt a real engine really
// signed (issue #271).
//
// The function re-derives what New derives rather than reading a constructed
// Engine, for the reason its doc gives, and a re-derivation is exactly the kind of
// thing that goes on answering confidently after the original moves. So the checks
// here are not "does the hash still hash": they build an exit engine, run the real
// accounting round trip through it, and compare the receipt that comes out —
// ExitID against the printed id, ExitAcctPub against the printed key, and the
// exit's signature re-verified against the printed key rather than against the one
// the receipt carries for itself.
//
// The last of those is the one worth being careful about. Receipt.Verify checks
// both signatures against the receipt's OWN keys, so it passes for a receipt
// nobody in this fleet minted; substituting the printed key and asking again is
// what turns "this receipt is internally consistent" into "this receipt was signed
// by the key that box prints", which is the only question a roster is asking.

package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/accounting"
)

// realExitReceipt runs one accounting interval against a real exit engine and
// returns the co-signed receipt, the same way TestAcctSentinelRoundTrip does:
// exitHandshake and handleAcctStream on one end of a net.Pipe, the client's
// ClientCosign on the other. Nothing here is a stand-in for the exit — it is the
// engine's own acctKey and cfg.ID that sign and stamp.
func realExitReceipt(t *testing.T, exitEng *Engine, bytesN uint64) accounting.Receipt {
	t.Helper()
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	const sid = "acct-identity-session"
	exitEng.acctCounter(sid).Add(bytesN)

	done := make(chan error, 1)
	go func() {
		nc, target, err := exitHandshake(sConn, exitEng.exitKey, nil)
		if err != nil {
			done <- err
			return
		}
		if target != acctSentinel {
			done <- fmt.Errorf("target = %q, want the accounting sentinel", target)
			return
		}
		exitEng.handleAcctStream(sid, nc)
		done <- nil
	}()

	nc, err := clientHandshake(cConn, exitEng.exitKey.Public, acctSentinel, nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	r, err := accounting.ClientCosign(nc, genEd25519(t), bytesN)
	if err != nil {
		t.Fatalf("ClientCosign: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("exit side: %v", err)
	}
	return r
}

// The whole of issue #271's correctness condition in one test: what a node prints
// is what its receipts carry, and the key it prints is the key that signed them.
func TestExitAcctIdentityIsWhatARealReceiptCarries(t *testing.T) {
	exitEng, err := New(Config{
		Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "203.0.113.5:20000",
		ExitKeyHex: testExitKeyHex, AcctDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New exit: %v", err)
	}
	defer exitEng.Stop()

	id, pub, err := ExitAcctIdentity(testExitKeyHex)
	if err != nil {
		t.Fatalf("ExitAcctIdentity: %v", err)
	}

	// First the engine's own state, which is the shortest path to a wrong
	// derivation and the one a receipt would only report at one remove.
	if exitEng.ID() != id {
		t.Errorf("ExitAcctIdentity printed id %s but an engine built from the same key registers as %s — "+
			"a roster row carrying the printed one would never match an arriving receipt, and it would "+
			"produce a zero rather than an error", shortID(id), shortID(exitEng.ID()))
	}
	if exitEng.acctKey == nil {
		t.Fatal("an exit with AcctDir set has no accounting key, so this test cannot compare anything")
	}
	if got := exitEng.acctKey.Public().(ed25519.PublicKey); !bytes.Equal(got, pub) {
		t.Errorf("ExitAcctIdentity printed accounting key %x but the engine signs with %x", pub, got)
	}

	const bytesN = 4096
	r := realExitReceipt(t, exitEng, bytesN)
	if err := r.Verify(); err != nil {
		t.Fatalf("the receipt this exit produced does not verify: %v", err)
	}
	if r.Bytes != bytesN {
		t.Fatalf("receipt bytes = %d, want %d", r.Bytes, bytesN)
	}
	if r.ExitID != id {
		t.Errorf("receipt ExitID = %q, printed id = %q", r.ExitID, id)
	}
	if !bytes.Equal(r.ExitAcctPub, pub) {
		t.Errorf("receipt ExitAcctPub = %x, printed key = %x", r.ExitAcctPub, pub)
	}

	// The attributing check, as a roster does it: verify against the key the
	// OPERATOR pinned rather than the one the receipt brought with it.
	pinned := r
	pinned.ExitAcctPub = pub
	if err := pinned.Verify(); err != nil {
		t.Errorf("the receipt does not verify against the printed accounting key (%v) — verification "+
			"against a receipt's own key proves nothing about whose it is, so this is the check that "+
			"makes the printed value worth anything", err)
	}

	// ...and the control, without which the line above would pass for any key of
	// the right length.
	wrong := r
	other := make(ed25519.PublicKey, len(pub))
	copy(other, pub)
	other[0] ^= 0xff
	wrong.ExitAcctPub = other
	if err := wrong.Verify(); err == nil {
		t.Error("a receipt verified against a key that is one flipped byte away from the printed one; " +
			"the check above is then vacuous")
	}
}

// The trap the roster fails silently on, in its likeliest real form: an operator
// who put -id in their unit file and reads it back as this node's identity.
//
// core.New OVERRIDES a configured ID for the exit role — the id must BE the
// X25519 public key or no client can run Noise_NK against it — so the -id value is
// not what a receipt carries and never was. A roster row keyed on it matches
// nothing, and nothing anywhere reports an error: the receipts are refused one at
// a time into a rejection tally and that node simply earns zero.
func TestExitAcctIdentityIgnoresAConfiguredNodeID(t *testing.T) {
	const wishful = "exit-alpha"
	eng, err := New(Config{
		Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "203.0.113.5:20000",
		ExitKeyHex: testExitKeyHex, ID: wishful, AcctDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("New exit: %v", err)
	}
	defer eng.Stop()

	id, _, err := ExitAcctIdentity(testExitKeyHex)
	if err != nil {
		t.Fatalf("ExitAcctIdentity: %v", err)
	}
	if id == wishful {
		t.Fatal("ExitAcctIdentity returned the configured -id; an exit registers and signs under its " +
			"X25519 public key, so printing -id would put a value in a roster that no receipt can match")
	}
	if eng.ID() != id {
		t.Errorf("engine id = %q, ExitAcctIdentity = %q — the two must not be able to disagree", eng.ID(), id)
	}
	if raw, err := hex.DecodeString(id); err != nil || len(raw) != ed25519.PublicKeySize {
		t.Errorf("id = %q, want 64 hex characters of X25519 public key", id)
	}
	if id != strings.ToLower(id) {
		t.Errorf("id = %q, want lowercase hex: a roster match is a byte comparison, so case is not cosmetic", id)
	}
}

// An identity nothing can rely on is refused rather than invented. The empty case
// is the one that matters — exitStaticKey GENERATES for it, so falling through
// would print a usable-looking pair belonging to a keypair this process discards.
func TestExitAcctIdentityRefusesAKeyItCannotStandBehind(t *testing.T) {
	for _, tc := range []struct{ name, key string }{
		{"empty", ""},
		{"whitespace", "   \t\n"},
		{"not hex", strings.Repeat("z", 64)},
		{"too short", strings.Repeat("11", 31)},
		{"too long", strings.Repeat("11", 33)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id, pub, err := ExitAcctIdentity(tc.key)
			if err == nil {
				t.Fatalf("accepted %q and printed id %q / key %x", tc.name, id, pub)
			}
			if id != "" || pub != nil {
				t.Errorf("refused %q but still returned id %q / key %x", tc.name, id, pub)
			}
		})
	}
}

// Stable across calls, and different per key. The roster's entire premise is that
// the pair an operator writes down once stays true, which is only worth asserting
// because the alternative — a key that drifted per process — would still print
// something plausible every time.
func TestExitAcctIdentityIsStableAndPerKey(t *testing.T) {
	firstID, firstPub, err := ExitAcctIdentity(testExitKeyHex)
	if err != nil {
		t.Fatalf("ExitAcctIdentity: %v", err)
	}
	secondID, secondPub, err := ExitAcctIdentity(testExitKeyHex)
	if err != nil {
		t.Fatalf("ExitAcctIdentity (again): %v", err)
	}
	if firstID != secondID || !bytes.Equal(firstPub, secondPub) {
		t.Fatalf("two calls with one key disagreed: %s/%x then %s/%x",
			shortID(firstID), firstPub, shortID(secondID), secondPub)
	}

	otherID, otherPub, err := ExitAcctIdentity(strings.Repeat("22", 32))
	if err != nil {
		t.Fatalf("ExitAcctIdentity (other key): %v", err)
	}
	if otherID == firstID || bytes.Equal(otherPub, firstPub) {
		t.Fatal("two different exit keys produced the same identity")
	}

	// The two halves are independent keys derived from one seed, not one key shown
	// twice — the cross-protocol footgun acctKeyDomain exists to avoid. An id and a
	// key that happened to be equal would also make the roster's two fields
	// mutually substitutable, which is the mistake the printed field names are
	// shaped to prevent.
	if firstID == hex.EncodeToString(firstPub) {
		t.Fatal("the node id and the accounting public key are the same bytes")
	}
}
