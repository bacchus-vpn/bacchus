// What `bacchus-node -print-acct-pubkey` actually prints, read back out of a
// built binary and checked against a receipt the accounting package really
// produced (issue #271).
//
// The split with core/accounting_identity_test.go is deliberate and neither half
// is sufficient. That file can reach an Engine's own acctKey and run the sentinel
// round trip through it, so it proves the DERIVATION is the one a serving exit
// uses; it cannot see this binary's stdout. This file can only see stdout, so it
// proves the printed bytes are the ones a receipt carries and that they arrive in
// the encodings a roster row is read in. A regression in either place is invisible
// to the other.

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/accounting"
)

// A fixed exit key, so every expectation below is reproducible and none of them
// is "whatever the binary said". Not a secret in any sense that matters: it is 32
// bytes of 0xab and it exists only inside this test.
const testAcctExitKeyHex = "abababababababababababababababababababababababababababababababab"

// printedIdentity is the one-shot's output, parsed into the fields it names.
type printedIdentity struct {
	id         string
	acctPub    string // base64, the encoding a roster's acct_pub field takes
	acctPubHex string
}

// runPrintAcctPubkey runs the built binary's one-shot and returns what it wrote.
//
// -coordinators points at loopback port 1, where nothing answers, and no -socks or
// -listen is given. A run that reached the network or bound a port would hang or
// fail here rather than returning in milliseconds, which is half of what "one-shot"
// is supposed to mean.
func runPrintAcctPubkey(t *testing.T, bin string, extra ...string) (stdout, stderr string, err error) {
	t.Helper()
	args := append([]string{"-print-acct-pubkey", "-coordinators", "127.0.0.1:1"}, extra...)
	var out, errb strings.Builder
	run := exec.Command(bin, args...)
	run.Stdout, run.Stderr = &out, &errb
	err = run.Run()
	return out.String(), errb.String(), err
}

// parsePrintedIdentity reads the three "field: value" lines, requiring all three
// and nothing else. Strict on purpose: this output is transcribed by hand into a
// file that fails open on a mistyped key name, so an extra line nobody expected is
// a change worth failing over rather than absorbing.
func parsePrintedIdentity(t *testing.T, stdout string) printedIdentity {
	t.Helper()
	got := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		name, value, ok := strings.Cut(line, ": ")
		if !ok {
			t.Fatalf("output line %q is not \"field: value\"; the whole output was:\n%s", line, stdout)
		}
		if _, dup := got[name]; dup {
			t.Fatalf("field %q printed twice:\n%s", name, stdout)
		}
		got[name] = value
	}
	if len(got) != 3 {
		t.Fatalf("expected exactly the three fields id, acct_pub and acct_pub_hex; got %d:\n%s", len(got), stdout)
	}
	for _, want := range []string{"id", "acct_pub", "acct_pub_hex"} {
		if got[want] == "" {
			t.Fatalf("no %q field in:\n%s", want, stdout)
		}
	}
	return printedIdentity{id: got["id"], acctPub: got["acct_pub"], acctPubHex: got["acct_pub_hex"]}
}

// realReceipt runs one accounting interval over a pipe and returns the co-signed
// receipt, using the exit key core's setupAccounting would derive and the node id
// core.New would register. It is the accounting package's own exchange, not a
// hand-built struct: a receipt assembled by the test could carry any field the
// test wanted it to.
func realReceipt(t *testing.T, exitKeyHex string, bytesN uint64) accounting.Receipt {
	t.Helper()
	seed, err := hex.DecodeString(exitKeyHex)
	if err != nil {
		t.Fatalf("decoding the test exit key: %v", err)
	}
	acctKey, err := accounting.AcctKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("AcctKeyFromSeed: %v", err)
	}
	// The id a real engine would register and stamp into ExitID, taken from core
	// rather than recomputed here.
	eng, err := core.New(core.Config{
		Coordinators: []string{"127.0.0.1:1"}, Roles: []string{"exit"},
		Advertise: "203.0.113.5:20000", ExitKeyHex: exitKeyHex,
	})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}

	exitEnd, clientEnd := net.Pipe()
	deadline := time.Now().Add(30 * time.Second)
	_ = exitEnd.SetDeadline(deadline)
	_ = clientEnd.SetDeadline(deadline)
	defer exitEnd.Close()
	defer clientEnd.Close()

	done := make(chan error, 1)
	go func() {
		_, err := accounting.ExitPropose(exitEnd, acctKey, eng.ID(), "acct-key-session", 0, 60, bytesN)
		done <- err
	}()

	_, clientKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a client accounting key: %v", err)
	}
	r, err := accounting.ClientCosign(clientEnd, clientKey, bytesN)
	if err != nil {
		t.Fatalf("ClientCosign: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("ExitPropose: %v", err)
	}
	if err := r.Verify(); err != nil {
		t.Fatalf("the receipt this exchange produced does not verify: %v", err)
	}
	return r
}

// The one-shot prints the id and the key a receipt actually carries, in the
// encodings the roster reads them in.
func TestPrintAcctPubkeyPrintsWhatARealReceiptCarries(t *testing.T) {
	bin := buildNode(t, t.TempDir(), "")
	stdout, stderr, err := runPrintAcctPubkey(t, bin, "-exit-key", testAcctExitKeyHex)
	if err != nil {
		t.Fatalf("-print-acct-pubkey: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	got := parsePrintedIdentity(t, stdout)

	const bytesN = 1 << 20
	r := realReceipt(t, testAcctExitKeyHex, bytesN)

	if r.ExitID != got.id {
		t.Errorf("the receipt names exit %q but the binary printed id %q — a roster row carrying the "+
			"printed value would match no receipt this node ever mints, and would report that as a zero "+
			"rather than as an error", r.ExitID, got.id)
	}

	pub, err := base64.StdEncoding.DecodeString(got.acctPub)
	if err != nil {
		t.Fatalf("acct_pub %q is not base64 (%v) — a roster's acct_pub field is an ed25519.PublicKey, "+
			"which is a []byte, so encoding/json reads it as base64 and nothing else", got.acctPub, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("acct_pub decoded to %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	if !ed25519.PublicKey(pub).Equal(r.ExitAcctPub) {
		t.Errorf("the receipt was signed under %x but the binary printed %x", []byte(r.ExitAcctPub), pub)
	}

	pubHex, err := hex.DecodeString(got.acctPubHex)
	if err != nil {
		t.Fatalf("acct_pub_hex %q is not hex: %v", got.acctPubHex, err)
	}
	if !ed25519.PublicKey(pubHex).Equal(ed25519.PublicKey(pub)) {
		t.Errorf("acct_pub and acct_pub_hex are two different keys: %x vs %x", pub, pubHex)
	}

	// The attributing check: re-verify against the PRINTED key rather than the one
	// the receipt carries for itself, which is what a roster does and the only
	// reason the printed value is worth having.
	pinned := r
	pinned.ExitAcctPub = pub
	if err := pinned.Verify(); err != nil {
		t.Errorf("the receipt does not verify against the printed key: %v", err)
	}
	forged := r
	other := append([]byte(nil), pub...)
	other[len(other)-1] ^= 0xff
	forged.ExitAcctPub = other
	if err := forged.Verify(); err == nil {
		t.Error("a one-byte-different key also verified this receipt, so the check above proves nothing")
	}
}

// A node with no persistent exit key is refused, and nothing key-shaped reaches
// stdout.
//
// This is the failure that would have been worst to ship. core.exitStaticKey
// GENERATES a keypair for an empty -exit-key, so a one-shot that simply called it
// would print a perfectly well-formed id and key belonging to an identity the
// process throws away on return — and an operator would paste that pair into a
// roster and watch the node earn nothing, with every receipt verifying and no
// error anywhere.
func TestPrintAcctPubkeyRefusesANodeWithNoStableIdentity(t *testing.T) {
	bin := buildNode(t, t.TempDir(), "")
	stdout, stderr, err := runPrintAcctPubkey(t, bin)

	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("-print-acct-pubkey with no -exit-key exited %v, want a non-zero status\nstdout:\n%s", err, stdout)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Fatalf("it refused but still wrote to stdout, which is where an operator copies from:\n%s", stdout)
	}
	if !strings.Contains(stderr, "-exit-key") {
		t.Errorf("the refusal does not name -exit-key, which is the flag the operator has to add:\n%s", stderr)
	}
}

// A malformed key is refused for its own reason rather than falling through to
// the generate path.
func TestPrintAcctPubkeyRefusesAMalformedExitKey(t *testing.T) {
	bin := buildNode(t, t.TempDir(), "")
	for _, tc := range []struct{ name, key string }{
		{"not hex", strings.Repeat("z", 64)},
		{"too short", strings.Repeat("11", 31)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, err := runPrintAcctPubkey(t, bin, "-exit-key", tc.key)
			if err == nil {
				t.Fatalf("accepted a %s exit key and printed:\n%s", tc.name, stdout)
			}
			if strings.TrimSpace(stdout) != "" {
				t.Fatalf("refused a %s exit key but still wrote to stdout:\n%s", tc.name, stdout)
			}
		})
	}
}

// The same box answers the same thing twice. The roster's whole premise is that a
// value written down once stays true, and the alternative failure would print
// something plausible on every run.
func TestPrintAcctPubkeyIsStableAcrossRuns(t *testing.T) {
	bin := buildNode(t, t.TempDir(), "")
	first, _, err := runPrintAcctPubkey(t, bin, "-exit-key", testAcctExitKeyHex)
	if err != nil {
		t.Fatalf("-print-acct-pubkey: %v", err)
	}
	second, _, err := runPrintAcctPubkey(t, bin, "-exit-key", testAcctExitKeyHex)
	if err != nil {
		t.Fatalf("-print-acct-pubkey (again): %v", err)
	}
	if first != second {
		t.Fatalf("two runs of one binary with one key disagreed:\n%s\nthen\n%s", first, second)
	}
}

// A roster row whose id does not match what arrives produces a ZERO, not an error,
// and this is what that looks like.
//
// The mirror below is the shape of bacchus-payment's earn.Roster.authorize and
// Reconciler.Ingest, reproduced here because the two repositories are separate Go
// modules and neither may import the other: attribute by id first, then verify
// against the key the roster pinned, and tally a refusal instead of returning it
// so that one bad line in a node's journal does not abandon the other ten
// thousand. The consequence is that every near-miss below is indistinguishable, at
// the operator's end, from a node that carried no traffic.
func TestARosterRowThatMissesTheIDEarnsZeroSilently(t *testing.T) {
	bin := buildNode(t, t.TempDir(), "")
	stdout, stderr, err := runPrintAcctPubkey(t, bin, "-exit-key", testAcctExitKeyHex)
	if err != nil {
		t.Fatalf("-print-acct-pubkey: %v\n%s", err, stderr)
	}
	got := parsePrintedIdentity(t, stdout)
	pub, err := base64.StdEncoding.DecodeString(got.acctPub)
	if err != nil {
		t.Fatalf("decoding acct_pub: %v", err)
	}

	const bytesN = 777
	r := realReceipt(t, testAcctExitKeyHex, bytesN)

	// ingest is the reconciler's loop: it counts what it can attribute and swallows
	// what it cannot, exactly as Ingest does.
	ingest := func(rosterID string, rosterKey ed25519.PublicKey, rs []accounting.Receipt) (counted uint64) {
		for _, rc := range rs {
			if rc.ExitID != rosterID {
				continue // ErrUnknownNode, tallied and not returned
			}
			if !rosterKey.Equal(rc.ExitAcctPub) {
				continue // ErrKeyMismatch, likewise
			}
			if err := rc.Verify(); err != nil {
				continue
			}
			counted += rc.Bytes
		}
		return counted
	}

	// The positive control first. Without it, every zero below is a zero for
	// whatever reason the mirror happens to have.
	if n := ingest(got.id, pub, []accounting.Receipt{r}); n != bytesN {
		t.Fatalf("a roster row built from the printed output counted %d bytes, want %d — the two values "+
			"this one-shot exists to supply do not attribute the receipt they were supposed to", n, bytesN)
	}

	for _, tc := range []struct {
		name string
		id   string
		why  string
	}{
		{"uppercased", strings.ToUpper(got.id), "a hand transcription that changed case"},
		{"the accounting key pasted as the id", got.acctPubHex, "the two hex strings in this output are the same length"},
		{"truncated", got.id[:len(got.id)-1], "one character lost between a terminal and a file"},
		{"a name the operator uses", "exit-alpha", "the value they passed to -id, which an exit overrides"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.id == got.id {
				t.Fatalf("this case is not a mutation of the printed id (%s)", tc.why)
			}
			if n := ingest(tc.id, pub, []accounting.Receipt{r}); n != 0 {
				t.Fatalf("expected a roster keyed on %q to count nothing, got %d bytes", tc.id, n)
			}
			// And the point: nothing was wrong with the receipt.
			if err := r.Verify(); err != nil {
				t.Fatalf("the unattributed receipt is also invalid (%v), which would make the zero above "+
					"a detectable failure rather than a silent one", err)
			}
		})
	}
}

// The hex form is printed for eyeballing, and it is NOT the roster's encoding.
// Pasting it into acct_pub is refused on length rather than accepted — loud, which
// is the reason the base64 form is printed under the field's own name.
func TestTheHexKeyIsNotAcceptableWhereBase64IsExpected(t *testing.T) {
	bin := buildNode(t, t.TempDir(), "")
	stdout, _, err := runPrintAcctPubkey(t, bin, "-exit-key", testAcctExitKeyHex)
	if err != nil {
		t.Fatalf("-print-acct-pubkey: %v", err)
	}
	got := parsePrintedIdentity(t, stdout)

	// 64 hex characters are all in the base64 alphabet, so this decodes rather than
	// erroring — to 48 bytes, which a roster refuses because it is not 32.
	misread, err := base64.StdEncoding.DecodeString(got.acctPubHex)
	if err == nil && len(misread) == ed25519.PublicKeySize {
		t.Fatal("the hex key read as base64 produced a well-formed accounting key, so a mis-transcription " +
			"would be accepted in silence rather than refused")
	}
	if err == nil {
		t.Logf("acct_pub_hex read as base64 decodes to %d bytes, which a roster refuses on length", len(misread))
	}
}
