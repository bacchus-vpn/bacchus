package accounting

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// deadline arms every pipe end with a test-wide deadline so a wiring bug fails
// fast instead of hanging (mirrors core/e2e_test.go's helper of the same name).
func deadline(t *testing.T, conns ...net.Conn) {
	t.Helper()
	for _, c := range conns {
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
	}
}

func genKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

// TestExitProposeClientCosignRoundTrip: matching counts produce a receipt both
// sides agree on, and it verifies.
func TestExitProposeClientCosignRoundTrip(t *testing.T) {
	exitKey, clientKey := genKey(t), genKey(t)
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	const (
		sessionID = "sess-1"
		exitID    = "exit-abc"
		seq       = uint64(3)
		interval  = uint32(60)
		bytesN    = uint64(123456)
	)

	type res struct {
		r   Receipt
		err error
	}
	done := make(chan res, 1)
	go func() {
		r, err := ExitPropose(sConn, exitKey, exitID, sessionID, seq, interval, bytesN)
		done <- res{r, err}
	}()

	clientR, err := ClientCosign(cConn, clientKey, bytesN)
	if err != nil {
		t.Fatalf("ClientCosign: %v", err)
	}
	exitRes := <-done
	if exitRes.err != nil {
		t.Fatalf("ExitPropose: %v", exitRes.err)
	}

	// Receipt has []byte-ish fields, so it isn't ==-comparable; check the
	// parts that matter instead.
	er, cr := exitRes.r, clientR
	if er.SessionID != cr.SessionID || er.Seq != cr.Seq || er.IntervalSec != cr.IntervalSec ||
		er.Bytes != cr.Bytes || er.ExitID != cr.ExitID ||
		!er.ExitAcctPub.Equal(cr.ExitAcctPub) || !er.ClientAcctPub.Equal(cr.ClientAcctPub) {
		t.Fatalf("exit and client assembled different receipts: %+v vs %+v", er, cr)
	}
	if err := clientR.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if clientR.Bytes != bytesN || clientR.SessionID != sessionID || clientR.Seq != seq || clientR.ExitID != exitID {
		t.Fatalf("receipt fields mismatch: %+v", clientR)
	}
}

// TestClientRejectsMismatch: the acceptance criterion in issue #20 -- neither
// side gets a receipt when their counts disagree, and the client's rejection
// tells the exit what it saw (the cross-check hook).
func TestClientRejectsMismatch(t *testing.T) {
	exitKey, clientKey := genKey(t), genKey(t)
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	done := make(chan error, 1)
	go func() {
		_, err := ExitPropose(sConn, exitKey, "exit-1", "sess-1", 0, 60, 1000)
		done <- err
	}()

	_, err := ClientCosign(cConn, clientKey, 999) // client saw fewer bytes than the exit claims
	if err == nil {
		t.Fatal("expected ClientCosign to reject a mismatched claim")
	}

	exitErr := <-done
	if exitErr == nil {
		t.Fatal("expected ExitPropose to fail when the client rejects")
	}
}

// TestVerifyFailsOnTamperedBytes is the other half of #20's acceptance
// criterion: a tampered count fails verification.
func TestVerifyFailsOnTamperedBytes(t *testing.T) {
	exitKey, clientKey := genKey(t), genKey(t)
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	done := make(chan Receipt, 1)
	go func() {
		r, err := ExitPropose(sConn, exitKey, "exit-1", "sess-1", 0, 60, 1000)
		if err != nil {
			t.Errorf("ExitPropose: %v", err)
		}
		done <- r
	}()
	if _, err := ClientCosign(cConn, clientKey, 1000); err != nil {
		t.Fatalf("ClientCosign: %v", err)
	}
	r := <-done

	tampered := r
	tampered.Bytes = r.Bytes + 1
	if err := tampered.Verify(); err == nil {
		t.Fatal("expected a tampered byte count to fail verification")
	}
	// Sanity: the untampered original still verifies.
	if err := r.Verify(); err != nil {
		t.Fatalf("original receipt should still verify: %v", err)
	}
}

// TestVerifyRequiresBothSignatures proves the "neither side alone" half of
// #20's acceptance criterion directly: a receipt is only as good as both
// signatures, not either one.
func TestVerifyRequiresBothSignatures(t *testing.T) {
	exitKey, clientKey := genKey(t), genKey(t)
	otherKey := genKey(t)

	c := canonical("sess-1", 0, 60, 1000, "exit-1")
	base := Receipt{
		SessionID: "sess-1", Seq: 0, IntervalSec: 60, Bytes: 1000, ExitID: "exit-1",
		ExitAcctPub:   exitKey.Public().(ed25519.PublicKey),
		ClientAcctPub: clientKey.Public().(ed25519.PublicKey),
	}

	onlyExit := base
	onlyExit.ExitSig = ed25519.Sign(exitKey, c)
	onlyExit.ClientSig = ed25519.Sign(otherKey, c) // signed by the wrong key
	if err := onlyExit.Verify(); err == nil {
		t.Fatal("a receipt with only a valid exit signature must not verify")
	}

	onlyClient := base
	onlyClient.ExitSig = ed25519.Sign(otherKey, c) // signed by the wrong key
	onlyClient.ClientSig = ed25519.Sign(clientKey, c)
	if err := onlyClient.Verify(); err == nil {
		t.Fatal("a receipt with only a valid client signature must not verify")
	}

	both := base
	both.ExitSig = ed25519.Sign(exitKey, c)
	both.ClientSig = ed25519.Sign(clientKey, c)
	if err := both.Verify(); err != nil {
		t.Fatalf("a receipt with both valid signatures should verify: %v", err)
	}
}

// TestAcctKeyFromSeedStable: the same exit seed always yields the same
// accounting identity (mirrors core's TestExitKeyStableFromHex).
func TestAcctKeyFromSeedStable(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	a, err := AcctKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("AcctKeyFromSeed: %v", err)
	}
	b, err := AcctKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("AcctKeyFromSeed: %v", err)
	}
	if !a.Equal(b) {
		t.Fatal("the same seed must derive the same accounting key")
	}

	seed2 := make([]byte, 32)
	copy(seed2, seed)
	seed2[0] ^= 0xff
	c, err := AcctKeyFromSeed(seed2)
	if err != nil {
		t.Fatalf("AcctKeyFromSeed: %v", err)
	}
	if a.Equal(c) {
		t.Fatal("different seeds must derive different accounting keys")
	}

	// The derived signing key must not just be the X25519 seed reused
	// verbatim -- that would defeat the point of a separate domain.
	if string(a.Seed()) == string(seed) {
		t.Fatal("accounting key must not reuse the raw X25519 seed bytes")
	}
}

func TestAcctKeyFromSeedRejectsWrongLength(t *testing.T) {
	if _, err := AcctKeyFromSeed(make([]byte, 16)); err == nil {
		t.Fatal("expected an error for a non-32-byte seed")
	}
}

func TestReconcileDefaultPolicy(t *testing.T) {
	cases := []struct {
		local, claimed uint64
		want           bool
	}{
		{1000, 1000, true},
		{1000, 999, false},
		{999, 1000, false},
		{0, 0, true},
	}
	for _, tc := range cases {
		if got := Reconcile(tc.local, tc.claimed); got != tc.want {
			t.Errorf("Reconcile(%d, %d) = %v, want %v", tc.local, tc.claimed, got, tc.want)
		}
	}
}

func TestCounterDeltaPartitionsIntoIntervals(t *testing.T) {
	var c Counter
	c.Add(100)
	c.Add(50)
	if got := c.Delta(); got != 150 {
		t.Fatalf("first Delta = %d, want 150", got)
	}
	if got := c.Delta(); got != 0 {
		t.Fatalf("Delta with nothing new = %d, want 0", got)
	}
	c.Add(10)
	if got := c.Delta(); got != 10 {
		t.Fatalf("second Delta = %d, want 10", got)
	}
	if got := c.Load(); got != 160 {
		t.Fatalf("Load (cumulative) = %d, want 160", got)
	}
}

func TestCounterCountReads(t *testing.T) {
	var c Counter
	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	go func() { _, _ = sConn.Write([]byte("hello world")); sConn.Close() }()

	buf := make([]byte, len("hello world"))
	n, err := io.ReadFull(c.CountReads(cConn), buf)
	if err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if uint64(n) != c.Load() {
		t.Fatalf("counted %d, read %d", c.Load(), n)
	}
}

func TestNilCounterIsInert(t *testing.T) {
	var c *Counter
	c.Add(5)
	if got := c.Load(); got != 0 {
		t.Fatalf("nil Counter Load() = %d, want 0", got)
	}
	if got := c.Delta(); got != 0 {
		t.Fatalf("nil Counter Delta() = %d, want 0", got)
	}
	// A nil Counter must hand back the exact same reader, not a wrapper --
	// callers rely on this to add zero overhead when accounting is disabled.
	src := strings.NewReader("x")
	if r := c.CountReads(src); r != io.Reader(src) {
		t.Fatal("nil Counter.CountReads must return the input reader unchanged")
	}
}

func TestStoreAppendAndLoadReceipts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "receipts.jsonl")

	// A missing file reads as no receipts, not an error.
	got, err := LoadReceipts(path)
	if err != nil || len(got) != 0 {
		t.Fatalf("LoadReceipts on a missing file: got %v, err %v", got, err)
	}

	store, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	r1 := Receipt{SessionID: "s1", Seq: 0, IntervalSec: 60, Bytes: 111, ExitID: "e1",
		ExitAcctPub: genKey(t).Public().(ed25519.PublicKey), ClientAcctPub: genKey(t).Public().(ed25519.PublicKey),
		ExitSig: []byte("sig1"), ClientSig: []byte("sig2")}
	r2 := r1
	r2.Seq = 1
	r2.Bytes = 222
	if err := store.Append(r1); err != nil {
		t.Fatalf("Append r1: %v", err)
	}
	if err := store.Append(r2); err != nil {
		t.Fatalf("Append r2: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	loaded, err := LoadReceipts(path)
	if err != nil {
		t.Fatalf("LoadReceipts: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d receipts, want 2", len(loaded))
	}
	if loaded[0].Bytes != 111 || loaded[1].Bytes != 222 {
		t.Fatalf("loaded receipts out of order or corrupted: %+v", loaded)
	}
}
