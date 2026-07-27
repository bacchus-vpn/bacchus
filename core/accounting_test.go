package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
)

func genEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

// TestAccountingDisabledByDefault: an engine built without Config.AcctDir has
// no accounting identity or store -- the feature is fully inert unless a
// caller opts in.
func TestAccountingDisabledByDefault(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if eng.acctKey != nil || eng.acctStore != nil || eng.acctClientStore != nil {
		t.Fatal("accounting must be off when AcctDir is unset")
	}
	if eng.acctEnabled() {
		t.Fatal("acctEnabled() should be false with no AcctDir")
	}
}

// TestAcctSentinelRoundTrip proves the direct-mode wiring end to end at the
// same layer core/e2e_test.go already tests at: a raw net.Pipe standing in
// for one transport stream, exitTerminate on one end (recognizing the
// accounting sentinel and calling into handleAcctStream), the client's
// accounting exchange on the other. This is #20's acceptance criterion: a
// co-signed receipt exists after the exchange, and it verifies.
func TestAcctSentinelRoundTrip(t *testing.T) {
	dir := t.TempDir()
	exitEng, err := New(Config{
		Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:1",
		AcctDir: dir,
	})
	if err != nil {
		t.Fatalf("New exit: %v", err)
	}
	defer exitEng.Stop()

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	const sid = "test-session-1"
	const bytesN = 12345

	// Simulate the exit having already counted bytesN for sid via real
	// proxied streams before this interval's accounting round trip.
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
	clientKey := genEd25519(t)
	r, err := accounting.ClientCosign(nc, clientKey, bytesN)
	if err != nil {
		t.Fatalf("ClientCosign: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("exit side: %v", err)
	}

	if err := r.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if r.Bytes != bytesN {
		t.Fatalf("receipt bytes = %d, want %d", r.Bytes, bytesN)
	}
	if r.SessionID != sid {
		t.Fatalf("receipt session = %q, want %q", r.SessionID, sid)
	}

	receipts, err := accounting.LoadReceipts(filepath.Join(dir, "receipts-exit.jsonl"))
	if err != nil {
		t.Fatalf("LoadReceipts: %v", err)
	}
	if len(receipts) != 1 {
		t.Fatalf("expected 1 persisted receipt, got %d", len(receipts))
	}
	if receipts[0].Bytes != bytesN {
		t.Fatalf("persisted receipt bytes = %d, want %d", receipts[0].Bytes, bytesN)
	}
}

// TestHandleAcctStreamNegativeIntervalUsesDefault guards against a regression
// where a negative AcctIntervalSec, cast straight to uint32 before the
// zero-check, would wrap to a huge value instead of falling back to
// defaultAcctIntervalSec (int64(-1) as uint32 is 4294967295, not 0).
func TestHandleAcctStreamNegativeIntervalUsesDefault(t *testing.T) {
	dir := t.TempDir()
	exitEng, err := New(Config{
		Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:1",
		AcctDir: dir, AcctIntervalSec: -1,
	})
	if err != nil {
		t.Fatalf("New exit: %v", err)
	}
	defer exitEng.Stop()

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)
	const sid = "neg-interval-session"
	exitEng.acctCounter(sid).Add(1)

	done := make(chan struct{})
	go func() {
		defer close(done)
		nc, target, err := exitHandshake(sConn, exitEng.exitKey, nil)
		if err != nil || target != acctSentinel {
			return
		}
		exitEng.handleAcctStream(sid, nc)
	}()

	nc, err := clientHandshake(cConn, exitEng.exitKey.Public, acctSentinel, nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	r, err := accounting.ClientCosign(nc, genEd25519(t), 1)
	if err != nil {
		t.Fatalf("ClientCosign: %v", err)
	}
	<-done
	if r.IntervalSec != defaultAcctIntervalSec {
		t.Fatalf("IntervalSec = %d, want the default %d for a negative config value", r.IntervalSec, defaultAcctIntervalSec)
	}
}

// TestAcctSentinelSkipsRelayForwardedConnections: an empty sid (the
// relay-forwarded case -- see handlerFor's doc) must not panic and must not
// produce a receipt; there is nothing to attribute the bytes to.
func TestAcctSentinelSkipsRelayForwardedConnections(t *testing.T) {
	dir := t.TempDir()
	exitEng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:1", AcctDir: dir})
	if err != nil {
		t.Fatalf("New exit: %v", err)
	}
	defer exitEng.Stop()

	cConn, sConn := net.Pipe()
	deadline(t, cConn, sConn)

	done := make(chan struct{})
	go func() {
		defer close(done)
		nc, target, err := exitHandshake(sConn, exitEng.exitKey, nil)
		if err != nil || target != acctSentinel {
			return
		}
		exitEng.handleAcctStream("", nc) // sid empty, as serveExit's relayed path passes
	}()

	nc, err := clientHandshake(cConn, exitEng.exitKey.Public, acctSentinel, nil)
	if err != nil {
		t.Fatalf("clientHandshake: %v", err)
	}
	// The exit closes its side without ever running the claim/ack exchange,
	// so this must fail rather than hang.
	if _, err := accounting.ClientCosign(nc, genEd25519(t), 100); err == nil {
		t.Fatal("expected ClientCosign to fail when the exit has no session to report")
	}
	<-done

	receipts, err := accounting.LoadReceipts(filepath.Join(dir, "receipts-exit.jsonl"))
	if err != nil {
		t.Fatalf("LoadReceipts: %v", err)
	}
	if len(receipts) != 0 {
		t.Fatalf("expected no receipts for a relay-forwarded (sid-less) connection, got %d", len(receipts))
	}
}

// TestClientAccountingLoopProducesReceipts drives the full client-side
// periodic loop (ticker -> OpenStream -> clientHandshake -> ClientCosign ->
// Store.Append) against a fake exit built from the existing loopbackTransport
// test harness (transport_test.go), so no real WebRTC/coordinator is needed --
// the same layering transport_test.go itself already uses.
func TestClientAccountingLoopProducesReceipts(t *testing.T) {
	exitDir := t.TempDir()
	exitEng, err := New(Config{Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "1.2.3.4:1", AcctDir: exitDir})
	if err != nil {
		t.Fatalf("New exit: %v", err)
	}
	defer exitEng.Stop()

	clientEng, err := New(Config{
		Coordinators: []string{testCoord}, Roles: []string{"client"},
		AcctDir: t.TempDir(), AcctIntervalSec: 1,
	})
	if err != nil {
		t.Fatalf("New client: %v", err)
	}
	defer clientEng.Stop()

	dialerSig, accepterSig := newMemSignalerPair()
	var tr loopbackTransport
	const sid = "acct-loop-session"

	accepted := make(chan Session, 1)
	go func() {
		sess, err := tr.Accept(context.Background(), accepterSig)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		accepted <- sess
		for {
			st, err := sess.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func(st Stream) {
				nc, target, err := exitHandshake(st, exitEng.exitKey, nil)
				if err != nil || target != acctSentinel {
					_ = st.Close()
					return
				}
				exitEng.handleAcctStream(sid, nc)
			}(st)
		}
	}()

	sess, err := tr.Dial(context.Background(), dialerSig)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer sess.Close()
	<-accepted

	// The exit key travels WITH the path now (issue #146): the coordinator picks the
	// exit, so there is no engine-lifetime key to set beforehand.
	ctr := clientEng.startAccounting(sid, sess, nil, exitEng.exitKey.Public) // nil link: this test exercises the receipt round trip, not the #158 report send
	if ctr == nil {
		t.Fatal("expected accounting to be enabled for this client")
	}
	const bytesN = 999
	exitEng.acctCounter(sid).Add(bytesN)
	ctr.Add(bytesN)

	deadlineAt := time.After(5 * time.Second)
	for {
		receipts, err := accounting.LoadReceipts(filepath.Join(exitDir, "receipts-exit.jsonl"))
		if err != nil {
			t.Fatalf("LoadReceipts: %v", err)
		}
		if len(receipts) >= 1 {
			if receipts[0].Bytes != bytesN {
				t.Fatalf("receipt bytes = %d, want %d", receipts[0].Bytes, bytesN)
			}
			if err := receipts[0].Verify(); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			return
		}
		select {
		case <-deadlineAt:
			t.Fatal("no receipt persisted in time")
		case <-time.After(50 * time.Millisecond):
		}
	}
}
