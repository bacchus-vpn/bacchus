// Where the client's accounting keypair comes from and how long it lives
// (bacchus-payment#98, claim 2).
//
// # The claim, and why a doc line was not enough to settle it
//
// The account service's payout model says points come from co-signed receipts that
// "carry no user identity". Every accounting.Receipt carries ClientAcctPub — an
// ed25519 public key belonging to the client — next to SessionID, Bytes and ExitID,
// and the exit's journal of those receipts is what reaches the account-service host.
// So the claim holds on one condition and no other: the key is fresh per session. A
// key stable across sessions would make every journal a per-client profile, linking
// a user's sessions to each other and to their byte counts, assembled out of files
// nobody filed as records.
//
// setupAccounting's doc says the client role "has no persistent accounting identity
// -- see runClientAccounting, which mints a fresh keypair per session", and
// accounting.Receipt's doc says the same. Neither is evidence: runClientAccounting
// takes the key as a PARAMETER, so it is not the generation site and cannot vouch
// for a lifetime. The generation site is startAccounting, which calls
// ed25519.GenerateKey(rand.Reader) on every invocation and hands the result to the
// goroutine as an argument — the key is a local, it reaches no Engine field, and it
// is unreachable once that goroutine returns. Engine.connectVia calls
// startAccounting once per established direct-disposition path, so a fresh key per
// session is what that arrangement produces.
//
// # What the tests below do about it
//
// Reading the generation site settles it today. These pin it for tomorrow, and they
// pin the OBSERVABLE form of the property rather than its implementation: the tests
// do not look at the variable, they run two real accounting round trips through two
// real sessions on one client engine and compare the key that comes out on each
// receipt. A future startAccounting that cached its keypair — for a plausible reason
// like reusing one signing key across a reconnect — would still satisfy every doc
// comment in this package and would fail here.

package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/accounting"
)

// receiptOverAFreshSession runs one complete accounting interval for sid: a
// loopback session between clientEng and exitEng, the exit answering the accounting
// sentinel with handleAcctStream, the client driving its real periodic loop through
// startAccounting. It returns the receipt the exit persisted for sid.
//
// It is TestClientAccountingLoopProducesReceipts' arrangement, factored so it can be
// run twice against ONE client engine — which is the whole experiment, since a key
// that outlived a session would have to outlive it on the engine.
func receiptOverAFreshSession(t *testing.T, exitEng, clientEng *Engine, exitDir, sid string, bytesN uint64) accounting.Receipt {
	t.Helper()

	dialerSig, accepterSig := newMemSignalerPair()
	var tr loopbackTransport

	accepted := make(chan Session, 1)
	failed := make(chan error, 1)
	go func() {
		sess, err := tr.Accept(context.Background(), accepterSig)
		if err != nil {
			failed <- err
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
		t.Fatalf("Dial for %s: %v", sid, err)
	}
	defer sess.Close()
	select {
	case <-accepted:
	case err := <-failed:
		t.Fatalf("Accept for %s: %v", sid, err)
	case <-time.After(5 * time.Second):
		t.Fatalf("no session accepted for %s", sid)
	}

	ctr := clientEng.startAccounting(sid, sess, nil, exitEng.exitKey.Public)
	if ctr == nil {
		t.Fatalf("accounting is not enabled on this client engine, so %s produces no receipt", sid)
	}
	exitEng.acctCounter(sid).Add(bytesN)
	ctr.Add(bytesN)

	deadline := time.After(10 * time.Second)
	for {
		receipts, err := accounting.LoadReceipts(filepath.Join(exitDir, "receipts-exit.jsonl"))
		if err != nil {
			t.Fatalf("LoadReceipts: %v", err)
		}
		for _, r := range receipts {
			if r.SessionID == sid {
				return r
			}
		}
		select {
		case <-deadline:
			t.Fatalf("no receipt persisted for %s in time", sid)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// TestClientAccountingKeyIsFreshPerSession is claim 2, measured on the artifact the
// claim is about.
//
// Two sessions, one client engine, one exit, and the two receipts that come out.
// Their ClientAcctPub values must differ, because that key is the only field on a
// receipt that could carry a client across sessions — SessionID is per session by
// construction, ExitID names the exit, and Bytes is a number.
//
// The client's OWN journal is checked alongside the exit's for the same two keys.
// The exit's copy is the one that reaches the account-service host, so it is the one
// the privacy claim is about; the client's copy is checked because it is written by
// a different call (acctClientStore.Append in runClientAccounting) and a key that
// had become stable would show up in both.
func TestClientAccountingKeyIsFreshPerSession(t *testing.T) {
	exitDir, clientDir := t.TempDir(), t.TempDir()
	exitEng, err := New(Config{
		Coordinators: []string{testCoord}, Roles: []string{"exit"}, Advertise: "203.0.113.5:20000",
		AcctDir: exitDir,
	})
	if err != nil {
		t.Fatalf("New exit: %v", err)
	}
	defer exitEng.Stop()

	clientEng, err := New(Config{
		Coordinators: []string{testCoord}, Roles: []string{"client"},
		AcctDir: clientDir, AcctIntervalSec: 1,
	})
	if err != nil {
		t.Fatalf("New client: %v", err)
	}
	defer clientEng.Stop()

	// Sequential, not concurrent. Two sessions running at once would prove the same
	// thing, but this ordering also covers the case a cache would most plausibly be
	// introduced for — the SECOND session on an engine that has already minted one.
	first := receiptOverAFreshSession(t, exitEng, clientEng, exitDir, "acct-session-one", 4096)
	second := receiptOverAFreshSession(t, exitEng, clientEng, exitDir, "acct-session-two", 8192)

	for _, r := range []accounting.Receipt{first, second} {
		if err := r.Verify(); err != nil {
			t.Fatalf("receipt for %s does not verify (%v) — a key this test then compares would be "+
				"meaningless", r.SessionID, err)
		}
		if len(r.ClientAcctPub) != ed25519.PublicKeySize {
			t.Fatalf("receipt for %s carries a %d-byte client accounting key", r.SessionID, len(r.ClientAcctPub))
		}
	}

	// The named form of the regression first, so that when it is the one that
	// happened the failure says which mistake it was rather than only that the keys
	// matched. Reusing the device key would trip the general check below too.
	//
	// Engine.deviceKey is the client's on-device entitlement keypair, and it is
	// stable by design — it survives restarts (core/devicestore) and every renewal,
	// which is what lets a device renew rather than re-enrol. Co-signing receipts
	// with it would look like a simplification and would put one identifier,
	// joinable to a device credential, in every receipt on the account-service host.
	if clientEng.deviceKey == nil {
		t.Fatal("this client engine has no device key, so the check below is vacuous — a client role " +
			"always gets one (newEngine, setupDeviceCredential)")
	}
	devicePub := clientEng.deviceKey.Public().(ed25519.PublicKey)
	for _, r := range []accounting.Receipt{first, second} {
		if bytes.Equal(r.ClientAcctPub, devicePub) {
			t.Fatalf("the receipt for %s was co-signed with the DEVICE key. That key is stable across "+
				"sessions and across restarts, and it is the identity the entitlement chain binds, so a "+
				"receipt carrying it hands the account-service host a per-device identifier next to a "+
				"session id and a byte count (bacchus-payment#98 claim 2)", r.SessionID)
		}
	}

	// And the general form: whatever the key is, two sessions must not share it.
	if bytes.Equal(first.ClientAcctPub, second.ClientAcctPub) {
		t.Fatalf("two sessions on one client engine co-signed with the SAME accounting key (%s…).\n\n"+
			"That key sits in every receipt next to a session id and a byte count, and the exit's journal "+
			"of those receipts reaches the account-service host. A key stable across sessions therefore "+
			"turns that journal into a per-client profile — every session a user opened, linked to each "+
			"other — which is exactly what the account model exists to prevent and what the public "+
			"privacy statement says does not happen (bacchus-payment#98 claim 2).\n\n"+
			"The generation site is Engine.startAccounting. If this became deliberate, the payout model's "+
			"\"receipts carry no user identity\" and the privacy statement both have to change, and the "+
			"change is much larger than this test.", hex.EncodeToString(first.ClientAcctPub)[:16])
	}

	// The client's own journal, written by a different call, must show the same two
	// distinct keys and no third one.
	own, err := accounting.LoadReceipts(filepath.Join(clientDir, "receipts-client.jsonl"))
	if err != nil {
		t.Fatalf("LoadReceipts (client journal): %v", err)
	}
	seen := map[string]string{}
	for _, r := range own {
		seen[hex.EncodeToString(r.ClientAcctPub)] = r.SessionID
	}
	if len(own) > 0 && len(seen) != len(own) {
		t.Errorf("the client's own journal holds %d receipts under only %d distinct accounting keys; "+
			"one key covering several sessions is the linkage this test exists to refuse", len(own), len(seen))
	}
}

// TestClientRoleHasNoPersistentAccountingIdentity pins the other half of the same
// property: there is nowhere for a client accounting key to live across sessions.
//
// setupAccounting derives a STABLE accounting key for the exit role only, because an
// exit is the metered party a receipt must be attributable to across sessions. The
// client role gets a store and no key. A client engine whose acctKey were non-nil
// would have a per-engine identity — one signing key for the whole process lifetime,
// which is a lifetime longer than a session by any measure.
func TestClientRoleHasNoPersistentAccountingIdentity(t *testing.T) {
	eng, err := New(Config{
		Coordinators: []string{testCoord}, Roles: []string{"client"},
		AcctDir: t.TempDir(), AcctIntervalSec: 1,
	})
	if err != nil {
		t.Fatalf("New client: %v", err)
	}
	defer eng.Stop()

	if eng.acctClientStore == nil {
		t.Fatal("a client engine with AcctDir set has no receipt store, so this test is not looking at " +
			"an engine that does accounting at all")
	}
	if eng.acctKey != nil {
		t.Errorf("a CLIENT engine holds a stable accounting key. setupAccounting derives one for the exit "+
			"role only, precisely because an exit is the party receipts are attributed to across sessions "+
			"and a client is not. A client-side key that outlives a session is a persistent identifier in "+
			"every receipt it co-signs (bacchus-payment#98 claim 2); got %s…",
			hex.EncodeToString(eng.acctKey.Public().(ed25519.PublicKey))[:16])
	}

	// And the structural form: an Engine field is the only place a signing key could
	// live long enough to outlast a session, so the set of them is worth enumerating.
	//
	// Two are expected, and neither is a client accounting key:
	//
	//	acctKey    the EXIT role's stable accounting identity. Stable on purpose — an
	//	           exit is the metered party receipts are attributed to across
	//	           sessions (accounting.AcctKeyFromSeed). Nil for a client.
	//	deviceKey  the client's on-device entitlement keypair (issue #50/#51). Also
	//	           stable on purpose, and a different disclosure surface with its own
	//	           record: it is presented to the COORDINATOR in a device assertion,
	//	           never put in a receipt, and the coordinator deliberately does not
	//	           log its public half for exactly the linkage reason at issue here.
	//
	// A third field is not automatically wrong. It is a place a stable client identity
	// could come to live, which is a thing to have decided rather than acquired, so
	// this reports rather than pronounces.
	et := reflect.TypeOf((*Engine)(nil)).Elem()
	priv := reflect.TypeOf(ed25519.PrivateKey(nil))
	expected := map[string]bool{"acctKey": true, "deviceKey": true}
	var unexpected []string
	found := map[string]bool{}
	for i := 0; i < et.NumField(); i++ {
		if et.Field(i).Type != priv {
			continue
		}
		found[et.Field(i).Name] = true
		if !expected[et.Field(i).Name] {
			unexpected = append(unexpected, et.Field(i).Name)
		}
	}
	for name := range expected {
		if !found[name] {
			t.Errorf("Engine no longer has an ed25519 field named %q; this test's expectations are stale "+
				"and its silence about the others is worth nothing until they are corrected", name)
		}
	}
	if len(unexpected) > 0 {
		t.Errorf("Engine has ed25519 signing-key fields this test does not account for: %v.\n\n"+
			"Check whether any of them can end up signing an accounting receipt. A client accounting key "+
			"needs somewhere to live to outlast a session, and an Engine field is that somewhere — "+
			"receipts carry whatever key co-signed them to the account-service host, where a value stable "+
			"across sessions is a per-user profile (bacchus-payment#98 claim 2). If the new field is "+
			"unrelated, add it to the expected set above with the reason.", unexpected)
	}
}
