package core

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/flynn/noise"
)

// Peer-relay data-plane transparency (issue #17, ADR-0033). Unlike
// core/e2e_test.go's TestE2ERelayIsBlind and exit_admission_test.go's
// TestE2EHostileExitRejectedThroughRelay — which stand in a hand-rolled io.Copy
// for the relay — these drive the *actual* forwarder splice, e.relayPipe, dialing
// a real exit TCP ingress exactly as a Bacchus relay node does when the
// coordinator assigns it a peer-relay session. That is what #17 ships, so the
// invariant it must preserve is proven against the shipped code: the Noise_NK
// channel (and the exit's admission credential riding inside it, #60/#69)
// terminates at the exit through the hop, and the relay stays blind.

// pipeStream adapts one end of a net.Pipe to the Stream interface, standing in
// for the transport stream a relay accepts from the client. relayPipe reads and
// writes it verbatim; the label is inert to the splice (it never looks inside).
type pipeStream struct {
	net.Conn
	label string
}

func (p pipeStream) Label() string { return p.label }

// startExitIngress binds a loopback TCP listener standing in for an exit's
// serveExit ingress (what a relay dials) and answers exactly one connection with
// the Noise_NK responder, presenting cred. It reports the exit's read of the
// client's target + payload (and echoes one byte back) over done, so the caller
// can assert the end-to-end channel terminated correctly through the relay. The
// listener address is returned for relayPipe to dial.
func startExitIngress(t *testing.T, key noise.DHKey, cred []byte, wantTarget, wantPayload string, done chan<- error) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("exit ingress listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		nc, tgt, err := exitHandshake(conn, key, cred)
		if err != nil {
			done <- err
			return
		}
		if tgt != wantTarget {
			done <- fmt.Errorf("exit target = %q, want %q", tgt, wantTarget)
			return
		}
		buf := make([]byte, len(wantPayload))
		if _, err := io.ReadFull(nc, buf); err != nil {
			done <- err
			return
		}
		if string(buf) != wantPayload {
			done <- fmt.Errorf("exit payload = %q, want %q", buf, wantPayload)
			return
		}
		_, err = nc.Write([]byte("k")) // return-path ack, proving the reverse splice too
		done <- err
	}()
	return ln.Addr().String()
}

// TestPeerRelaySplicePreservesE2E is the #17 invariant: a client reaches an exit
// through the real relayPipe splice, and the end-to-end Noise channel — target,
// payload, and the exit's admission credential (#60) — terminates at the exit
// exactly as in the direct case. The client verifies the *exit's* credential
// end-to-end and routes, oblivious to the relay hop.
func TestPeerRelaySplicePreservesE2E(t *testing.T) {
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	exitID := hex.EncodeToString(key.Public)
	cred := issueExitCred(t, rootPriv, exitID, []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour))

	const target = "example.com:443"
	const payload = "PEER_RELAY_E2E_PAYLOAD_1234567890"

	exitDone := make(chan error, 1)
	exitAddr := startExitIngress(t, key, cred, target, payload, exitDone)

	// The client<->relay hop, as a transport Stream; relayPipe splices it to the
	// exit's TCP ingress — the exact shape of an assigned peer-relay session.
	clientConn, relayEnd := net.Pipe()
	deadline(t, clientConn, relayEnd)
	var relay Engine // relayPipe uses no engine state (see its doc)
	// nil pace: this test is about transparency, not shaping, and must stay that way
	// — it is the regression barrier issue #74's relay-side pacing is checked against
	// (a nil *Limiter is inert, so the splice is byte-for-byte what it was).
	go relay.relayPipe(pipeStream{Conn: relayEnd, label: e2eLabel}, nil, exitAddr)

	nc, err := clientHandshake(clientConn, key.Public, target, verifierBoundTo(rootPub, key.Public))
	if err != nil {
		t.Fatalf("client rejected an admission-authorized exit through the peer relay: %v", err)
	}
	defer nc.Close()
	if _, err := nc.Write([]byte(payload)); err != nil {
		t.Fatalf("write through relay: %v", err)
	}
	ack := make([]byte, 1)
	if _, err := io.ReadFull(nc, ack); err != nil {
		t.Fatalf("read return-path ack through relay: %v", err)
	}
	if err := <-exitDone; err != nil {
		t.Fatalf("exit side (through the real relayPipe splice): %v", err)
	}
}

// TestPeerRelaySpliceRejectsUnauthorizedExitE2E is the security half of the
// invariant: the relay hop must not weaken #60/#69. An exit reached through the
// real relayPipe splice that presents no valid admission credential is rejected
// by the client before any traffic flows — the relay cannot vouch for the exit,
// because the credential is verified end-to-end inside the Noise channel the
// relay only forwards.
func TestPeerRelaySpliceRejectsUnauthorizedExitE2E(t *testing.T) {
	// The client trusts rootPub; the exit's credential below is signed by a
	// different (rogue) root, so the anchor rejects it.
	rootPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key, err := generateExitKey()
	if err != nil {
		t.Fatalf("generateExitKey: %v", err)
	}
	exitID := hex.EncodeToString(key.Public)

	// The exit still completes Noise_NK (it holds its own key), so only the
	// end-to-end admission check stands between the client and a hostile exit
	// vouched for through the relay.
	_, rogueRoot, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rogueCred := issueExitCred(t, rogueRoot, exitID, []admission.Role{admission.RoleExit}, admissionNow.Add(-time.Hour), admissionNow.Add(time.Hour))

	exitDone := make(chan error, 1)
	// wantTarget/wantPayload are unreachable here (the client aborts first); the
	// exit goroutine just needs somewhere to send its (ignored) handshake result.
	exitAddr := startExitIngress(t, key, rogueCred, "example.com:443", "unused", exitDone)

	clientConn, relayEnd := net.Pipe()
	deadline(t, clientConn, relayEnd)
	var relay Engine
	go relay.relayPipe(pipeStream{Conn: relayEnd, label: e2eLabel}, nil, exitAddr)

	nc, err := clientHandshake(clientConn, key.Public, "example.com:443", verifierBoundTo(rootPub, key.Public))
	_ = clientConn.Close() // unblock the splice + exit goroutine
	if err == nil {
		_ = nc.Close()
		t.Fatal("client accepted an exit with no valid credential through the peer-relay splice; want abort")
	}
	<-exitDone // drain so the goroutine can't outlive the test
}

// ---------------------------------------------------------------------------
// Relay-side tier shaping (issue #74, ADR-0048 §5).
// ---------------------------------------------------------------------------

// blastingUpstream binds a loopback TCP listener that answers one connection by
// writing n bytes as fast as it can, then closing. It stands in for whatever the
// relay splices to — relayPipe forwards ciphertext blindly and never completes a
// handshake of its own, so a bare listener is indistinguishable from a real exit
// as far as the splice is concerned. What is under test is the PACING of that
// splice, which is why these tests deliberately do not build a Noise channel.
func blastingUpstream(t *testing.T, n int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(make([]byte, n))
	}()
	return ln.Addr().String()
}

// TestPeerRelaySpliceShapesToTheTierCap is issue #74's ruling actually DENYING
// throughput, which is the bar #58 set for the exit's own cap: a tier system whose
// tests have never been seen to deny anything is not testing enforcement.
//
// It drives handlerFor rather than relayPipe directly, so it covers the production
// wiring end to end — the assign's cap becoming a limiter (handlerFor's ExitAddr
// branch) and that limiter reaching both copies (relayPipe). A mutation in either
// one goes red here.
//
// The bucket starts full at burstBytes, so the assertion is on the bytes BEYOND the
// burst: at 512 kbit/s (64 KB/s) a 64 KB overshoot cannot cross in under a second
// however fast the machine is, because a token bucket's rate is not a property of
// the hardware.
//
// MUTATION: drop sessionPace from handlerFor's ExitAddr branch, or the
// pace.LimitReads wraps from relayPipe's copies, and this goes red — the transfer
// completes immediately.
func TestPeerRelaySpliceShapesToTheTierCap(t *testing.T) {
	const capBps = 512_000     // 64 KB/s
	const payload = 128 * 1024 // two bursts' worth
	const wantAtLeast = 900 * time.Millisecond

	upstream := blastingUpstream(t, payload)
	clientConn, relayEnd := net.Pipe()
	deadline(t, clientConn, relayEnd)

	e := &Engine{limiterCtx: context.Background()}
	handle := e.handlerFor(wire{Type: "assign", Session: "s1", ExitAddr: upstream, SessionCapBps: capBps})
	go handle(pipeStream{Conn: relayEnd, label: e2eLabel})

	start := time.Now()
	n, err := io.ReadFull(clientConn, make([]byte, payload))
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("read %d of %d bytes through the shaped splice: %v", n, payload, err)
	}
	if elapsed < wantAtLeast {
		t.Errorf("%d bytes crossed a %d bps relay cap in %s; want at least %s — a peer-relayed session is NOT shaped to its tier",
			payload, capBps, elapsed.Truncate(time.Millisecond), wantAtLeast)
	}
}

// TestUncappedPeerRelaySpliceIsNotShaped is the control for the test above, and the
// regression guard for every relay assign that carries no cap — an unpoliced
// coordinator's, and any coordinator predating #58. A CHAINED connect is no longer
// one of them: issue #84 stamps the tier's cap at the chain's head like any other
// relayed session (cmd/coordinator's
// TestChainedPeerRelayAssignCarriesTheSessionCap). Without this control the timing
// assertion above could be satisfied by any accidental stall and would keep passing
// while proving nothing about the cap.
func TestUncappedPeerRelaySpliceIsNotShaped(t *testing.T) {
	const payload = 128 * 1024

	upstream := blastingUpstream(t, payload)
	clientConn, relayEnd := net.Pipe()
	deadline(t, clientConn, relayEnd)

	e := &Engine{limiterCtx: context.Background()}
	handle := e.handlerFor(wire{Type: "assign", Session: "s1", ExitAddr: upstream})
	go handle(pipeStream{Conn: relayEnd, label: e2eLabel})

	start := time.Now()
	if _, err := io.ReadFull(clientConn, make([]byte, payload)); err != nil {
		t.Fatalf("ReadFull through the unshaped splice: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("an UNCAPPED peer relay took %s to move %d bytes — a relay assign carrying no cap is being shaped anyway", elapsed, payload)
	}
}
