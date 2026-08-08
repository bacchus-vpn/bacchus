package core

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
	"github.com/bacchus-vpn/bacchus/core/rendezvous"
)

// The client's own path to a coordinator stops being cleartext (issue #175 slice
// 2, ADR-0062).
//
// Nothing here can prove the change correct, and it is worth saying so at the top
// of the file rather than leaving it to be discovered. Loopback carries anything —
// its MTU is 65536, which is why issue #183's 1453-byte connect passed every test
// in this repository and failed on a real home link — and a loopback socket is not
// a censored network, so no test here can show that the shape helps. What these
// tests CAN do is pin the two things that are decidable from inside: what leaves
// the socket, byte for byte, and that nothing leaves it in the clear.
//
// The rest is the testbed's job. See the needs-owner-test card this lane filed.

// servePeer wraps a loopback socket in the peer half of the shaped hop, so a fake
// coordinator in this package is reachable by a client that speaks it.
//
// Every client-role fake in this package goes through one. That is not a
// convenience: a client with no cleartext fallback cannot talk to a socket that
// answers JSON, so "bind a UDP socket and speak wire" stopped standing in for a
// coordinator the moment ADR-0062 landed, and a fake that still did would be
// testing a client this repository no longer builds.
func servePeer(t *testing.T, pc *net.UDPConn) *rendezvous.Peer {
	t.Helper()
	p, err := rendezvous.Serve(pc)
	if err != nil {
		t.Fatalf("rendezvous.Serve: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// ---------------------------------------------------------------------------
// A logging UDP proxy, which is how issue #183 was found in the first place
// ---------------------------------------------------------------------------

// wireTap is a UDP relay that sits between a client and a coordinator and records
// every datagram in both directions, at full size, before passing it on.
//
// It exists because the two ends are not where the interesting measurement is. A
// path MTU applies to the DATAGRAM, and once the hop is shaped the datagram is a
// DTLS record wrapped around a payload neither end weighs on its own — so a check
// at either end measures its own arithmetic. ADR-0057's own account of #183 names
// this instrument: "a logging UDP proxy between cmd/node -role client and a real
// gated coordinator measured a connect of 1453 bytes". This is that, in a test.
//
// It is deliberately dumb: no parsing, no reordering, no loss. What it knows is how
// many bytes went past and which way.
type wireTap struct {
	front *net.UDPConn // what the client dials
	back  *net.UDPConn // what talks to the coordinator

	mu       sync.Mutex
	outbound [][]byte // client -> coordinator, in order
	inbound  [][]byte // coordinator -> client, in order
}

func newWireTap(t *testing.T, coord string) *wireTap {
	t.Helper()
	upstream, err := net.ResolveUDPAddr("udp", coord)
	if err != nil {
		t.Fatalf("resolve %q: %v", coord, err)
	}
	front, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	back, err := net.DialUDP("udp", nil, upstream)
	if err != nil {
		t.Fatalf("dial %s: %v", upstream, err)
	}
	w := &wireTap{front: front, back: back}
	t.Cleanup(func() { _ = front.Close(); _ = back.Close() })

	var clientMu sync.Mutex
	var client *net.UDPAddr

	go func() { // client -> coordinator
		buf := make([]byte, 65535)
		for {
			n, src, err := front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			clientMu.Lock()
			client = src
			clientMu.Unlock()
			w.record(&w.outbound, buf[:n])
			_, _ = back.Write(buf[:n])
		}
	}()
	go func() { // coordinator -> client
		buf := make([]byte, 65535)
		for {
			n, err := back.Read(buf)
			if err != nil {
				return
			}
			w.record(&w.inbound, buf[:n])
			clientMu.Lock()
			to := client
			clientMu.Unlock()
			if to != nil {
				_, _ = front.WriteToUDP(buf[:n], to)
			}
		}
	}()
	return w
}

func (w *wireTap) record(into *[][]byte, b []byte) {
	c := make([]byte, len(b))
	copy(c, b)
	w.mu.Lock()
	*into = append(*into, c)
	w.mu.Unlock()
}

func (w *wireTap) addr() string { return w.front.LocalAddr().String() }

func (w *wireTap) sent() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.outbound...)
}

// tappedClient builds a client engine that reaches coord through a wireTap, with a
// full device-credential chain and a production-sized admission credential in play
// — the configuration that measured 1453 bytes on the testbed.
func tappedClient(t *testing.T, coord *fakeDeviceCoordinator) (*Engine, *coordLink, *wireTap) {
	t.Helper()
	tap := newWireTap(t, coord.addr())
	eng, link := newTestClientEngine(t, tap.addr())

	now := time.Now()
	_, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour)
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     credEnc,
		IssuerCert: issuerCertEnc,
		Admission:  prodSizedAdmissionCred(t),
	}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}
	return eng, link, tap
}

// largestConnectRequest is the biggest connect this client can assemble: a chained
// relay request with an excluded session and a 64-character first hop.
func largestConnectRequest() connectReq {
	return connectReq{
		mode:    modeRelay,
		exclude: []string{"0123456789abcdef"},
		plan: &chainPlan{hops: []relayHop{
			{id: "3b1f0c9d2e7a4b6c8d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e"},
		}},
	}
}

// ---------------------------------------------------------------------------
// The ruling: no cleartext leaves the client
// ---------------------------------------------------------------------------

// TestNoCleartextRendezvousCanLeaveTheClient is ruling B3 written as an assertion,
// and it is the test this change most needs to exist.
//
// ADR-0059 §4 planned "try DTLS, fall back, remember". It was ruled out: a censor
// dropping the handshake and a coordinator predating slice 1 produce the same
// silence, so the fallback would have sent the plaintext the shape exists to remove
// at exactly the moment it mattered. Removal has to be ASSERTED rather than merely
// done — the discipline ADR-0057 used to pin the datagram size — because a fallback
// is easy to reintroduce as a kindness and impossible to withdraw afterwards with
// no signed release channel (#34).
//
// It measures at the socket, on bytes a real attemptWith wrote, and it looks for
// the signature the whole slice exists to remove: the literal bytes {"type" that a
// DPI box read off a UDP payload to one port.
func TestNoCleartextRendezvousCanLeaveTheClient(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link, tap := tappedClient(t, coord)

	eng.attemptWith(context.Background(), link, largestConnectRequest(), eng.transport, 3*time.Second, nil)

	sent := tap.sent()
	if len(sent) == 0 {
		t.Fatal("the client sent nothing at all, so this proved nothing about what it sends")
	}
	// The exchange has to have got somewhere, or "no cleartext" would be satisfied
	// by a client that never spoke.
	if got := coord.sizesOf("connect"); len(got) == 0 {
		t.Fatal("no connect reached the coordinator — this test only means something if the shaped path WORKS")
	}

	for _, marker := range [][]byte{
		[]byte(`{"type"`),
		[]byte("connect"),
		[]byte("challenge"),
		[]byte("bacchus"),
		[]byte("nonce"),
	} {
		for i, d := range sent {
			if bytes.Contains(d, marker) {
				t.Fatalf("datagram %d of %d that this client put on the wire contains %q in the clear:\n%q\nThis is the signature issue #175 exists to remove, and ADR-0062 rules that there is no path by which it may be sent",
					i+1, len(sent), marker, d)
			}
		}
	}
}

// TestNoCleartextLeavesTheClientWhenTheSHAPEFAILSEITHER is the half of ruling B3
// that the test above cannot reach, and it is the half that matters.
//
// Above, the handshake completes, so a fallback would never be taken and the
// assertion passes whether or not one exists — a mutation reintroducing "try DTLS,
// then write the JSON" survived it. B3 is a rule about what happens when the shape
// does NOT work: that is the only moment a fallback fires, and it is exactly the
// moment a censor has engineered. So this test puts the client in front of a
// coordinator that does not speak the shape — a build predating slice 1, or one run
// with -rendezvous-dtls=false, which is also what a censor dropping the handshake
// looks like — and asserts that the client sends nothing readable and gives up.
func TestNoCleartextLeavesTheClientWhenTheShapeFails(t *testing.T) {
	// A pre-slice-1 coordinator: it reads raw JSON, cannot parse an ICE check or a
	// ClientHello, and answers a datagram it does not understand with nothing. It
	// terminates no DTLS, so this client's handshake can never complete.
	old, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = old.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := old.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var m wire
			if json.Unmarshal(buf[:n], &m) != nil {
				continue // exactly what a pre-#175 coordinator does with these bytes
			}
			// It would happily answer a cleartext connect, which is what makes this
			// the right fixture: if a fallback existed, the exchange would COMPLETE.
			b, _ := json.Marshal(wire{Type: "session", Session: "s1", ExitID: strings.Repeat("ab", 32)})
			_, _ = old.WriteToUDP(b, src)
		}
	}()

	tap := newWireTap(t, old.LocalAddr().String())
	eng, link := newTestClientEngine(t, tap.addr())

	r := eng.attemptWith(context.Background(), link, largestConnectRequest(), eng.transport, 3*time.Second, nil)

	// A connect this client sent in the clear would be ANSWERED by that fixture,
	// which is what makes the outcome load-bearing rather than decorative.
	if r.outcome != coordinatorSilent {
		t.Fatalf("outcome = %v, want coordinatorSilent — a coordinator that does not speak the shaped hop is unreachable to this client, and anything else means a datagram it could read got through", r.outcome)
	}
	sent := tap.sent()
	if len(sent) == 0 {
		t.Fatal("the client sent nothing at all, so this proved nothing")
	}
	for _, marker := range [][]byte{[]byte(`{"type"`), []byte("connect"), []byte("challenge"), []byte("bacchus"), []byte("nonce")} {
		for i, d := range sent {
			if bytes.Contains(d, marker) {
				t.Fatalf("with the shaped handshake unanswered, datagram %d of %d went out containing %q in the clear:\n%q\nThis is the fallback ADR-0062 withdrew: a censor buys the plaintext by dropping two datagrams",
					i+1, len(sent), marker, d)
			}
		}
	}
}

// TestACoordinatorAnsweringInCleartextIsReportedRatherThanIgnored. Under ADR-0062
// such a member is unreachable, which is a fact somebody has to be able to learn
// from something other than a timeout — issue #5's lesson applied to a condition #5
// could not have had.
func TestACoordinatorAnsweringInCleartextIsReportedRatherThanIgnored(t *testing.T) {
	chatty, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = chatty.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := chatty.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// Answers everything in the clear, including the handshake it cannot
			// parse — the shape a coordinator with the feature switched off does not
			// actually produce, but the one this branch has to be able to name.
			_ = n
			b, _ := json.Marshal(wire{Type: "reject", Reason: "this coordinator speaks cleartext only"})
			_, _ = chatty.WriteToUDP(b, src)
		}
	}()

	var mu sync.Mutex
	var msgs []string
	eng, err := New(Config{
		Coordinators: []string{chatty.LocalAddr().String()},
		Roles:        []string{RoleClient},
		OnEvent:      func(ev Event) { mu.Lock(); msgs = append(msgs, ev.Message); mu.Unlock() },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)

	eng.links[0].send(eng, helloWire()) // fails: the handshake is never answered
	eng.links[0].send(eng, helloWire()) // reports what came back in the meantime

	mu.Lock()
	got := strings.Join(msgs, "\n")
	mu.Unlock()
	if !strings.Contains(got, "answered in cleartext") {
		t.Fatalf("a coordinator answering in the clear was dropped without a word — which reads, at the waiting leg, exactly like silence:\n%s", got)
	}
}

// TestEveryDatagramTheClientSendsFitsThePath is issue #183's requirement restated
// where the shaped hop puts it: on the DATAGRAM rather than on the payload.
//
// Once the hop is shaped there are two ways to overflow a 1280-byte path and only
// one of them is a wire field. The other is the record overhead ADR-0059 measured
// at 37 bytes, and neither end weighs the sum on its own — which is why this is
// measured between them. It covers the handshake flights too, which no other check
// in this repository does.
func TestEveryDatagramTheClientSendsFitsThePath(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link, tap := tappedClient(t, coord)

	eng.attemptWith(context.Background(), link, largestConnectRequest(), eng.transport, 3*time.Second, nil)

	sent := tap.sent()
	if len(sent) == 0 {
		t.Fatal("the client sent nothing at all")
	}
	if got := coord.sizesOf("connect"); len(got) == 0 {
		t.Fatal("no connect reached the coordinator, so the largest datagram was never built")
	}
	largest := 0
	for i, d := range sent {
		if len(d) > largest {
			largest = len(d)
		}
		if len(d) > maxRendezvousPayload {
			t.Fatalf("datagram %d of %d is %d bytes, over the %d-byte payload that fits a %d-byte path (it needs a %d-byte IP datagram). This is issue #183 on the shaped hop: delivered on Ethernet, refused on Tailscale, on the IPv6 minimum MTU, and on a clamped mobile link",
				i+1, len(sent), len(d), maxRendezvousPayload, safePathMTU, len(d)+28)
		}
	}
	t.Logf("%d datagrams on the wire, largest %d bytes of a %d-byte budget", len(sent), largest, maxRendezvousPayload)
}

// TestTheShapeIsACheckThenAHandshake pins what the datagrams ARE, not only that
// they are not JSON.
//
// A DTLS ClientHello arriving from nowhere is DTLS-shaped and not WebRTC-shaped,
// and a classifier reads the difference for free: no other traffic on the internet
// begins a DTLS association without a connectivity check on the same 5-tuple. That
// is the whole reason #202 landed the coordinator's answer first, and it is
// undetectable from "the datagram is not cleartext".
func TestTheShapeIsACheckThenAHandshake(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link, tap := tappedClient(t, coord)

	eng.attemptWith(context.Background(), link, largestConnectRequest(), eng.transport, 3*time.Second, nil)

	sent := tap.sent()
	if len(sent) < 2 {
		t.Fatalf("the client put %d datagrams on the wire; a check and a handshake is at least two", len(sent))
	}
	if !isSTUNBindingRequest(sent[0]) {
		t.Fatalf("the FIRST datagram this client sends is not an ICE connectivity check (%d bytes, first byte %#x). A ClientHello arriving from nowhere is DTLS-shaped, not WebRTC-shaped", len(sent[0]), sent[0][0])
	}
	if !rendezvous.LooksLikeDTLS(sent[1]) {
		t.Fatalf("the datagram after the connectivity check is not a DTLS record (%d bytes, first byte %#x)", len(sent[1]), sent[1][0])
	}
	if sent[1][0] != 22 {
		t.Fatalf("the first DTLS record is content type %d, want 22 (handshake) — the check must be followed by a ClientHello, not by application data", sent[1][0])
	}
}

// isSTUNBindingRequest is cmd/coordinator's looksLikeSTUN, restated here over the
// bytes a client emits rather than the ones a coordinator receives: the exact
// method, the magic cookie at bytes 4..8, and a declared length that accounts for
// the whole datagram.
func isSTUNBindingRequest(raw []byte) bool {
	if len(raw) < 20 {
		return false
	}
	return raw[0] == 0x00 && raw[1] == 0x01 &&
		raw[4] == 0x21 && raw[5] == 0x12 && raw[6] == 0xA4 && raw[7] == 0x42 &&
		20+int(raw[2])<<8+int(raw[3]) == len(raw)
}

// TestTheConnectivityCheckIsShapedLikeARealOne. The check is camouflage, so its
// only job is to look like the thing it imitates: a real ICE connectivity check
// carries USERNAME, MESSAGE-INTEGRITY and FINGERPRINT, and a bare Binding Request
// carries none of them and is a distinguisher of its own.
func TestTheConnectivityCheckIsShapedLikeARealOne(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link, tap := tappedClient(t, coord)

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, 3*time.Second, nil)

	sent := tap.sent()
	if len(sent) == 0 || !isSTUNBindingRequest(sent[0]) {
		t.Fatal("no connectivity check was sent")
	}
	// A bare Binding Request is exactly the 20-byte header. Ours carries three
	// attributes, so it is comfortably longer; the attribute types themselves are
	// core/coldstart's to encode and its own tests pin them.
	if len(sent[0]) <= 20 {
		t.Fatalf("the connectivity check is %d bytes — a bare Binding Request with no credential, which is not what an ICE agent emits", len(sent[0]))
	}
	// And it must be answerable by the real coordinator's codec, or the check is
	// shaped like nothing and the coordinator this client dials will ignore it.
	if _, ok := coldstart.BindingResponse(sent[0], netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 9)); !ok {
		t.Fatal("the coordinator's own STUN codec does not recognise this client's connectivity check as a Binding Request")
	}
}

// ---------------------------------------------------------------------------
// The lifecycle: lazy, re-establishable, and it does not dial the whole pool
// ---------------------------------------------------------------------------

// TestDiallingThePoolStillPutsNothingOnTheWire. dialPool's own doc promises that
// dialling every member up front reveals nothing to a censor, because only an
// actual send does and the client controls those through rotation. A handshake at
// dial time would have quietly cost that: a client would hand over its entire
// fallback set at startup.
func TestDiallingThePoolStillPutsNothingOnTheWire(t *testing.T) {
	a := newFakeDeviceCoordinator(t)
	b := newFakeDeviceCoordinator(t)
	tapA := newWireTap(t, a.addr())
	tapB := newWireTap(t, b.addr())

	eng, err := New(Config{Coordinators: []string{tapA.addr(), tapB.addr()}, Roles: []string{RoleClient}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)

	// Long enough that a handshake started at Start would have finished.
	time.Sleep(300 * time.Millisecond)
	if n := len(tapA.sent()) + len(tapB.sent()); n != 0 {
		t.Fatalf("starting a client put %d datagrams on the wire before it rotated anywhere — dialling the pool must reveal nothing", n)
	}

	// One send to one member, and only that member hears anything.
	eng.links[0].send(eng, helloWire())
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(tapA.sent())+len(tapB.sent()) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if len(tapA.sent()) == 0 && len(tapB.sent()) == 0 {
		t.Fatal("a send to one member produced nothing on the wire")
	}
	if len(tapA.sent()) != 0 && len(tapB.sent()) != 0 {
		t.Fatal("a send to one member touched both — a client must not reveal its fallback set")
	}
}

// TestAFailedHandshakeIsReportedAsItselfRatherThanAsSilence. A member this client
// cannot handshake with IS unreachable, so the CONCLUSION is unchanged and rotation
// is still the recovery. What must not happen is the #183 shape: a definite local
// fact presenting as an unexplained timeout, leaving the user to supply the
// diagnosis themselves.
func TestAFailedHandshakeIsReportedAsItselfRatherThanAsSilence(t *testing.T) {
	// A socket nobody reads: the ICE check and the ClientHello are dropped, which
	// is what a censor's silence looks like and also what a coordinator running
	// with -rendezvous-dtls=false produces.
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = dead.Close() })

	var mu sync.Mutex
	var msgs []string
	eng, err := New(Config{
		Coordinators: []string{dead.LocalAddr().String()},
		Roles:        []string{RoleClient},
		OnEvent: func(ev Event) {
			mu.Lock()
			msgs = append(msgs, ev.Message)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)

	eng.links[0].send(eng, helloWire())

	mu.Lock()
	got := strings.Join(msgs, "\n")
	mu.Unlock()
	if !strings.Contains(got, "shaped rendezvous handshake") {
		t.Fatalf("a coordinator that never completed the handshake was not reported as such:\n%s", got)
	}
	for _, want := range []string{"no cleartext fallback", "ADR-0062", "Rotating"} {
		if !strings.Contains(got, want) {
			t.Errorf("the diagnosis does not mention %q — a reader cannot tell why the member is unusable:\n%s", want, got)
		}
	}
}

// TestASecondSendReestablishesAfterTheAssociationDies. A coordinator restart must
// not leave the link permanently dead: the next send starts a fresh handshake.
// Without this the first blip would cost a client that member until it restarted.
//
// BOTH ends are restarted, and that is the finding rather than the fixture. A
// re-handshake on the same 5-tuple is swallowed while the far end still holds the
// old association — its mux finds the source in its table before it looks at the
// record type, so the ClientHello is delivered INTO the conversation it is trying to
// replace. That is why rendezvousAssocIdle is longer than the coordinator's sweep
// rather than shorter, and it is why a client whose own association dies while the
// coordinator's lives rotates away rather than recovering in place. ADR-0062
// records the residual.
func TestASecondSendReestablishesAfterTheAssociationDies(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)
	first := len(coord.sizesOf("connect"))
	if first == 0 {
		t.Fatal("the first attempt reached nothing")
	}

	// The coordinator forgets, as a restart or an idle sweep makes it.
	coord.forget()
	// And the client's own association goes with it, as rendezvousAssocIdle makes it
	// once the far end's window has passed.
	link.shaped.mu.Lock()
	a := link.shaped.cur
	link.shaped.mu.Unlock()
	if a == nil {
		t.Fatal("the link holds no association after a successful attempt")
	}
	link.shaped.drop(a)

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)
	if got := len(coord.sizesOf("connect")); got <= first {
		t.Fatalf("the coordinator saw %d connects after both ends dropped the association and %d before — the link did not re-establish", got, first)
	}
}

// TestASizeRefusalDoesNotCostTheAssociation. EMSGSIZE says something about this
// host's path and nothing about the peer, so retiring the association over one would
// turn a local path limit into a lost coordinator — and, because a re-handshake on
// the same 5-tuple is swallowed while the far end still holds the old association,
// lose it for minutes rather than for a datagram.
//
// It is also the end-to-end proof that the kernel's refusal reaches this client
// through pion at all. It does, measured: the errno arrives intact, which is what
// keeps issue #183's diagnosis alive on the shaped hop.
func TestASizeRefusalDoesNotCostTheAssociation(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)
	before := len(coord.sizesOf("connect"))
	if before == 0 {
		t.Fatal("the first attempt reached nothing")
	}
	link.shaped.mu.Lock()
	assoc := link.shaped.cur
	link.shaped.mu.Unlock()

	mark := link.tooLargeMark()
	r := eng.attemptWith(context.Background(), link,
		connectReq{country: oversizeCountry(t), mode: modeDirect},
		eng.transport, time.Second, nil)
	if r.outcome != requestTooLarge {
		t.Fatalf("outcome = %v, want requestTooLarge — the kernel's size refusal did not survive the DTLS layer, and with it issue #183's whole diagnosis", r.outcome)
	}
	if !link.refusedForSize(mark) {
		t.Fatal("the size refusal was not counted")
	}

	link.shaped.mu.Lock()
	after := link.shaped.cur
	link.shaped.mu.Unlock()
	if after != assoc {
		t.Fatal("a datagram refused for its SIZE cost the association; the member is now unreachable until the far end forgets, over a message that was merely too big")
	}
	// And the link still works, which is the whole point of keeping it.
	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)
	if got := len(coord.sizesOf("connect")); got <= before {
		t.Fatalf("the coordinator saw %d connects after the oversize one and %d before — the link did not survive it", got, before)
	}
}

// TestAStaleAssociationIsReplacedRatherThanWedging is the other half of the same
// finding, and the one that bites without an error to notice.
//
// A rendezvous is a burst and then nothing: greet, list, connect, signal a handshake
// through, and then silence for as long as the session lasts. The coordinator sweeps
// an idle association after two minutes; nothing on the client side errors when it
// does, so the next datagram is a record from a source the coordinator no longer
// knows, which it drops. The send succeeds, the reply never comes, and the member
// reads as blocked forever.
func TestAStaleAssociationIsReplacedRatherThanWedging(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)
	first := len(coord.sizesOf("connect"))
	if first == 0 {
		t.Fatal("the first attempt reached nothing")
	}
	link.shaped.mu.Lock()
	before := link.shaped.cur
	// Age the link past the coordinator's window, which is what a client that
	// connected and then sat idle does.
	link.shaped.lastUsed = time.Now().Add(-rendezvousAssocIdle - time.Second)
	link.shaped.mu.Unlock()
	coord.forget() // the far end swept, which is the whole premise

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)

	link.shaped.mu.Lock()
	after := link.shaped.cur
	link.shaped.mu.Unlock()
	if after == before {
		t.Fatal("a stale association was reused; the coordinator has swept its half by now and drops every record this one sends")
	}
	if got := len(coord.sizesOf("connect")); got <= first {
		t.Fatalf("the coordinator saw %d connects after the association went stale and %d before", got, first)
	}
}

// TestAShapedLinkReportsAgainstTheSmallerBudget. Every message on a shaped link
// travels inside a DTLS record, so the budget that applies to it is 37 bytes
// smaller — and a warning that quoted the larger one would be silent for exactly
// the 37 bytes this slice spent.
func TestAShapedLinkReportsAgainstTheSmallerBudget(t *testing.T) {
	if maxShapedRendezvousPayload != maxRendezvousPayload-dtlsRecordOverhead {
		t.Fatalf("maxShapedRendezvousPayload = %d, want %d", maxShapedRendezvousPayload, maxRendezvousPayload-dtlsRecordOverhead)
	}
	plain := &coordLink{raw: "198.51.100.7:8080"}
	if got := plain.budget(); got != maxRendezvousPayload {
		t.Fatalf("a cleartext link's budget is %d, want %d", got, maxRendezvousPayload)
	}

	coord := newFakeDeviceCoordinator(t)
	_, link := newTestClientEngine(t, coord.addr())
	if link.shaped == nil {
		t.Fatal("a client's link is not shaped")
	}
	if got := link.budget(); got != maxShapedRendezvousPayload {
		t.Fatalf("a shaped link's budget is %d, want %d", got, maxShapedRendezvousPayload)
	}

	// And the warning fires on a datagram that is inside the plain budget and over
	// the shaped one — the 37-byte band this test exists for.
	eng, events := eventSink(t)
	link.noteOversize(eng, "connect", maxRendezvousPayload-1)
	got := events()
	if len(got) != 1 {
		t.Fatalf("emitted %d events for a payload inside the plain budget and over the shaped one, want 1: %v", len(got), got)
	}
	if !strings.Contains(got[0], "1195") || !strings.Contains(got[0], "DTLS record") {
		t.Errorf("the warning does not name the shaped budget or why it is smaller:\n%s", got[0])
	}
}

// TestAForwardersLinksAreNotShaped pins the scope line ADR-0062 draws. Slice 2 is
// the client half: a relay or exit's register wire is a different case from a
// censored user's first packet, and shaping both in one wave would double the blast
// radius of a change no test here can prove correct. If that changes, it should
// change deliberately and this test is where it says so.
func TestAForwardersLinksAreNotShaped(t *testing.T) {
	coord := fakeCoordinator(t)
	eng, err := New(Config{Coordinators: []string{coord.LocalAddr().String()}, Roles: []string{"relay"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)
	if eng.links[0].shaped != nil {
		t.Fatal("a pure forwarder's coordinator link is shaped; slice 2 is the client half — see ADR-0062's residual")
	}
}

// TestAClientThatAlsoForwardsIsShaped is the other side of that line, and it is not
// symmetric with it. ADR-0053 lets a routed machine serve, so one engine can hold
// both roles on one link — and a link cannot be half shaped. The client role wins,
// which puts the register inside the association too; the coordinator handles that
// without a branch, because handle() never learned which shape a peer arrived in.
func TestAClientThatAlsoForwardsIsShaped(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, err := New(Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{RoleClient, "relay"},
		SocksAddr:    "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)

	if eng.links[0].shaped == nil {
		t.Fatal("an engine with the client role has an unshaped link")
	}
	// The register a forwarder broadcasts at Start must arrive, inside the
	// association, decrypted, and be readable as a register.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, regs := coord.creds(); len(regs) > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no register arrived through the shaped link")
}

// TestStopDuringAHandshakeDoesNotWedge. The handshake blocks a send for up to
// rendezvousHandshakeTimeout, and Stop waits on the goroutines that send. Without
// the association's teardown cancelling the handshake, stopping a client pointed at
// a black hole would take five seconds.
func TestStopDuringAHandshakeDoesNotWedge(t *testing.T) {
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = dead.Close() })

	eng, err := New(Config{Coordinators: []string{dead.LocalAddr().String()}, Roles: []string{RoleClient}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	sending := make(chan struct{})
	go func() { close(sending); eng.links[0].send(eng, helloWire()) }()
	<-sending
	time.Sleep(100 * time.Millisecond) // let the handshake get going

	done := make(chan struct{})
	go func() { eng.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Stop did not return within 2s while a handshake was in flight; the handshake timeout is %s", rendezvousHandshakeTimeout)
	}
}

// TestTheDecryptedMessagesAreTheSameWire is the join between the two halves: what
// the client puts inside the association is exactly what a coordinator reads out of
// it, field for field. Encryption that quietly reshaped a message would be caught
// nowhere else, because both ends would agree with themselves.
func TestTheDecryptedMessagesAreTheSameWire(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link, _ := tappedClient(t, coord)

	eng.attemptWith(context.Background(), link, largestConnectRequest(), eng.transport, 3*time.Second, nil)

	_, connects := coord.snapshot()
	if len(connects) == 0 {
		t.Fatal("no connect arrived")
	}
	c := connects[0]
	if c.Type != "connect" || c.Mode != modeRelay || c.Nonce == "" {
		t.Fatalf("the decrypted connect is not the one that was sent: %+v", c)
	}
	if c.Challenge == "" || c.DeviceCred == "" || c.DeviceAssert == "" {
		t.Fatalf("the decrypted connect lost a device-credential field: %+v", c)
	}
	if c.IssuerCert != "" {
		t.Fatalf("the decrypted connect carries an issuer cert; it rides the challenge (issue #206)")
	}
	// And it round-trips: re-marshalling the decrypted struct reproduces something
	// the same size, so nothing was truncated on the way through.
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if sizes := coord.sizesOf("connect"); len(sizes) > 0 && len(b) != sizes[0] {
		t.Fatalf("the decrypted connect re-marshals to %d bytes but arrived as %d", len(b), sizes[0])
	}
}
