package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/handshake"
	dtls "github.com/pion/dtls/v3"
)

// TestLooksLikeDTLSSeparatesTheTwoShapes is the whole compatibility argument of
// #175 slice 1, reduced to the function that carries it. If this classifier ever
// calls a JSON datagram DTLS, every client on the current build stops being
// served — so the JSON side of the table is every byte a JSON document can begin
// with, not a sample.
func TestLooksLikeDTLSSeparatesTheTwoShapes(t *testing.T) {
	pad := func(b []byte) []byte {
		for len(b) < dtlsRecordHeaderSize {
			b = append(b, 0)
		}
		return b
	}

	// Every DTLS content type, at both record versions this accepts.
	for _, ct := range []byte{20, 21, 22, 23, 25} {
		for _, minor := range []byte{0xff, 0xfd} {
			raw := pad([]byte{ct, 0xfe, minor})
			if !looksLikeDTLS(raw) {
				t.Fatalf("content type %d at version fe%02x must be recognised as DTLS", ct, minor)
			}
		}
	}

	// Everything a JSON value may begin with, per RFC 8259: the structural
	// characters, a string, a number, the three literals, and leading whitespace.
	jsonLeads := []string{
		`{"type":"connect"}`, `{"type":"hello","magic":"bacchus-hello-1"}`,
		`[1,2,3]`, `"a string"`, `12345`, `-1`, `true`, `false`, `null`,
		" {\"type\":\"list\"}", "\t{\"type\":\"list\"}", "\n{\"type\":\"list\"}", "\r{\"type\":\"list\"}",
	}
	for _, s := range jsonLeads {
		if looksLikeDTLS(pad([]byte(s))) {
			t.Fatalf("a JSON datagram beginning %q must NOT be taken for DTLS — "+
				"every client on the current build would stop being served", s[:1])
		}
	}

	// Near misses that must fall through to the JSON path rather than mint an
	// association: a right content type with a TLS (not DTLS) version, a right
	// version with a wrong content type, and a runt.
	for _, bad := range [][]byte{
		pad([]byte{22, 0x03, 0x03}), // TLS 1.2 record version, not DTLS
		pad([]byte{22, 0xfe, 0x00}), // 0xfe followed by neither 0xff nor 0xfd
		pad([]byte{24, 0xfe, 0xfd}), // not a content type this accepts
		{22, 0xfe, 0xfd},            // shorter than a record header
	} {
		if looksLikeDTLS(bad) {
			t.Fatalf("% x must not be classified as DTLS", bad[:3])
		}
	}
}

// signalingPortUnderTest runs the PRODUCTION read loop — servePackets, the same
// function main() calls — on a loopback socket with the DTLS mux installed, and
// returns the address to point a peer at.
func signalingPortUnderTest(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	pc = conn

	mux, err := newRendezvousMux(conn)
	if err != nil {
		t.Fatalf("newRendezvousMux: %v", err)
	}
	rendezvous = mux
	ctx, cancel := context.WithCancel(context.Background())
	go mux.sweepLoop(ctx)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); servePackets(conn) }()
	t.Cleanup(func() {
		cancel()
		conn.Close()
		wg.Wait()
		rendezvous = nil
	})
	return conn.LocalAddr().(*net.UDPAddr)
}

// staleHello is a greeting the coordinator is guaranteed to answer: a bad magic
// draws a "reject" from handle()'s "hello" case, needing no admission anchor, no
// registry state and no key material. It is the smallest complete request/reply
// pair on this wire, which is what makes it the right probe for "did a reply come
// back, and in which shape".
func staleHello() []byte {
	b, _ := json.Marshal(wire{Type: "hello", Magic: "not-bacchus", Version: handshake.ProtocolVersion})
	return b
}

func assertReject(t *testing.T, raw []byte) {
	t.Helper()
	var got wire
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("reply is not JSON (%v): %q", err, raw)
	}
	if got.Type != "reject" {
		t.Fatalf("reply type = %q, want \"reject\"", got.Type)
	}
	if !strings.Contains(got.Reason, "magic") {
		t.Fatalf("reject reason = %q, want it to name the magic", got.Reason)
	}
}

// TestOnePortServesRawJSONAndDTLS is the property slice 1 exists to establish:
// ONE coordinator socket answers a client speaking the cleartext wire it has
// always spoken AND a client speaking DTLS, with no port, flag or address
// difference between them — and it answers each in the shape it was asked in.
//
// The two legs run against the same live listener, and the cleartext leg runs
// AFTER the DTLS one so the association table cannot be what makes it work.
func TestOnePortServesRawJSONAndDTLS(t *testing.T) {
	addr := signalingPortUnderTest(t)

	// --- Leg 1: DTLS. ---
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sock.Close()

	conn, err := dtls.Client(sock, addr, &dtls.Config{
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})
	if err != nil {
		t.Fatalf("dtls.Client: %v", err)
	}
	defer conn.Close()
	hctx, hcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer hcancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		t.Fatalf("the coordinator did not complete a DTLS handshake on its signaling port: %v", err)
	}
	if _, err := conn.Write(staleHello()); err != nil {
		t.Fatalf("write inside DTLS: %v", err)
	}
	buf := make([]byte, 65535)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no reply inside the DTLS association: %v", err)
	}
	assertReject(t, buf[:n])

	// --- Leg 2: raw JSON, same port, same moment. ---
	plain, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer plain.Close()
	if _, err := plain.Write(staleHello()); err != nil {
		t.Fatalf("write cleartext: %v", err)
	}
	_ = plain.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err = plain.Read(buf)
	if err != nil {
		t.Fatalf("a cleartext client got no reply from a DTLS-enabled coordinator: %v", err)
	}
	assertReject(t, buf[:n])
}

// TestTheDTLSReplyIsNotReadableOnTheWire is the point of the whole exercise
// stated as a test. The cleartext leg's reply can be parsed straight off the
// socket; the DTLS leg's cannot, and neither can its request. A DPI box reading
// the literal bytes {"type": off a UDP payload is what #175 is about.
func TestTheDTLSReplyIsNotReadableOnTheWire(t *testing.T) {
	addr := signalingPortUnderTest(t)

	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sock.Close()

	// A sniffing wrapper on the client's own socket sees exactly what a censor
	// on the path sees: the bytes as they leave and arrive.
	sniff := &sniffPC{UDPConn: sock}
	conn, err := dtls.Client(sniff, addr, &dtls.Config{
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	})
	if err != nil {
		t.Fatalf("dtls.Client: %v", err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if _, err := conn.Write(staleHello()); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 65535)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	for _, d := range sniff.seen() {
		if !looksLikeDTLS(d) {
			head := d
			if len(head) > 16 {
				head = head[:16]
			}
			t.Fatalf("a datagram on the wire was not a DTLS record: % x", head)
		}
		for _, tell := range []string{`{"type"`, "reject", "bacchus", "magic"} {
			if strings.Contains(string(d), tell) {
				t.Fatalf("the literal string %q is readable in a rendezvous datagram — "+
					"that is the signature #175 exists to remove", tell)
			}
		}
	}
}

// sniffPC records every datagram crossing a client socket in both directions.
type sniffPC struct {
	*net.UDPConn
	mu    sync.Mutex
	seen_ [][]byte
}

func (s *sniffPC) record(b []byte) {
	c := make([]byte, len(b))
	copy(c, b)
	s.mu.Lock()
	s.seen_ = append(s.seen_, c)
	s.mu.Unlock()
}

func (s *sniffPC) seen() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.seen_...)
}

func (s *sniffPC) WriteTo(b []byte, a net.Addr) (int, error) {
	s.record(b)
	return s.UDPConn.WriteTo(b, a)
}

func (s *sniffPC) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := s.UDPConn.ReadFrom(b)
	if n > 0 {
		s.record(b[:n])
	}
	return n, a, err
}

// TestARealCurrentClientIsStillServed is the compatibility half, demonstrated
// rather than asserted: the REAL core client, unmodified and speaking the
// cleartext wire it ships with today, reads the country list from a coordinator
// that has DTLS switched on. Nothing about the client knows this change happened.
func TestARealCurrentClientIsStillServed(t *testing.T) {
	resetRegistry(t)
	t.Cleanup(func() { resetRegistry(t) })
	addr := signalingPortUnderTest(t)
	registerExitIn(t, "NL")

	eng, _ := newRealClient(t, addr.String(), "")
	got, err := eng.ListCountries(context.Background(), 8*time.Second)
	if err != nil {
		t.Fatalf("a current client could not read the country list from a DTLS-enabled coordinator: %v", err)
	}
	var found bool
	for _, c := range got {
		if c.Country == "NL" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the registered NL exit did not reach a current client: %+v", got)
	}
}

// TestAnAssociationIsOnlyMintedByAHandshake keeps the DoS surface where the
// design put it. A UDP source is spoofable, so a stray application-data or alert
// record from a source with no association must NOT create one: doing so would
// let an attacker mint association state without ever starting a handshake,
// skipping the cookie exchange that is the only reason a spoofed source is cheap
// to refuse.
func TestAnAssociationIsOnlyMintedByAHandshake(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	mux, err := newRendezvousMux(conn)
	if err != nil {
		t.Fatalf("newRendezvousMux: %v", err)
	}

	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 40000}
	appData := make([]byte, dtlsRecordHeaderSize+8)
	appData[0], appData[1], appData[2] = 23, 0xfe, 0xfd // application_data, DTLS 1.2

	if consumed := mux.route(appData, src); !consumed {
		t.Fatal("an application-data record must still be consumed as DTLS, not fall through to the JSON path")
	}
	mux.mu.Lock()
	n := len(mux.assocs)
	mux.mu.Unlock()
	if n != 0 {
		t.Fatalf("a non-handshake record from an unknown source minted %d association(s); "+
			"only a handshake may create state", n)
	}
}

// TestTheAssociationTableIsBounded pins the cap. maxPendingChallenges exists for
// the same reason one layer up, and an unbounded per-source table on a spoofable
// key is memory exhaustion with extra steps.
func TestTheAssociationTableIsBounded(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	mux, err := newRendezvousMux(conn)
	if err != nil {
		t.Fatalf("newRendezvousMux: %v", err)
	}
	mux.capacity = 4

	hello := make([]byte, dtlsRecordHeaderSize+8)
	hello[0], hello[1], hello[2] = 22, 0xfe, 0xfd // handshake, DTLS 1.2
	for i := 0; i < 50; i++ {
		src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, byte(1+i%200)), Port: 40000 + i}
		a, fresh := mux.assocFor(hello, src)
		if fresh && a != nil {
			// Do not start a real handshake goroutine; the table is what is under test.
			continue
		}
	}
	mux.mu.Lock()
	n := len(mux.assocs)
	mux.mu.Unlock()
	if n > 4 {
		t.Fatalf("association table grew to %d past its capacity of 4", n)
	}
	if n != 4 {
		t.Fatalf("association table holds %d, want it filled to its capacity of 4", n)
	}
}

// TestReplyToFallsBackToCleartextWithoutAnAssociation pins send()'s branch. Every
// client on the current build reaches exactly this path, and getting it wrong
// means a coordinator that answers nobody.
func TestReplyToFallsBackToCleartextWithoutAnAssociation(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	mux, err := newRendezvousMux(conn)
	if err != nil {
		t.Fatalf("newRendezvousMux: %v", err)
	}
	src := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 40000}
	if mux.replyTo(src, []byte(`{"type":"reject"}`)) {
		t.Fatal("a peer with no association must fall through to the cleartext reply path")
	}
	// A nil mux is the -rendezvous-dtls=false build and every test that drives
	// handle() directly; it must behave as if nobody is on the new shape.
	var nilMux *rendezvousMux
	if nilMux.replyTo(src, []byte(`{}`)) {
		t.Fatal("a nil mux must never claim a reply")
	}
	if nilMux.route([]byte{22, 0xfe, 0xfd}, src) {
		t.Fatal("a nil mux must never consume a datagram")
	}
}
