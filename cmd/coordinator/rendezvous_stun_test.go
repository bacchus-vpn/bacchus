package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/stun/v3"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// bindingRequest builds a bare Binding Request — reflexive-address gathering,
// the smallest thing a STUN server is ever asked.
func bindingRequest(t *testing.T) *stun.Message {
	t.Helper()
	m, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		t.Fatalf("build binding request: %v", err)
	}
	return m
}

// iceConnectivityCheck builds the shape this feature actually exists to answer:
// a Binding Request carrying the attributes an ICE agent puts on a connectivity
// check, including a MESSAGE-INTEGRITY this coordinator has no key to verify.
func iceConnectivityCheck(t *testing.T) *stun.Message {
	t.Helper()
	m, err := stun.Build(
		stun.TransactionID,
		stun.BindingRequest,
		stun.NewUsername("bacchus:remote"),
		stun.NewShortTermIntegrity("a-pwd-the-coordinator-does-not-have"),
		stun.Fingerprint,
	)
	if err != nil {
		t.Fatalf("build connectivity check: %v", err)
	}
	return m
}

// TestLooksLikeSTUNIsDisjointFromTheOtherTwoShapes is the classification
// argument of #202 reduced to the two functions that carry it, and it runs in
// BOTH directions because a one-way check would not establish the property.
//
// A misclassification here is not cosmetic. Calling a DTLS record STUN would
// answer a handshake flight with a Binding Response and break every client on
// the shaped hop; calling a STUN check DTLS would mint an association from a
// datagram that never starts a handshake, which is exactly the state
// assocFor refuses to create.
func TestLooksLikeSTUNIsDisjointFromTheOtherTwoShapes(t *testing.T) {
	// Every DTLS ContentType the mux accepts, as a minimal record. All of them
	// have their two high bits clear, which is why the magic cookie and not the
	// first byte is what separates the shapes.
	for _, ct := range []byte{20, 21, 22, 23, 25} {
		rec := make([]byte, dtlsRecordHeaderSize)
		rec[0], rec[1], rec[2] = ct, 0xfe, 0xfd
		if looksLikeSTUN(rec) {
			t.Fatalf("DTLS record type %d classified as STUN", ct)
		}
		if !looksLikeDTLS(rec) {
			t.Fatalf("DTLS record type %d stopped being DTLS", ct)
		}
	}

	// A padded DTLS record whose epoch/sequence bytes are attacker-chosen still
	// must not reach the STUN responder. Bytes 4..8 are where the cookie would
	// be; write the cookie there deliberately and the method check refuses it.
	hostile := make([]byte, 32)
	hostile[0], hostile[1], hostile[2] = 22, 0xfe, 0xfd
	binary.BigEndian.PutUint32(hostile[4:8], stunMagicCookie)
	if looksLikeSTUN(hostile) {
		t.Fatal("a DTLS record carrying the cookie in its sequence bytes was classified as STUN")
	}

	// Both real STUN shapes are STUN, and neither is DTLS.
	for name, m := range map[string]*stun.Message{
		"bare binding request":   bindingRequest(t),
		"ice connectivity check": iceConnectivityCheck(t),
	} {
		if !looksLikeSTUN(m.Raw) {
			t.Fatalf("%s was not classified as STUN", name)
		}
		if looksLikeDTLS(m.Raw) {
			t.Fatalf("%s was classified as DTLS", name)
		}
	}

	// Everything a JSON document can begin with stays JSON.
	for _, b := range []byte{'{', '[', '"', '-', 't', 'f', 'n', '0', '9', ' ', '\t', '\r', '\n'} {
		raw := make([]byte, stunHeaderSize)
		raw[0] = b
		if looksLikeSTUN(raw) {
			t.Fatalf("JSON opener %q classified as STUN", b)
		}
	}

	// The narrowing checks, one at a time, each starting from a valid request.
	valid := bindingRequest(t).Raw
	if !looksLikeSTUN(valid) {
		t.Fatal("the control case is not classified as STUN")
	}
	t.Run("short", func(t *testing.T) {
		if looksLikeSTUN(valid[:stunHeaderSize-1]) {
			t.Fatal("a truncated header was classified as STUN")
		}
	})
	t.Run("wrong cookie", func(t *testing.T) {
		bad := bytes.Clone(valid)
		binary.BigEndian.PutUint32(bad[4:8], stunMagicCookie+1)
		if looksLikeSTUN(bad) {
			t.Fatal("a bad magic cookie was classified as STUN")
		}
	})
	t.Run("wrong method", func(t *testing.T) {
		for _, typ := range []stun.MessageType{
			stun.BindingSuccess,
			stun.NewType(stun.MethodAllocate, stun.ClassRequest),
			stun.NewType(stun.MethodRefresh, stun.ClassRequest),
		} {
			bad := bytes.Clone(valid)
			binary.BigEndian.PutUint16(bad[0:2], typ.Value())
			if looksLikeSTUN(bad) {
				t.Fatalf("method %s was classified as STUN", typ)
			}
		}
	})
	t.Run("length does not account for the datagram", func(t *testing.T) {
		if looksLikeSTUN(append(bytes.Clone(valid), 0)) {
			t.Fatal("a trailing byte past the declared length was classified as STUN")
		}
		bad := bytes.Clone(valid)
		binary.BigEndian.PutUint16(bad[2:4], 4) // claims attributes that are not there
		if looksLikeSTUN(bad) {
			t.Fatal("a declared length longer than the datagram was classified as STUN")
		}
	})
}

// TestTheSTUNReplyIsByteIdenticalToWhatTheTURNPortSends is the blend claim of
// ADR-0060, tested rather than asserted.
//
// The whole argument for answering openly is that the signaling port then looks
// like the generic STUN infrastructure it sits among — and this coordinator
// already runs a real one on -turn-addr. If the two ports on one host answered
// the same question with differently-shaped bytes, that difference would itself
// be the distinguisher the feature exists to remove. The expected value here is
// built the way pion/turn's handleBindingRequest builds it: XOR-MAPPED-ADDRESS
// then Fingerprint, over the request's transaction ID.
func TestTheSTUNReplyIsByteIdenticalToWhatTheTURNPortSends(t *testing.T) {
	req := bindingRequest(t)
	from := netip.MustParseAddrPort("203.0.113.7:51820")

	got, ok := coldstart.BindingResponse(req.Raw, from)
	if !ok {
		t.Fatal("BindingResponse refused a bare Binding Request")
	}

	want, err := stun.Build(
		&stun.Message{TransactionID: req.TransactionID},
		stun.BindingSuccess,
		&stun.XORMappedAddress{IP: net.IP(from.Addr().AsSlice()), Port: int(from.Port())},
		stun.Fingerprint,
	)
	if err != nil {
		t.Fatalf("build reference response: %v", err)
	}
	if !bytes.Equal(got, want.Raw) {
		t.Fatalf("reply differs from what pion/turn would send:\n got %x\nwant %x", got, want.Raw)
	}

	// And it decodes as a real client would read it.
	m := &stun.Message{Raw: bytes.Clone(got)}
	if err := m.Decode(); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := stun.Fingerprint.Check(m); err != nil {
		t.Fatalf("FINGERPRINT does not verify: %v", err)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(m); err != nil {
		t.Fatalf("XOR-MAPPED-ADDRESS: %v", err)
	}
	if !xor.IP.Equal(net.ParseIP("203.0.113.7")) || xor.Port != 51820 {
		t.Fatalf("XOR-MAPPED-ADDRESS = %s:%d, want 203.0.113.7:51820", xor.IP, xor.Port)
	}
}

// TestAnIPv4PeerGetsTheIPv4AddressFamily guards a mistake that would be invisible
// in any test using a v6 or a string-compared address: net.UDPAddr.AddrPort
// hands back an IPv4 peer as a 4-in-6 MAPPED address, whose Is4 is false. Encode
// that without unmapping and a v4 client receives the 20-byte v6 form of
// XOR-MAPPED-ADDRESS — still parseable, and something no real STUN server has
// ever sent, which is precisely the kind of tell this feature exists to avoid.
func TestAnIPv4PeerGetsTheIPv4AddressFamily(t *testing.T) {
	mapped := netip.AddrPortFrom(netip.MustParseAddr("::ffff:198.51.100.9"), 4444)
	if mapped.Addr().Is4() {
		t.Fatal("premise broken: the mapped address already reports Is4")
	}

	resp, ok := coldstart.BindingResponse(bindingRequest(t).Raw, netip.AddrPortFrom(mapped.Addr().Unmap(), mapped.Port()))
	if !ok {
		t.Fatal("BindingResponse refused the request")
	}
	// XOR-MAPPED-ADDRESS is the first attribute: type(2) len(2) then the value,
	// whose second byte is the family — 0x01 IPv4, 0x02 IPv6.
	if family := resp[stunHeaderSize+5]; family != 0x01 {
		t.Fatalf("address family = 0x%02x, want 0x01 (IPv4)", family)
	}
	if attrLen := binary.BigEndian.Uint16(resp[stunHeaderSize+2 : stunHeaderSize+4]); attrLen != 8 {
		t.Fatalf("XOR-MAPPED-ADDRESS value length = %d, want 8 (the IPv4 form)", attrLen)
	}
}

// TestAV4PeerOnAWildcardSocketGetsTheV4Form is the only test in this package
// that can see whether answerSTUN unmaps, and it exists because every other one
// binds 127.0.0.1 explicitly and therefore cannot.
//
// Production binds the signaling socket to a WILDCARD (-addr :8080), which is
// dual-stack. ReadFromUDP then reports a v4 peer as a 16-byte 4-in-6 MAPPED
// address whose Is4 is false — asserted as the premise below rather than assumed
// — and encoding that without unmapping sends a v4 client the 20-byte IPv6 form
// of XOR-MAPPED-ADDRESS. It still parses, so nothing breaks and no other
// assertion notices; it is simply a shape no real STUN server emits, which is
// exactly the kind of tell #202 exists to remove. A socket bound to 127.0.0.1
// hands back a 4-byte IP and makes the whole bug invisible.
func TestAV4PeerOnAWildcardSocketGetsTheV4Form(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0}) // wildcard, as production binds
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	mux, err := newRendezvousMux(conn)
	if err != nil {
		t.Fatalf("newRendezvousMux: %v", err)
	}

	peer, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: conn.LocalAddr().(*net.UDPAddr).Port,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer peer.Close()
	if _, err := peer.Write(bindingRequest(t).Raw); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1500)
	n, src, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if src.AddrPort().Addr().Is4() {
		t.Skip("this platform's wildcard bind is not dual-stack, so the mapping this test guards cannot arise here")
	}

	if !mux.answerSTUN(buf[:n], src) {
		t.Fatal("answerSTUN did not consume a Binding Request")
	}
	if err := peer.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	rn, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	if family := buf[stunHeaderSize+5]; family != 0x01 {
		t.Fatalf("a v4 peer on a dual-stack socket got address family 0x%02x, want 0x01 — answerSTUN is not unmapping", family)
	}
	if rn != 40 {
		t.Fatalf("reply is %d bytes, want 40 (the IPv4 form)", rn)
	}
}

// TestTheReflectionFactorIsWhatTheADRClaims pins the numbers ADR-0060 accepts the
// exposure on. They are the entire quantitative basis for choosing the open
// responder over the padded one, so if an attribute is ever added to the reply
// the ADR has to be re-argued rather than silently outgrown.
func TestTheReflectionFactorIsWhatTheADRClaims(t *testing.T) {
	req := bindingRequest(t).Raw
	if len(req) != 20 {
		t.Fatalf("a bare Binding Request is %d bytes, want 20", len(req))
	}
	for _, tc := range []struct {
		name string
		from netip.AddrPort
		want int
	}{
		{"IPv4", netip.MustParseAddrPort("203.0.113.7:51820"), 40},
		{"IPv6", netip.MustParseAddrPort("[2001:db8::1]:51820"), 52},
	} {
		resp, ok := coldstart.BindingResponse(req, tc.from)
		if !ok {
			t.Fatalf("%s: BindingResponse refused the request", tc.name)
		}
		if len(resp) != tc.want {
			t.Fatalf("%s: reply is %d bytes, want %d — ADR-0060's amplification figure is now wrong",
				tc.name, len(resp), tc.want)
		}
	}
}

// TestTheSignalingPortAnswersAConnectivityCheckAndStillServesJSON runs the
// PRODUCTION read loop and establishes the property #202 is for: one socket now
// carries three shapes. The JSON leg runs last and deliberately — it is the
// compatibility half, and it must survive a STUN exchange having happened first.
func TestTheSignalingPortAnswersAConnectivityCheckAndStillServesJSON(t *testing.T) {
	addr := signalingPortUnderTest(t)

	peer, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer peer.Close()
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}

	check := iceConnectivityCheck(t)
	if _, err := peer.Write(check.Raw); err != nil {
		t.Fatalf("write connectivity check: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("no answer to the connectivity check: %v", err)
	}

	resp := &stun.Message{Raw: bytes.Clone(buf[:n])}
	if err := resp.Decode(); err != nil {
		t.Fatalf("reply is not STUN (%v): %x", err, buf[:n])
	}
	if resp.Type != stun.BindingSuccess {
		t.Fatalf("reply type = %s, want %s", resp.Type, stun.BindingSuccess)
	}
	if resp.TransactionID != check.TransactionID {
		t.Fatal("reply carries a different transaction ID")
	}
	if err := stun.Fingerprint.Check(resp); err != nil {
		t.Fatalf("FINGERPRINT does not verify: %v", err)
	}
	// The reflexive address must be the port we actually sent from — the one
	// thing a connectivity check is asking.
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		t.Fatalf("XOR-MAPPED-ADDRESS: %v", err)
	}
	local := peer.LocalAddr().(*net.UDPAddr)
	if xor.Port != local.Port {
		t.Fatalf("reflexive port = %d, want %d", xor.Port, local.Port)
	}
	// The family has to be read off the WIRE, not off the decoded value: pion
	// decodes the v6 form of a 4-in-6 address into an IP that still answers To4,
	// so a missing Unmap in answerSTUN is invisible to every check above. This is
	// the only assertion in the file that covers it, because it is the only one
	// that goes through a real UDPAddr.
	if family := buf[stunHeaderSize+5]; family != 0x01 {
		t.Fatalf("a v4 peer got address family 0x%02x on the wire, want 0x01 — answerSTUN is not unmapping", family)
	}

	// The cleartext wire still works, on the same socket, after all that.
	if _, err := peer.Write(staleHello()); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	n, err = peer.Read(buf)
	if err != nil {
		t.Fatalf("no answer to the JSON hello: %v", err)
	}
	assertReject(t, buf[:n])
}

// TestTheSignalingPortIsNotATURNServer keeps the new reply path to exactly one
// method. A coordinator that answered Allocate would be advertising relay
// capacity it does not have on that port, and would draw a class of traffic the
// signaling socket has no handler for.
func TestTheSignalingPortIsNotATURNServer(t *testing.T) {
	addr := signalingPortUnderTest(t)

	peer, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer peer.Close()

	alloc, err := stun.Build(stun.TransactionID, stun.NewType(stun.MethodAllocate, stun.ClassRequest))
	if err != nil {
		t.Fatalf("build allocate: %v", err)
	}
	if _, err := peer.Write(alloc.Raw); err != nil {
		t.Fatalf("write allocate: %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if n, err := peer.Read(make([]byte, 1500)); err == nil {
		t.Fatalf("an Allocate drew a %d-byte reply; this port must answer only Binding Requests", n)
	}
}

// TestSTUNIsSilentWhenTheShapedHopIsOff — an operator who has not enabled the
// shaped rendezvous must not acquire a new unauthenticated reply path. The mux
// is nil in that configuration, and nil is the whole switch.
func TestSTUNIsSilentWhenTheShapedHopIsOff(t *testing.T) {
	var off *rendezvousMux
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	if off.answerSTUN(bindingRequest(t).Raw, src) {
		t.Fatal("a nil mux answered a Binding Request")
	}
	if off.answerSTUN(nil, src) {
		t.Fatal("a nil mux consumed a nil datagram")
	}
}
