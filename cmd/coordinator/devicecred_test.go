package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// Connect-time device-credential verification at the coordinator (issue #50,
// ADR-0045). core/devicecred owns the cryptographic decisions and is tested
// against frozen conformance vectors; these tests cover the WIRING — that the gate
// is consulted on the connect path at all, that the challenge it issues is the one
// it demands back, and that a refusal stops the connect rather than merely logging.

// signObj builds body || sig, where sig covers tag || 0x00 || body — the framing
// every signed object in this chain uses.
func signObj(t *testing.T, priv ed25519.PrivateKey, tag string, v any) []byte {
	t.Helper()
	body, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	msg := append(append([]byte(tag), 0x00), body...)
	return append(body, ed25519.Sign(priv, msg)...)
}

// testChain is a locally minted root -> issuer cert -> device credential chain.
type testChain struct {
	rootPub    ed25519.PublicKey
	issuerCert string
	deviceCred string
	devPriv    ed25519.PrivateKey
}

type chainWindow struct {
	credNotBefore, credNotAfter time.Time
}

func mintChain(t *testing.T, w chainWindow) testChain {
	t.Helper()
	now := time.Now()
	rootPub, rootPriv, _ := ed25519.GenerateKey(nil)
	issuerPub, issuerPriv, _ := ed25519.GenerateKey(nil)
	devPub, devPriv, _ := ed25519.GenerateKey(nil)

	if w.credNotBefore.IsZero() {
		w.credNotBefore = now.Add(-time.Minute)
	}
	if w.credNotAfter.IsZero() {
		w.credNotAfter = now.Add(24 * time.Hour)
	}

	cert := devicecred.IssuerCert{
		Version:    devicecred.Version,
		Serial:     "cccccccccccccccc",
		IssuerPub:  issuerPub,
		NotBefore:  now.Add(-time.Hour),
		NotAfter:   now.Add(365 * 24 * time.Hour),
		MaxCredTTL: 72 * time.Hour,
	}
	cred := devicecred.DeviceCredential{
		Version:   devicecred.Version,
		Serial:    "dddddddddddddddd",
		DevicePub: devPub,
		Epoch:     3,
		NotBefore: w.credNotBefore,
		NotAfter:  w.credNotAfter,
	}
	return testChain{
		rootPub:    rootPub,
		issuerCert: devicecred.EncodeIssuerCert(signObj(t, rootPriv, "bacchus/issuer-cert/v1", cert)),
		deviceCred: devicecred.EncodeDeviceCredential(signObj(t, issuerPriv, "bacchus/device-cred/v1", cred)),
		devPriv:    devPriv,
	}
}

// connectMsg builds a connect carrying the chain and an assertion over challenge.
func (c testChain) connectMsg(t *testing.T, audience, challenge string) wire {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	a, err := devicecred.SignAssertion(c.devPriv, devicecred.PurposeConnect, audience, raw)
	if err != nil {
		t.Fatalf("SignAssertion: %v", err)
	}
	return wire{
		Type:         "connect",
		Challenge:    challenge,
		DeviceCred:   c.deviceCred,
		IssuerCert:   c.issuerCert,
		DeviceAssert: base64.StdEncoding.EncodeToString(a),
	}
}

// setDeviceGate installs a verifier for the duration of a test and restores the
// disabled (nil) default after, so tests expecting the pre-#50 behavior are
// unaffected. It also clears the challenge store both before and after.
func setDeviceGate(t *testing.T, root ed25519.PublicKey, audience string) {
	t.Helper()
	v, err := devicecred.NewVerifier(root, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	deviceVerifier, deviceAudience = v, audience
	resetChallenges()
	t.Cleanup(func() {
		deviceVerifier, deviceAudience = nil, ""
		resetChallenges()
	})
}

func resetChallenges() {
	challenges.mu.Lock()
	challenges.entries = map[string]pendingChallenge{}
	challenges.atCapacity = false
	challenges.mu.Unlock()
}

// requestChallenge drives the "challenge" handler and returns the issued nonce.
func requestChallenge(t *testing.T, peer *net.UDPConn, src *net.UDPAddr) string {
	t.Helper()
	handle(wire{Type: "challenge"}, src)
	reply, ok := readReply(t, peer, time.Second)
	if !ok {
		t.Fatal("no reply to a challenge request")
	}
	if reply.Type != "challenge" {
		t.Fatalf("reply type = %q, want challenge", reply.Type)
	}
	return reply.Challenge
}

func TestChallengeIsFreshUnpredictableAndLongEnough(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	setDeviceGate(t, c.rootPub, "coord-1")
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	seen := map[string]bool{}
	for i := 0; i < 8; i++ {
		got := requestChallenge(t, peer, src)
		raw, err := base64.StdEncoding.DecodeString(got)
		if err != nil {
			t.Fatalf("challenge is not base64: %v", err)
		}
		if len(raw) != deviceChallengeLen {
			t.Fatalf("challenge is %d bytes, want %d", len(raw), deviceChallengeLen)
		}
		if len(raw) < devicecred.MinChallenge {
			t.Fatalf("challenge is below the verifier's floor of %d", devicecred.MinChallenge)
		}
		if seen[got] {
			t.Fatalf("challenge %q issued twice — a repeated nonce is a replayable connect", got)
		}
		seen[got] = true
	}
}

func TestConnectWithAValidChainIsAdmitted(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	setDeviceGate(t, c.rootPub, "coord-1")
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	ch := requestChallenge(t, peer, src)
	if !admitDevice(c.connectMsg(t, "coord-1", ch), src) {
		reply, _ := readReply(t, peer, 200*time.Millisecond)
		t.Fatalf("a valid chain was refused: %s", reply.Reason)
	}
}

// TestConnectRefusalsAtTheGate walks the ways a connect fails the gate. Each must
// be refused, and refused with a reject the client can act on.
func TestConnectRefusalsAtTheGate(t *testing.T) {
	for _, tc := range []struct {
		name string
		// build returns the connect to present, given the issued challenge.
		build func(t *testing.T, c testChain, ch string) wire
		// window places the credential's validity relative to now.
		window chainWindow
		// skipChallenge omits the challenge request entirely.
		skipChallenge bool
		wantReason    string
	}{
		{
			name:          "no challenge was ever issued",
			skipChallenge: true,
			build:         func(t *testing.T, c testChain, ch string) wire { return c.connectMsg(t, "coord-1", dummyChallenge()) },
			wantReason:    "no outstanding device-credential challenge",
		},
		{
			name: "assertion bound to a different audience",
			build: func(t *testing.T, c testChain, ch string) wire {
				return c.connectMsg(t, "some-other-coordinator", ch)
			},
			wantReason: "assertion invalid",
		},
		{
			name: "echoed challenge is not the one issued",
			build: func(t *testing.T, c testChain, ch string) wire {
				m := c.connectMsg(t, "coord-1", ch)
				m.Challenge = dummyChallenge()
				return m
			},
			wantReason: "does not answer the challenge",
		},
		{
			name: "no device credential presented at all",
			build: func(t *testing.T, c testChain, ch string) wire {
				return wire{Type: "connect", Challenge: ch}
			},
			wantReason: "malformed",
		},
		{
			name: "credential expired",
			window: chainWindow{
				credNotBefore: time.Now().Add(-2 * time.Hour),
				credNotAfter:  time.Now().Add(-time.Hour),
			},
			build:      func(t *testing.T, c testChain, ch string) wire { return c.connectMsg(t, "coord-1", ch) },
			wantReason: "expired",
		},
		{
			name: "assertion made by a key that is not the credential's",
			build: func(t *testing.T, c testChain, ch string) wire {
				m := c.connectMsg(t, "coord-1", ch)
				_, other, _ := ed25519.GenerateKey(nil)
				raw, _ := base64.StdEncoding.DecodeString(ch)
				a, err := devicecred.SignAssertion(other, devicecred.PurposeConnect, "coord-1", raw)
				if err != nil {
					t.Fatalf("SignAssertion: %v", err)
				}
				m.DeviceAssert = base64.StdEncoding.EncodeToString(a)
				return m
			},
			wantReason: "assertion invalid",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setPC(t)
			c := mintChain(t, tc.window)
			setDeviceGate(t, c.rootPub, "coord-1")
			peer := fakePeer(t)
			src := peer.LocalAddr().(*net.UDPAddr)

			ch := ""
			if !tc.skipChallenge {
				ch = requestChallenge(t, peer, src)
			}
			if admitDevice(tc.build(t, c, ch), src) {
				t.Fatal("ADMITTED a connect that must be refused")
			}
			reply, ok := readReply(t, peer, time.Second)
			if !ok {
				t.Fatal("refused without telling the client why")
			}
			if reply.Type != "reject" {
				t.Fatalf("reply type = %q, want reject", reply.Type)
			}
			if !strings.Contains(reply.Reason, tc.wantReason) {
				t.Fatalf("reason = %q, want it to mention %q", reply.Reason, tc.wantReason)
			}
		})
	}
}

// TestChallengeAnswersOneRequestNotOneDatagram is the distinction the gate has to
// draw, and it cuts both ways.
//
// core's sendN puts three copies of one connect on the wire against UDP loss, so
// refusing the second copy would refuse every honest client. But a SECOND request
// re-presenting a spent challenge is a replay, and admitting it would mean a
// captured connect stayed good for the nonce's whole lifetime.
//
// The connect nonce is what separates them: it identifies the request rather than
// the datagram.
func TestChallengeAnswersOneRequestNotOneDatagram(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	setDeviceGate(t, c.rootPub, "coord-1")
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	ch := requestChallenge(t, peer, src)
	m := c.connectMsg(t, "coord-1", ch)
	m.Nonce = "request-A"

	// The three copies sendN puts on the wire are all answered.
	for i := 0; i < 3; i++ {
		if !admitDevice(m, src) {
			t.Fatalf("copy %d of one request was refused — an honest client retransmits", i+1)
		}
	}

	// A DIFFERENT request re-presenting the same spent challenge is a replay.
	replay := c.connectMsg(t, "coord-1", ch)
	replay.Nonce = "request-B"
	if admitDevice(replay, src) {
		t.Fatal("a second request replayed a spent challenge")
	}
}

// TestAFailedAttemptBurnsTheChallenge, so a rejected attempt cannot be retried
// against a nonce that is still live.
//
// Both attempts carry the SAME connect nonce deliberately. That is the only way to
// isolate the drop: a differing nonce is already refused by the request binding, so
// a test using two nonces would pass whether or not a failure burns anything.
func TestAFailedAttemptBurnsTheChallenge(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	setDeviceGate(t, c.rootPub, "coord-1")
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	ch := requestChallenge(t, peer, src)
	const nonce = "one-request"

	// A wrong-audience attempt against a live challenge.
	bad := c.connectMsg(t, "wrong", ch)
	bad.Nonce = nonce
	if admitDevice(bad, src) {
		t.Fatal("a wrong-audience connect was admitted")
	}
	readReply(t, peer, time.Second)

	// The correct connect, same request nonce, same challenge, must now fail too:
	// the nonce is spent AND burned, not merely unsatisfied. Otherwise a rejected
	// attempt buys unlimited further attempts against a challenge that is still live.
	good := c.connectMsg(t, "coord-1", ch)
	good.Nonce = nonce
	if admitDevice(good, src) {
		t.Fatal("a burned challenge was accepted on a second attempt")
	}
}

// TestAChallengeCannotBeSpentFromAnotherAddress. Not authentication — UDP sources
// are spoofable — but it does stop a blind attacker spending a nonce issued to
// someone else.
func TestAChallengeCannotBeSpentFromAnotherAddress(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	setDeviceGate(t, c.rootPub, "coord-1")
	peer := fakePeer(t)
	other := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	ch := requestChallenge(t, peer, src)
	if admitDevice(c.connectMsg(t, "coord-1", ch), other.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("a challenge issued to one address was spent from another")
	}
}

// TestGateDisabledAdmitsEverything preserves the pre-#50 behavior when
// -device-root-pubkey is not set: connects are gated by admission alone.
func TestGateDisabledAdmitsEverything(t *testing.T) {
	setPC(t)
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	if deviceVerifier != nil {
		t.Fatal("the gate should be disabled by default")
	}
	if !admitDevice(wire{Type: "connect"}, src) {
		t.Fatal("a connect was refused with the gate disabled")
	}
	if _, ok := readReply(t, peer, 200*time.Millisecond); ok {
		t.Fatal("a disabled gate replied to a connect")
	}
}

// TestExpiredChallengeIsRefused pins the TTL, using the store directly so the test
// does not have to wait deviceChallengeTTL.
func TestExpiredChallengeIsRefused(t *testing.T) {
	s := &challengeStore{entries: map[string]pendingChallenge{}}
	now := time.Now()

	v := s.issue("peer", now)
	if v == nil {
		t.Fatal("issue returned nothing")
	}
	// One nanosecond before expiry it is still usable.
	if got := s.spend("peer", "req-1", now.Add(deviceChallengeTTL-time.Nanosecond)); got == nil {
		t.Fatal("a challenge expired before its TTL")
	}

	v = s.issue("peer", now)
	if v == nil {
		t.Fatal("issue returned nothing")
	}
	// Exactly on expiry it is dead — the same strict boundary the credential
	// windows use.
	if got := s.spend("peer", "req-2", now.Add(deviceChallengeTTL)); got != nil {
		t.Fatal("a challenge exactly at its expiry was still accepted")
	}
}

// TestChallengeStoreIsBounded. UDP sources are spoofable, so the store is fillable
// by an attacker who never completes a handshake. At capacity it refuses to issue
// rather than evicting a live entry — evicting would let a spoofer knock honest
// clients out, turning a memory bound into a denial of service against exactly the
// traffic it protects.
func TestChallengeStoreIsBounded(t *testing.T) {
	// A small cap, so the flood below is the store's behaviour under pressure rather
	// than a test that spends real time minting 65536 nonces.
	const testCap = 64
	s := &challengeStore{entries: map[string]pendingChallenge{}, capacity: testCap}
	now := time.Now()

	honest := s.issue("honest-client", now)
	if honest == nil {
		t.Fatal("the first issue failed")
	}
	for i := 0; i < testCap*4; i++ {
		s.issue(spoofKey(i), now)
	}
	if got := s.len(); got > testCap {
		t.Fatalf("store holds %d entries, above the %d cap", got, testCap)
	}
	// The honest client's challenge survived the flood and is still spendable.
	if got := s.spend("honest-client", "req", now); got == nil {
		t.Fatal("a live challenge was evicted by a flood of spoofed sources")
	}

	// Expiry frees the store again: once the flood ages out, issuing resumes.
	if v := s.issue("later-client", now.Add(deviceChallengeTTL+time.Second)); v == nil {
		t.Fatal("the store never recovered after its entries expired")
	}
}

func spoofKey(i int) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	return "spoof-" + base64.RawURLEncoding.EncodeToString(b[:])
}

func dummyChallenge() string {
	b := make([]byte, deviceChallengeLen)
	for i := range b {
		b[i] = 0x5A
	}
	return base64.StdEncoding.EncodeToString(b)
}

// TestRetransmittedConnectIsNotRefusedByTheGate.
//
// core's sendN puts THREE copies of every connect on the wire against UDP loss
// (core/client.go). Per-connect idempotency (issue #1, ADR-0042 §2) exists exactly
// so the later copies replay the first one's answer instead of drawing a fresh
// exit — but the device gate spends a challenge, so a gate that treated each
// DATAGRAM as a fresh use would refuse copies two and three, and one request would
// be answered with one session and two rejects.
//
// A retransmission is not a replay attack: it is the same request arriving twice.
// Verified end to end through handle() with a real exit registered, so this covers
// the gate, the idempotency layer and the ordering between them together.
func TestRetransmittedConnectIsNotRefusedByTheGate(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	c := mintChain(t, chainWindow{})
	setDeviceGate(t, c.rootPub, "coord-1")
	client := fakePeer(t)
	src := client.LocalAddr().(*net.UDPAddr)
	exitFleet(t, 3, "NL")

	ch := requestChallenge(t, client, src)
	m := c.connectMsg(t, "coord-1", ch)
	m.Nonce = randID()
	m.Country = "NL"
	m.Mode = "direct"

	const copies = 3
	for i := 0; i < copies; i++ {
		handle(m, src)
	}

	// One request is still one assignment: the gate must not have disturbed the
	// dedupe it now sits behind.
	if got := sessionCount(); got != 1 {
		t.Fatalf("three copies of one connect minted %d sessions; want exactly 1", got)
	}

	// And every copy is answered with a session — none refused by the gate.
	var first wire
	for i := 0; i < copies; i++ {
		r := recvWire(t, client, time.Second)
		if r.Type != "session" {
			t.Fatalf("copy %d answered %s (%s); want a session — a retransmit must still be answered", i+1, r.Type, r.Reason)
		}
		if i == 0 {
			first = r
		} else if r.Session != first.Session || r.ExitID != first.ExitID {
			t.Errorf("copy %d answered session=%q exit=%q; copy 1 answered session=%q exit=%q", i+1, r.Session, r.ExitID, first.Session, first.ExitID)
		}
	}
}
