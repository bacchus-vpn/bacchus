package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/delegation"
	"github.com/bacchus-vpn/bacchus/core/devicecred"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
)

// ---------------------------------------------------------------------------
// Test fixtures: a throwaway root -> issuer cert -> device credential chain,
// minted using only devicecred's exported API (types, envelope encoders) plus
// core/delegation's tag registry and stdlib crypto. Self-contained on purpose:
// these tests must not depend on core/devicecred's own frozen testdata clock, and
// must not need any change to that package to construct a chain its real Verifier
// accepts.
// ---------------------------------------------------------------------------

// signBody reproduces core/delegation's "tag || 0x00 || body" signing frame
// (delegation.go's unexported signingMessage) so this file can mint fixtures
// against the exact bytes devicecred.Verify checks, without importing anything
// unexported and without this package owning that framing.
func signBody(priv ed25519.PrivateKey, tag string, body []byte) []byte {
	msg := make([]byte, 0, len(tag)+1+len(body))
	msg = append(msg, tag...)
	msg = append(msg, 0x00)
	msg = append(msg, body...)
	sig := ed25519.Sign(priv, msg)
	signed := make([]byte, 0, len(body)+ed25519.SignatureSize)
	signed = append(signed, body...)
	signed = append(signed, sig...)
	return signed
}

// mintTestChain builds a throwaway chain valid at now for credTTL, and returns
// the root's public key (what a coordinator-side Verifier is anchored to), the
// two envelope strings a device presents, and the device's own private key.
func mintTestChain(t *testing.T, now time.Time, credTTL time.Duration) (rootPub ed25519.PublicKey, issuerCertEnc, credEnc string, devicePriv ed25519.PrivateKey) {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}
	devicePub, devicePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}

	cert := devicecred.IssuerCert{
		Version:    devicecred.Version,
		Serial:     "test-issuer-cert",
		IssuerPub:  issuerPub,
		NotBefore:  now.Add(-time.Hour),
		NotAfter:   now.Add(365 * 24 * time.Hour),
		MaxCredTTL: 72 * time.Hour,
	}
	certBody, err := json.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal issuer cert: %v", err)
	}
	issuerCertEnc = devicecred.EncodeIssuerCert(signBody(rootPriv, delegation.TagIssuerCert, certBody))

	cred := devicecred.DeviceCredential{
		Version:   devicecred.Version,
		Serial:    "test-device-cred",
		DevicePub: devicePub,
		Epoch:     0,
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(credTTL),
	}
	credBody, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal device credential: %v", err)
	}
	credEnc = devicecred.EncodeDeviceCredential(signBody(issuerPriv, delegation.TagDeviceCred, credBody))

	return rootPub, issuerCertEnc, credEnc, devicePriv
}

// ---------------------------------------------------------------------------
// Fake coordinator: answers "challenge" per test-configured behavior and
// captures every "connect" it receives. It never verifies anything itself —
// verification happens in the test goroutine, against the real
// devicecred.Verifier, so a pass means the real coordinator (which calls the
// identical Verifier.Verify) would accept the same bytes.
// ---------------------------------------------------------------------------

type fakeDeviceCoordinator struct {
	pc *net.UDPConn

	mu            sync.Mutex
	challengeReqs int
	challenges    []wire
	connects      []wire
	registers     []wire
	// sizes are the RAW datagram lengths, per message type, as they arrived on the
	// wire. Recorded because issue #183 is a fact about bytes on a network and not
	// about a struct: a size assert that re-marshals a wire the test built itself
	// proves the test's arithmetic, while this proves what attemptWith actually put
	// on the socket. That distinction is the whole card — #166's +423 bytes were
	// invisible to every struct-level check in the repository.
	sizes           map[string][]int
	answerChallenge bool
	emptyChallenge  bool
}

func newFakeDeviceCoordinator(t *testing.T) *fakeDeviceCoordinator {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	f := &fakeDeviceCoordinator{pc: pc, answerChallenge: true, sizes: map[string][]int{}}
	go f.serve()
	return f
}

// sizesOf returns the raw datagram lengths seen for one message type, in arrival
// order.
func (f *fakeDeviceCoordinator) sizesOf(msgType string) []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int(nil), f.sizes[msgType]...)
}

func (f *fakeDeviceCoordinator) addr() string { return f.pc.LocalAddr().String() }

func (f *fakeDeviceCoordinator) setBehavior(answer, empty bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answerChallenge, f.emptyChallenge = answer, empty
}

func (f *fakeDeviceCoordinator) snapshot() (challengeReqs int, connects []wire) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.challengeReqs, append([]wire(nil), f.connects...)
}

// creds returns the admission credential carried by every "challenge" and
// "register" this coordinator has seen, in arrival order. It is what a peer
// actually received, as opposed to what the engine believes it holds.
func (f *fakeDeviceCoordinator) creds() (challenges, registers []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.challenges {
		challenges = append(challenges, m.Cred)
	}
	for _, m := range f.registers {
		registers = append(registers, m.Cred)
	}
	return challenges, registers
}

func (f *fakeDeviceCoordinator) serve() {
	buf := make([]byte, 65535)
	for {
		n, src, err := f.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		var m wire
		if json.Unmarshal(buf[:n], &m) != nil {
			continue
		}
		f.mu.Lock()
		f.sizes[m.Type] = append(f.sizes[m.Type], n)
		f.mu.Unlock()
		switch m.Type {
		case "challenge":
			f.mu.Lock()
			f.challengeReqs++
			f.challenges = append(f.challenges, m)
			answer, empty := f.answerChallenge, f.emptyChallenge
			f.mu.Unlock()
			if !answer {
				continue // blackhole: simulates a lost or silently-dropped request
			}
			if empty {
				f.send(src, wire{Type: "challenge"})
				continue
			}
			nonce := make([]byte, 32)
			_, _ = rand.Read(nonce)
			f.send(src, wire{Type: "challenge", Challenge: base64.StdEncoding.EncodeToString(nonce)})
		case "connect":
			f.mu.Lock()
			f.connects = append(f.connects, m)
			f.mu.Unlock()
		case "register":
			f.mu.Lock()
			f.registers = append(f.registers, m)
			f.mu.Unlock()
		}
	}
}

func (f *fakeDeviceCoordinator) send(to *net.UDPAddr, m wire) {
	b, _ := json.Marshal(m)
	_, _ = f.pc.WriteToUDP(b, to)
}

// newTestClientEngine starts a client-role engine against addr and returns it
// along with its one coordLink, ready for presentDeviceCredential/attemptWith
// calls. t.Cleanup stops it.
func newTestClientEngine(t *testing.T, addr string) (*Engine, *coordLink) {
	t.Helper()
	eng, err := New(Config{Coordinators: []string{addr}, Roles: []string{RoleClient}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)
	if len(eng.links) != 1 {
		t.Fatalf("expected exactly one link, got %d", len(eng.links))
	}
	return eng, eng.links[0]
}

// ---------------------------------------------------------------------------
// Wire-contract pinning (mirrors TestCountryReplyWireContract's shape):
// core's wire and cmd/coordinator's wire are deliberately separate types in
// non-importing packages, so the four device-credential field names have to be
// pinned against a hand-written encoding of what the OTHER side actually
// sends/reads (cmd/coordinator/main.go's wire struct).
// ---------------------------------------------------------------------------

func TestDeviceCredWireContract(t *testing.T) {
	const challengeReply = `{"type":"challenge","challenge":"Y2hhbGxlbmdl"}`
	var cr wire
	if err := json.Unmarshal([]byte(challengeReply), &cr); err != nil {
		t.Fatalf("a challenge reply in the coordinator's own encoding did not decode: %v", err)
	}
	if cr.Challenge != "Y2hhbGxlbmdl" {
		t.Fatalf("decoded Challenge=%q, want %q — the `challenge` field name has drifted from cmd/coordinator's wire", cr.Challenge, "Y2hhbGxlbmdl")
	}

	const connectReply = `{"type":"connect","challenge":"Y2hhbGxlbmdl","deviceCred":"bacchusd1:AAAA","issuerCert":"bacchusi1:BBBB","deviceAssert":"c2ln"}`
	var m wire
	if err := json.Unmarshal([]byte(connectReply), &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Challenge != "Y2hhbGxlbmdl" || m.DeviceCred != "bacchusd1:AAAA" || m.IssuerCert != "bacchusi1:BBBB" || m.DeviceAssert != "c2ln" {
		t.Fatalf("decoded %+v — a device-credential field name has drifted from cmd/coordinator's wire", m)
	}

	// And the round trip: what this client encodes on a "challenge" request is
	// what cmd/coordinator's admit()/issueDeviceChallenge reads (only Type+Cred).
	out, err := json.Marshal(wire{Type: "challenge", Cred: "admission-cred"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const wantOut = `{"type":"challenge","cred":"admission-cred"}`
	if string(out) != wantOut {
		t.Fatalf("encoded %s, want %s", out, wantOut)
	}
}

// ---------------------------------------------------------------------------
// presentDeviceCredential
// ---------------------------------------------------------------------------

func TestPresentDeviceCredential_NoStoredCredential(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr()) // deviceStore starts empty — nothing Put yet

	fields, ok := eng.presentDeviceCredential(context.Background(), link, time.Second)
	if ok {
		t.Fatalf("expected ok=false with no stored credential, got fields=%+v", fields)
	}
	if reqs, _ := coord.snapshot(); reqs != 0 {
		t.Fatalf("expected no \"challenge\" request when there is nothing to present, coordinator saw %d", reqs)
	}
}

func TestPresentDeviceCredential_FullExchangeAcceptedByRealVerifier(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	now := time.Now()
	rootPub, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour)
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: issuerCertEnc}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	fields, ok := eng.presentDeviceCredential(context.Background(), link, 5*time.Second)
	if !ok {
		t.Fatal("expected presentDeviceCredential to succeed with a stored credential and a live coordinator")
	}
	if fields.cred != credEnc || fields.issuerCert != issuerCertEnc {
		t.Fatalf("presented (cred, issuerCert) = (%q, %q), want the stored pair", fields.cred, fields.issuerCert)
	}

	challenge, err := base64.StdEncoding.DecodeString(fields.challenge)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	assertion, err := base64.StdEncoding.DecodeString(fields.assert)
	if err != nil {
		t.Fatalf("decode assertion: %v", err)
	}
	p, err := devicecred.ParsePresentation(fields.cred, fields.issuerCert, assertion)
	if err != nil {
		t.Fatalf("ParsePresentation: %v", err)
	}
	v, err := devicecred.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// audience = link.raw: exactly what cmd/coordinator's admitDevice checks
	// against (its OWN advertised/configured audience), proving this is a chain
	// the real coordinator gate would admit, not merely one that decodes.
	if _, err := v.Verify(p, now, link.raw, challenge); err != nil {
		t.Fatalf("the real devicecred.Verifier refused this client's presentation: %v", err)
	}
}

func TestPresentDeviceCredential_AudienceBindsToDialledAddress(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	now := time.Now()
	rootPub, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour)
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: issuerCertEnc}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	fields, ok := eng.presentDeviceCredential(context.Background(), link, 5*time.Second)
	if !ok {
		t.Fatal("expected presentDeviceCredential to succeed")
	}
	challenge, _ := base64.StdEncoding.DecodeString(fields.challenge)
	assertion, _ := base64.StdEncoding.DecodeString(fields.assert)
	p, err := devicecred.ParsePresentation(fields.cred, fields.issuerCert, assertion)
	if err != nil {
		t.Fatalf("ParsePresentation: %v", err)
	}
	v, err := devicecred.NewVerifier(rootPub, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// The address actually dialled must verify...
	if _, err := v.Verify(p, now, link.raw, challenge); err != nil {
		t.Fatalf("verification against the dialled address failed: %v", err)
	}
	// ...but a coordinator merely CLAIMING a different identity must not: if this
	// passed, a hostile pool member could announce an honest coordinator's
	// audience, relay the challenge, and spend this device's entitlement itself
	// (ADR-0045 §4) — exactly the attack the audience binding exists to close.
	if _, err := v.Verify(p, now, "attacker-announced-identity:9999", challenge); err == nil {
		t.Fatal("verification succeeded against an audience the client never dialled — the assertion is not actually bound to l.raw")
	}
}

// TestPresentDeviceCredential_FreshChallengePerCoordinatorOnRotation is the
// other half of this lane's rotation sharp edge: audience differs per pool
// member (ADR-0020), so a challenge from one coordinator cannot be presented to
// another, and a rotating client must fetch a fresh one from whichever member it
// actually tries. Each member here is a genuinely separate socket/audience, not
// a second call against the same link (TestPresentDeviceCredential_FreshChallengePerCall
// covers that half).
func TestPresentDeviceCredential_FreshChallengePerCoordinatorOnRotation(t *testing.T) {
	coordA := newFakeDeviceCoordinator(t)
	coordB := newFakeDeviceCoordinator(t)

	eng, err := New(Config{Coordinators: []string{coordA.addr(), coordB.addr()}, Roles: []string{RoleClient}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)
	if len(eng.links) != 2 {
		t.Fatalf("expected two links, got %d", len(eng.links))
	}
	// Identify which link is which member, independent of dialPool's ordering.
	var linkA, linkB *coordLink
	for _, l := range eng.links {
		switch l.raw {
		case coordA.addr():
			linkA = l
		case coordB.addr():
			linkB = l
		}
	}
	if linkA == nil || linkB == nil {
		t.Fatalf("could not map links to coordinators: %+v", eng.links)
	}

	_, _, credEnc, devicePriv := mintTestChain(t, time.Now(), 48*time.Hour)
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: "bacchusi1:whatever"}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	// Simulate rotation: member A first (as connectVia would try, in some
	// order), then member B.
	fA, ok := eng.presentDeviceCredential(context.Background(), linkA, 2*time.Second)
	if !ok {
		t.Fatal("expected ok=true against member A")
	}
	fB, ok := eng.presentDeviceCredential(context.Background(), linkB, 2*time.Second)
	if !ok {
		t.Fatal("expected ok=true against member B")
	}

	if reqsA, _ := coordA.snapshot(); reqsA != 1 {
		t.Fatalf("member A saw %d \"challenge\" requests, want 1", reqsA)
	}
	if reqsB, _ := coordB.snapshot(); reqsB != 1 {
		t.Fatalf("member B saw %d \"challenge\" requests, want 1", reqsB)
	}
	if fA.challenge == fB.challenge {
		t.Fatal("the same challenge value was used against two different coordinators")
	}
	if fA.assert == fB.assert {
		t.Fatal("the same assertion was presented to two different coordinators — the audience (l.raw) must differ per member, so the signature must too")
	}
}

func TestPresentDeviceCredential_NoChallengeReplyDegradesGracefully(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	coord.setBehavior(false, false) // blackhole every "challenge"
	eng, link := newTestClientEngine(t, coord.addr())

	_, _, credEnc, devicePriv := mintTestChain(t, time.Now(), 48*time.Hour)
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: "bacchusi1:whatever"}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	start := time.Now()
	fields, ok := eng.presentDeviceCredential(context.Background(), link, 300*time.Millisecond)
	if ok {
		t.Fatalf("expected ok=false when the coordinator never answers, got %+v", fields)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("presentDeviceCredential took %v to give up on a silent coordinator, want well under its budget", elapsed)
	}
}

func TestPresentDeviceCredential_EmptyChallengeDegradesGracefully(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	coord.setBehavior(true, true) // gate off / at capacity: reply with no challenge value
	eng, link := newTestClientEngine(t, coord.addr())

	_, _, credEnc, devicePriv := mintTestChain(t, time.Now(), 48*time.Hour)
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: "bacchusi1:whatever"}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	fields, ok := eng.presentDeviceCredential(context.Background(), link, 2*time.Second)
	if ok {
		t.Fatalf("expected ok=false on an empty challenge reply, got %+v", fields)
	}
	if reqs, _ := coord.snapshot(); reqs != 1 {
		t.Fatalf("expected exactly one \"challenge\" request, coordinator saw %d", reqs)
	}
}

func TestPresentDeviceCredential_FreshChallengePerCall(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	_, _, credEnc, devicePriv := mintTestChain(t, time.Now(), 48*time.Hour)
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: "bacchusi1:whatever"}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	f1, ok := eng.presentDeviceCredential(context.Background(), link, 2*time.Second)
	if !ok {
		t.Fatal("first call: expected ok=true")
	}
	f2, ok := eng.presentDeviceCredential(context.Background(), link, 2*time.Second)
	if !ok {
		t.Fatal("second call: expected ok=true")
	}
	if reqs, _ := coord.snapshot(); reqs != 2 {
		t.Fatalf("expected two separate \"challenge\" requests (one per call — a challenge must never be cached or reused across a retry or rotation), coordinator saw %d", reqs)
	}
	if f1.challenge == f2.challenge {
		t.Fatal("two calls produced the SAME challenge — a challenge is single-use and per-coordinator; reusing one is exactly what #50's TTL/single-use design exists to prevent")
	}
	if f1.assert == f2.assert {
		t.Fatal("two calls produced the SAME assertion — each must be signed over its own fresh challenge")
	}
}

// TestAttemptWith_ConnectCarriesSameChallengeAcrossRetransmissions is the
// sharp-edge case named explicitly in this lane's brief: core's sendN puts
// three copies of every connect on the wire against UDP loss, and all three
// must carry the SAME challenge/assertion — fetching a fresh challenge per copy
// would burn the single-use nonce on copy one and leave copies two and three
// unanswerable.
func TestAttemptWith_ConnectCarriesSameChallengeAcrossRetransmissions(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	_, _, credEnc, devicePriv := mintTestChain(t, time.Now(), 48*time.Hour)
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: "bacchusi1:whatever"}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	// No "session"/"error" reply is configured, so this call runs out its full
	// budget — kept short so the test stays fast. Only what landed on the wire
	// matters here, not attemptWith's return value.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	eng.attemptWith(ctx, link, connectReq{country: "XX", mode: modeDirect}, eng.transport, time.Second, nil)

	reqs, connects := coord.snapshot()
	if reqs != 1 {
		t.Fatalf("expected exactly one \"challenge\" request for one attempt, coordinator saw %d", reqs)
	}
	if len(connects) != 3 {
		t.Fatalf("expected sendN's three connect copies, coordinator saw %d", len(connects))
	}
	first := connects[0]
	if first.Challenge == "" || first.DeviceCred == "" || first.IssuerCert == "" || first.DeviceAssert == "" {
		t.Fatalf("first connect is missing device-credential fields: %+v", first)
	}
	for i, c := range connects[1:] {
		if c.Challenge != first.Challenge || c.DeviceAssert != first.DeviceAssert ||
			c.DeviceCred != first.DeviceCred || c.IssuerCert != first.IssuerCert || c.Nonce != first.Nonce {
			t.Fatalf("connect copy %d diverged from copy 0's device-credential fields: %+v vs %+v", i+1, c, first)
		}
	}
}

// TestAttemptWith_NoStoredCredentialConnectsExactlyAsBeforeIssue50 pins the
// backward-compat claim in the Config.DeviceCredDir doc: a client with nothing
// to present sends a connect with all four fields empty.
func TestAttemptWith_NoStoredCredentialConnectsExactlyAsBeforeIssue50(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	eng.attemptWith(ctx, link, connectReq{country: "XX", mode: modeDirect}, eng.transport, time.Second, nil)

	reqs, connects := coord.snapshot()
	if reqs != 0 {
		t.Fatalf("expected no \"challenge\" request with nothing to present, coordinator saw %d", reqs)
	}
	if len(connects) != 3 {
		t.Fatalf("expected sendN's three connect copies, coordinator saw %d", len(connects))
	}
	for i, c := range connects {
		if c.Challenge != "" || c.DeviceCred != "" || c.IssuerCert != "" || c.DeviceAssert != "" {
			t.Fatalf("connect copy %d carries device-credential fields with nothing stored: %+v", i, c)
		}
	}
}

// ---------------------------------------------------------------------------
// Renewal
// ---------------------------------------------------------------------------

func TestMaybeRenewDeviceCred_NoSeamConfigured(t *testing.T) {
	eng, err := New(Config{Coordinators: []string{"127.0.0.1:1"}, Roles: []string{RoleClient}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, credEnc, devicePriv := mintTestChain(t, time.Now(), time.Minute) // already due
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: "bacchusi1:whatever"}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}
	eng.maybeRenewDeviceCred(context.Background(), time.Now()) // must not panic with DeviceRenew == nil
	held, _ := eng.deviceStore.Get()
	gotCred := held.Device
	if gotCred != credEnc {
		t.Fatal("store must be unchanged when no renewal seam is configured")
	}
}

func TestMaybeRenewDeviceCred_NothingStoredYet(t *testing.T) {
	called := false
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			called = true
			return devicestore.Credential{}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.maybeRenewDeviceCred(context.Background(), time.Now())
	if called {
		t.Fatal("DeviceRenew must not be called when nothing has been enrolled yet")
	}
}

func TestMaybeRenewDeviceCred_NotDueYet(t *testing.T) {
	called := false
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			called = true
			return devicestore.Credential{}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	_, _, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour) // well past the default 6h margin
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: "bacchusi1:whatever"}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}
	eng.maybeRenewDeviceCred(context.Background(), now)
	if called {
		t.Fatal("DeviceRenew must not be called before the credential is due for renewal")
	}
}

func TestMaybeRenewDeviceCred_RenewsWhenDue(t *testing.T) {
	now := time.Now()
	_, _, oldCred, devicePriv := mintTestChain(t, now, time.Hour) // inside the default 6h margin
	_, newIssuerCert, newCred, _ := mintTestChain(t, now, 48*time.Hour)
	const newAdmission = "bacchusc1:renewed-admission"

	var gotReq DeviceRenewRequest
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			gotReq = req
			return devicestore.Credential{Device: newCred, IssuerCert: newIssuerCert, Admission: newAdmission}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: oldCred, IssuerCert: "bacchusi1:old-issuer"}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.maybeRenewDeviceCred(context.Background(), now)

	got, ok := eng.deviceStore.Get()
	want := devicestore.Credential{Device: newCred, IssuerCert: newIssuerCert, Admission: newAdmission}
	if !ok || got != want {
		t.Fatalf("store after renewal = (%+v, %v), want %+v — all three, written together", got, ok, want)
	}
	if string(gotReq.DevicePub) != string(devicePriv.Public().(ed25519.PublicKey)) {
		t.Fatal("DeviceRenewRequest.DevicePub did not match this device's own public key")
	}
	if gotReq.Current.Device != oldCred {
		t.Fatalf("DeviceRenewRequest.Current.Device = %q, want the credential about to expire", gotReq.Current.Device)
	}
	// Sign must produce a genuine PurposeRenew assertion under whatever
	// audience/challenge the account service's own protocol asks for — proven by
	// verifying it with devicecred's own (exported) assertion verifier.
	sig, err := gotReq.Sign("account-service", []byte("0123456789abcdef"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := devicecred.VerifyAssertion(devicePriv.Public().(ed25519.PublicKey), purposeRenew, "account-service", []byte("0123456789abcdef"), sig); err != nil {
		t.Fatalf("Sign produced an assertion that does not verify as PurposeRenew: %v", err)
	}
	// And it must NOT verify under PurposeConnect — the whole point of a
	// purpose tag is that a signature made for one context is useless in another.
	if err := devicecred.VerifyAssertion(devicePriv.Public().(ed25519.PublicKey), devicecred.PurposeConnect, "account-service", []byte("0123456789abcdef"), sig); err == nil {
		t.Fatal("a renewal assertion verified under PurposeConnect — purpose separation is broken")
	}
}

func TestMaybeRenewDeviceCred_FailurePreservesOldCredential(t *testing.T) {
	now := time.Now()
	_, oldIssuerCert, oldCred, devicePriv := mintTestChain(t, now, time.Hour)

	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			return devicestore.Credential{}, errBoom
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: oldCred, IssuerCert: oldIssuerCert}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.maybeRenewDeviceCred(context.Background(), now)

	got, ok := eng.deviceStore.Get()
	want := devicestore.Credential{Device: oldCred, IssuerCert: oldIssuerCert}
	if !ok || got != want {
		t.Fatalf("a failed renewal must leave the store untouched, got (%+v, %v)", got, ok)
	}
}

// ---------------------------------------------------------------------------
// setupDeviceCredential (construction)
// ---------------------------------------------------------------------------

func TestSetupDeviceCredential_NonClientRoleGetsNothing(t *testing.T) {
	key, store, err := setupDeviceCredential(Config{}, map[string]bool{RoleExit: true})
	if err != nil {
		t.Fatalf("setupDeviceCredential: %v", err)
	}
	if key != nil || store != nil {
		t.Fatalf("expected (nil, nil) for a non-client role, got (%v, %v)", key, store)
	}
}

func TestSetupDeviceCredential_EmptyDirIsEphemeralAndInMemory(t *testing.T) {
	key, store, err := setupDeviceCredential(Config{}, map[string]bool{RoleClient: true})
	if err != nil {
		t.Fatalf("setupDeviceCredential: %v", err)
	}
	if key == nil || store == nil {
		t.Fatal("expected a usable key and store even with DeviceCredDir empty")
	}
	if _, ok := store.Get(); ok {
		t.Fatal("expected an empty store with nothing provisioned")
	}
}

func TestSetupDeviceCredential_PropagatesKeyLoadError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/device.key", []byte("not hex"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	if _, _, err := setupDeviceCredential(Config{DeviceCredDir: dir}, map[string]bool{RoleClient: true}); err == nil {
		t.Fatal("expected setupDeviceCredential to fail construction on a corrupt key file rather than silently regenerate")
	}
}

var errBoom = &testError{"renewal transport failed"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

// TestRenewalFailureEventTextIsPinned holds one end of a coupling the other end
// cannot hold on its own.
//
// An embedder that fills Config.DeviceRenew sees a failure through its own
// closure and says something useful about it to its user — clients/fyne turns it
// into an escalating sentence with the credential's remaining life in it. This
// event is emitted AFTERWARDS, carrying the transport's own diagnostic, and it
// lands on the same detail line: last writer wins, so a subscription warning
// gets replaced by an HTTP status unless the embedder recognises and drops it.
// clients/fyne does exactly that (its deviceRenewFailedPrefix), which makes this
// message text part of a contract rather than a log line.
//
// Pinning it here is what turns a reword into a red test in the package doing
// the rewording, instead of a silent regression in a user-facing warning.
func TestRenewalFailureEventTextIsPinned(t *testing.T) {
	const pinned = "device credential: renewal failed"

	now := time.Now()
	_, oldIssuerCert, oldCred, devicePriv := mintTestChain(t, now, time.Hour)

	var events []Event
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		OnEvent:      func(ev Event) { events = append(events, ev) },
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			return devicestore.Credential{}, errBoom
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: oldCred, IssuerCert: oldIssuerCert}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.maybeRenewDeviceCred(context.Background(), now)

	var got string
	for _, ev := range events {
		if ev.Kind == EventError {
			got = ev.Message
		}
	}
	if got == "" {
		t.Fatal("a failed renewal emitted no error event")
	}
	if !strings.HasPrefix(got, pinned) {
		t.Fatalf("the renewal-failure event now reads %q; it must start with %q, which clients/fyne matches on to keep this diagnostic from overwriting the user-facing warning it already showed", got, pinned)
	}
}

// ---------------------------------------------------------------------------
// The admission credential rides with the device credential (bacchus#166)
//
// The defect these cover is invisible from either side alone: renewal succeeded,
// the device credential was fresh, the store looked healthy, and network
// membership expired on the ORIGINAL schedule because the admission credential
// minted in the same response over the same window had nowhere to go. Every
// assertion below is therefore about what a PEER received, not about what the
// engine believes it holds.
// ---------------------------------------------------------------------------

// TestRenewalPersistsTheAdmissionCredential is the store half: all three arrive
// in one response and all three are written by one Put.
func TestRenewalPersistsTheAdmissionCredential(t *testing.T) {
	now := time.Now()
	_, _, oldCred, devicePriv := mintTestChain(t, now, time.Hour) // inside the default 6h margin
	_, newIssuerCert, newCred, _ := mintTestChain(t, now, 48*time.Hour)

	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			// What the seam is handed is what the device holds, including the
			// admission credential it is about to replace.
			if req.Current.Admission != "bacchusc1:old-admission" {
				t.Errorf("DeviceRenewRequest.Current.Admission = %q, want the one being replaced", req.Current.Admission)
			}
			return devicestore.Credential{Device: newCred, IssuerCert: newIssuerCert, Admission: "bacchusc1:new-admission"}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     oldCred,
		IssuerCert: "bacchusi1:old-issuer",
		Admission:  "bacchusc1:old-admission",
	}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.maybeRenewDeviceCred(context.Background(), now)

	got, ok := eng.deviceStore.Get()
	if !ok || got.Admission != "bacchusc1:new-admission" {
		t.Fatalf("store after renewal = %+v, want the renewed admission credential", got)
	}
	if eng.admissionCred() != "bacchusc1:new-admission" {
		t.Fatalf("admissionCred() = %q after renewal, want the fresh one", eng.admissionCred())
	}
}

// TestRenewalWithNoAdmissionKeepsTheStoredOne: a deployment can gain an
// admission authority between two renewals, but a response that omitted the
// field is not evidence that what this device already holds was withdrawn —
// withdrawal is what the revocation list is for. Clearing it here would take a
// working client off an admission-enforcing network on the strength of a field
// that was never populated.
func TestRenewalWithNoAdmissionKeepsTheStoredOne(t *testing.T) {
	now := time.Now()
	_, _, oldCred, devicePriv := mintTestChain(t, now, time.Hour)
	_, newIssuerCert, newCred, _ := mintTestChain(t, now, 48*time.Hour)

	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			return devicestore.Credential{Device: newCred, IssuerCert: newIssuerCert}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     oldCred,
		IssuerCert: "bacchusi1:old-issuer",
		Admission:  "bacchusc1:kept",
	}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.maybeRenewDeviceCred(context.Background(), now)

	got, _ := eng.deviceStore.Get()
	if got.Device != newCred {
		t.Fatal("the device credential was not renewed")
	}
	if got.Admission != "bacchusc1:kept" {
		t.Fatalf("Admission = %q after a response that carried none, want the stored one kept", got.Admission)
	}
}

// TestRenewalRefusesAnIncompleteCredential: a seam that answers with no error
// and half a credential would otherwise ERASE a working one.
func TestRenewalRefusesAnIncompleteCredential(t *testing.T) {
	now := time.Now()
	_, oldIssuerCert, oldCred, devicePriv := mintTestChain(t, now, time.Hour)

	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			return devicestore.Credential{Device: "bacchusd1:orphan"}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	want := devicestore.Credential{Device: oldCred, IssuerCert: oldIssuerCert, Admission: "bacchusc1:old"}
	if err := eng.deviceStore.Put(want); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.maybeRenewDeviceCred(context.Background(), now)

	if got, _ := eng.deviceStore.Get(); got != want {
		t.Fatalf("store = %+v after a half-credential renewal, want it untouched (%+v)", got, want)
	}
}

// TestRegisterCarriesTheRenewedAdmissionCredential is the wire half, and the
// one that pins the actual defect: a volunteering client that renews mid-run
// must register with the credential it holds NOW, not the copy its register
// template was built with. registerLoop's template is built once at Start and
// re-sent every ten seconds, so a value baked into it goes stale silently.
func TestRegisterCarriesTheRenewedAdmissionCredential(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	now := time.Now()
	_, _, oldCred, devicePriv := mintTestChain(t, now, time.Hour)
	_, newIssuerCert, newCred, _ := mintTestChain(t, now, 48*time.Hour)

	// A volunteering desktop client: the client role (which owns the device
	// store) plus a serve role (which registers).
	eng, err := New(Config{
		Coordinators: []string{coord.addr()},
		Roles:        []string{RoleClient, RoleRelay},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			return devicestore.Credential{Device: newCred, IssuerCert: newIssuerCert, Admission: "bacchusc1:renewed"}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Seeded BEFORE Start, and this ordering is load-bearing. registerLoop
	// sends its first register the instant it is entered, from its own
	// goroutine, so a store seeded afterwards races it: the engine is a third
	// sender this test does not drive, and asserting on fixed indices of what
	// the coordinator received made this test fail about one run in ten.
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     oldCred,
		IssuerCert: "bacchusi1:old-issuer",
		Admission:  "bacchusc1:enrolled",
	}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)

	regs := []wire{{Type: "register", Role: "relay", ID: eng.cfg.ID}}
	eng.sendRegisters(regs, now)
	eng.maybeRenewDeviceCred(context.Background(), now)
	eng.sendRegisters(regs, now)

	// The registers are UDP to a loopback listener the fixture is already
	// draining; give the second one a moment to land rather than racing it.
	// The assertions below are on the SET rather than on positions, because
	// registerLoop can interleave a register of its own at any point — and
	// with the store seeded first, every register it sends is one of the same
	// two values, so an interleaving cannot make a passing run look like a
	// failing one or the reverse.
	deadline := time.Now().Add(2 * time.Second)
	var sent []string
	renewed := func() bool {
		for _, c := range sent {
			if c == "bacchusc1:renewed" {
				return true
			}
		}
		return false
	}
	for time.Now().Before(deadline) {
		if _, sent = coord.creds(); len(sent) >= 2 && renewed() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(sent) < 2 {
		t.Fatalf("the coordinator saw %d registers, want at least 2", len(sent))
	}
	if !renewed() {
		// The whole of bacchus#166: before the fix the stamp came from
		// Config.AdmissionCred, a construction-time copy, so the freshly
		// minted credential never reached a coordinator at all.
		t.Fatalf("no register carried the freshly minted credential after a renewal; the coordinator saw %q — this is bacchus#166", sent)
	}
	if sent[0] != "bacchusc1:enrolled" {
		t.Fatalf("the first register carried %q, want the credential this device held at the time", sent[0])
	}
	for i, c := range sent {
		if c != "bacchusc1:enrolled" && c != "bacchusc1:renewed" {
			t.Fatalf("register %d carried %q, want one of the two credentials this device has held; an empty one would mean the stamp did not read the store at all", i, c)
		}
	}
	if regs[0].Cred != "" {
		t.Fatal("sendRegisters mutated the caller's template; the stamp must be on a copy")
	}
}

// TestConnectPathCarriesTheRenewedAdmissionCredential is the same property on
// the client's own path: a "challenge" request precedes every gated connect and
// carries this node's admission credential, so it is where an
// admission-enforcing coordinator meets a renewed client first.
func TestConnectPathCarriesTheRenewedAdmissionCredential(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	now := time.Now()
	_, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour)
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     credEnc,
		IssuerCert: issuerCertEnc,
		Admission:  "bacchusc1:enrolled",
	}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}
	if _, ok := eng.presentDeviceCredential(context.Background(), link, 5*time.Second); !ok {
		t.Fatal("presentDeviceCredential failed with a stored credential and a live coordinator")
	}

	// Renewal, out of band: exactly what deviceRenewLoop does under a running
	// engine, which is the case the old code could not survive.
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     credEnc,
		IssuerCert: issuerCertEnc,
		Admission:  "bacchusc1:renewed",
	}); err != nil {
		t.Fatalf("re-Put: %v", err)
	}
	if _, ok := eng.presentDeviceCredential(context.Background(), link, 5*time.Second); !ok {
		t.Fatal("presentDeviceCredential failed after renewal")
	}

	got, _ := coord.creds()
	if len(got) != 2 {
		t.Fatalf("the coordinator saw %d challenge requests, want 2", len(got))
	}
	if got[0] != "bacchusc1:enrolled" || got[1] != "bacchusc1:renewed" {
		t.Fatalf("challenge requests carried %q then %q, want the enrolled then the renewed credential", got[0], got[1])
	}
}

// TestConfiguredAdmissionCredWinsOverTheStore keeps this change additive for
// every deployment that already had one: an operator who set Config.AdmissionCred
// gets exactly the credential they set, and the store is a fallback rather than
// an override.
func TestConfiguredAdmissionCredWinsOverTheStore(t *testing.T) {
	eng, err := New(Config{
		Coordinators:  []string{"127.0.0.1:1"},
		Roles:         []string{RoleClient},
		AdmissionCred: "bacchusc1:operator-minted",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     "bacchusd1:d",
		IssuerCert: "bacchusi1:i",
		Admission:  "bacchusc1:from-the-account-service",
	}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}
	if got := eng.admissionCred(); got != "bacchusc1:operator-minted" {
		t.Fatalf("admissionCred() = %q, want the configured value to win", got)
	}
}

// TestAdmissionCredIsEmptyWithNothingConfiguredAndNothingStored is the
// pre-bacchus#166 posture, byte for byte: a node with no account service and no
// -admission-cred presents none.
func TestAdmissionCredIsEmptyWithNothingConfiguredAndNothingStored(t *testing.T) {
	client, err := New(Config{Coordinators: []string{"127.0.0.1:1"}, Roles: []string{RoleClient}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := client.admissionCred(); got != "" {
		t.Fatalf("admissionCred() = %q on a fresh client, want empty", got)
	}
	// And a pure forwarder, which has no device store at all, must not
	// dereference one.
	fwd, err := New(Config{Coordinators: []string{"127.0.0.1:1"}, Roles: []string{RoleRelay}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if fwd.deviceStore != nil {
		t.Fatal("a pure forwarder was given a device store")
	}
	if got := fwd.admissionCred(); got != "" {
		t.Fatalf("admissionCred() = %q on a pure forwarder, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// Enrollment primitives (bacchus#163, ADR-0056)
// ---------------------------------------------------------------------------

// TestDeviceEnrollmentAndTheEngineUseTheSameFilesIsTheWholePoint is the test
// that would have caught the silent failure this API exists to prevent.
//
// Enrollment writes a credential from OUTSIDE the engine, and the engine reads
// it back at construction. If the two disagreed about the filename — or about
// which key the credential is bound to — enrollment would report success, the
// file would be on disk, and every connect thereafter would present nothing.
// Neither side would log an error, because from each side the operation
// succeeded.
func TestDeviceEnrollmentAndTheEngineUseTheSameFilesIsTheWholePoint(t *testing.T) {
	dir := t.TempDir()

	dev, err := OpenDeviceEnrollment(dir)
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	if dev.Enrolled() {
		t.Fatal("a fresh directory reported an enrolled device")
	}
	if dev.Dir() != dir {
		t.Fatalf("Dir() = %q, want %q", dev.Dir(), dir)
	}

	if err := dev.Put(devicestore.Credential{Device: "bacchusd1:enrolled-out-of-band", IssuerCert: "bacchusi1:its-issuer"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !dev.Enrolled() {
		t.Fatal("Enrolled() is false immediately after Put")
	}

	// The engine, built the way a client builds it, must find exactly that.
	key, store, err := setupDeviceCredential(Config{DeviceCredDir: dir}, map[string]bool{RoleClient: true})
	if err != nil {
		t.Fatalf("setupDeviceCredential: %v", err)
	}
	held, ok := store.Get()
	if !ok {
		t.Fatal("the engine found no credential where enrollment wrote one — the two disagree about the path")
	}
	if held.Device != "bacchusd1:enrolled-out-of-band" || held.IssuerCert != "bacchusi1:its-issuer" {
		t.Fatalf("the engine read back %q / %q", held.Device, held.IssuerCert)
	}
	// And the same key: a credential bound to one key and presented under
	// another is refused by the coordinator with no local sign of why.
	if !key.Public().(ed25519.PublicKey).Equal(dev.DevicePub()) {
		t.Fatal("enrollment and the engine loaded different device keys from one directory")
	}
}

// TestDeviceEnrollmentSignsUnderExactlyOnePurposeEach: a key that signs in four
// contexts is only safe if nothing outside the intended context can produce its
// output, which is why the purpose is a constant at each call site rather than
// an argument a caller supplies.
func TestDeviceEnrollmentSignsUnderExactlyOnePurposeEach(t *testing.T) {
	dev, err := OpenDeviceEnrollment(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	challenge := bytes.Repeat([]byte{7}, 32)
	const audience = "account.example"

	enrollSig, err := dev.SignEnroll(audience, challenge)
	if err != nil {
		t.Fatalf("SignEnroll: %v", err)
	}
	renewSig, err := dev.SignRenew(audience, challenge)
	if err != nil {
		t.Fatalf("SignRenew: %v", err)
	}

	// Each verifies under its own tag...
	if err := devicecred.VerifyAssertion(dev.DevicePub(), purposeEnroll, audience, challenge, enrollSig); err != nil {
		t.Fatalf("the enrollment assertion does not verify under its own purpose: %v", err)
	}
	if err := devicecred.VerifyAssertion(dev.DevicePub(), purposeRenew, audience, challenge, renewSig); err != nil {
		t.Fatalf("the renewal assertion does not verify under its own purpose: %v", err)
	}
	// ...and under no other. A single one of these passing would mean a
	// signature collected for one context is spendable in another.
	for _, tc := range []struct {
		name string
		sig  []byte
		as   devicecred.Purpose
	}{
		{"enroll as renew", enrollSig, purposeRenew},
		{"enroll as connect", enrollSig, devicecred.PurposeConnect},
		{"renew as enroll", renewSig, purposeEnroll},
		{"renew as connect", renewSig, devicecred.PurposeConnect},
	} {
		if err := devicecred.VerifyAssertion(dev.DevicePub(), tc.as, audience, challenge, tc.sig); err == nil {
			t.Fatalf("%s verified; the purpose tag is doing nothing", tc.name)
		}
	}
	// And the audience binds, so an assertion made for one service is useless
	// at another.
	if err := devicecred.VerifyAssertion(dev.DevicePub(), purposeEnroll, "other.example", challenge, enrollSig); err == nil {
		t.Fatal("the enrollment assertion verified under an audience it was never bound to")
	}
}

// TestDeviceEnrollmentRefusesAShortChallenge: the device does not choose the
// challenge and must not sign a weak one, because a signature over a predictable
// value is a reusable token rather than a proof.
func TestDeviceEnrollmentRefusesAShortChallenge(t *testing.T) {
	dev, err := OpenDeviceEnrollment(t.TempDir())
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	if _, err := dev.SignEnroll("account.example", []byte("short")); err == nil {
		t.Fatal("SignEnroll accepted a 5-byte challenge")
	}
	if _, err := dev.SignRenew("account.example", []byte("short")); err == nil {
		t.Fatal("SignRenew accepted a 5-byte challenge")
	}
}

// TestOpenDeviceEnrollmentKeepsTheKeyAcrossOpens: an enrollment binds a
// credential to a public key, so a key regenerated on the next launch would
// strand the entitlement it just bought.
func TestOpenDeviceEnrollmentKeepsTheKeyAcrossOpens(t *testing.T) {
	dir := t.TempDir()
	first, err := OpenDeviceEnrollment(dir)
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	second, err := OpenDeviceEnrollment(dir)
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment (again): %v", err)
	}
	if !first.DevicePub().Equal(second.DevicePub()) {
		t.Fatal("two opens of one directory produced two device identities")
	}
}

// TestOpenDeviceEnrollmentRefusesACorruptKey mirrors setupDeviceCredential's own
// posture: a present-but-broken key file is a hard error, never a silent
// regeneration, because regenerating would orphan whatever credential this
// device already holds with nothing to see from here.
func TestOpenDeviceEnrollmentRefusesACorruptKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device.key"), []byte("not hex"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDeviceEnrollment(dir); err == nil {
		t.Fatal("OpenDeviceEnrollment silently regenerated a corrupt device key")
	}
}

func TestDeviceCredPathIsEmptyForAnEmptyDir(t *testing.T) {
	if got := DeviceCredPath(""); got != "" {
		t.Fatalf("DeviceCredPath(\"\") = %q, want empty (devicestore's in-memory mode)", got)
	}
	if got := DeviceCredPath("/x"); got != filepath.Join("/x", "credential.json") {
		t.Fatalf("DeviceCredPath = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Renewal's first check (issue #184, ADR-0057)
//
// deviceRenewLoop used to wait a full deviceRenewCheckInterval before doing
// anything, and it is started by an engine that a desktop client builds only at
// connect time and tears down about thirty seconds later when the connect is
// refused. So the loop's first action never happened, renewal only ever ran while a
// connect had SUCCEEDED, and a device whose credential had expired — 48 hours without
// connecting, i.e. a weekend — could never renew the credential that was causing the
// refusal. Recovery was an operator minting a fresh claim code for a paid account the
// account service would have renewed on request.
//
// The tests below all prove the fix WITHOUT a ticker, because a test that waited for
// one would take ten minutes and would prove the thing that already worked.
// ---------------------------------------------------------------------------

// renewOnEntryEngine builds a started client engine holding a credential inside its
// renewal margin, with a renewal seam that reports each call on a channel.
func renewOnEntryEngine(t *testing.T, renew func(context.Context, DeviceRenewRequest) (devicestore.Credential, error), seedCred bool) *Engine {
	t.Helper()
	now := time.Now()
	// One hour of life against the default six-hour margin: due, and due by a margin
	// no clock skew in a test can close.
	_, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, time.Hour)
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew:  renew,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	if seedCred {
		if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: issuerCertEnc}); err != nil {
			t.Fatalf("seed device store: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)
	return eng
}

// TestRenewalHappensOnTheLoopsFirstPassNotOnItsFirstTick is #184's headline. A
// started engine holding an in-margin credential must renew it without any tick
// firing — deviceRenewCheckInterval is ten minutes and the engine that starts this
// loop lives for about thirty seconds.
func TestRenewalHappensOnTheLoopsFirstPassNotOnItsFirstTick(t *testing.T) {
	now := time.Now()
	_, freshIssuer, freshCred, _ := mintTestChain(t, now, 48*time.Hour)
	called := make(chan DeviceRenewRequest, 4)
	eng := renewOnEntryEngine(t, func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
		called <- req
		return devicestore.Credential{Device: freshCred, IssuerCert: freshIssuer}, nil
	}, true)

	select {
	case req := <-called:
		if req.Current.Device == "" {
			t.Error("the renewal request did not carry what this device is renewing FROM")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no renewal within 5s of Start. deviceRenewCheckInterval is %s, and the client that starts this loop is torn down in about 30s — so a first check on the first TICK is a check that never happens (#184)", deviceRenewCheckInterval)
	}

	// And the fresh credential was actually persisted, so the next connect presents it.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if held, ok := eng.deviceStore.Get(); ok && held.Device == freshCred {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the renewal ran but the fresh credential was never stored")
}

// TestTheEntryCheckDoesNotEnrollADeviceThatHoldsNothing. maybeRenewDeviceCred returns
// early when the store is empty, and that early return is correct and stays: renewal
// is not enrollment, a claim code is spent exactly once, and the second spend does not
// fail safely. Moving the first check earlier must not turn a device that has never
// enrolled into one that tries to.
func TestTheEntryCheckDoesNotEnrollADeviceThatHoldsNothing(t *testing.T) {
	called := make(chan struct{}, 4)
	renewOnEntryEngine(t, func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
		called <- struct{}{}
		return devicestore.Credential{}, nil
	}, false)

	select {
	case <-called:
		t.Fatal("the entry check called the renewal seam with nothing enrolled — see ADR-0046; renewal is not enrollment")
	case <-time.After(500 * time.Millisecond):
	}
}

// TestTheEntryCheckDoesNotRenewACredentialThatIsNotDue. The margin still decides;
// only the timing of the first look changed.
func TestTheEntryCheckDoesNotRenewACredentialThatIsNotDue(t *testing.T) {
	now := time.Now()
	_, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour) // well past the 6h margin
	called := make(chan struct{}, 4)
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
			called <- struct{}{}
			return devicestore.Credential{}, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(devicestore.Credential{Device: credEnc, IssuerCert: issuerCertEnc}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := eng.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(eng.Stop)

	select {
	case <-called:
		t.Fatal("a credential outside its renewal margin was renewed on entry — the entry check moved WHEN the margin is consulted, not whether")
	case <-time.After(500 * time.Millisecond):
	}
}

// TestStopIsNotHeldByARenewalThatHangs is what the entry check costs and pays for.
// The first call now happens immediately, so a Stop shortly after Start can land on
// an in-flight renewal — and Config.DeviceRenew is an embedder's transport that this
// package does not get to assume returns promptly. Before the entry check the first
// call was ten minutes away and this could not arise; without the shutdown
// cancellation it would hold Stop for deviceRenewCallTimeout, turning a fix for a
// client that tears its engine down quickly into a client that cannot tear it down at
// all.
func TestStopIsNotHeldByARenewalThatHangs(t *testing.T) {
	entered := make(chan struct{})
	var once sync.Once
	eng := renewOnEntryEngine(t, func(ctx context.Context, req DeviceRenewRequest) (devicestore.Credential, error) {
		once.Do(func() { close(entered) })
		<-ctx.Done() // an account service that accepts the connection and never answers
		return devicestore.Credential{}, ctx.Err()
	}, true)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the renewal seam was never called")
	}

	done := make(chan struct{})
	go func() { eng.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("Stop was still blocked 5s in. deviceRenewCallTimeout is %s, so an unreachable account service would hold shutdown for that long", deviceRenewCallTimeout)
	}
}
