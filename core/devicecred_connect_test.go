package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// ---------------------------------------------------------------------------
// Test fixtures: a throwaway root -> issuer cert -> device credential chain,
// minted using only devicecred's exported API (types, tag constants, envelope
// encoders) plus stdlib crypto. Self-contained on purpose: these tests must not
// depend on core/devicecred's own frozen testdata clock, and must not need any
// change to that package to construct a chain its real Verifier accepts.
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
	issuerCertEnc = devicecred.EncodeIssuerCert(signBody(rootPriv, devicecred.TagIssuerCert, certBody))

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
	credEnc = devicecred.EncodeDeviceCredential(signBody(issuerPriv, devicecred.TagDeviceCred, credBody))

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

	mu              sync.Mutex
	challengeReqs   int
	connects        []wire
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
	f := &fakeDeviceCoordinator{pc: pc, answerChallenge: true}
	go f.serve()
	return f
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
		switch m.Type {
		case "challenge":
			f.mu.Lock()
			f.challengeReqs++
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
	if err := eng.deviceStore.Put(credEnc, issuerCertEnc); err != nil {
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
	if err := eng.deviceStore.Put(credEnc, issuerCertEnc); err != nil {
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
	if err := eng.deviceStore.Put(credEnc, "bacchusi1:whatever"); err != nil {
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
	if err := eng.deviceStore.Put(credEnc, "bacchusi1:whatever"); err != nil {
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
	if err := eng.deviceStore.Put(credEnc, "bacchusi1:whatever"); err != nil {
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
	if err := eng.deviceStore.Put(credEnc, "bacchusi1:whatever"); err != nil {
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
	if err := eng.deviceStore.Put(credEnc, "bacchusi1:whatever"); err != nil {
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
	if err := eng.deviceStore.Put(credEnc, "bacchusi1:whatever"); err != nil {
		t.Fatalf("seed device store: %v", err)
	}
	eng.maybeRenewDeviceCred(context.Background(), time.Now()) // must not panic with DeviceRenew == nil
	gotCred, _, _ := eng.deviceStore.Get()
	if gotCred != credEnc {
		t.Fatal("store must be unchanged when no renewal seam is configured")
	}
}

func TestMaybeRenewDeviceCred_NothingStoredYet(t *testing.T) {
	called := false
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (string, string, error) {
			called = true
			return "", "", nil
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
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (string, string, error) {
			called = true
			return "", "", nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	_, _, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour) // well past the default 6h margin
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(credEnc, "bacchusi1:whatever"); err != nil {
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

	var gotReq DeviceRenewRequest
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (string, string, error) {
			gotReq = req
			return newCred, newIssuerCert, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(oldCred, "bacchusi1:old-issuer"); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.maybeRenewDeviceCred(context.Background(), now)

	gotCred, gotIssuerCert, ok := eng.deviceStore.Get()
	if !ok || gotCred != newCred || gotIssuerCert != newIssuerCert {
		t.Fatalf("store after renewal = (%q, %q, %v), want the renewed pair", gotCred, gotIssuerCert, ok)
	}
	if string(gotReq.DevicePub) != string(devicePriv.Public().(ed25519.PublicKey)) {
		t.Fatal("DeviceRenewRequest.DevicePub did not match this device's own public key")
	}
	if gotReq.CurrentCred != oldCred {
		t.Fatalf("DeviceRenewRequest.CurrentCred = %q, want the credential about to expire", gotReq.CurrentCred)
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
		DeviceRenew: func(ctx context.Context, req DeviceRenewRequest) (string, string, error) {
			return "", "", errBoom
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng.deviceKey = devicePriv
	if err := eng.deviceStore.Put(oldCred, oldIssuerCert); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.maybeRenewDeviceCred(context.Background(), now)

	gotCred, gotIssuerCert, ok := eng.deviceStore.Get()
	if !ok || gotCred != oldCred || gotIssuerCert != oldIssuerCert {
		t.Fatalf("a failed renewal must leave the store untouched, got (%q, %q, %v)", gotCred, gotIssuerCert, ok)
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
	if _, _, ok := store.Get(); ok {
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
