package core

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
)

// The rendezvous datagram budget and the send-error reporting (issue #183,
// ADR-0057).
//
// Nothing in this repository can reproduce the original failure by running it:
// loopback's MTU is 65536, so a 1453-byte connect is delivered here exactly as
// happily as a 40-byte one, which is why the defect survived unit tests, both PR CI
// runs and a combination build and was found by a person on real hardware. Every
// test below is therefore built to constrain the datagram DIRECTLY — against a named
// constant, on bytes actually written to a socket — rather than to hope a transport
// surfaces the problem.

// prodSizedAdmissionCred mints an admission credential the size the account service
// really issues. The number matters: this file's asserts are only worth anything if
// the fixture is at least as heavy as production, and a test that quietly used a
// short credential would report headroom nobody has.
//
// The reference measurement is the testbed proxy in issue #183, which saw a
// `challenge` grow from 20 bytes to 443 when bacchus#166 first populated this field
// — 413 bytes of credential. The credential below is minted with a full-length
// serial, a 64-hex-character subject and the account service's trust/plan/vouched
// stamps, and comes out slightly larger than that.
func prodSizedAdmissionCred(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate admission key: %v", err)
	}
	now := time.Now()
	signed, err := admission.Sign(priv, admission.Credential{
		Version:   admission.CredentialVersion,
		Serial:    "0123456789abcdef",
		Subject:   "b8f0c2e4a6d81357b8f0c2e4a6d81357b8f0c2e4a6d81357b8f0c2e4a6d81357",
		Roles:     []admission.Role{admission.RoleClient},
		NotBefore: now.Add(-time.Hour).UTC(),
		NotAfter:  now.Add(47 * time.Hour).UTC(),
		Vouched:   true,
		Trust:     "vouched",
		Plan:      "standard",
	})
	if err != nil {
		t.Fatalf("sign admission credential: %v", err)
	}
	enc := admission.Encode(signed)
	if len(enc) < 400 {
		t.Fatalf("the fixture credential is %d bytes, below the ~413 measured on the testbed — every size assert below would be reporting headroom that does not exist", len(enc))
	}
	return enc
}

// TestConnectDatagramFitsASafePath is issue #183's headline and the test that fails
// if the connect grows back.
//
// It asserts on the bytes a real attemptWith wrote to a real socket, with a device
// credential chain and a production-sized admission credential both in play — the
// exact configuration that measured 1453 bytes on the testbed, which needs a
// 1481-byte IP datagram and does not fit Tailscale's 1280, the IPv6 minimum MTU, or a
// clamped mobile path.
func TestConnectDatagramFitsASafePath(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	now := time.Now()
	_, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour)
	eng.deviceKey = devicePriv
	admissionEnc := prodSizedAdmissionCred(t)
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     credEnc,
		IssuerCert: issuerCertEnc,
		Admission:  admissionEnc,
	}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	// A CHAINED relay request with an excluded session: the largest connect this
	// client can assemble. firstHop is a 64-character node id and country is dropped,
	// so it is a net ~60 bytes heavier than an ordinary direct connect. exclude is
	// capped by countryAttempts, which puts at most one session id on the wire.
	req := connectReq{
		mode:    modeRelay,
		exclude: []string{"0123456789abcdef"},
		plan: &chainPlan{hops: []relayHop{
			{id: "3b1f0c9d2e7a4b6c8d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e"},
		}},
	}
	// The fake coordinator answers the challenge and then says nothing, so this
	// returns on the session deadline. The bytes are what the test is here for.
	eng.attemptWith(context.Background(), link, req, eng.transport, time.Second, nil)

	if got := coord.sizesOf("challenge"); len(got) == 0 {
		t.Fatal("no challenge was sent, so this measured the wrong path entirely")
	}
	sizes := coord.sizesOf("connect")
	if len(sizes) == 0 {
		t.Fatal("the coordinator saw no connect at all")
	}
	for i, n := range sizes {
		if n > maxRendezvousPayload {
			t.Fatalf("connect copy %d is %d bytes, over the %d-byte payload that fits a %d-byte path (it needs a %d-byte IP datagram). This is issue #183: it is delivered on Ethernet and refused on Tailscale, on the IPv6 minimum MTU, and on a clamped mobile link",
				i+1, n, maxRendezvousPayload, safePathMTU, n+28)
		}
	}
	t.Logf("largest connect this client can build: %d bytes of a %d-byte budget (%d bytes of headroom)",
		sizes[0], maxRendezvousPayload, maxRendezvousPayload-sizes[0])
}

// TestTheFieldsThatMovedOffTheConnectAreWhatOverflowedThePath pins the causality,
// not just the result. The connect fits because two fields no longer ride it — the
// admission credential (issue #183) and the issuer cert (issue #206) — and without
// this the test above would still pass on a day both happened to be small, with the
// margin gone the next time the account service added a field.
//
// It restores BOTH, and that is a correction #206 forced on the shape this test had.
// It used to restore the admission credential alone, because at the time that was
// the whole of the difference; with the issuer cert also gone, the same
// reconstruction now measures ~1065 bytes and FITS, so a test that still restored
// one copy would have quietly stopped asserting anything. The claim being protected
// was never "the credential is 200 bytes over" — it is "what this connect no longer
// carries is what put it over a real path", and that claim needs every field that
// left.
func TestTheFieldsThatMovedOffTheConnectAreWhatOverflowedThePath(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	now := time.Now()
	_, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour)
	eng.deviceKey = devicePriv
	admissionEnc := prodSizedAdmissionCred(t)
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     credEnc,
		IssuerCert: issuerCertEnc,
		Admission:  admissionEnc,
	}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)

	_, connects := coord.snapshot()
	if len(connects) == 0 {
		t.Fatal("the coordinator saw no connect at all")
	}
	sent := connects[0]
	if sent.Cred != "" {
		t.Fatalf("the connect carried the admission credential (%d bytes) even though its challenge did — this is the second copy issue #183 is about", len(sent.Cred))
	}
	if sent.IssuerCert != "" {
		t.Fatalf("the connect carried the issuer cert (%d bytes) — it rides the challenge as of issue #206", len(sent.IssuerCert))
	}

	// The pre-#183/pre-#206 shape, reconstructed from the wire that was actually
	// sent, one field at a time so each one's cost is a measured number rather than
	// a share of a total.
	base, err := json.Marshal(sent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sent.IssuerCert = issuerCertEnc
	withCert, err := json.Marshal(sent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if cost := len(withCert) - len(base); cost < 362 {
		t.Fatalf("putting the issuer cert back on the connect cost %d bytes; ADR-0057 measured 362, so either the fixture cert is smaller than the account service's or this is no longer measuring the field #206 moved", cost)
	}
	sent.Cred = admissionEnc
	both, err := json.Marshal(sent)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(both) <= maxRendezvousPayload {
		t.Fatalf("the same connect WITH both the admission credential and the issuer cert is %d bytes, still inside the %d-byte budget. Either the fixtures have shrunk below what the account service issues, or this test is no longer measuring what made #183 happen",
			len(both), maxRendezvousPayload)
	}
	t.Logf("connect as sent: %d bytes; + issuer cert: %d (+%d, issue #206); + admission credential: %d (%d over the %d-byte budget, issue #183)",
		len(base), len(withCert), len(withCert)-len(base), len(both), len(both)-maxRendezvousPayload, maxRendezvousPayload)
}

// TestChallengeCarriesTheAdmissionCredentialAndTheConnectDoesNot is the wire contract
// D1's ruling turns on, stated as one assertion over both messages of one exchange.
func TestChallengeCarriesTheAdmissionCredentialAndTheConnectDoesNot(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	now := time.Now()
	_, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour)
	eng.deviceKey = devicePriv
	admissionEnc := prodSizedAdmissionCred(t)
	if err := eng.deviceStore.Put(devicestore.Credential{
		Device:     credEnc,
		IssuerCert: issuerCertEnc,
		Admission:  admissionEnc,
	}); err != nil {
		t.Fatalf("seed device store: %v", err)
	}

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)

	challenges, _ := coord.creds()
	if len(challenges) == 0 {
		t.Fatal("no challenge was sent")
	}
	if challenges[0] != admissionEnc {
		t.Fatalf("the challenge carried %q; want the stored admission credential — with nothing on the challenge and nothing on the connect, an admission-enforcing coordinator refuses every connect", challenges[0])
	}
	_, connects := coord.snapshot()
	for i, c := range connects {
		if c.Cred != "" {
			t.Fatalf("connect copy %d still carries the admission credential", i+1)
		}
		// The device-credential fields that stayed must still be there. The issuer
		// cert is deliberately not among them — it moved to the challenge under
		// issue #206, which TestTheIssuerCertRidesTheChallengeAndNotTheConnect pins.
		if c.Challenge == "" || c.DeviceCred == "" || c.DeviceAssert == "" {
			t.Fatalf("connect copy %d lost a device-credential field: %+v", i+1, c)
		}
	}
}

// TestTheIssuerCertRidesTheChallengeAndNotTheConnect is issue #206's wire contract,
// stated as one assertion over both messages of one exchange — the shape
// TestChallengeCarriesTheAdmissionCredentialAndTheConnectDoesNot established for the
// admission credential, applied to the field ADR-0057 named as the next lever.
//
// Unlike the admission credential this is UNCONDITIONAL, and the asymmetry is worth
// pinning rather than assuming. The credential has to ride a connect whenever no
// challenge was answered, because the coordinator may have no state for this source
// and admission would refuse it. The issuer cert has no such case: it only ever went
// out on a connect that presentDeviceCredential had already succeeded for, so a
// connect with no answered challenge never carried one to begin with.
func TestTheIssuerCertRidesTheChallengeAndNotTheConnect(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

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

	eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)

	certs := coord.issuerCerts()
	if len(certs) == 0 {
		t.Fatal("no challenge was sent")
	}
	if certs[0] != issuerCertEnc {
		t.Fatalf("the challenge carried issuerCert=%q; want the stored one — with it on neither message the coordinator holds no tier-one cert and refuses every connect", certs[0])
	}
	_, connects := coord.snapshot()
	if len(connects) == 0 {
		t.Fatal("the coordinator saw no connect at all")
	}
	for i, c := range connects {
		if c.IssuerCert != "" {
			t.Fatalf("connect copy %d still carries the issuer cert (%d bytes)", i+1, len(c.IssuerCert))
		}
		// What is left of the chain must still be on the connect: the assertion and
		// the credential are per-device and per-connect, and moving THEM would move a
		// proof away from the thing it proves.
		if c.Challenge == "" || c.DeviceCred == "" || c.DeviceAssert == "" {
			t.Fatalf("connect copy %d lost a device-credential field: %+v", i+1, c)
		}
	}
}

// minConnectHeadroom is the slack this build's largest connect must leave under the
// rendezvous budget, and it exists so that a field added later cannot spend the room
// issue #206 recovered without somebody deciding to.
//
// The number is measured rather than chosen. Moving the issuer cert off the connect
// took the largest connect this client can assemble from 1097 bytes to 719, so the
// headroom under the 1232-byte budget went from 135 to 513. ADR-0057 records that
// production credentials measured ~34 bytes heavier than these fixtures, and
// ADR-0059 measured DTLS records at 37 bytes, both of which come out of that 513
// once slice 2's shaped hop carries this datagram. 400 is the floor that leaves,
// rounded down.
//
// Raising it is a decision about the budget and should read like one. This is not a
// number to bump because a test went red.
const minConnectHeadroom = 400

// TestTheRecoveredHeadroomIsAsserted is the other half of issue #206's "done when",
// and it is the half ADR-0057 did not have. That record pinned the connect against
// maxRendezvousPayload, which catches the moment the datagram stops fitting and not a
// byte sooner — so a field that spent 130 of the 135 bytes then available would have
// shipped green. #206 bought roughly 378 bytes back; this is what stops them being
// spent one silent field at a time.
func TestTheRecoveredHeadroomIsAsserted(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

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

	// The same largest-possible connect TestConnectDatagramFitsASafePath builds: a
	// chained relay request with an excluded session and the full device chain.
	req := connectReq{
		mode:    modeRelay,
		exclude: []string{"0123456789abcdef"},
		plan: &chainPlan{hops: []relayHop{
			{id: "3b1f0c9d2e7a4b6c8d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e"},
		}},
	}
	eng.attemptWith(context.Background(), link, req, eng.transport, time.Second, nil)

	sizes := coord.sizesOf("connect")
	if len(sizes) == 0 {
		t.Fatal("the coordinator saw no connect at all")
	}
	if got := maxRendezvousPayload - sizes[0]; got < minConnectHeadroom {
		t.Fatalf("the largest connect is %d bytes, leaving %d of headroom under the %d-byte budget; this build is required to leave at least %d. Something has spent the room issue #206 recovered — if that was deliberate, move minConnectHeadroom and say why in the same change",
			sizes[0], got, maxRendezvousPayload, minConnectHeadroom)
	}
	t.Logf("largest connect: %d bytes, %d of headroom under the %d-byte budget (floor %d)",
		sizes[0], maxRendezvousPayload-sizes[0], maxRendezvousPayload, minConnectHeadroom)
}

// TestConnectStillCarriesTheAdmissionCredentialWhenNoChallengeWasAnswered is the
// correction this lane made to D1's condition, and it is the case that would have
// broken a real deployment.
//
// D1 ruled the credential onto the challenge "and connect carries it only on the path
// where no challenge was SENT". But presentDeviceCredential sends a challenge whenever
// this device holds a credential — it cannot see the coordinator's gate. On a
// deployment running admission (#42) with the device-credential gate (#50) switched
// off, the challenge goes out, the coordinator answers with an EMPTY challenge and
// stores nothing, and a client that reasoned "I sent a challenge, so I need not send
// the credential" would have every connect refused by admission. The condition is a
// challenge ANSWERED, not a challenge sent.
func TestConnectStillCarriesTheAdmissionCredentialWhenNoChallengeWasAnswered(t *testing.T) {
	for _, tc := range []struct {
		name          string
		answer, empty bool
	}{
		// The gate is off, or the coordinator's challenge store is at capacity: both
		// answer with an empty challenge and both store nothing.
		{name: "gate disabled or store full", answer: true, empty: true},
		// The reply was lost. The coordinator MAY hold state; this client cannot know,
		// and carrying the credential is free of consequence where it does.
		{name: "challenge reply lost", answer: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			coord := newFakeDeviceCoordinator(t)
			coord.setBehavior(tc.answer, tc.empty)
			eng, link := newTestClientEngine(t, coord.addr())

			now := time.Now()
			_, issuerCertEnc, credEnc, devicePriv := mintTestChain(t, now, 48*time.Hour)
			eng.deviceKey = devicePriv
			admissionEnc := prodSizedAdmissionCred(t)
			if err := eng.deviceStore.Put(devicestore.Credential{
				Device:     credEnc,
				IssuerCert: issuerCertEnc,
				Admission:  admissionEnc,
			}); err != nil {
				t.Fatalf("seed device store: %v", err)
			}

			eng.attemptWith(context.Background(), link, connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)

			_, connects := coord.snapshot()
			if len(connects) == 0 {
				t.Fatal("the coordinator saw no connect at all")
			}
			for i, c := range connects {
				if c.Cred != admissionEnc {
					t.Fatalf("connect copy %d carries Cred=%q; want the admission credential — no challenge was answered, so this connect is the only place it can be and an admission-enforcing coordinator refuses it without one", i+1, c.Cred)
				}
			}
		})
	}
}

// TestAClientWithNoDeviceCredentialStillCarriesTheAdmissionCredential covers the
// plain path D1 did name: no device store entry, so no challenge is sent at all.
func TestAClientWithNoDeviceCredentialStillCarriesTheAdmissionCredential(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	admissionEnc := prodSizedAdmissionCred(t)
	eng, err := New(Config{
		Coordinators:  []string{coord.addr()},
		Roles:         []string{RoleClient},
		AdmissionCred: admissionEnc,
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

	eng.attemptWith(context.Background(), eng.links[0], connectReq{country: "NL", mode: modeDirect}, eng.transport, time.Second, nil)

	if reqs, _ := coord.snapshot(); reqs != 0 {
		t.Fatalf("a client with nothing stored sent %d challenge requests; want none", reqs)
	}
	_, connects := coord.snapshot()
	if len(connects) == 0 {
		t.Fatal("the coordinator saw no connect at all")
	}
	for i, c := range connects {
		if c.Cred != admissionEnc {
			t.Fatalf("connect copy %d carries Cred=%q; want the configured admission credential", i+1, c.Cred)
		}
	}
}

// ---------------------------------------------------------------------------
// The write error the client used to discard (issue #183's separable half)
// ---------------------------------------------------------------------------

// eventSink builds an engine that records every event it emits, without starting it.
// emit needs no running engine, and not starting one keeps these tests free of
// goroutines racing the recorder.
func eventSink(t *testing.T) (*Engine, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var msgs []string
	eng, err := New(Config{
		Coordinators: []string{"127.0.0.1:1"},
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
	return eng, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), msgs...)
	}
}

// wrapWriteErr reproduces how the net package hands a socket errno back — through a
// *net.OpError around an *os.SyscallError — so the classification below is tested on
// the shape it will actually meet rather than on a bare errno.
func wrapWriteErr(errno syscall.Errno) error {
	return &net.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("write", errno)}
}

// TestOnlyASizeRefusalChangesWhatTheClientConcludes is the correction the existing
// suite forced on the first version of this change, and the reason the control-flow
// signal is EMSGSIZE and not "the write failed".
//
// A connected UDP socket reports a dead peer's ICMP port-unreachable as ECONNREFUSED
// on the NEXT write. So an unreachable coordinator — the exact condition
// ErrNoCoordinatorReachable names and mesh-walk exists to recover from — also fails
// the write. Counting every write error would have reclassified it, and the repository
// noticed: TestConnectWithNoCountryFailsAgainstAnUnreachableCoordinator went red.
func TestOnlyASizeRefusalChangesWhatTheClientConcludes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		counted bool
	}{
		{name: "EMSGSIZE", err: wrapWriteErr(syscall.EMSGSIZE), counted: true},
		// Windows returns WSAEMSGSIZE, and syscall.EMSGSIZE on that platform is one of
		// the "invented values to support what package os expects" — a number no socket
		// produces. The public syscall package does not export WSAEMSGSIZE, so this is
		// the only place the mapping can be asserted, and it can only be asserted by
		// number. Without this row, #183's fix would be silently inert on Windows.
		{name: "WSAEMSGSIZE (Windows)", err: wrapWriteErr(syscall.Errno(10040)), counted: true},
		{name: "ECONNREFUSED — an unreachable coordinator", err: wrapWriteErr(syscall.ECONNREFUSED), counted: false},
		{name: "EHOSTUNREACH", err: wrapWriteErr(syscall.EHOSTUNREACH), counted: false},
		{name: "ENETUNREACH", err: wrapWriteErr(syscall.ENETUNREACH), counted: false},
		{name: "socket closed under a shutdown", err: net.ErrClosed, counted: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng, events := eventSink(t)
			l := &coordLink{raw: "198.51.100.7:8080"}
			mark := l.tooLargeMark()
			l.noteSendFailed(eng, "connect", 1453, tc.err)

			if got := l.refusedForSize(mark); got != tc.counted {
				t.Fatalf("refusedForSize = %v, want %v — this decides whether the client reports a path limit or an unreachable coordinator, and mesh-walk hangs off the difference", got, tc.counted)
			}
			// Logged either way: a datagram that never left the host is worth a line
			// whatever refused it. Before #183 there was no line at all.
			if got := events(); len(got) != 1 {
				t.Fatalf("emitted %d events, want exactly 1: %v", len(got), got)
			}
		})
	}
}

// TestASizeRefusalNamesTheSizeAndTheFloor. The card's whole complaint is that a
// client holding a complete diagnosis reported something else, so the diagnosis has
// to actually contain the numbers a user can act on.
func TestASizeRefusalNamesTheSizeAndTheFloor(t *testing.T) {
	eng, events := eventSink(t)
	l := &coordLink{raw: "198.51.100.7:8080"}
	l.noteSendFailed(eng, "connect", 1453, wrapWriteErr(syscall.EMSGSIZE))

	got := events()
	if len(got) != 1 {
		t.Fatalf("emitted %d events, want 1: %v", len(got), got)
	}
	for _, want := range []string{"1453", "1481", "1280", "connect", "198.51.100.7:8080"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("the diagnosis does not mention %q — a user reading it cannot act on it:\n%s", want, got[0])
		}
	}
	// And it must actively deny the diagnosis the client used to produce. "No
	// coordinator reachable" is what a user on a censored network reports, and it is
	// what sent this issue's reporter looking at the coordinator for two hours; a
	// message that merely omits it leaves the user to supply it themselves.
	if !strings.Contains(got[0], "not a blocked or unreachable coordinator") {
		t.Errorf("the diagnosis does not rule out the coordinator, which is the conclusion a user reaches unaided:\n%s", got[0])
	}
	if strings.Contains(got[0], ErrNoCoordinatorReachable.Error()) {
		t.Errorf("the diagnosis repeats the mesh-walk sentinel's text for a datagram that never left the host:\n%s", got[0])
	}
}

// TestARepeatedRefusalIsLoggedOnceAndCountedEveryTime. sendN puts three copies of
// every connect on the wire and the client retries across the pool, so an unmemoized
// line here would flood the log — and a flooded log is as good as a silent one. The
// COUNT has to keep moving regardless, or the second attempt's leg would read the
// refusal as silence.
func TestARepeatedRefusalIsLoggedOnceAndCountedEveryTime(t *testing.T) {
	eng, events := eventSink(t)
	l := &coordLink{raw: "198.51.100.7:8080"}
	for i := 0; i < 3; i++ {
		mark := l.tooLargeMark()
		l.noteSendFailed(eng, "connect", 1453, wrapWriteErr(syscall.EMSGSIZE))
		if !l.refusedForSize(mark) {
			t.Fatalf("refusal %d was not counted — the memo must bound logging, never the signal", i+1)
		}
	}
	if got := events(); len(got) != 1 {
		t.Fatalf("emitted %d events for three copies of one connect, want 1: %v", len(got), got)
	}
	// A different message type is a different condition and gets its own line.
	l.noteSendFailed(eng, "list", 438, wrapWriteErr(syscall.EMSGSIZE))
	if got := events(); len(got) != 2 {
		t.Fatalf("emitted %d events after a second message type, want 2: %v", len(got), got)
	}
}

// TestTheKernelReallyReturnsASizeRefusalThisBuildRecognises closes the loop between
// the synthetic errors above and a real socket. It is the one place isMessageTooLong
// meets an errno this build did not construct itself.
//
// It has to go via the UDP maximum (65507 bytes) rather than via a small MTU, because
// loopback's MTU is 65536 and there is no smaller path to be had in a test — which is
// verified fact 7 and the reason #183 was invisible here.
func TestTheKernelReallyReturnsASizeRefusalThisBuildRecognises(t *testing.T) {
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer peer.Close()
	conn, err := net.DialUDP("udp", nil, peer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(make([]byte, 70000))
	if err == nil {
		t.Skip("this platform accepted a 70000-byte datagram; there is no oversize refusal to recognise here")
	}
	if !isMessageTooLong(err) {
		t.Fatalf("the kernel refused a 70000-byte datagram with %v, which this build does not recognise as a size refusal — #183's diagnosis would never fire on this platform", err)
	}
}

// TestAConnectRefusedForSizeIsNotReportedAsASilentCoordinator is issue #183's
// headline behaviour: the client must not turn a datagram it never sent into "no
// coordinator reachable", which is the mesh-walk trigger and the sentence a user on a
// censored network will believe and report.
//
// The oversize is forced through the country field rather than through a real 1280
// path, for the reason above: loopback has no small MTU, so the only reachable
// EMSGSIZE here is above the UDP maximum. What is under test is the classification,
// which is identical either way.
func TestAConnectRefusedForSizeIsNotReportedAsASilentCoordinator(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, link := newTestClientEngine(t, coord.addr())

	r := eng.attemptWith(context.Background(), link,
		connectReq{country: strings.Repeat("x", 70000), mode: modeDirect},
		eng.transport, time.Second, nil)

	if r.outcome == coordinatorSilent {
		t.Fatal("a connect the socket refused was reported as a silent coordinator — this is the misdiagnosis #183 is about, and it is what triggers mesh-walk against a healthy pool")
	}
	if r.outcome != requestTooLarge {
		t.Fatalf("outcome = %v, want requestTooLarge", r.outcome)
	}
	if got := coord.sizesOf("connect"); len(got) != 0 {
		t.Fatalf("the coordinator received %d connects; the point of this test is that none was sent", len(got))
	}
}

// TestAnOversizedDatagramIsFlaggedEvenOnAPathThatCarriesIt is the check that does not
// need a small path — the one that would have caught #166's +423 bytes on a
// developer's own machine, on the day it merged, instead of on real hardware two days
// later.
func TestAnOversizedDatagramIsFlaggedEvenOnAPathThatCarriesIt(t *testing.T) {
	coord := newFakeDeviceCoordinator(t)
	eng, events := eventSink(t)
	links, err := dialPool([]string{coord.addr()}, func(string, error) {})
	if err != nil {
		t.Fatalf("dialPool: %v", err)
	}
	l := links[0]
	defer l.conn.Close()

	// Comfortably over the budget and comfortably under loopback's MTU: this datagram
	// is DELIVERED, and must still be reported.
	mark := l.tooLargeMark()
	l.send(eng, wire{Type: "connect", Country: strings.Repeat("x", 2000)})

	got := events()
	if len(got) != 1 {
		t.Fatalf("emitted %d events for a datagram over the budget, want 1: %v", len(got), got)
	}
	if !strings.Contains(got[0], "#183") || !strings.Contains(got[0], "1232") {
		t.Errorf("the warning does not name the budget or the issue:\n%s", got[0])
	}
	// It is a warning about a datagram that WAS sent, so it must not move the signal
	// that decides whether a connect is reported as undeliverable.
	if l.refusedForSize(mark) {
		t.Fatal("an oversize warning counted as a refusal — a datagram that arrived must not make the client report a path limit")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(coord.sizesOf("connect")) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the oversized datagram never arrived, so this test proved nothing about a path that carries it")
}
