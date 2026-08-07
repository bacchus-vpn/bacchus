package main

import (
	"crypto/ed25519"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// The issuer cert rides the challenge (issue #206, ADR-0062).
//
// It is 362 bytes, it is identical for every device from one issuer, and it was
// re-sent on every connect — the lever ADR-0057 named and slice 2 of #175 needed
// pulled before it could spend 37 bytes on a DTLS record. These tests cover the
// coordinator half: what may be held, for how long, and that holding it admits
// nothing a connect would not have had to earn anyway.

// challengeWithCert drives the "challenge" handler with an issuer cert on it and
// returns the issued nonce, which is what a current client's exchange looks like.
func challengeWithCert(t *testing.T, peer *net.UDPConn, src *net.UDPAddr, issuerCert string) string {
	t.Helper()
	handle(wire{Type: "challenge", IssuerCert: issuerCert}, src)
	reply, ok := readReply(t, peer, time.Second)
	if !ok {
		t.Fatal("no reply to a challenge request")
	}
	if reply.Type != "challenge" {
		t.Fatalf("reply type = %q, want challenge", reply.Type)
	}
	return reply.Challenge
}

// connectWithoutCert is connectMsg with the issuer cert stripped: the connect a
// client that speaks #206 actually sends.
func (c testChain) connectWithoutCert(t *testing.T, audience, challenge string) wire {
	t.Helper()
	m := c.connectMsg(t, audience, challenge)
	m.IssuerCert = ""
	return m
}

// TestAConnectWithNoIssuerCertIsAdmittedOnTheStashedOne is the headline: the whole
// exchange, end to end, with the cert only ever on the challenge. If this fails,
// every enrolled client on a coordinator running the gate is refused.
func TestAConnectWithNoIssuerCertIsAdmittedOnTheStashedOne(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	setDeviceGate(t, c.rootPub, "coord-1")
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	ch := challengeWithCert(t, peer, src, c.issuerCert)
	m := c.connectWithoutCert(t, "coord-1", ch)
	m.Nonce = "req-1"
	m.IssuerCert = issuerCertFor(m, src)
	if m.IssuerCert != c.issuerCert {
		t.Fatalf("a connect with no issuer cert resolved %q; want the one its challenge carried", m.IssuerCert)
	}
	if !admitDevice(m, src) {
		reply, _ := readReply(t, peer, 200*time.Millisecond)
		t.Fatalf("the stashed issuer cert did not admit the connect: %s", reply.Reason)
	}
}

// TestAConnectCarryingItsOwnIssuerCertStillSucceeds is the compatibility half. A
// client that predates #206 puts the cert on the connect; nothing about that stopped
// working, and the stash is not consulted for it.
func TestAConnectCarryingItsOwnIssuerCertStillSucceeds(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	setDeviceGate(t, c.rootPub, "coord-1")
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	// The challenge carries none, exactly as a pre-#206 client's does.
	ch := requestChallenge(t, peer, src)
	if got := challenges.stashedIssuerCert(challengeKey(src), time.Now()); got != "" {
		t.Fatalf("a challenge that carried no cert left %q in the stash", got)
	}
	m := c.connectMsg(t, "coord-1", ch)
	m.Nonce = "req-1"
	m.IssuerCert = issuerCertFor(m, src)
	if m.IssuerCert != c.issuerCert {
		t.Fatalf("a connect carrying its own cert resolved %q; want the one it sent", m.IssuerCert)
	}
	if !admitDevice(m, src) {
		reply, _ := readReply(t, peer, 200*time.Millisecond)
		t.Fatalf("a pre-#206 connect was refused: %s", reply.Reason)
	}
}

// TestAConnectCarryingItsOwnIssuerCertIsJudgedOnThatOne. The stash is a fallback,
// not an override — admissionCredFor's rule, and for the same reason: verifying what
// was sent is both the simpler rule and the one a stash cannot be used to bend.
func TestAConnectCarryingItsOwnIssuerCertIsJudgedOnThatOne(t *testing.T) {
	setPC(t)
	stashed := mintChain(t, chainWindow{})
	carried := mintChain(t, chainWindow{})
	setDeviceGate(t, stashed.rootPub, "coord-1")
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	challengeWithCert(t, peer, src, stashed.issuerCert)
	got := issuerCertFor(wire{Type: "connect", IssuerCert: carried.issuerCert}, src)
	if got != carried.issuerCert {
		t.Fatalf("a connect carrying its own issuer cert resolved %q; want the one it sent", got)
	}
}

// TestOnlyACertTheRootSignedIsStashed is the security property, and it is the one
// place this stash differs from the credential stash beside it. An admission
// credential reaches stashCred already verified by admit(); an issuer cert reaches
// stashIssuerCert verified by nothing, so it is verified HERE — against the anchored
// root, which is the only authority that can speak for it.
func TestOnlyACertTheRootSignedIsStashed(t *testing.T) {
	c := mintChain(t, chainWindow{})
	foreign := mintChain(t, chainWindow{}) // a real cert, signed by a root this coordinator does not anchor

	for _, tc := range []struct {
		name string
		cert string
	}{
		{name: "empty", cert: ""},
		{name: "not an envelope", cert: "definitely-not-a-cert"},
		{name: "a well-formed cert from another root", cert: foreign.issuerCert},
		{name: "the envelope with a flipped signature byte", cert: c.issuerCert[:len(c.issuerCert)-2] + "AA"},
		{name: "over the size bound", cert: "bacchusi1:" + strings.Repeat("A", maxStashedIssuerCert)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setPC(t)
			setDeviceGate(t, c.rootPub, "coord-1")
			peer := fakePeer(t)
			src := peer.LocalAddr().(*net.UDPAddr)

			challengeWithCert(t, peer, src, tc.cert)
			if got := challenges.stashedIssuerCert(challengeKey(src), time.Now()); got != "" {
				t.Fatalf("stashed %d bytes of a cert the anchored root did not sign; want nothing kept", len(got))
			}
		})
	}

	// And the control: the cert this coordinator's root DID sign is kept, so the
	// cases above are refusals rather than a stash that never works.
	setPC(t)
	setDeviceGate(t, c.rootPub, "coord-1")
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)
	challengeWithCert(t, peer, src, c.issuerCert)
	if got := challenges.stashedIssuerCert(challengeKey(src), time.Now()); got != c.issuerCert {
		t.Fatalf("the anchored root's own cert was not stashed (got %d bytes)", len(got))
	}
}

// TestARevokedIssuerCertIsNotStashed. Revocation is checked on the way in as well as
// on the way out, so a killed cert does not sit in a bounded store for two minutes
// waiting to be refused.
func TestARevokedIssuerCertIsNotStashed(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	v, err := devicecred.NewVerifier(c.rootPub, func(serial string) bool { return serial == "cccccccccccccccc" })
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	deviceVerifier, deviceAudience = v, "coord-1"
	resetChallenges()
	t.Cleanup(func() { deviceVerifier, deviceAudience = nil, ""; resetChallenges() })

	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)
	challengeWithCert(t, peer, src, c.issuerCert)
	if got := challenges.stashedIssuerCert(challengeKey(src), time.Now()); got != "" {
		t.Fatalf("a revoked issuer cert was stashed (%d bytes)", len(got))
	}
}

// TestTheIssuerCertStashWorksWithAdmissionOFF is the correction #206's own wording
// needed, and the reason it is worth a test of its own rather than a sentence in a
// doc.
//
// The card asks for the cert to be stashed "only under the same condition the
// existing stash uses", which is `admissionVerifier != nil`. Applied literally, a
// deployment running the device-credential gate (#50) with admission (#42) switched
// off — an ordinary configuration — would issue a nonce, receive a connect the
// client had therefore stripped the cert from, hold nothing, and refuse EVERY
// connect. That is the shape of the mistake ADR-0057 §2 had to correct in its own
// ruling: total rather than degraded, and invisible until a real deployment hits it.
func TestTheIssuerCertStashWorksWithAdmissionOFF(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	setDeviceGate(t, c.rootPub, "coord-1") // device gate ON, admission deliberately never set
	if admissionVerifier != nil {
		t.Fatal("this test is only meaningful with admission disabled")
	}
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	ch := challengeWithCert(t, peer, src, c.issuerCert)
	m := c.connectWithoutCert(t, "coord-1", ch)
	m.Nonce = "req-1"
	m.IssuerCert = issuerCertFor(m, src)
	if !admitDevice(m, src) {
		reply, _ := readReply(t, peer, 200*time.Millisecond)
		t.Fatalf("a connect was refused on a device-gate-on / admission-off deployment: %s", reply.Reason)
	}
}

// TestTheStashedIssuerCertDiesWithItsChallenge. The stash has no life of its own: it
// is read out of the challenge entry, so the entry's TTL is its TTL — stashedCred's
// property, restated because a second field could have been given a second lifetime
// by accident.
func TestTheStashedIssuerCertDiesWithItsChallenge(t *testing.T) {
	s := &challengeStore{entries: map[string]pendingChallenge{}}
	now := time.Now()
	if v := s.issue("peer", "", "bacchusi1:whatever", now); v == nil {
		t.Fatal("issue returned nothing")
	}
	if got := s.stashedIssuerCert("peer", now.Add(deviceChallengeTTL-time.Nanosecond)); got == "" {
		t.Fatal("the stash expired before its challenge did")
	}
	if got := s.stashedIssuerCert("peer", now.Add(deviceChallengeTTL)); got != "" {
		t.Fatalf("a challenge exactly at its expiry still yielded %q", got)
	}
	if got := s.stashedIssuerCert("someone-else", now); got != "" {
		t.Fatalf("a source with no outstanding challenge yielded %q — the stash is per-source or it is nothing", got)
	}
}

// TestASecondChallengeReplacesTheStashedIssuerCert. issue() replaces an outstanding
// entry wholesale, because a client that asks twice is retrying and only the newest
// nonce is honoured. The cert must travel with it rather than survive from the
// previous request — a stale cert paired with a fresh nonce is a combination nothing
// sent.
func TestASecondChallengeReplacesTheStashedIssuerCert(t *testing.T) {
	setPC(t)
	first := mintChain(t, chainWindow{})
	setDeviceGate(t, first.rootPub, "coord-1")
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	challengeWithCert(t, peer, src, first.issuerCert)
	challengeWithCert(t, peer, src, "") // a retry from a client with nothing to present
	if got := challenges.stashedIssuerCert(challengeKey(src), time.Now()); got != "" {
		t.Fatalf("the previous request's issuer cert survived a fresh challenge: %q", got)
	}
}

// TestTheIssuerCertStashCannotOutliveTheDeviceGate. An entry exists only while the
// device gate is enabled — issueDeviceChallenge returns before touching the store
// otherwise — so a connect that reads from this stash must still pass admitDevice,
// which requires an assertion over the nonce this coordinator issued to this source.
// A blind spoofer cannot see the reply, cannot produce one, and therefore cannot
// spend a stashed cert. That is the whole argument for why holding it widens nothing.
func TestTheIssuerCertStashCannotOutliveTheDeviceGate(t *testing.T) {
	setPC(t)
	c := mintChain(t, chainWindow{})
	pub, priv, _ := ed25519.GenerateKey(nil)
	setAdmission(t, pub, nil)
	_, cred := issueCred(t, priv, "device-1", admission.RoleClient)
	resetChallenges()
	peer := fakePeer(t)
	src := peer.LocalAddr().(*net.UDPAddr)

	if deviceVerifier != nil {
		t.Fatal("the device gate should be disabled here")
	}
	handle(wire{Type: "challenge", Cred: cred, IssuerCert: c.issuerCert}, src)
	if _, ok := readReply(t, peer, time.Second); !ok {
		t.Fatal("no reply to a challenge request")
	}
	if got := challenges.stashedIssuerCert(challengeKey(src), time.Now()); got != "" {
		t.Fatalf("an issuer cert was stashed with the device gate disabled: %q", got)
	}
}
