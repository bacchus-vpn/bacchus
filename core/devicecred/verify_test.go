package devicecred_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// The frozen vectors pin the WIRE FORMAT. These tests pin the DECISIONS around it
// — ordering, boundaries, and the bindings — which no fixture can express, because
// a fixture can only say "this chain is refused", not "it is refused for the first
// of the three reasons it is wrong".
//
// Chains here are minted locally against a per-test root, so a test can place a
// window, a cap or a serial exactly where the boundary is.

// b64 is the encoding the fixtures and these tests use for raw key bytes.
var b64 = base64.StdEncoding

// signObject builds the wire form of a signed object: body || sig, where sig
// covers tag || 0x00 || body.
//
// The framing is written out independently here rather than reached for inside the
// package, so these tests would still fail if the package changed its framing —
// and it is only safe to hand-roll because the frozen vectors pin the same framing
// against an implementation written elsewhere.
func signObject(t *testing.T, priv ed25519.PrivateKey, tag string, body []byte) []byte {
	t.Helper()
	msg := make([]byte, 0, len(tag)+1+len(body))
	msg = append(msg, tag...)
	msg = append(msg, 0x00)
	msg = append(msg, body...)
	sig := ed25519.Sign(priv, msg)
	return append(append([]byte{}, body...), sig...)
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// chain is a complete locally minted chain plus everything needed to present it.
type chain struct {
	rootPub    ed25519.PublicKey
	issuerCert []byte
	credential []byte
	devPriv    ed25519.PrivateKey
	certSerial string
	credSerial string
}

// chainOpts places each part of a chain exactly where a test needs it. The zero
// value builds a chain that is live and valid at `now`.
type chainOpts struct {
	certNotBefore, certNotAfter time.Time
	credNotBefore, credNotAfter time.Time
	maxCredTTL                  time.Duration
	// Versions are pointers so a test can set the version to ZERO, which is the
	// case an int would swallow — and a credential predating the format is exactly
	// what a "version must match exactly" check exists to refuse.
	certVersion       *int
	credVersion       *int
	devicePubOverride []byte
	issuerPubOverride []byte
	// credBody, when set, is used verbatim as the credential's signed body instead
	// of marshaling the struct — the only way to test that verification runs over
	// the bytes AS RECEIVED.
	credBody []byte
}

func newChain(t *testing.T, now time.Time, o chainOpts) chain {
	t.Helper()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate root: %v", err)
	}
	issuerPub, issuerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate issuer: %v", err)
	}
	devPub, devPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate device: %v", err)
	}

	if o.certNotBefore.IsZero() {
		o.certNotBefore = now.Add(-time.Hour)
	}
	if o.certNotAfter.IsZero() {
		o.certNotAfter = now.Add(365 * 24 * time.Hour)
	}
	if o.credNotBefore.IsZero() {
		o.credNotBefore = now.Add(-time.Minute)
	}
	if o.credNotAfter.IsZero() {
		o.credNotAfter = now.Add(24 * time.Hour)
	}
	if o.maxCredTTL == 0 {
		o.maxCredTTL = 72 * time.Hour
	}
	certVer, credVer := devicecred.Version, devicecred.Version
	if o.certVersion != nil {
		certVer = *o.certVersion
	}
	if o.credVersion != nil {
		credVer = *o.credVersion
	}

	ipub := []byte(issuerPub)
	if o.issuerPubOverride != nil {
		ipub = o.issuerPubOverride
	}
	cert := devicecred.IssuerCert{
		Version:    certVer,
		Serial:     "aaaaaaaaaaaaaaaa",
		IssuerPub:  ipub,
		NotBefore:  o.certNotBefore,
		NotAfter:   o.certNotAfter,
		MaxCredTTL: o.maxCredTTL,
		Note:       "unit test issuer",
	}

	dpub := []byte(devPub)
	if o.devicePubOverride != nil {
		dpub = o.devicePubOverride
	}
	cred := devicecred.DeviceCredential{
		Version:   credVer,
		Serial:    "bbbbbbbbbbbbbbbb",
		DevicePub: dpub,
		Epoch:     7,
		NotBefore: o.credNotBefore,
		NotAfter:  o.credNotAfter,
	}

	credBody := o.credBody
	if credBody == nil {
		credBody = marshal(t, cred)
	}

	return chain{
		rootPub:    rootPub,
		issuerCert: signObject(t, rootPriv, "bacchus/issuer-cert/v1", marshal(t, cert)),
		credential: signObject(t, issuerPriv, "bacchus/device-cred/v1", credBody),
		devPriv:    devPriv,
		certSerial: cert.Serial,
		credSerial: cred.Serial,
	}
}

// present builds a Presentation with a valid assertion over audience/challenge.
func (c chain) present(t *testing.T, audience string, challenge []byte) devicecred.Presentation {
	t.Helper()
	a, err := devicecred.SignAssertion(c.devPriv, devicecred.PurposeConnect, audience, challenge)
	if err != nil {
		t.Fatalf("SignAssertion: %v", err)
	}
	return devicecred.Presentation{Credential: c.credential, IssuerCert: c.issuerCert, Assertion: a}
}

func fixedNow() time.Time { return time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC) }

func goodChallenge() []byte {
	ch := make([]byte, devicecred.MinChallenge)
	for i := range ch {
		ch[i] = byte(i + 1)
	}
	return ch
}

func mustVerifier(t *testing.T, root ed25519.PublicKey, revoked func(string) bool) *devicecred.Verifier {
	t.Helper()
	v, err := devicecred.NewVerifier(root, revoked)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// TestNewVerifierFailsClosedWithoutARoot: a verifier with no trust anchor cannot
// verify anything, so construction refuses rather than handing back an object
// named "Verifier" that admits everything.
func TestNewVerifierFailsClosedWithoutARoot(t *testing.T) {
	for _, tc := range []struct {
		name string
		root ed25519.PublicKey
	}{
		{"nil", nil},
		{"empty", ed25519.PublicKey{}},
		{"short", make([]byte, ed25519.PublicKeySize-1)},
		{"long", make([]byte, ed25519.PublicKeySize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := devicecred.NewVerifier(tc.root, nil); !errors.Is(err, devicecred.ErrNoRoot) {
				t.Fatalf("err = %v, want ErrNoRoot", err)
			}
		})
	}
}

// TestIssuerCertIsVerifiedBeforeTheCredential is the ordering discipline itself.
//
// The chain below has a issuer cert that expired an hour ago AND a credential that
// is fine. If the descent ran the other way — or ran the credential's checks first
// because they are cheaper — the issuer key would have been trusted before the
// root's signature over it was known to be live. The observable consequence is
// which error comes back.
func TestIssuerCertIsVerifiedBeforeTheCredential(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{
		certNotBefore: now.Add(-2 * time.Hour),
		certNotAfter:  now.Add(-time.Hour), // dead
	})
	v := mustVerifier(t, c.rootPub, nil)
	_, err := v.Verify(c.present(t, "coord-1", goodChallenge()), now, "coord-1", goodChallenge())
	if !errors.Is(err, devicecred.ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired from the issuer cert", err)
	}
}

// TestRevocationIsCheckedBeforeTheWindow: an object the operator explicitly killed
// reports ErrRevoked even when it has also expired. The operator killed it, and
// that is the more actionable reason — "expired" would send them looking at clocks.
func TestRevocationIsCheckedBeforeTheWindow(t *testing.T) {
	now := fixedNow()

	t.Run("issuer cert", func(t *testing.T) {
		c := newChain(t, now, chainOpts{
			certNotBefore: now.Add(-2 * time.Hour),
			certNotAfter:  now.Add(-time.Hour),
		})
		v := mustVerifier(t, c.rootPub, func(s string) bool { return s == c.certSerial })
		_, err := v.Verify(c.present(t, "coord-1", goodChallenge()), now, "coord-1", goodChallenge())
		if !errors.Is(err, devicecred.ErrRevoked) {
			t.Fatalf("err = %v, want ErrRevoked", err)
		}
	})

	t.Run("credential", func(t *testing.T) {
		c := newChain(t, now, chainOpts{
			credNotBefore: now.Add(-2 * time.Hour),
			credNotAfter:  now.Add(-time.Hour),
		})
		v := mustVerifier(t, c.rootPub, func(s string) bool { return s == c.credSerial })
		_, err := v.Verify(c.present(t, "coord-1", goodChallenge()), now, "coord-1", goodChallenge())
		if !errors.Is(err, devicecred.ErrRevoked) {
			t.Fatalf("err = %v, want ErrRevoked", err)
		}
	})
}

// TestClockSkewAppliesToTheLowerBoundOnly. Leniency about when something starts is
// harmless; leniency about when it ends would extend a rotated or revoked
// credential past the point an operator believes it is dead, and expiry is most of
// how revocation works here.
func TestClockSkewAppliesToTheLowerBoundOnly(t *testing.T) {
	now := fixedNow()
	skew := devicecred.ClockSkew

	t.Run("just inside skew is accepted", func(t *testing.T) {
		c := newChain(t, now, chainOpts{credNotBefore: now.Add(skew - time.Second)})
		v := mustVerifier(t, c.rootPub, nil)
		if _, err := v.Verify(c.present(t, "c", goodChallenge()), now, "c", goodChallenge()); err != nil {
			t.Fatalf("unexpected refusal: %v", err)
		}
	})

	t.Run("beyond skew is refused", func(t *testing.T) {
		c := newChain(t, now, chainOpts{credNotBefore: now.Add(skew + time.Second)})
		v := mustVerifier(t, c.rootPub, nil)
		_, err := v.Verify(c.present(t, "c", goodChallenge()), now, "c", goodChallenge())
		if !errors.Is(err, devicecred.ErrNotYetValid) {
			t.Fatalf("err = %v, want ErrNotYetValid", err)
		}
	})

	t.Run("NotAfter is strict — no skew past expiry", func(t *testing.T) {
		// Exactly on NotAfter is already dead, and one nanosecond past it gets no
		// grace at all.
		for _, d := range []time.Duration{0, time.Nanosecond, skew} {
			c := newChain(t, now, chainOpts{
				credNotBefore: now.Add(-time.Hour),
				credNotAfter:  now.Add(-d),
			})
			v := mustVerifier(t, c.rootPub, nil)
			_, err := v.Verify(c.present(t, "c", goodChallenge()), now, "c", goodChallenge())
			if !errors.Is(err, devicecred.ErrExpired) {
				t.Fatalf("expired by %v: err = %v, want ErrExpired", d, err)
			}
		}
	})
}

// TestCredentialTTLCapBindsAtVerification. An issuer key in the wrong hands mints
// whatever it likes; the only party that can constrain it is the offline root,
// through the cert's cap. Checking the cap only where credentials are minted would
// put the constraint inside the thing being constrained.
func TestCredentialTTLCapBindsAtVerification(t *testing.T) {
	now := fixedNow()
	const ttlCap = 48 * time.Hour

	t.Run("exactly at the cap is accepted", func(t *testing.T) {
		c := newChain(t, now, chainOpts{
			maxCredTTL:    ttlCap,
			credNotBefore: now.Add(-time.Hour),
			credNotAfter:  now.Add(-time.Hour).Add(ttlCap),
		})
		v := mustVerifier(t, c.rootPub, nil)
		if _, err := v.Verify(c.present(t, "c", goodChallenge()), now, "c", goodChallenge()); err != nil {
			t.Fatalf("unexpected refusal: %v", err)
		}
	})

	t.Run("one nanosecond over the cap is refused", func(t *testing.T) {
		c := newChain(t, now, chainOpts{
			maxCredTTL:    ttlCap,
			credNotBefore: now.Add(-time.Hour),
			credNotAfter:  now.Add(-time.Hour).Add(ttlCap + time.Nanosecond),
		})
		v := mustVerifier(t, c.rootPub, nil)
		_, err := v.Verify(c.present(t, "c", goodChallenge()), now, "c", goodChallenge())
		if !errors.Is(err, devicecred.ErrCredTTLTooLong) {
			t.Fatalf("err = %v, want ErrCredTTLTooLong", err)
		}
	})
}

// TestAudienceBindingIsEnforced. Bacchus runs a POOL of coordinators. Without this
// binding a hostile pool member could take a challenge issued by an honest
// coordinator, relay it to a device, collect the signature, and present the
// device's whole chain as its own — spending someone else's entitlement.
func TestAudienceBindingIsEnforced(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{})
	v := mustVerifier(t, c.rootPub, nil)
	ch := goodChallenge()

	// Signed for coordinator A, presented at coordinator B.
	p := c.present(t, "coordinator-A", ch)
	if _, err := v.Verify(p, now, "coordinator-B", ch); !errors.Is(err, devicecred.ErrBadAssertion) {
		t.Fatalf("err = %v, want ErrBadAssertion", err)
	}
	// The same presentation at its own audience is fine, so the refusal above is the
	// binding and not something else about the chain.
	if _, err := v.Verify(p, now, "coordinator-A", ch); err != nil {
		t.Fatalf("unexpected refusal at the right audience: %v", err)
	}
}

// TestAudienceBindingIsUnambiguouslyFramed. The audience and challenge are
// length-prefixed, so a shift of bytes from one field to the other cannot produce
// the same signed message. Without the prefixes, audience "ab" + challenge "cd..."
// and audience "abc" + challenge "d..." would be identical bytes.
func TestAudienceBindingIsUnambiguouslyFramed(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{})
	v := mustVerifier(t, c.rootPub, nil)

	full := append([]byte("XY"), goodChallenge()...)
	p := c.present(t, "ab", full)

	// Move one byte from the challenge's front onto the audience's end.
	if _, err := v.Verify(p, now, "abX", full[1:]); !errors.Is(err, devicecred.ErrBadAssertion) {
		t.Fatalf("a byte shifted between audience and challenge verified: err = %v", err)
	}
}

// TestChallengeBindingIsEnforced. Without it, an assertion captured once is an
// entitlement forever.
func TestChallengeBindingIsEnforced(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{})
	v := mustVerifier(t, c.rootPub, nil)

	issued := goodChallenge()
	p := c.present(t, "coord", issued)

	fresh := goodChallenge()
	fresh[0] ^= 0xff
	if _, err := v.Verify(p, now, "coord", fresh); !errors.Is(err, devicecred.ErrBadAssertion) {
		t.Fatalf("replayed assertion accepted against a fresh challenge: err = %v", err)
	}
}

// TestWeakChallengeIsRefusedOnBothSides. A coordinator picks the connect challenge
// and is not trusted to pick it well, so the device must refuse to sign a weak one
// and a verifier must refuse to accept one.
func TestWeakChallengeIsRefusedOnBothSides(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{})
	v := mustVerifier(t, c.rootPub, nil)
	short := make([]byte, devicecred.MinChallenge-1)

	if _, err := devicecred.SignAssertion(c.devPriv, devicecred.PurposeConnect, "c", short); !errors.Is(err, devicecred.ErrBadAssertion) {
		t.Fatalf("signer accepted a weak challenge: err = %v", err)
	}

	p := c.present(t, "c", goodChallenge())
	if _, err := v.Verify(p, now, "c", short); !errors.Is(err, devicecred.ErrBadAssertion) {
		t.Fatalf("verifier accepted a weak challenge: err = %v", err)
	}
}

// TestAssertionIsCheckedAgainstTheCredentialsKey, never against anything the
// presenter supplied alongside it. This is what makes a stolen credential
// worthless: whoever holds it still cannot produce the assertion.
func TestAssertionIsCheckedAgainstTheCredentialsKey(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{})
	v := mustVerifier(t, c.rootPub, nil)
	ch := goodChallenge()

	// An attacker holding the credential, signing with a key of its own.
	_, attackerPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	a, err := devicecred.SignAssertion(attackerPriv, devicecred.PurposeConnect, "c", ch)
	if err != nil {
		t.Fatalf("SignAssertion: %v", err)
	}
	p := devicecred.Presentation{Credential: c.credential, IssuerCert: c.issuerCert, Assertion: a}
	if _, err := v.Verify(p, now, "c", ch); !errors.Is(err, devicecred.ErrBadAssertion) {
		t.Fatalf("err = %v, want ErrBadAssertion", err)
	}
}

// TestVerificationRunsOverTheBytesAsReceived. The credential below is signed over a
// body whose fields are in an order encoding/json would never produce, with
// whitespace it would never emit. A verifier that re-marshaled the decoded struct
// to check the signature would compute different bytes and refuse it.
//
// This is why JSON field order, whitespace and escaping are deliberately not part
// of the wire contract.
func TestVerificationRunsOverTheBytesAsReceived(t *testing.T) {
	now := fixedNow()
	nbf := now.Add(-time.Minute).UTC().Format(time.RFC3339Nano)
	exp := now.Add(24 * time.Hour).UTC().Format(time.RFC3339Nano)

	_, devPrivProbe, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	devPubProbe := devPrivProbe.Public().(ed25519.PublicKey)

	// Fields reversed relative to the struct, indented, with a trailing newline.
	body := []byte(fmt.Sprintf("{\n  \"exp\": %q,\n  \"nbf\": %q,\n  \"epoch\": 7,\n  \"dpub\": %q,\n  \"serial\": \"cccccccccccccccc\",\n  \"v\": 1\n}\n",
		exp, nbf, base64Std(devPubProbe)))

	c := newChain(t, now, chainOpts{credBody: body})
	// newChain generated its own device key for the struct path; this body names a
	// different one, so present with the key the BODY names.
	c.devPriv = devPrivProbe

	v := mustVerifier(t, c.rootPub, nil)
	ch := goodChallenge()
	cred, err := v.Verify(c.present(t, "c", ch), now, "c", ch)
	if err != nil {
		t.Fatalf("refused a body it was given verbatim: %v", err)
	}
	if cred.Serial != "cccccccccccccccc" {
		t.Errorf("serial = %q, want the one in the received body", cred.Serial)
	}
	if cred.Epoch != 7 {
		t.Errorf("epoch = %d, want 7", cred.Epoch)
	}
}

func intp(i int) *int { return &i }

// TestUnsupportedVersionIsRefusedExactly, not treated as a minimum, and on BOTH
// tiers. A verifier that does not know a format refuses it rather than reading the
// subset it recognises, so an old coordinator never silently misreads a newer
// credential.
//
// The versions BELOW the current one are the half that is easy to leave untested:
// a `>` comparison passes every "newer format" case while silently admitting a
// credential minted under a format that predates every check here.
func TestUnsupportedVersionIsRefusedExactly(t *testing.T) {
	now := fixedNow()
	versions := []int{0, -1, devicecred.Version + 1, 99}

	t.Run("credential", func(t *testing.T) {
		for _, ver := range versions {
			c := newChain(t, now, chainOpts{credVersion: intp(ver)})
			v := mustVerifier(t, c.rootPub, nil)
			_, err := v.Verify(c.present(t, "c", goodChallenge()), now, "c", goodChallenge())
			if !errors.Is(err, devicecred.ErrUnsupportedVersion) {
				t.Errorf("credential version %d: err = %v, want ErrUnsupportedVersion", ver, err)
			}
		}
	})

	t.Run("issuer cert", func(t *testing.T) {
		for _, ver := range versions {
			c := newChain(t, now, chainOpts{certVersion: intp(ver)})
			v := mustVerifier(t, c.rootPub, nil)
			_, err := v.Verify(c.present(t, "c", goodChallenge()), now, "c", goodChallenge())
			if !errors.Is(err, devicecred.ErrUnsupportedVersion) {
				t.Errorf("issuer cert version %d: err = %v, want ErrUnsupportedVersion", ver, err)
			}
		}
	})
}

// rawAssertion builds and signs an assertion message directly, bypassing
// SignAssertion's own guards, so a test can present bytes a well-behaved device
// would refuse to produce. A hostile device is not bound by its own client.
func rawAssertion(priv ed25519.PrivateKey, p devicecred.Purpose, audience string, challenge []byte) []byte {
	msg := make([]byte, 0, len(p)+1+4+len(audience)+4+len(challenge))
	msg = append(msg, p...)
	msg = append(msg, 0x00)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(audience)))
	msg = append(msg, audience...)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(challenge)))
	msg = append(msg, challenge...)
	return ed25519.Sign(priv, msg)
}

// TestVerifierRefusesAWeakChallengeItWasHandedAValidSignatureFor isolates the
// MinChallenge floor on the verifying side.
//
// Pairing a short challenge with an assertion made over something else does NOT
// test this: that is refused as a bad signature whether or not the floor exists.
// The floor only shows up when the signature over the weak challenge is genuinely
// valid — which is the case that matters, because a coordinator coerced or
// misconfigured into issuing a predictable challenge would otherwise accept a
// replayable assertion and believe it had proof of possession.
func TestVerifierRefusesAWeakChallengeItWasHandedAValidSignatureFor(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{})
	v := mustVerifier(t, c.rootPub, nil)

	for _, n := range []int{0, 1, devicecred.MinChallenge - 1} {
		weak := make([]byte, n)
		for i := range weak {
			weak[i] = 0xAB
		}
		p := devicecred.Presentation{
			Credential: c.credential,
			IssuerCert: c.issuerCert,
			Assertion:  rawAssertion(c.devPriv, devicecred.PurposeConnect, "c", weak),
		}
		if _, err := v.Verify(p, now, "c", weak); !errors.Is(err, devicecred.ErrBadAssertion) {
			t.Errorf("challenge of %d bytes with a VALID signature over it: err = %v, want ErrBadAssertion", n, err)
		}
	}

	// A challenge exactly at the floor, signed the same way, is accepted — so the
	// refusals above are the floor and not the hand-rolled signing.
	ok := goodChallenge()
	p := devicecred.Presentation{
		Credential: c.credential,
		IssuerCert: c.issuerCert,
		Assertion:  rawAssertion(c.devPriv, devicecred.PurposeConnect, "c", ok),
	}
	if _, err := v.Verify(p, now, "c", ok); err != nil {
		t.Fatalf("challenge exactly at the floor refused: %v", err)
	}
}

// TestVerifyIssuerCertFailsClosedWithoutARoot covers the exported tier-one entry
// point directly. Reaching it only through Verify never exercises this, because a
// Verifier cannot be constructed without a root in the first place — so the guard
// here is the one an operator tool trips over, and it had no test.
func TestVerifyIssuerCertFailsClosedWithoutARoot(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{})

	for _, tc := range []struct {
		name string
		root ed25519.PublicKey
	}{
		{"nil", nil},
		{"empty", ed25519.PublicKey{}},
		{"short", make([]byte, ed25519.PublicKeySize-1)},
		{"long", make([]byte, ed25519.PublicKeySize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := devicecred.VerifyIssuerCert(tc.root, c.issuerCert, now, nil); !errors.Is(err, devicecred.ErrNoRoot) {
				t.Fatalf("err = %v, want ErrNoRoot", err)
			}
		})
	}

	// The real root verifies it, so the refusals above are about the anchor.
	if _, err := devicecred.VerifyIssuerCert(c.rootPub, c.issuerCert, now, nil); err != nil {
		t.Fatalf("the real root refused its own cert: %v", err)
	}
}

// TestIssuerCertWithAMalformedIssuerKeyIsRefused rather than carried forward into
// tier two.
//
// Like the device key length check, this one is redundant with the framing layer's
// own guard — core/delegation refuses a bad public key length before it verifies
// anything — so removing it alone does not change behaviour. The behaviour is
// pinned here anyway: what must not change is that a cert delegating to an
// unusable key is refused as malformed rather than reaching ed25519.Verify.
func TestIssuerCertWithAMalformedIssuerKeyIsRefused(t *testing.T) {
	now := fixedNow()
	for _, n := range []int{0, 1, ed25519.PublicKeySize - 1, ed25519.PublicKeySize + 1} {
		c := newChain(t, now, chainOpts{issuerPubOverride: make([]byte, n)})
		v := mustVerifier(t, c.rootPub, nil)
		_, err := v.Verify(c.present(t, "c", goodChallenge()), now, "c", goodChallenge())
		if !errors.Is(err, devicecred.ErrMalformed) {
			t.Errorf("ipub of %d bytes: err = %v, want ErrMalformed", n, err)
		}
	}
}

// TestMalformedDevicePubIsRefusedRatherThanCrashing. A forged credential can carry
// any dpub at all, and ed25519.Verify panics on a short key — which would be a
// remote crash on every coordinator that verified it.
func TestMalformedDevicePubIsRefusedRatherThanCrashing(t *testing.T) {
	now := fixedNow()
	for _, n := range []int{0, 1, ed25519.PublicKeySize - 1, ed25519.PublicKeySize + 1} {
		c := newChain(t, now, chainOpts{devicePubOverride: make([]byte, n)})
		v := mustVerifier(t, c.rootPub, nil)
		ch := goodChallenge()
		a, err := devicecred.SignAssertion(c.devPriv, devicecred.PurposeConnect, "c", ch)
		if err != nil {
			t.Fatalf("SignAssertion: %v", err)
		}
		p := devicecred.Presentation{Credential: c.credential, IssuerCert: c.issuerCert, Assertion: a}
		_, err = v.Verify(p, now, "c", ch)
		if !errors.Is(err, devicecred.ErrMalformed) {
			t.Fatalf("dpub of %d bytes: err = %v, want ErrMalformed", n, err)
		}
	}
}

// TestEnvelopePrefixesAreDistinctAndChecked. The prefixes are convenience, never
// what keeps one object from being read as another — but a decoder that ignored
// them would hand the wrong bytes to the wrong verifier and produce a confusing
// signature failure instead of a clear one.
func TestEnvelopePrefixesAreDistinctAndChecked(t *testing.T) {
	signed := []byte("not really signed, envelopes only")
	cert := devicecred.EncodeIssuerCert(signed)
	cred := devicecred.EncodeDeviceCredential(signed)

	if !strings.HasPrefix(cert, "bacchusi1:") {
		t.Errorf("issuer cert prefix = %q", cert)
	}
	if !strings.HasPrefix(cred, "bacchusd1:") {
		t.Errorf("device credential prefix = %q", cred)
	}

	if got, err := devicecred.DecodeIssuerCert(cert); err != nil || string(got) != string(signed) {
		t.Errorf("issuer cert roundtrip: %q %v", got, err)
	}
	if got, err := devicecred.DecodeDeviceCredential(cred); err != nil || string(got) != string(signed) {
		t.Errorf("credential roundtrip: %q %v", got, err)
	}

	// Crossed envelopes are refused rather than silently decoded.
	if _, err := devicecred.DecodeIssuerCert(cred); !errors.Is(err, devicecred.ErrMalformed) {
		t.Errorf("a device credential decoded as an issuer cert: %v", err)
	}
	if _, err := devicecred.DecodeDeviceCredential(cert); !errors.Is(err, devicecred.ErrMalformed) {
		t.Errorf("an issuer cert decoded as a device credential: %v", err)
	}
	for _, bad := range []string{"", "   ", "bacchusi1", "bacchusd1:!!!not base64!!!"} {
		if _, err := devicecred.DecodeDeviceCredential(bad); !errors.Is(err, devicecred.ErrMalformed) {
			t.Errorf("DecodeDeviceCredential(%q) err = %v, want ErrMalformed", bad, err)
		}
	}
}

// TestParsePresentationRefusesEmptyParts, so an absent part is a clear malformed
// refusal at the edge rather than a confusing signature failure deeper in.
func TestParsePresentationRefusesEmptyParts(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{})
	cert := devicecred.EncodeIssuerCert(c.issuerCert)
	cred := devicecred.EncodeDeviceCredential(c.credential)
	a, err := devicecred.SignAssertion(c.devPriv, devicecred.PurposeConnect, "c", goodChallenge())
	if err != nil {
		t.Fatalf("SignAssertion: %v", err)
	}

	for _, tc := range []struct {
		name       string
		cred, cert string
		assertion  []byte
	}{
		{"no credential", "", cert, a},
		{"no issuer cert", cred, "", a},
		{"no assertion", cred, cert, nil},
		{"nothing at all", "", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := devicecred.ParsePresentation(tc.cred, tc.cert, tc.assertion); !errors.Is(err, devicecred.ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}

	// The complete presentation parses, so the refusals above are about the missing
	// part and not about the fixture.
	if _, err := devicecred.ParsePresentation(cred, cert, a); err != nil {
		t.Fatalf("complete presentation refused: %v", err)
	}
}

// TestVerifierIsSafeForConcurrentUse. A coordinator verifies on every connect, from
// its read loop, and shares one Verifier across them.
func TestVerifierIsSafeForConcurrentUse(t *testing.T) {
	now := fixedNow()
	c := newChain(t, now, chainOpts{})
	var revocations sync.Map
	v := mustVerifier(t, c.rootPub, func(s string) bool {
		_, dead := revocations.Load(s)
		return dead
	})
	ch := goodChallenge()
	p := c.present(t, "coord", ch)

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(p, now, "coord", ch); err != nil {
				t.Errorf("concurrent verify: %v", err)
			}
		}()
	}
	wg.Wait()
}

func base64Std(b []byte) string { return b64.EncodeToString(b) }
