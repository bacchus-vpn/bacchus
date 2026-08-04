package accountclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/devicecred"
)

// ---------------------------------------------------------------------------
// A fake account service.
//
// It answers the three verbs this package speaks, over real TLS, and it records
// every request. It never verifies anything itself: the assertions are checked
// in the test goroutine against the real devicecred.VerifyAssertion, so a pass
// means the bytes this client produced would satisfy the account service's own
// verifier rather than merely being well-formed.
//
// The conformance test in this directory does the other half — it replays what
// the REAL bacchus-payment handlers emitted, so the shapes below cannot quietly
// become a private agreement between this fake and this client.
// ---------------------------------------------------------------------------

const testAudience = "account.test"

type recordedRequest struct {
	Path string
	Body []byte
}

type fakeService struct {
	t   *testing.T
	srv *httptest.Server
	ca  string // path to the PEM the client pins

	mu       sync.Mutex
	requests []recordedRequest

	// Per-verb scripted behaviour. A nil handler answers the default.
	enrollHandler     func(w http.ResponseWriter, body []byte)
	credentialHandler func(w http.ResponseWriter, body []byte)
	challengeHandler  func(w http.ResponseWriter)

	// What the default handlers return.
	device     string
	issuerCert string
	admission  string

	lastChallenge []byte
}

func newFakeService(t *testing.T) *fakeService {
	t.Helper()
	f := &fakeService{
		t:          t,
		device:     "bacchusd1:device-credential",
		issuerCert: "bacchusi1:issuer-cert",
		admission:  "bacchusc1:admission-credential",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/challenge", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.challengeHandler != nil {
			f.challengeHandler(w)
			return
		}
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("rand: %v", err)
		}
		f.mu.Lock()
		f.lastChallenge = nonce
		f.mu.Unlock()
		writeJSON(w, map[string]any{
			"challenge":  nonce,
			"expires_at": time.Now().Add(5 * time.Minute).UTC(),
		})
	})
	mux.HandleFunc("/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		body := f.record(r)
		if f.enrollHandler != nil {
			f.enrollHandler(w, body)
			return
		}
		f.writeCredentials(w)
	})
	mux.HandleFunc("/v1/credential", func(w http.ResponseWriter, r *http.Request) {
		body := f.record(r)
		if f.credentialHandler != nil {
			f.credentialHandler(w, body)
			return
		}
		f.writeCredentials(w)
	})
	// A certificate of this service's own, rather than httptest's shared one.
	// Every httptest TLS server uses the same built-in certificate, so a test
	// that pinned one and dialled another would pass while proving nothing —
	// which is exactly what TestClientDoesNotTrustThePublicRootPool is for.
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)

	// Pin the server's own certificate, which is what a real deployment does
	// with the CA it was handed out of band.
	caPath := filepath.Join(t.TempDir(), "service-ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	f.ca = caPath
	return f
}

func (f *fakeService) writeCredentials(w http.ResponseWriter) {
	out := map[string]any{"device": f.device, "issuer_cert": f.issuerCert}
	if f.admission != "" {
		out["admission"] = f.admission
	}
	writeJSON(w, out)
}

func (f *fakeService) record(r *http.Request) []byte {
	body := make([]byte, 0, 512)
	buf := make([]byte, 512)
	for {
		n, err := r.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err != nil {
			break
		}
	}
	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{Path: r.URL.Path, Body: body})
	f.mu.Unlock()
	return body
}

func (f *fakeService) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.Path == path {
			n++
		}
	}
	return n
}

func (f *fakeService) bodyFor(path string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if r.Path == path {
			return r.Body
		}
	}
	return nil
}

func (f *fakeService) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: f.srv.URL, Audience: testAudience, ServerCAFile: f.ca})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// selfSignedCert mints a throwaway certificate for 127.0.0.1, one per fake
// service, so two services in one test are two distinct TLS identities.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate TLS key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "account service (test)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func writeJSON(w http.ResponseWriter, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func writeCoded(w http.ResponseWriter, status int, code string) {
	b, _ := json.Marshal(map[string]any{"error": map[string]any{"code": code}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func newDevice(t *testing.T) (*core.DeviceEnrollment, string) {
	t.Helper()
	dir := t.TempDir()
	dev, err := core.OpenDeviceEnrollment(dir)
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	return dev, dir
}

// ---------------------------------------------------------------------------
// New: every refusal is a value that cannot be defaulted.
// ---------------------------------------------------------------------------

func TestNewRefusesUnpinnableConfigurations(t *testing.T) {
	f := newFakeService(t)
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"no base URL", Config{Audience: "a", ServerCAFile: f.ca}, "BaseURL is required"},
		{"plain http", Config{BaseURL: "http://x.example", Audience: "a", ServerCAFile: f.ca}, "must be https"},
		{"base carries a path", Config{BaseURL: "https://x.example/api", Audience: "a", ServerCAFile: f.ca}, "scheme and host only"},
		{"no audience", Config{BaseURL: "https://x.example", ServerCAFile: f.ca}, "Audience is required"},
		{"no pinned CA", Config{BaseURL: "https://x.example", Audience: "a"}, "ServerCAFile is required"},
		{"CA file missing", Config{BaseURL: "https://x.example", Audience: "a", ServerCAFile: filepath.Join(t.TempDir(), "nope.pem")}, "read ServerCAFile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New(%s) = %v, want an error containing %q", tc.name, err, tc.want)
			}
		})
	}
}

// TestNewRefusesACAFileThatIsNotOne is separate because the failure it guards
// against is the quiet one: a file that exists and is readable but holds no
// certificate would produce an EMPTY pool, and an empty RootCAs pool is not
// "trust nothing" in crypto/tls — it is a pool that trusts nothing, which fails
// closed, but only if AppendCertsFromPEM's return value is checked.
func TestNewRefusesACAFileThatIsNotOne(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(p, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{BaseURL: "https://x.example", Audience: "a", ServerCAFile: p})
	if err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Fatalf("New = %v, want a refusal naming the file as holding no certificate", err)
	}
}

// TestClientDoesNotTrustThePublicRootPool proves the pin is doing work rather
// than merely being configured: a client pinned to one service's certificate
// must fail against a DIFFERENT service, even though that other service's
// certificate is perfectly valid for its own name.
func TestClientDoesNotTrustThePublicRootPool(t *testing.T) {
	a := newFakeService(t)
	b := newFakeService(t)

	// Pinned to a, pointed at b.
	c, err := New(Config{BaseURL: b.srv.URL, Audience: testAudience, ServerCAFile: a.ca})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, _, err = c.Challenge(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Challenge against an unpinned server = %v, want ErrUnreachable", err)
	}
}

// ---------------------------------------------------------------------------
// The enrollment exchange.
// ---------------------------------------------------------------------------

// TestEnrollProducesAnAssertionTheServiceVerifierAccepts is the test that makes
// the rest of this file mean something. It checks the SIGNATURE, under the real
// verifier, against the pinned audience and the challenge the service issued —
// so a pass means the account service would have admitted these exact bytes.
func TestEnrollProducesAnAssertionTheServiceVerifierAccepts(t *testing.T) {
	f := newFakeService(t)
	dev, dir := newDevice(t)

	res, err := f.client(t).Enroll(context.Background(), dev, "BC1-TESTCODE", "desktop")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	var req struct {
		Claim     string `json:"claim"`
		DevicePub []byte `json:"device_pub"`
		Label     string `json:"label"`
		Challenge []byte `json:"challenge"`
		Sig       []byte `json:"sig"`
	}
	if err := json.Unmarshal(f.bodyFor("/v1/enroll"), &req); err != nil {
		t.Fatalf("decode enroll request: %v", err)
	}
	if req.Claim != "BC1-TESTCODE" || req.Label != "desktop" {
		t.Fatalf("enroll request = claim %q label %q", req.Claim, req.Label)
	}
	if got, want := ed25519.PublicKey(req.DevicePub), dev.DevicePub(); !got.Equal(want) {
		t.Fatalf("enroll bound the wrong public key")
	}
	f.mu.Lock()
	issued := f.lastChallenge
	f.mu.Unlock()
	if string(req.Challenge) != string(issued) {
		t.Fatalf("enroll echoed a challenge the service never issued")
	}

	// The real verifier, the real purpose tag, the pinned audience.
	if err := devicecred.VerifyAssertion(dev.DevicePub(), devicecred.Purpose("bacchus/assert-enroll/v1"),
		testAudience, req.Challenge, req.Sig); err != nil {
		t.Fatalf("the account service's verifier would reject this assertion: %v", err)
	}
	// And it must NOT verify under any other audience: that binding is the only
	// thing stopping an assertion collected by one service being spent at
	// another.
	if err := devicecred.VerifyAssertion(dev.DevicePub(), devicecred.Purpose("bacchus/assert-enroll/v1"),
		"someone.else", req.Challenge, req.Sig); err == nil {
		t.Fatal("the assertion verified under an audience it was never bound to")
	}

	if res.Device != f.device || res.IssuerCert != f.issuerCert || res.Admission != f.admission {
		t.Fatalf("Enroll returned %+v", res)
	}
	cred, cert, ok := dev.Current()
	if !ok || cred != f.device || cert != f.issuerCert {
		t.Fatalf("the credential and issuer cert were not persisted together: %q %q %v", cred, cert, ok)
	}
	if got := LoadAdmission(dir); got != f.admission {
		t.Fatalf("admission credential = %q, want %q", got, f.admission)
	}
}

// TestEnrollSendsTheEnrollVerbExactlyOnce is the regression test for the one
// failure this package exists to make impossible. Every non-200 outcome, and
// every transport failure, must leave exactly one /v1/enroll on the wire — a
// second one answers claim_rejected forever and destroys a paying customer's
// access.
func TestEnrollSendsTheEnrollVerbExactlyOnce(t *testing.T) {
	cases := []struct {
		name    string
		handler func(w http.ResponseWriter, body []byte)
	}{
		{"unknown_challenge", func(w http.ResponseWriter, _ []byte) { writeCoded(w, 400, "unknown_challenge") }},
		{"claim_rejected", func(w http.ResponseWriter, _ []byte) { writeCoded(w, 403, "claim_rejected") }},
		{"internal", func(w http.ResponseWriter, _ []byte) { writeCoded(w, 500, "internal") }},
		{"rate_limited", func(w http.ResponseWriter, _ []byte) { writeCoded(w, 429, "rate_limited") }},
		{"no body at all", func(w http.ResponseWriter, _ []byte) {
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(500)
				return
			}
			conn, _, err := hj.Hijack()
			if err == nil {
				conn.Close() // the ambiguous case: the request was sent, the answer is unknown
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeService(t)
			f.enrollHandler = tc.handler
			// Nothing to recover with either, so the recovery attempt (which is
			// allowed) cannot mask a retry of the enroll verb.
			f.credentialHandler = func(w http.ResponseWriter, _ []byte) { writeCoded(w, 403, "bad_assertion") }
			dev, _ := newDevice(t)

			if _, err := f.client(t).Enroll(context.Background(), dev, "BC1-TESTCODE", "desktop"); err == nil {
				t.Fatal("Enroll succeeded against a service that refused it")
			}
			if n := f.count("/v1/enroll"); n != 1 {
				t.Fatalf("/v1/enroll was sent %d times; a claim code is spent by the first one", n)
			}
			if _, _, ok := dev.Current(); ok {
				t.Fatal("a failed enrollment stored a credential")
			}
		})
	}
}

// TestEnrollDoesNotProbeAfterClaimRejected pins the deliberate exception to the
// recovery path. A failed /v1/credential answers bad_assertion, which counts
// toward a per-device-key cooldown on the service, so probing after every typo
// would let a user lock their own key out while hunting for the code they
// mistyped.
func TestEnrollDoesNotProbeAfterClaimRejected(t *testing.T) {
	f := newFakeService(t)
	f.enrollHandler = func(w http.ResponseWriter, _ []byte) { writeCoded(w, 403, "claim_rejected") }
	dev, _ := newDevice(t)

	_, err := f.client(t).Enroll(context.Background(), dev, "BC1-TYPO", "desktop")
	if code, ok := CodeOf(err); !ok || code != CodeClaimRejected {
		t.Fatalf("Enroll = %v, want claim_rejected", err)
	}
	if n := f.count("/v1/credential"); n != 0 {
		t.Fatalf("/v1/credential was called %d times after a typo; each call spends a bad_assertion against this device key's cooldown", n)
	}
}

// TestEnrollRecoversFromAnUnreadResponse is the other half of "not safely
// retryable": when the enroll verb's outcome is genuinely unknown, the credential
// is recovered through /v1/credential rather than by re-spending the claim code.
func TestEnrollRecoversFromAnUnreadResponse(t *testing.T) {
	f := newFakeService(t)
	f.enrollHandler = func(w http.ResponseWriter, _ []byte) {
		// Served, then the connection dies before the client reads it — the
		// case where the claim code IS spent and a retry cannot get it back.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("no hijacker")
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			conn.Close()
		}
	}
	dev, dir := newDevice(t)

	res, err := f.client(t).Enroll(context.Background(), dev, "BC1-TESTCODE", "desktop")
	if err != nil {
		t.Fatalf("Enroll did not recover: %v", err)
	}
	if res.Device != f.device {
		t.Fatalf("recovered %+v", res)
	}
	if n := f.count("/v1/enroll"); n != 1 {
		t.Fatalf("/v1/enroll sent %d times during recovery", n)
	}
	if n := f.count("/v1/credential"); n != 1 {
		t.Fatalf("/v1/credential sent %d times during recovery, want 1", n)
	}
	if got := LoadAdmission(dir); got != f.admission {
		t.Fatalf("recovery did not persist the admission credential")
	}
}

func TestEnrollCollectsWhenAlreadyEnrolled(t *testing.T) {
	f := newFakeService(t)
	f.enrollHandler = func(w http.ResponseWriter, _ []byte) { writeCoded(w, 403, "already_enrolled") }
	dev, _ := newDevice(t)

	res, err := f.client(t).Enroll(context.Background(), dev, "BC1-TESTCODE", "desktop")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if res.Device != f.device {
		t.Fatalf("Enroll returned %+v", res)
	}
}

func TestEnrollRefusesToSpendAClaimCodeForADeviceThatHasOne(t *testing.T) {
	f := newFakeService(t)
	dev, _ := newDevice(t)
	if err := dev.Put("bacchusd1:existing", "bacchusi1:existing"); err != nil {
		t.Fatal(err)
	}
	_, err := f.client(t).Enroll(context.Background(), dev, "BC1-TESTCODE", "desktop")
	if !errors.Is(err, ErrAlreadyHaveCredential) {
		t.Fatalf("Enroll = %v, want ErrAlreadyHaveCredential", err)
	}
	if n := f.count("/v1/enroll"); n != 0 {
		t.Fatalf("a claim code was spent for a device that already held a credential (%d calls)", n)
	}
}

// TestAdmissionAbsentIsNotAnError pins the deployment shape the transport
// specification calls out by name: a service with no admission key mints no
// admission credential, and that is a real configuration.
func TestAdmissionAbsentIsNotAnError(t *testing.T) {
	f := newFakeService(t)
	f.admission = ""
	dev, dir := newDevice(t)

	res, err := f.client(t).Enroll(context.Background(), dev, "BC1-TESTCODE", "desktop")
	if err != nil {
		t.Fatalf("Enroll against a service with no admission key: %v", err)
	}
	if res.Admission != "" {
		t.Fatalf("Admission = %q, want empty", res.Admission)
	}
	if _, _, ok := dev.Current(); !ok {
		t.Fatal("the device credential was not stored")
	}
	if got := LoadAdmission(dir); got != "" {
		t.Fatalf("LoadAdmission = %q on a deployment that mints none", got)
	}
}

// TestAnEmptyAdmissionDoesNotClearAStoredOne: a deployment can gain an admission
// authority between two renewals, but one response that omitted the field is not
// evidence that what this device already holds has been withdrawn.
func TestAnEmptyAdmissionDoesNotClearAStoredOne(t *testing.T) {
	f := newFakeService(t)
	dev, dir := newDevice(t)
	if _, err := f.client(t).Enroll(context.Background(), dev, "BC1-TESTCODE", "desktop"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	f.admission = ""
	if _, err := f.client(t).Collect(context.Background(), dev); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := LoadAdmission(dir); got == "" {
		t.Fatal("a response with no admission field erased the stored admission credential")
	}
}

// ---------------------------------------------------------------------------
// /v1/credential: retryable, unlike its neighbour.
// ---------------------------------------------------------------------------

func TestCollectRetriesOnceOnUnknownChallenge(t *testing.T) {
	f := newFakeService(t)
	var calls int
	f.credentialHandler = func(w http.ResponseWriter, _ []byte) {
		calls++
		if calls == 1 {
			writeCoded(w, 400, "unknown_challenge")
			return
		}
		f.writeCredentials(w)
	}
	dev, _ := newDevice(t)

	if _, err := f.client(t).Collect(context.Background(), dev); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if calls != 2 {
		t.Fatalf("/v1/credential called %d times, want 2 (one retry with a fresh challenge)", calls)
	}
	if n := f.count("/v1/challenge"); n != 2 {
		t.Fatalf("the retry reused the dead challenge (%d /v1/challenge calls)", n)
	}
}

func TestCollectDoesNotRetryForever(t *testing.T) {
	f := newFakeService(t)
	f.credentialHandler = func(w http.ResponseWriter, _ []byte) { writeCoded(w, 400, "unknown_challenge") }
	dev, _ := newDevice(t)

	if _, err := f.client(t).Collect(context.Background(), dev); err == nil {
		t.Fatal("Collect succeeded against a service that never accepts a challenge")
	}
	if n := f.count("/v1/credential"); n != 2 {
		t.Fatalf("/v1/credential called %d times, want exactly 2", n)
	}
}

// ---------------------------------------------------------------------------
// The renewal seam.
// ---------------------------------------------------------------------------

func TestRenewSatisfiesTheSeamAndRefreshesAdmission(t *testing.T) {
	f := newFakeService(t)
	dev, dir := newDevice(t)

	// Assigning to the seam's own type is what proves the shape matches; a
	// mismatch is a compile error here rather than a discovery at an embedder.
	var seam func(context.Context, core.DeviceRenewRequest) (string, string, error) = f.client(t).RenewInto(dir)

	f.admission = "bacchusc1:fresh-admission"
	cred, cert, err := seam(context.Background(), core.DeviceRenewRequest{
		DevicePub: dev.DevicePub(),
		Sign:      dev.SignRenew,
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if cred != f.device || cert != f.issuerCert {
		t.Fatalf("renew returned %q %q", cred, cert)
	}
	if got := LoadAdmission(dir); got != "bacchusc1:fresh-admission" {
		t.Fatalf("renewal did not refresh the admission credential: %q", got)
	}

	// The renewal assertion carries the renewal purpose, not the enrollment one.
	var req struct {
		DevicePub []byte `json:"device_pub"`
		Challenge []byte `json:"challenge"`
		Sig       []byte `json:"sig"`
	}
	if err := json.Unmarshal(f.bodyFor("/v1/credential"), &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := devicecred.VerifyAssertion(dev.DevicePub(), devicecred.Purpose("bacchus/assert-renew/v1"),
		testAudience, req.Challenge, req.Sig); err != nil {
		t.Fatalf("renewal assertion rejected by the real verifier: %v", err)
	}
	if err := devicecred.VerifyAssertion(dev.DevicePub(), devicecred.Purpose("bacchus/assert-enroll/v1"),
		testAudience, req.Challenge, req.Sig); err == nil {
		t.Fatal("a renewal assertion verified as an enrollment assertion; the purpose tag is doing nothing")
	}
}

// TestRenewNeverSendsTheCurrentCredential: the service resolves the account by
// public key and has no parameter for these, and a field the service ignores is
// a field that will eventually be trusted by mistake.
func TestRenewNeverSendsTheCurrentCredential(t *testing.T) {
	f := newFakeService(t)
	dev, _ := newDevice(t)

	if _, _, err := f.client(t).Renew(context.Background(), core.DeviceRenewRequest{
		DevicePub:         dev.DevicePub(),
		CurrentCred:       "bacchusd1:SECRET-CURRENT",
		CurrentIssuerCert: "bacchusi1:SECRET-CERT",
		Sign:              dev.SignRenew,
	}); err != nil {
		t.Fatalf("Renew: %v", err)
	}
	body := string(f.bodyFor("/v1/credential"))
	for _, forbidden := range []string{"SECRET-CURRENT", "SECRET-CERT", "current_cred", "issuer_cert"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("/v1/credential request carried %q: %s", forbidden, body)
		}
	}
}

// TestRenewIntoKeepsTheCredentialWhenTheAdmissionFileCannotBeWritten: core reads
// a non-nil error from the seam as "renewal failed, retry later" and discards
// both return values, so failing here would throw away a good credential over a
// file this client could not write.
func TestRenewIntoKeepsTheCredentialWhenTheAdmissionFileCannotBeWritten(t *testing.T) {
	f := newFakeService(t)
	dev, _ := newDevice(t)
	var logged []string
	c, err := New(Config{
		BaseURL: f.srv.URL, Audience: testAudience, ServerCAFile: f.ca,
		Logf: func(format string, args ...any) { logged = append(logged, format) },
	})
	if err != nil {
		t.Fatal(err)
	}

	// A path that is a FILE, so MkdirAll fails.
	blocked := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cred, cert, err := c.RenewInto(blocked)(context.Background(), core.DeviceRenewRequest{
		DevicePub: dev.DevicePub(),
		Sign:      dev.SignRenew,
	})
	if err != nil {
		t.Fatalf("renewal failed over an admission file: %v", err)
	}
	if cred == "" || cert == "" {
		t.Fatal("the device credential was discarded")
	}
	if len(logged) == 0 {
		t.Fatal("the admission failure was silent")
	}
}

// ---------------------------------------------------------------------------
// Errors: the taxonomy, and the interference rule.
// ---------------------------------------------------------------------------

// TestBare404IsInterferenceNotAnOldDeployment is the specification's rule that a
// client must not disable a feature because something answered 404. Only a
// well-formed unknown_verb body is a statement by the service.
func TestBare404IsInterferenceNotAnOldDeployment(t *testing.T) {
	f := newFakeService(t)
	f.challengeHandler = func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }

	_, _, err := f.client(t).Challenge(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("bare 404 = %v, want ErrUnreachable", err)
	}
	if _, ok := CodeOf(err); ok {
		t.Fatal("a bare 404 was read as a coded refusal")
	}
}

func TestWellFormedUnknownVerbIsACodedRefusal(t *testing.T) {
	f := newFakeService(t)
	f.challengeHandler = func(w http.ResponseWriter) { writeCoded(w, 404, "unknown_verb") }

	_, _, err := f.client(t).Challenge(context.Background())
	code, ok := CodeOf(err)
	if !ok || code != CodeUnknownVerb {
		t.Fatalf("Challenge = %v, want a coded unknown_verb", err)
	}
	if !errors.Is(err, ErrRefused) {
		t.Fatal("a coded refusal did not match ErrRefused")
	}
}

// TestAnUnrecognizedCodeIsNotTerminal: adding a code to the service's vocabulary
// must not strand a deployed client, so an unknown token is reported as
// unrecognized and treated as transient.
func TestAnUnrecognizedCodeIsNotTerminal(t *testing.T) {
	f := newFakeService(t)
	f.challengeHandler = func(w http.ResponseWriter) { writeCoded(w, 503, "some_future_code") }

	_, _, err := f.client(t).Challenge(context.Background())
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("Challenge = %v, want a coded refusal", err)
	}
	if e.Recognized {
		t.Fatal("an unknown code was reported as recognized")
	}
	if Terminal(err) {
		t.Fatal("an unknown code was treated as terminal, which would strand this build on the day a code is added")
	}
	if !strings.Contains(e.Error(), "some_future_code") {
		t.Fatalf("the unrecognized code was not named: %v", e)
	}
}

func TestRetryAfterIsCarried(t *testing.T) {
	f := newFakeService(t)
	f.challengeHandler = func(w http.ResponseWriter) {
		b, _ := json.Marshal(map[string]any{"error": map[string]any{"code": "rate_limited", "retry_after_ms": 60000}})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		_, _ = w.Write(b)
	}
	_, _, err := f.client(t).Challenge(context.Background())
	var e *Error
	if !errors.As(err, &e) || e.RetryAfter != time.Minute {
		t.Fatalf("Challenge = %v (retry after %v), want rate_limited with a one-minute hint", err, e.RetryAfter)
	}
}

// TestA200ThatDoesNotParseIsUnreachable: a captive portal's login page is a 200.
func TestA200ThatDoesNotParseIsUnreachable(t *testing.T) {
	f := newFakeService(t)
	f.challengeHandler = func(w http.ResponseWriter) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html>sign in to continue</html>"))
	}
	_, _, err := f.client(t).Challenge(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Challenge = %v, want ErrUnreachable", err)
	}
}

// TestRedirectsAreRefused: a redirect moves the request off the host whose
// identity was pinned, and none of these verbs has any reason to be redirected.
func TestRedirectsAreRefused(t *testing.T) {
	f := newFakeService(t)
	f.challengeHandler = func(w http.ResponseWriter) {
		w.Header().Set("Location", "https://elsewhere.example/v1/challenge")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
	_, _, err := f.client(t).Challenge(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("Challenge = %v, want ErrUnreachable", err)
	}
}

// TestAnIncompleteCredentialIsRefused: a 200 missing either half is not a
// credential, and storing what arrived would break devicestore's invariant that
// the two are written together.
func TestAnIncompleteCredentialIsRefused(t *testing.T) {
	f := newFakeService(t)
	f.enrollHandler = func(w http.ResponseWriter, _ []byte) {
		writeJSON(w, map[string]any{"device": "bacchusd1:orphan"})
	}
	f.credentialHandler = func(w http.ResponseWriter, _ []byte) { writeCoded(w, 403, "bad_assertion") }
	dev, _ := newDevice(t)

	if _, err := f.client(t).Enroll(context.Background(), dev, "BC1-TESTCODE", "desktop"); err == nil {
		t.Fatal("a credential with no issuer cert was accepted")
	}
	if _, _, ok := dev.Current(); ok {
		t.Fatal("half a credential was persisted")
	}
}

// ---------------------------------------------------------------------------
// The admission file.
// ---------------------------------------------------------------------------

func TestLoadAdmissionSoftFails(t *testing.T) {
	dir := t.TempDir()
	if got := LoadAdmission(dir); got != "" {
		t.Fatalf("LoadAdmission on an empty dir = %q", got)
	}
	if got := LoadAdmission(""); got != "" {
		t.Fatalf("LoadAdmission(\"\") = %q", got)
	}
	if err := os.WriteFile(AdmissionPath(dir), []byte("half a file\nand another line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadAdmission(dir); got != "" {
		t.Fatalf("LoadAdmission on a multi-line file = %q, want empty", got)
	}
}

func TestSaveAdmissionIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	if err := saveAdmission(dir, "bacchusc1:one"); err != nil {
		t.Fatal(err)
	}
	if err := saveAdmission(dir, "bacchusc1:two"); err != nil {
		t.Fatal(err)
	}
	if got := LoadAdmission(dir); got != "bacchusc1:two" {
		t.Fatalf("LoadAdmission = %q", got)
	}
	fi, err := os.Stat(AdmissionPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("admission file mode = %v, want 0600 (it sits next to this device's private key)", fi.Mode().Perm())
	}
	// No temporary files left behind: a directory that accumulates them is a
	// directory whose contents stop being a reliable statement about the device.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("saveAdmission left %d files behind", len(entries))
	}
}
