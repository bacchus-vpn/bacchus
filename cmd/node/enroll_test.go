package main

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
	"flag"
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
	"github.com/bacchus-vpn/bacchus/core/accountclient"
	"github.com/bacchus-vpn/bacchus/core/devicecred"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
)

// ---------------------------------------------------------------------------
// A fake account service, over real TLS with a certificate of its own.
//
// It answers the three verbs core/accountclient speaks and counts every request
// by path, because almost every assertion in this file is about HOW MANY TIMES
// /v1/enroll was sent — that is what "a restart does not present a spent code"
// means when written down as a test.
//
// httptest's built-in certificate is deliberately not used: every httptest TLS
// server shares one, so a test that pinned it would pass without the pin doing
// anything.
// ---------------------------------------------------------------------------

const testAudience = "account.test"

type fakeAccount struct {
	srv *httptest.Server
	ca  string // path to the PEM the node pins

	mu       sync.Mutex
	calls    map[string]int
	lastBody map[string][]byte

	// Scripted refusals, by path. Nil answers the default.
	enrollHandler     func(w http.ResponseWriter)
	credentialHandler func(w http.ResponseWriter)

	// What the issuing verbs return. Replaced by tests that care about expiry.
	device     string
	issuerCert string
	admission  string
}

func newFakeAccount(t *testing.T) *fakeAccount {
	t.Helper()
	f := &fakeAccount{
		calls:      map[string]int{},
		lastBody:   map[string][]byte{},
		device:     mintCredential(t, time.Now().Add(48*time.Hour)),
		issuerCert: devicecred.EncodeIssuerCert([]byte("issuer-cert")),
		admission:  "bacchusc1:admission",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/challenge", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			t.Errorf("rand: %v", err)
			return
		}
		writeTestJSON(w, http.StatusOK, map[string]any{
			"challenge":  nonce,
			"expires_at": time.Now().Add(5 * time.Minute).UTC(),
		})
	})
	mux.HandleFunc("/v1/enroll", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.enrollHandler != nil {
			f.enrollHandler(w)
			return
		}
		f.writeCredentials(w)
	})
	mux.HandleFunc("/v1/credential", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.credentialHandler != nil {
			f.credentialHandler(w)
			return
		}
		f.writeCredentials(w)
	})
	f.srv = httptest.NewUnstartedServer(mux)
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{testCert(t)}}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)

	caPath := filepath.Join(t.TempDir(), "service-ca.pem")
	block := &pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}
	if err := os.WriteFile(caPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	f.ca = caPath
	return f
}

func (f *fakeAccount) record(r *http.Request) {
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
	defer f.mu.Unlock()
	f.calls[r.URL.Path]++
	f.lastBody[r.URL.Path] = body
}

func (f *fakeAccount) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[path]
}

func (f *fakeAccount) body(path string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastBody[path]
}

func (f *fakeAccount) writeCredentials(w http.ResponseWriter) {
	writeTestJSON(w, http.StatusOK, map[string]any{
		"device":      f.device,
		"issuer_cert": f.issuerCert,
		"admission":   f.admission,
	})
}

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func writeTestCoded(w http.ResponseWriter, status int, code string) {
	writeTestJSON(w, status, map[string]any{"error": map[string]any{"code": code}})
}

func testCert(t *testing.T) tls.Certificate {
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

// mintCredential builds a device-credential envelope whose CLAIMED expiry is
// exp. The signature is zero bytes and never checked by anything in this file:
// devicestore.Expiry is signature-blind by design (ADR-0046 §5), and the only
// party that verifies this chain is a coordinator, which is not in this test.
// What it buys is a fixture whose remaining life the renewal logic can actually
// read, so a test can put a credential inside the renewal margin instead of
// asserting against an opaque string.
func mintCredential(t *testing.T, exp time.Time) string {
	t.Helper()
	body, err := json.Marshal(map[string]any{"exp": exp.UTC()})
	if err != nil {
		t.Fatalf("marshal credential body: %v", err)
	}
	return devicecred.EncodeDeviceCredential(append(body, make([]byte, ed25519.SignatureSize)...))
}

// testFlags builds the flag struct directly rather than calling
// registerAccountFlags, which declares on the process-wide default flag set and
// would panic on a second call. The values are what a command line would have
// produced.
func testFlags(f *fakeAccount) accountFlags {
	service, audience, ca, label := "", "", "", ""
	if f != nil {
		service, audience, ca = f.srv.URL, testAudience, f.ca
	}
	enroll := false
	codeFile := defaultClaimCodeFile
	return accountFlags{
		service:  &service,
		audience: &audience,
		ca:       &ca,
		label:    &label,
		enroll:   &enroll,
		codeFile: &codeFile,
	}
}

func writeClaimFile(t *testing.T, dir, code string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, "claim-code")
	if err := os.WriteFile(p, []byte(code+"\n"), mode); err != nil {
		t.Fatalf("write claim file: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// The failure ADR-0056 named: a spent code presented again by the next start.
// ---------------------------------------------------------------------------

// TestEnrollSpendsTheClaimCodeExactlyOnceAcrossRestarts is this card's whole
// point, written as a test.
//
// It runs the one-shot, then runs it AGAIN with the same arguments — which is
// what a provisioning script re-run, or a unit file that carried the code, would
// do — and then starts the node's daemon-side account wiring twice more. Across
// all four, /v1/enroll must have been sent exactly once. A shape that
// re-presented a spent code would show up here as a second POST answering
// claim_rejected.
func TestEnrollSpendsTheClaimCodeExactlyOnceAcrossRestarts(t *testing.T) {
	f := newFakeAccount(t)
	// After the first enrollment the service behaves as it really would: the
	// claim hash is erased, so a second presentation is refused outright.
	firstDone := false
	f.enrollHandler = func(w http.ResponseWriter) {
		if firstDone {
			writeTestCoded(w, http.StatusForbidden, string(accountclient.CodeClaimRejected))
			return
		}
		firstDone = true
		f.writeCredentials(w)
	}

	dir := t.TempDir()
	af := testFlags(f)
	codePath := writeClaimFile(t, t.TempDir(), "CLAIM-CODE-1", 0o600)
	*af.codeFile = codePath

	if err := runEnrollment(context.Background(), af, dir); err != nil {
		t.Fatalf("first -enroll: %v", err)
	}
	// The same command line, run again. It must not reach the service at all:
	// the device already holds a credential, and the claim-code file it was
	// pointed at is gone.
	if err := runEnrollment(context.Background(), af, dir); err != nil {
		t.Fatalf("second -enroll: %v", err)
	}
	// And two ordinary starts of the service, which is where a -claim-code flag
	// would have been re-supplied. The service's command line names no claim
	// code under any flag — that is the whole shape, and setupAccountService
	// refuses one outright (see its own test).
	*af.codeFile = defaultClaimCodeFile
	for i := 0; i < 2; i++ {
		if _, err := setupAccountService(af, dir, []string{core.RoleClient}); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}

	if got := f.count("/v1/enroll"); got != 1 {
		t.Fatalf("POST /v1/enroll sent %d times across one enrollment, one re-run and two starts, want exactly 1", got)
	}
}

// TestEnrollIsIdempotentForADeviceThatAlreadyHoldsOne: the guard that makes the
// re-run above safe is asked BEFORE anything is spent, so a second -enroll with a
// DIFFERENT, live claim code does not burn it either. That is the case a
// provisioning script gets wrong: it re-runs with a fresh code because the first
// run's output was lost.
func TestEnrollIsIdempotentForADeviceThatAlreadyHoldsOne(t *testing.T) {
	f := newFakeAccount(t)
	dir := t.TempDir()
	af := testFlags(f)

	first := writeClaimFile(t, t.TempDir(), "CLAIM-1", 0o600)
	*af.codeFile = first
	if err := runEnrollment(context.Background(), af, dir); err != nil {
		t.Fatalf("first -enroll: %v", err)
	}

	second := writeClaimFile(t, t.TempDir(), "CLAIM-2", 0o600)
	*af.codeFile = second
	if err := runEnrollment(context.Background(), af, dir); err != nil {
		t.Fatalf("second -enroll with a fresh code: %v", err)
	}
	if got := f.count("/v1/enroll"); got != 1 {
		t.Fatalf("POST /v1/enroll sent %d times, want 1 — the second, live claim code was spent on a device that already held a credential", got)
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatalf("the second claim code file was removed even though it was never spent: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The code does not stay readable once it has been spent.
// ---------------------------------------------------------------------------

func TestEnrollRemovesTheClaimCodeFileOnSuccess(t *testing.T) {
	f := newFakeAccount(t)
	dir := t.TempDir()
	af := testFlags(f)
	codePath := writeClaimFile(t, t.TempDir(), "CLAIM-CODE-1", 0o600)
	*af.codeFile = codePath

	if err := runEnrollment(context.Background(), af, dir); err != nil {
		t.Fatalf("-enroll: %v", err)
	}
	if _, err := os.Stat(codePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the claim code is still readable at %s after being spent (stat err = %v)", codePath, err)
	}
	// And the credential really did land where the engine will read it from.
	dev, err := core.OpenDeviceEnrollment(dir)
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	if !dev.Enrolled() {
		t.Fatal("the claim code was spent and the file removed, but no credential was persisted")
	}
}

// TestEnrollLeavesTheClaimCodeFileOnARefusal: a refused code is left in place,
// because the operator who mistyped it needs to see and correct what they typed.
// Erasing it would leave them with nothing to fix.
func TestEnrollLeavesTheClaimCodeFileOnARefusal(t *testing.T) {
	f := newFakeAccount(t)
	f.enrollHandler = func(w http.ResponseWriter) {
		writeTestCoded(w, http.StatusForbidden, string(accountclient.CodeClaimRejected))
	}
	dir := t.TempDir()
	af := testFlags(f)
	codePath := writeClaimFile(t, t.TempDir(), "TYPO", 0o600)
	*af.codeFile = codePath

	err := runEnrollment(context.Background(), af, dir)
	if err == nil {
		t.Fatal("-enroll reported success against a service that refused the claim code")
	}
	if _, serr := os.Stat(codePath); serr != nil {
		t.Fatalf("the refused claim code was removed, leaving the operator nothing to correct: %v", serr)
	}
	// And the refusal names the service rather than being a bare error string.
	if !strings.Contains(err.Error(), "refused") {
		t.Fatalf("refusal text = %q, want it to say the account service refused", err)
	}
}

// TestEnrollReadsTheClaimCodeFromStdin covers the DEFAULT source, and the reason
// it is the default: a code piped in is never written to a disk, so there is
// nothing to erase and no erasure that can fail.
func TestEnrollReadsTheClaimCodeFromStdin(t *testing.T) {
	f := newFakeAccount(t)
	dir := t.TempDir()
	af := testFlags(f)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = saved })
	go func() {
		_, _ = w.WriteString("CLAIM-FROM-STDIN\n")
		_ = w.Close()
	}()

	if err := runEnrollment(context.Background(), af, dir); err != nil {
		t.Fatalf("-enroll from stdin: %v", err)
	}
	if got := f.count("/v1/enroll"); got != 1 {
		t.Fatalf("POST /v1/enroll sent %d times, want 1", got)
	}
	var sent struct {
		Claim string `json:"claim"`
	}
	if err := json.Unmarshal(f.body("/v1/enroll"), &sent); err != nil {
		t.Fatalf("decode the enroll request: %v", err)
	}
	if sent.Claim != "CLAIM-FROM-STDIN" {
		t.Fatalf("claim code on the wire = %q, want the trimmed value read from stdin", sent.Claim)
	}
}

func TestReadClaimCodeRefusesAnEmptySource(t *testing.T) {
	dir := t.TempDir()
	empty := writeClaimFile(t, dir, "", 0o600)
	if _, _, err := readClaimCode(empty); err == nil {
		t.Fatal("an empty claim-code file was accepted; it must be reported rather than silently read as 'collect'")
	}
	if _, _, err := readClaimCode(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Fatal("a missing claim-code file was accepted")
	}
	// Empty means collect, and is not an error.
	code, src, err := readClaimCode("")
	if err != nil || code != "" || src.path != "" {
		t.Fatalf(`readClaimCode("") = %q, %+v, %v; want the collect-only shape`, code, src, err)
	}
}

// ---------------------------------------------------------------------------
// -device-cred-dir: the refusal that keeps a claim code from being spent on an
// identity that ceases to exist when the process does.
// ---------------------------------------------------------------------------

func TestEnrollRefusesAnEmptyDeviceCredDirWithoutSpendingAnything(t *testing.T) {
	f := newFakeAccount(t)
	af := testFlags(f)
	codePath := writeClaimFile(t, t.TempDir(), "CLAIM", 0o600)
	*af.codeFile = codePath

	err := runEnrollment(context.Background(), af, "")
	if !errors.Is(err, errNoCredDir) {
		t.Fatalf("runEnrollment with no -device-cred-dir = %v, want errNoCredDir", err)
	}
	if got := f.count("/v1/challenge") + f.count("/v1/enroll"); got != 0 {
		t.Fatalf("the refusal still reached the account service %d times; a claim code must not be spent on an in-memory identity", got)
	}
	if _, serr := os.Stat(codePath); serr != nil {
		t.Fatalf("the unspent claim code was removed: %v", serr)
	}
}

func TestSetupAccountServiceRefusesAnEmptyDeviceCredDir(t *testing.T) {
	f := newFakeAccount(t)
	if _, err := setupAccountService(testFlags(f), "  ", []string{core.RoleClient}); !errors.Is(err, errNoCredDir) {
		t.Fatalf("setupAccountService with no -device-cred-dir = %v, want errNoCredDir", err)
	}
}

// TestSetupAccountServiceIsInertWithNoAccountService: a deployment that names no
// account service configures nothing and gets nil, which core reads as renewal
// off. This is the posture every existing node has, and it must survive.
func TestSetupAccountServiceIsInertWithNoAccountService(t *testing.T) {
	hook, err := setupAccountService(testFlags(nil), "", []string{core.RoleClient})
	if err != nil {
		t.Fatalf("a node with no account service failed to start: %v", err)
	}
	if hook != nil {
		t.Fatal("a node with no account service was given a renewal hook")
	}
}

// TestSetupAccountServiceRefusesABrokenConfiguration: every value
// accountclient.New refuses is one that cannot be defaulted, so a typo stops the
// start and names itself rather than leaving the node silently unrenewable — or,
// worse, pinned to nothing.
func TestSetupAccountServiceRefusesABrokenConfiguration(t *testing.T) {
	f := newFakeAccount(t)
	cases := []struct {
		name  string
		mut   func(af accountFlags)
		wants string
	}{
		{"no audience", func(af accountFlags) { *af.audience = "" }, "Audience is required"},
		{"no pinned CA", func(af accountFlags) { *af.ca = "" }, "ServerCAFile is required"},
		{"plain http", func(af accountFlags) { *af.service = "http://account.example" }, "must be https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			af := testFlags(f)
			tc.mut(af)
			_, err := setupAccountService(af, t.TempDir(), []string{core.RoleClient})
			if err == nil || !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("setupAccountService = %v, want an error containing %q", err, tc.wants)
			}
		})
	}
}

// TestSetupAccountServiceRefusesAClaimCodeFileOnARunningStart: the flag is read
// by the one-shot and by nothing else, so a unit file carrying it describes an
// enrollment that will never happen.
func TestSetupAccountServiceRefusesAClaimCodeFileOnARunningStart(t *testing.T) {
	f := newFakeAccount(t)
	af := testFlags(f)
	*af.codeFile = "/etc/bacchus/claim-code"
	_, err := setupAccountService(af, t.TempDir(), []string{core.RoleClient})
	if err == nil || !strings.Contains(err.Error(), "-enroll") {
		t.Fatalf("setupAccountService with a -claim-code-file = %v, want a refusal pointing at -enroll", err)
	}
	// The default value is not a mistake, with or without an account service.
	if _, err := setupAccountService(testFlags(f), t.TempDir(), []string{core.RoleClient}); err != nil {
		t.Fatalf("the default -claim-code-file was refused: %v", err)
	}
}

// TestNoFlagCarriesAClaimCodeValue is the structural half of ADR-0056's ruling:
// there is no -claim-code, so no command line can carry the secret and no restart
// can re-present it. Registered on a throwaway flag set, since the real one is
// process-wide.
func TestNoFlagCarriesAClaimCodeValue(t *testing.T) {
	fs := flag.NewFlagSet("node", flag.ContinueOnError)
	saved := flag.CommandLine
	flag.CommandLine = fs
	t.Cleanup(func() { flag.CommandLine = saved })
	registerAccountFlags()

	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	for _, n := range names {
		if n == "claim-code" || n == "claim" {
			t.Fatalf("a -%s flag exists; ADR-0056 rules that a claim code must not be a command-line value", n)
		}
	}
	if fs.Lookup("claim-code-file") == nil {
		t.Fatal("-claim-code-file is missing")
	}
	if got := fs.Lookup("claim-code-file").DefValue; got != defaultClaimCodeFile {
		t.Fatalf("-claim-code-file default = %q, want %q (stdin, so a code need never reach a disk)", got, defaultClaimCodeFile)
	}
}

// ---------------------------------------------------------------------------
// Collect: the path for a node whose credential was lost and whose key was not.
// ---------------------------------------------------------------------------

// TestEnrollWithNoClaimCodeCollects covers the recovery ADR-0046 §4 makes
// possible: core/devicestore soft-fails an unreadable credential to empty, so a
// node can lose its credential while keeping the device key the account service
// resolves it by. No claim code exists to re-spend; /v1/credential is the way
// back.
func TestEnrollWithNoClaimCodeCollects(t *testing.T) {
	f := newFakeAccount(t)
	dir := t.TempDir()
	af := testFlags(f)
	codePath := writeClaimFile(t, t.TempDir(), "CLAIM", 0o600)
	*af.codeFile = codePath
	if err := runEnrollment(context.Background(), af, dir); err != nil {
		t.Fatalf("-enroll: %v", err)
	}
	before, err := core.OpenDeviceEnrollment(dir)
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	wantPub := before.DevicePub()

	// The credential file is destroyed; the device key survives.
	if err := os.Remove(core.DeviceCredPath(dir)); err != nil {
		t.Fatalf("remove the credential file: %v", err)
	}

	*af.codeFile = "" // no claim code to spend
	if err := runEnrollment(context.Background(), af, dir); err != nil {
		t.Fatalf("-enroll with no claim code: %v", err)
	}
	if got := f.count("/v1/enroll"); got != 1 {
		t.Fatalf("POST /v1/enroll sent %d times, want 1 — collecting must not spend a claim code", got)
	}
	if got := f.count("/v1/credential"); got != 1 {
		t.Fatalf("POST /v1/credential sent %d times, want 1", got)
	}
	after, err := core.OpenDeviceEnrollment(dir)
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	if !after.Enrolled() {
		t.Fatal("collecting did not restore a credential")
	}
	if !after.DevicePub().Equal(wantPub) {
		t.Fatal("the device key changed across the loss; the collected credential is bound to a different identity than the one enrolled")
	}
}

// ---------------------------------------------------------------------------
// Renewal.
// ---------------------------------------------------------------------------

// TestRenewalInsideTheMarginRefreshesTheCredential drives the seam this card
// fills. The premise is asserted rather than assumed: the fixture credential is
// checked to be inside core's own renewal margin, so this test would fail if the
// margin or the fixture drifted apart and stopped meaning what the name says.
func TestRenewalInsideTheMarginRefreshesTheCredential(t *testing.T) {
	f := newFakeAccount(t)
	dir := t.TempDir()

	// 2h left against the 6h default margin: due now.
	const engineDefaultMargin = 6 * time.Hour
	expiring := mintCredential(t, time.Now().Add(2*time.Hour))
	if !devicestore.NeedsRenewal(expiring, time.Now(), engineDefaultMargin) {
		t.Fatal("the fixture is not actually inside the renewal margin; this test would pass without exercising anything")
	}
	fresh := mintCredential(t, time.Now().Add(48*time.Hour))
	f.device = fresh

	dev, err := core.OpenDeviceEnrollment(dir)
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	if err := dev.Put(devicestore.Credential{Device: expiring, IssuerCert: "issuer", Admission: "old-admission"}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	hook, err := setupAccountService(testFlags(f), dir, []string{core.RoleClient})
	if err != nil {
		t.Fatalf("setupAccountService: %v", err)
	}
	if hook == nil {
		t.Fatal("a node with an account service configured got no renewal hook")
	}
	current, _ := dev.Current()
	got, err := hook(context.Background(), core.DeviceRenewRequest{
		DevicePub: dev.DevicePub(),
		Current:   current,
		Sign:      dev.SignRenew,
	})
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if got.Device != fresh {
		t.Fatalf("renewal returned the old credential; the seam must hand back what the service issued")
	}
	// All three, from one response. A seam that dropped the admission credential
	// would refresh the entitlement and let network membership lapse
	// (ADR-0056 §7).
	if got.Admission != f.admission || got.IssuerCert != f.issuerCert {
		t.Fatalf("renewal returned %+v, want the issuer cert and admission credential the same response carried", got)
	}
	if got := f.count("/v1/enroll"); got != 0 {
		t.Fatalf("renewal sent %d enroll requests; renewal spends no claim code", got)
	}
}

// TestRenewalFailureIsReportedNotSwallowed: the seam's error reaches core, which
// keeps the credential the node already holds and retries at the next tick.
func TestRenewalFailureIsReportedNotSwallowed(t *testing.T) {
	f := newFakeAccount(t)
	f.credentialHandler = func(w http.ResponseWriter) {
		writeTestCoded(w, http.StatusForbidden, string(accountclient.CodeDeviceRevoked))
	}
	dir := t.TempDir()
	hook, err := setupAccountService(testFlags(f), dir, []string{core.RoleClient})
	if err != nil {
		t.Fatalf("setupAccountService: %v", err)
	}
	dev, err := core.OpenDeviceEnrollment(dir)
	if err != nil {
		t.Fatalf("OpenDeviceEnrollment: %v", err)
	}
	_, err = hook(context.Background(), core.DeviceRenewRequest{
		DevicePub: dev.DevicePub(),
		Current:   devicestore.Credential{Device: mintCredential(t, time.Now().Add(time.Hour))},
		Sign:      dev.SignRenew,
	})
	if code, ok := accountclient.CodeOf(err); !ok || code != accountclient.CodeDeviceRevoked {
		t.Fatalf("renewal error = %v, want the service's coded refusal to survive the wrapper", err)
	}
}

// TestRenewalFailureTextEscalatesOnTheClock. What went wrong is mostly not
// actionable; how long is left always is.
func TestRenewalFailureTextEscalatesOnTheClock(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	boom := errors.New("dial tcp: connection refused")

	cases := []struct {
		name    string
		cred    string
		err     error
		wants   []string
		unwants []string
	}{
		{
			name:    "plenty of time left is a note",
			cred:    mintCredential(t, now.Add(30*time.Hour)),
			err:     boom,
			wants:   []string{"will be retried", "keeps connecting"},
			unwants: []string{"WARNING"},
		},
		{
			name:  "inside the escalation threshold is a warning",
			cred:  mintCredential(t, now.Add(90*time.Minute)),
			err:   boom,
			wants: []string{"WARNING", "will refuse"},
		},
		{
			name:  "already expired says so",
			cred:  mintCredential(t, now.Add(-time.Minute)),
			err:   boom,
			wants: []string{"EXPIRED", "refusing"},
		},
		{
			name:  "an unreadable credential admits it cannot tell",
			cred:  "not-a-credential",
			err:   boom,
			wants: []string{"cannot be read"},
		},
		{
			name:    "a revoked device ignores the clock",
			cred:    mintCredential(t, now.Add(30*time.Hour)),
			err:     &accountclient.Error{Code: accountclient.CodeDeviceRevoked},
			wants:   []string{"REVOKED"},
			unwants: []string{"will be retried"},
		},
		{
			name:    "a lapsed subscription ignores the clock",
			cred:    mintCredential(t, now.Add(30*time.Hour)),
			err:     &accountclient.Error{Code: accountclient.CodeEntitlementExpired},
			wants:   []string{"subscription has lapsed"},
			unwants: []string{"will be retried"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := renewalFailureText(tc.cred, tc.err, now)
			for _, w := range tc.wants {
				if !strings.Contains(got, w) {
					t.Fatalf("text = %q, want it to contain %q", got, w)
				}
			}
			for _, u := range tc.unwants {
				if strings.Contains(got, u) {
					t.Fatalf("text = %q, want it NOT to contain %q", got, u)
				}
			}
		})
	}
}

// TestCoarseRendersARemainingLifetime. Minutes under an hour, whole hours above
// it — the extra precision would suggest the number means more than it does.
func TestCoarseRendersARemainingLifetime(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "1m"},
		{45 * time.Minute, "45m"},
		{90 * time.Minute, "1h"},
		{4*time.Hour + 37*time.Minute, "4h"},
	} {
		if got := coarse(tc.d); got != tc.want {
			t.Fatalf("coarse(%s) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

// TestDefaultDeviceLabelIsNeverDerivedFromTheMachine. The label travels to the
// account service in the clear and is stored there durably; a server hostname is
// routinely the provider's, the datacenter's, or a person's name.
func TestDefaultDeviceLabelIsNeverDerivedFromTheMachine(t *testing.T) {
	af := testFlags(nil)
	if got := af.effectiveLabel(); got != defaultDeviceLabel {
		t.Fatalf("default label = %q, want the constant %q", got, defaultDeviceLabel)
	}
	host, err := os.Hostname()
	if err == nil && strings.EqualFold(host, defaultDeviceLabel) {
		t.Skip("this machine is called the default label, so the check below proves nothing here")
	}
	if err == nil && strings.Contains(strings.ToLower(af.effectiveLabel()), strings.ToLower(host)) {
		t.Fatalf("the default device label %q carries this machine's hostname", af.effectiveLabel())
	}
	*af.label = "  the-amsterdam-box  "
	if got := af.effectiveLabel(); got != "the-amsterdam-box" {
		t.Fatalf("effectiveLabel() = %q, want the trimmed operator value", got)
	}
}
