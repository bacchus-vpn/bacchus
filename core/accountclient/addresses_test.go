package accountclient

import (
	"context"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core"
)

// pinBoth writes one PEM file holding every given service's certificate, which
// is what an operator running the successor address alongside the current one
// hands over: one pinned identity set, applied to the whole list. It is still one
// authority — the client has no way to say "this CA for that address" and that is
// the property bacchus#192 turns on.
func pinBoth(t *testing.T, services ...*fakeService) string {
	t.Helper()
	var bundle []byte
	for _, f := range services {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})...)
	}
	p := filepath.Join(t.TempDir(), "service-ca-bundle.pem")
	if err := os.WriteFile(p, bundle, 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	return p
}

func twoAddressClient(t *testing.T, first, second *fakeService, ca string) *Client {
	t.Helper()
	c, err := New(Config{
		BaseURLs:     []string{first.srv.URL, second.srv.URL},
		Audience:     testAudience,
		ServerCAFile: ca,
		Logf:         func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// TestRenewalRotatesWhenTheFirstAddressIsUnreachable is bacchus#192's whole
// point. The account service runs on anonymously rented infrastructure and its
// address will change; because a device renews the moment it enters its margin,
// an unreachable service takes the first devices offline about six hours later.
// A successor address named before the move is what the client rotates to by
// itself.
func TestRenewalRotatesWhenTheFirstAddressIsUnreachable(t *testing.T) {
	gone := newFakeService(t)
	live := newFakeService(t)
	ca := pinBoth(t, gone, live)
	c := twoAddressClient(t, gone, live, ca)
	dev, _ := newDevice(t)

	// The move has happened: the first address answers nothing at all.
	gone.srv.Close()

	got, err := c.Renew(context.Background(), core.DeviceRenewRequest{
		DevicePub: dev.DevicePub(),
		Sign:      dev.SignRenew,
	})
	if err != nil {
		t.Fatalf("Renew with a dead first address: %v", err)
	}
	if got.Device != live.device || got.IssuerCert != live.issuerCert {
		t.Fatalf("Renew returned %+v, want the second address's credential", got)
	}
	if n := live.count("/v1/credential"); n != 1 {
		t.Fatalf("the second address served %d credential requests, want 1", n)
	}
	// Both legs went to the address that answered. A challenge is server state —
	// the service holds live challenges in memory — so a challenge minted at one
	// address means nothing at another, and splitting the pair across addresses
	// would be a permanent unknown_challenge rather than a failover.
	if n := live.count("/v1/challenge"); n != 1 {
		t.Fatalf("the second address served %d challenge requests, want 1: the exchange did not stay on one address", n)
	}
}

// TestAFailedAddressIsNotPreferredAgainImmediately: the memo is what makes the
// second exchange cheap. Without it every renewal would re-dial the dead address
// first, ten minutes apart, for as long as the outage lasted.
func TestAFailedAddressIsNotPreferredAgainImmediately(t *testing.T) {
	gone := newFakeService(t)
	live := newFakeService(t)
	ca := pinBoth(t, gone, live)
	c := twoAddressClient(t, gone, live, ca)
	dev, _ := newDevice(t)

	gone.srv.Close()

	for i := 0; i < 3; i++ {
		if _, err := c.Renew(context.Background(), core.DeviceRenewRequest{
			DevicePub: dev.DevicePub(),
			Sign:      dev.SignRenew,
		}); err != nil {
			t.Fatalf("renewal %d: %v", i+1, err)
		}
	}
	if n := live.count("/v1/credential"); n != 3 {
		t.Fatalf("the live address served %d of 3 renewals", n)
	}
	if got := c.baseOrder(); got[0] != live.srv.URL {
		t.Fatalf("baseOrder() = %v, want the address that answered first", got)
	}
}

// TestASecondAddressIsASecondLocationAndNeverASecondAuthority is the constraint
// that makes a list safe rather than a liability. Audience and ServerCAFile are
// single fields validated once, so there is no way to express "trust this other
// root for that other address" — and an address that does not present the pinned
// identity has to be unreachable rather than trusted, or the field quietly
// becomes a list of trust roots.
func TestASecondAddressIsASecondLocationAndNeverASecondAuthority(t *testing.T) {
	pinned := newFakeService(t)
	stranger := newFakeService(t) // a perfectly valid certificate, for itself

	c, err := New(Config{
		BaseURLs:     []string{pinned.srv.URL, stranger.srv.URL},
		Audience:     testAudience,
		ServerCAFile: pinned.ca, // only the first address's identity is pinned
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dev, _ := newDevice(t)

	pinned.srv.Close()

	if _, err := c.Renew(context.Background(), core.DeviceRenewRequest{
		DevicePub: dev.DevicePub(),
		Sign:      dev.SignRenew,
	}); err == nil {
		t.Fatal("a renewal succeeded through an address whose TLS identity was never pinned")
	}
	if n := stranger.count("/v1/challenge") + stranger.count("/v1/credential"); n != 0 {
		t.Fatalf("the unpinned address received %d requests; the handshake must fail before any assertion is sent to it", n)
	}
}

// TestEnrollIsSentToExactlyOneAddress is the trap in making this a list. A claim
// code spent by a request whose response was lost is GONE — the service erases a
// spent claim hash rather than flagging it — so a rotation that re-sent
// /v1/enroll to the next address would destroy a paying customer's access in
// precisely the situation the list exists to survive.
//
// The two halves are different rules, which is why the rotation in Enroll is
// written out by hand rather than run through overExchanges: a challenge costs
// nothing and may be fetched from anywhere, and the enroll request that follows
// it pins the address for good.
func TestEnrollIsSentToExactlyOneAddress(t *testing.T) {
	t.Run("a dead first address moves the whole enrollment", func(t *testing.T) {
		gone := newFakeService(t)
		live := newFakeService(t)
		ca := pinBoth(t, gone, live)
		c := twoAddressClient(t, gone, live, ca)
		dev, _ := newDevice(t)

		gone.srv.Close()

		if _, err := c.Enroll(context.Background(), dev, "claim-code", "desktop"); err != nil {
			t.Fatalf("Enroll: %v", err)
		}
		if n := live.count("/v1/enroll"); n != 1 {
			t.Fatalf("the live address served %d enrollments, want 1", n)
		}
	})

	t.Run("an enroll that fails after it was sent is never re-sent", func(t *testing.T) {
		first := newFakeService(t)
		second := newFakeService(t)
		ca := pinBoth(t, first, second)
		c := twoAddressClient(t, first, second, ca)
		dev, _ := newDevice(t)

		// The request arrives and the answer does not come back: the outcome is
		// genuinely unknown and the claim code may already be spent.
		first.enrollHandler = func(w http.ResponseWriter, _ []byte) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{ this is not the answer"))
		}

		_, err := c.Enroll(context.Background(), dev, "claim-code", "desktop")

		if n := first.count("/v1/enroll"); n != 1 {
			t.Fatalf("the first address served %d enrollments, want exactly 1", n)
		}
		if n := second.count("/v1/enroll"); n != 0 {
			t.Fatalf("the enrollment was re-sent to %d further addresses; a claim code is spent once and a second attempt cannot recover it", n)
		}
		// Recovery, not retry: Collect asks /v1/credential with the device key this
		// process still holds. It is free to rotate, and it starts where the
		// enrollment was sent — that address answered its challenge, so nothing
		// marked it unreachable, and it is the address most likely to know whether
		// the enrollment landed.
		if err != nil {
			t.Fatalf("the ambiguous enrollment was not recovered: %v", err)
		}
		if n := first.count("/v1/credential"); n != 1 {
			t.Fatalf("the recovery made %d /v1/credential calls to the address that took the enrollment, want 1", n)
		}
	})
}

// TestOneServiceAtTwoAddressesIsStillOneRefusal: a coded refusal is the service
// ANSWERING, and every address in this list is that same service. Rotating past
// an answer would turn one refusal into as many refusals as there are addresses
// — each spending a challenge, and each counting toward the per-device-key
// cooldown the service applies to a failed assertion.
func TestOneServiceAtTwoAddressesIsStillOneRefusal(t *testing.T) {
	first := newFakeService(t)
	second := newFakeService(t)
	ca := pinBoth(t, first, second)
	c := twoAddressClient(t, first, second, ca)
	dev, _ := newDevice(t)

	first.credentialHandler = func(w http.ResponseWriter, _ []byte) {
		writeCoded(w, http.StatusForbidden, string(CodeEntitlementExpired))
	}

	_, err := c.Renew(context.Background(), core.DeviceRenewRequest{
		DevicePub: dev.DevicePub(),
		Sign:      dev.SignRenew,
	})
	if code, ok := CodeOf(err); !ok || code != CodeEntitlementExpired {
		t.Fatalf("Renew = %v, want the service's own refusal", err)
	}
	if n := second.count("/v1/credential"); n != 0 {
		t.Fatalf("the refusal was re-asked at %d further addresses", n)
	}
}

// TestDuplicateAddressesAreOneAddress: the same address twice is not a second
// location, and leaving it in would spend two rotations on one outage.
func TestDuplicateAddressesAreOneAddress(t *testing.T) {
	f := newFakeService(t)
	c, err := New(Config{
		BaseURLs:     []string{f.srv.URL, f.srv.URL + "/", strings.ToLower(f.srv.URL)},
		Audience:     testAudience,
		ServerCAFile: f.ca,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := c.baseOrder(); len(got) != 1 {
		t.Fatalf("baseOrder() = %v, want one address", got)
	}
}
