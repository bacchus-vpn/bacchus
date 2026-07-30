package admission

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The (trust, plan) key a credential carries (issue #58, the public half of
// bacchus-payment#6). These tests are about the WIRE, not about what the pair means
// — the meaning lives in core/policy's tiers table and its enforcement in
// cmd/coordinator.

func tierCredential() Credential {
	return Credential{
		Version:   CredentialVersion,
		Serial:    "00000000000000ff",
		Subject:   "acct-1",
		Roles:     []Role{RoleClient},
		NotBefore: time.Date(2026, 8, 15, 11, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	}
}

// TestTierKeyIsDeclaredAfterVouchedInThatOrder is the cross-repo wire contract, and
// it is the one property in this file that a passing test suite on either side
// cannot establish on its own.
//
// encoding/json marshals struct fields in DECLARATION order and the marshaled form
// is the signed body, so two independent implementations of one signed format must
// declare the same fields in the same order or a credential minted by one will not
// verify under the other. bacchus-payment's internal/admission.Credential declares
// Vouched, then Trust, then Plan; this pins the same here.
//
// Note what this does NOT catch, so nobody reads more into it than it proves:
// VERIFICATION is order-independent (parse checks the signature over the bytes as
// received and then unmarshals), so a swap would still accept every credential the
// account service mints. It is MINTING that breaks. That is why this asserts on the
// key order in the marshaled body rather than on a verify.
func TestTierKeyIsDeclaredAfterVouchedInThatOrder(t *testing.T) {
	c := tierCredential()
	c.Vouched, c.Trust, c.Plan = true, "stable", "pro"

	body, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(body)
	iv, it, ip := strings.Index(s, `"vouched"`), strings.Index(s, `"trust"`), strings.Index(s, `"plan"`)
	if iv < 0 || it < 0 || ip < 0 {
		t.Fatalf("a fully-populated credential is missing one of vouched/trust/plan: %s", s)
	}
	if !(iv < it && it < ip) {
		t.Errorf("signed-body field order is vouched@%d trust@%d plan@%d; want vouched < trust < plan — this is the order bacchus-payment declares, and a credential minted here would no longer match one minted there: %s", iv, it, ip, s)
	}
}

// TestUnsetTierKeyIsByteIdenticalToAPreTierCredential is what makes these fields
// additive. A credential that names no tier must marshal to exactly the bytes it
// would have before #58, so an operator-issued credential is unchanged and an older
// verifier reads the same body it always did.
func TestUnsetTierKeyIsByteIdenticalToAPreTierCredential(t *testing.T) {
	body, err := json.Marshal(tierCredential())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"trust", "plan", "vouched"} {
		if _, ok := m[k]; ok {
			t.Errorf("%q present on a credential that claims no tier: %s", k, body)
		}
	}
}

// TestFreeTierCredentialOmitsPlanNotTrust pins the asymmetry the two fields have on
// the wire, because it looks like an inconsistency and is not. The empty string is
// policy.TierLimit.Plan's legitimate "no paid plan" value, so a free-tier credential
// carries a real trust tier and no plan key at all — and that pair still resolves,
// because the policy's row for it is keyed by the empty plan explicitly.
func TestFreeTierCredentialOmitsPlanNotTrust(t *testing.T) {
	c := tierCredential()
	c.Trust = "ephemeral"

	body, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["trust"] != "ephemeral" {
		t.Errorf("trust = %v, want ephemeral: %s", m["trust"], body)
	}
	if _, ok := m["plan"]; ok {
		t.Errorf("plan present on a credential with no paid plan: %s", body)
	}
}

// TestTierKeySurvivesSignAndVerify: the pair a verifier hands back is the pair the
// issuer signed, and it is covered by the signature like every other field. The
// coordinator resolves a policy row from these two strings, so a tier that could be
// edited in flight would be a tier a client could choose for itself.
func TestTierKeySurvivesSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := tierCredential()
	c.NotBefore, c.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	c.Vouched, c.Trust, c.Plan = true, "stable", "pro"

	signed, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, err := NewVerifier(pub, nil).Verify(Encode(signed), time.Now(), RoleClient, "acct-1")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Trust != "stable" || got.Plan != "pro" || !got.Vouched {
		t.Errorf("verified credential = trust %q / plan %q / vouched %v; want stable / pro / true", got.Trust, got.Plan, got.Vouched)
	}
}

// TestTamperedTierKeyIsRefused is the same property from the attacker's side: the
// pair is signed data, so upgrading yourself is a signature failure and not a
// negotiation. It is worth its own test because trust and plan are the first fields
// on this credential whose value a HOLDER has a direct financial reason to change.
func TestTamperedTierKeyIsRefused(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	c := tierCredential()
	c.NotBefore, c.NotAfter = time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	c.Trust, c.Plan = "ephemeral", ""

	signed, err := Sign(priv, c)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// Rewrite the body's tier to the most expensive row and keep the signature.
	body := signed[:len(signed)-signedLen]
	sig := signed[len(signed)-signedLen:]
	forged := append([]byte(strings.Replace(string(body), `"trust":"ephemeral"`, `"trust":"stable___"`, 1)), sig...)
	if len(forged) != len(signed) {
		t.Fatalf("the forgery changed the body length (%d vs %d), so this would fail for the wrong reason", len(forged), len(signed))
	}

	if _, err := NewVerifier(pub, nil).Verify(Encode(forged), time.Now(), RoleClient, "acct-1"); err == nil {
		t.Fatal("a credential whose trust tier was rewritten after signing VERIFIED — a client can pick its own tier")
	}
}

// TestIssueStampsNoTierKey pins the provenance rule the fields' docs state: nothing
// in this repository is the account service, so the public issuer must not be able
// to mint a tiered credential. If this ever fails, cmd/admission-issue has grown the
// ability to grant paid standing.
func TestIssueStampsNoTierKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Now()
	c, _, err := Issue(priv, "acct-1", []Role{RoleClient}, now, now.Add(time.Hour), "test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if c.Trust != "" || c.Plan != "" || c.Vouched {
		t.Errorf("Issue stamped standing: trust %q / plan %q / vouched %v — this repo has no trust graph and must not grant one", c.Trust, c.Plan, c.Vouched)
	}
}
