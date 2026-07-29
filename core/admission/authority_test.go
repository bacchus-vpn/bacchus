package admission

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

// Two authorities standing in for the two issuers #64 exists to separate: the
// operator's offline key, which mints relay/exit credentials bound to a node id,
// and the account service's key, which mints bearer client credentials
// automatically. Held together so every test in this file reads against the same
// deployment shape.
type twoAuthorities struct {
	operatorPub  ed25519.PublicKey
	operatorPriv ed25519.PrivateKey
	accountPub   ed25519.PublicKey
	accountPriv  ed25519.PrivateKey
}

func newTwoAuthorities(t *testing.T) twoAuthorities {
	t.Helper()
	opPub, opPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate operator key: %v", err)
	}
	acPub, acPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	return twoAuthorities{operatorPub: opPub, operatorPriv: opPriv, accountPub: acPub, accountPriv: acPriv}
}

// verifier anchors the split #64 makes expressible: the operator admits relay
// and exit, the account service admits client, and neither admits the other's.
func (k twoAuthorities) verifier(t *testing.T, revoked func(string) bool) *Verifier {
	t.Helper()
	v, err := NewAuthoritySetVerifier([]Authority{
		{Pub: k.operatorPub, Roles: []Role{RoleRelay, RoleExit}},
		{Pub: k.accountPub, Roles: []Role{RoleClient}},
	}, revoked)
	if err != nil {
		t.Fatalf("NewAuthoritySetVerifier: %v", err)
	}
	return v
}

func issue(t *testing.T, priv ed25519.PrivateKey, subject string, roles []Role) string {
	t.Helper()
	_, enc, err := Issue(priv, subject, roles, base.Add(-time.Hour), base.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return enc
}

// TestAnchoredRoleDecidesNotTheCredentialsOwnRoles is the mutation check for the
// role filter in Verify, and the reason #64 is a security change rather than a
// configuration convenience.
//
// The account service holds a signing key, so it writes whatever it likes into
// the Roles field of what it mints — including "exit". The credential below is
// therefore internally perfect: correctly signed, unexpired, unrevoked, bound to
// the right subject, and claiming exactly the role it is presented for. The ONLY
// thing that rejects it is the anchor: the account authority is anchored for
// client, so its key is not a candidate for an exit check and never gets a
// signature verification at all.
//
// DELETE the `if !a.admits(want) { continue }` line in Verify and this test
// fails with the credential ADMITTED — not with a different error, an actual
// admission. That is the mutation this test exists to catch: without the filter
// the decision falls back to the credential's own roles field, which is written
// by the very key whose compromise the split is meant to contain.
func TestAnchoredRoleDecidesNotTheCredentialsOwnRoles(t *testing.T) {
	k := newTwoAuthorities(t)
	v := k.verifier(t, nil)

	const nodeID = "exit-node-A"
	forged := issue(t, k.accountPriv, nodeID, []Role{RoleClient, RoleExit})

	if _, err := v.Verify(forged, base, RoleExit, nodeID); err == nil {
		t.Fatal("the account authority minted itself an exit credential and the coordinator ADMITTED it — the anchor's role scoping is not being enforced, so a compromised client issuer can join the network as forwarding infrastructure (issue #64)")
	} else if !errors.Is(err, ErrBadSignature) {
		t.Errorf("rejected with %v, want ErrBadSignature — the account key must not be a signature candidate for an exit check at all", err)
	}

	// Non-vacuity, twice over. The same credential is admitted for the role
	// its authority IS anchored for, so the rejection above is the anchor
	// and not something wrong with the credential...
	if _, err := v.Verify(forged, base, RoleClient, ""); err != nil {
		t.Errorf("the account authority's own client credential was rejected: %v — the split is refusing the wrong side", err)
	}
	// ...and the operator, which IS anchored for exit, is admitted for it,
	// so the rejection is not "exit is refused here".
	if _, err := v.Verify(issue(t, k.operatorPriv, nodeID, []Role{RoleExit}), base, RoleExit, nodeID); err != nil {
		t.Errorf("the operator's exit credential was rejected: %v", err)
	}
}

// The credential the DONE bar names: one credential from the account authority,
// admitted as client and refused as exit, on the same verifier, without the
// credential changing.
func TestSameCredentialAdmittedAsClientRefusedAsExit(t *testing.T) {
	k := newTwoAuthorities(t)
	v := k.verifier(t, nil)
	cred := issue(t, k.accountPriv, "user-7", []Role{RoleClient})

	if _, err := v.Verify(cred, base, RoleClient, ""); err != nil {
		t.Fatalf("client credential rejected for RoleClient: %v", err)
	}
	if _, err := v.Verify(cred, base, RoleExit, "user-7"); err == nil {
		t.Fatal("the same client credential was admitted as an exit")
	}
}

// The operator authority is anchored for relay and exit but NOT client, so its
// hand-minted client credential is refused — the split cuts both ways, which is
// what makes it a scoping of authorities rather than a demotion of one of them.
func TestOperatorAuthorityIsNotAnchoredForClient(t *testing.T) {
	k := newTwoAuthorities(t)
	v := k.verifier(t, nil)

	cred := issue(t, k.operatorPriv, "user-7", []Role{RoleClient})
	if _, err := v.Verify(cred, base, RoleClient, ""); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("operator-signed client credential: err = %v, want ErrBadSignature (the operator is anchored for relay/exit only)", err)
	}
}

// One authority may hold several roles, and a credential from it is admitted for
// each of them — anchoring is per-authority-per-role, not one role per key.
func TestOneAuthorityCoversEachRoleItIsAnchoredFor(t *testing.T) {
	k := newTwoAuthorities(t)
	v := k.verifier(t, nil)

	const nodeID = "node-M"
	cred := issue(t, k.operatorPriv, nodeID, []Role{RoleRelay, RoleExit})
	for _, want := range []Role{RoleRelay, RoleExit} {
		if _, err := v.Verify(cred, base, want, nodeID); err != nil {
			t.Errorf("Verify(%s) = %v, want admit", want, err)
		}
	}
}

// Revocation is unaffected by the split (explicitly out of scope in #64): one
// list covers every anchored authority, because a serial names a credential and
// not an issuer.
func TestOneRevocationListCoversEveryAuthority(t *testing.T) {
	k := newTwoAuthorities(t)

	opCred, opEnc, err := Issue(k.operatorPriv, "exit-A", []Role{RoleExit}, base.Add(-time.Hour), base.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	acCred, acEnc, err := Issue(k.accountPriv, "user-7", []Role{RoleClient}, base.Add(-time.Hour), base.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	rl := NewRevocationList()
	rl.Revoke(opCred.Serial)
	rl.Revoke(acCred.Serial)
	v := k.verifier(t, rl.Revoked)

	if _, err := v.Verify(opEnc, base, RoleExit, "exit-A"); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked operator credential: err = %v, want ErrRevoked", err)
	}
	if _, err := v.Verify(acEnc, base, RoleClient, ""); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked account credential: err = %v, want ErrRevoked", err)
	}
}

// A role no anchored authority covers is reported as such rather than as a bad
// signature. It is a fact about this coordinator's configuration, not about the
// credential, and an operator who forgot an anchor has to be able to tell the
// two apart in a log.
func TestRoleWithNoAnchoredAuthority(t *testing.T) {
	k := newTwoAuthorities(t)
	v, err := NewAuthoritySetVerifier([]Authority{{Pub: k.accountPub, Roles: []Role{RoleClient}}}, nil)
	if err != nil {
		t.Fatalf("NewAuthoritySetVerifier: %v", err)
	}
	cred := issue(t, k.operatorPriv, "exit-A", []Role{RoleExit})
	if _, err := v.Verify(cred, base, RoleExit, "exit-A"); !errors.Is(err, ErrNoAuthorityForRole) {
		t.Fatalf("err = %v, want ErrNoAuthorityForRole", err)
	}
}

// A credential this build cannot read must say so, not be masked as a bad
// signature by a later candidate. parse's non-ErrBadSignature failures are facts
// about the credential that no other anchored key would read differently, so
// they short-circuit the loop.
func TestUnsupportedVersionSurvivesTheAuthorityLoop(t *testing.T) {
	k := newTwoAuthorities(t)
	v := k.verifier(t, nil)

	future := Credential{
		Version: CredentialVersion + 1, Serial: "cafe", Subject: "exit-A",
		Roles: []Role{RoleExit}, NotBefore: base.Add(-time.Hour), NotAfter: base.Add(time.Hour),
	}
	signed, err := Sign(k.operatorPriv, future)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := v.Verify(Encode(signed), base, RoleExit, "exit-A"); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want ErrUnsupportedVersion", err)
	}
}

// NewVerifier's single authority is trusted for every role, so a coordinator or
// client that anchors one key behaves as it did before #64 — including that the
// credential's OWN roles field still decides, and still reports
// ErrRoleNotAuthorized when it does.
func TestSingleAnchorIsUnchangedByTheSplit(t *testing.T) {
	k := newTwoAuthorities(t)
	v := NewVerifier(k.operatorPub, nil)

	const nodeID = "node-M"
	for _, want := range AllRoles() {
		cred := issue(t, k.operatorPriv, nodeID, []Role{want})
		if _, err := v.Verify(cred, base, want, nodeID); err != nil {
			t.Errorf("single anchor, role %s: %v, want admit", want, err)
		}
	}

	clientCred := issue(t, k.operatorPriv, nodeID, []Role{RoleClient})
	if _, err := v.Verify(clientCred, base, RoleExit, nodeID); !errors.Is(err, ErrRoleNotAuthorized) {
		t.Errorf("single anchor, client credential presented as exit: err = %v, want ErrRoleNotAuthorized (unchanged from before #64)", err)
	}

	other := newTwoAuthorities(t)
	if _, err := v.Verify(issue(t, other.operatorPriv, nodeID, []Role{RoleExit}), base, RoleExit, nodeID); !errors.Is(err, ErrBadSignature) {
		t.Errorf("single anchor, foreign key: err = %v, want ErrBadSignature", err)
	}
}

// The one behaviour change a single-anchor deployment can observe: a role string
// no build knows. cmd/coordinator passes the register message's role field
// straight through, so this is peer-controlled, and it now stops at the anchor
// (ErrNoAuthorityForRole, before any signature verification) instead of reaching
// the credential's roles field (ErrRoleNotAuthorized). Same rejection, named
// closer to its cause and one ed25519 verification cheaper. Pinned so the change
// is a decision on the record rather than a surprise.
func TestUnknownRoleStopsAtTheAnchor(t *testing.T) {
	k := newTwoAuthorities(t)
	cred := issue(t, k.operatorPriv, "node-M", []Role{RoleExit})

	for name, v := range map[string]*Verifier{
		"single anchor": NewVerifier(k.operatorPub, nil),
		"authority set": k.verifier(t, nil),
	} {
		if _, err := v.Verify(cred, base, Role("courier"), "node-M"); !errors.Is(err, ErrNoAuthorityForRole) {
			t.Errorf("%s: unknown role err = %v, want ErrNoAuthorityForRole", name, err)
		}
	}
}

// Construction fails closed on every ambiguous anchor set. Each of these would
// otherwise produce a coordinator that looks configured and trusts something
// other than what the unit file says.
func TestNewAuthoritySetVerifierRejectsAmbiguousAnchors(t *testing.T) {
	k := newTwoAuthorities(t)
	short := ed25519.PublicKey(k.operatorPub[:16])

	cases := []struct {
		name        string
		authorities []Authority
	}{
		{"no authorities at all", nil},
		{"empty slice", []Authority{}},
		{"key of the wrong length", []Authority{{Pub: short, Roles: []Role{RoleExit}}}},
		{"nil key", []Authority{{Pub: nil, Roles: []Role{RoleExit}}}},
		{"anchored for no roles", []Authority{{Pub: k.operatorPub, Roles: nil}}},
		{"unknown role", []Authority{{Pub: k.operatorPub, Roles: []Role{RoleExit, "courier"}}}},
		{"same key anchored twice", []Authority{
			{Pub: k.operatorPub, Roles: []Role{RoleExit}},
			{Pub: k.operatorPub, Roles: []Role{RoleRelay}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewAuthoritySetVerifier(tc.authorities, nil); err == nil {
				t.Fatal("construction succeeded, want a refusal — an ambiguous anchor set must not become a running coordinator")
			}
		})
	}
}

// The anchor is fixed at construction: a caller that reuses and edits the Roles
// slice it passed cannot widen what an already-built verifier admits.
func TestAnchoredRolesAreNotAliasedToTheCaller(t *testing.T) {
	k := newTwoAuthorities(t)
	roles := []Role{RoleClient}
	v, err := NewAuthoritySetVerifier([]Authority{{Pub: k.accountPub, Roles: roles}}, nil)
	if err != nil {
		t.Fatalf("NewAuthoritySetVerifier: %v", err)
	}
	roles[0] = RoleExit // the caller reuses its slice

	cred := issue(t, k.accountPriv, "exit-A", []Role{RoleExit})
	if _, err := v.Verify(cred, base, RoleExit, "exit-A"); !errors.Is(err, ErrNoAuthorityForRole) {
		t.Fatalf("editing the caller's slice changed what the verifier admits: err = %v, want ErrNoAuthorityForRole", err)
	}
}

// AllRoles is what a single anchor is trusted for, so a role missing from it is
// one -admission-pubkey silently stops admitting. Pinned against the Role
// constants so adding a role and forgetting AllRoles fails here.
func TestAllRolesCoversEveryRoleConstant(t *testing.T) {
	for _, r := range []Role{RoleClient, RoleRelay, RoleExit} {
		if !r.Known() {
			t.Errorf("role %q is not in AllRoles(); a single-key deployment would stop admitting it", r)
		}
	}
	if got := len(AllRoles()); got != 3 {
		t.Errorf("AllRoles() has %d entries, want 3 — add the new role to this test and confirm every anchor path covers it", got)
	}
	if Role("courier").Known() {
		t.Error("Known() accepted a role that does not exist")
	}
}
