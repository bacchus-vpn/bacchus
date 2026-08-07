package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
)

// splitAnchors is the deployment #64 exists to make expressible: the operator's
// offline key anchored for relay and exit, the account service's key anchored
// for client, and neither able to admit the other's role. Installed for the
// duration of a test, restoring the open (nil) default after.
type splitAnchors struct {
	operatorPriv ed25519.PrivateKey
	accountPriv  ed25519.PrivateKey
}

func setSplitAdmission(t *testing.T) splitAnchors {
	t.Helper()
	opPub, opPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate operator key: %v", err)
	}
	acPub, acPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	v, err := admission.NewAuthoritySetVerifier([]admission.Authority{
		{Pub: opPub, Roles: []admission.Role{admission.RoleRelay, admission.RoleExit}},
		{Pub: acPub, Roles: []admission.Role{admission.RoleClient}},
	}, nil)
	if err != nil {
		t.Fatalf("NewAuthoritySetVerifier: %v", err)
	}
	admissionVerifier = v
	t.Cleanup(func() { admissionVerifier = nil })
	return splitAnchors{operatorPriv: opPriv, accountPriv: acPriv}
}

// TestSplitAnchorsAdmitClientAndRefuseTheSameCredentialAsExit is the end-to-end
// bar for #64, run through the real handlers rather than the verifier alone: one
// coordinator, two anchored authorities, one credential — admitted for the role
// its authority is anchored for and refused for the role it is not, with nothing
// about the credential changing between the two.
func TestSplitAnchorsAdmitClientAndRefuseTheSameCredentialAsExit(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	k := setSplitAdmission(t)

	// The account service mints a client credential for a subject that also
	// happens to name a node id, so the same string is presentable on both
	// paths and the only thing that differs is the role being taken.
	const id = "exit-A"
	_, cred := issueCred(t, k.accountPriv, id, admission.RoleClient)

	client := fakePeer(t)
	handle(wire{Type: "list", Cred: cred}, client.LocalAddr().(*net.UDPAddr))
	if m, ok := readReply(t, client, time.Second); !ok || m.Type != "countries" {
		t.Fatalf("account-authority client credential was not admitted for list: got %+v (ok=%v)", m, ok)
	}

	node := fakePeer(t)
	handle(wire{Type: "register", Role: "exit", ID: id, Country: "nl", Addr: "192.0.2.10:20000", Cred: cred}, node.LocalAddr().(*net.UDPAddr))
	if m, ok := readReply(t, node, time.Second); !ok || m.Type != "reject" {
		t.Fatalf("the same credential was not rejected when presented as an exit: got %+v (ok=%v)", m, ok)
	}
	mu.Lock()
	_, registered := exits[id]
	mu.Unlock()
	if registered {
		t.Fatal("a credential from the client-only authority registered an EXIT — the anchored role scoping is not reaching the register handler")
	}
}

// The security claim in full: the rejection above holds even when the account
// service writes "exit" into the credential's own roles field, which it can,
// because it holds a signing key. The decision is the anchor's, not the
// credential's.
func TestAccountAuthorityCannotMintItselfAnExit(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	k := setSplitAdmission(t)

	const id = "exit-B"
	_, forged := issueCred(t, k.accountPriv, id, admission.RoleClient, admission.RoleExit)

	node := fakePeer(t)
	handle(wire{Type: "register", Role: "exit", ID: id, Country: "nl", Addr: "192.0.2.11:20000", Cred: forged}, node.LocalAddr().(*net.UDPAddr))
	if m, ok := readReply(t, node, time.Second); !ok || m.Type != "reject" {
		t.Fatalf("an account-signed credential CLAIMING the exit role was not rejected: got %+v (ok=%v)", m, ok)
	}
	mu.Lock()
	_, registered := exits[id]
	mu.Unlock()
	if registered {
		t.Fatal("the always-online client issuer minted itself a place in the forwarding path (issue #64)")
	}

	// Non-vacuity: the operator, which IS anchored for exit, registers the
	// same id fine — so this refuses the authority and not the role.
	_, real := issueCred(t, k.operatorPriv, id, admission.RoleExit)
	good := fakePeer(t)
	handle(wire{Type: "register", Role: "exit", ID: id, Country: "nl", Addr: "192.0.2.12:20000", Cred: real}, good.LocalAddr().(*net.UDPAddr))
	if m, ok := readReply(t, good, 150*time.Millisecond); ok {
		t.Fatalf("the operator's own exit register was rejected: %+v", m)
	}
	mu.Lock()
	_, registered = exits[id]
	mu.Unlock()
	if !registered {
		t.Fatal("the operator's exit credential did not register")
	}
}

// The operator authority is anchored for relay and exit only, so a client
// credential it minted does not get a client past the list handler. The split
// constrains both authorities, not just the new one.
func TestOperatorAuthorityCannotAdmitAClient(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	k := setSplitAdmission(t)

	client := fakePeer(t)
	_, cred := issueCred(t, k.operatorPriv, "alice", admission.RoleClient)
	handle(wire{Type: "list", Cred: cred}, client.LocalAddr().(*net.UDPAddr))
	if m, ok := readReply(t, client, time.Second); !ok || m.Type != "reject" {
		t.Fatalf("an operator-signed client credential was admitted for list: got %+v (ok=%v)", m, ok)
	}
}

// A relay registers against the operator authority just as an exit does — the
// authority carries both roles, so #26's per-hop relay work has an anchored
// authority to verify against without any further reshaping here.
func TestOperatorAuthorityAdmitsRelayAndExit(t *testing.T) {
	setPC(t)
	resetRegistry(t)
	k := setSplitAdmission(t)

	for _, tc := range []struct {
		role string
		id   string
		addr string
	}{
		{"relay", "relay-A", "192.0.2.20:20000"},
		{"exit", "exit-C", "192.0.2.21:20000"},
	} {
		_, cred := issueCred(t, k.operatorPriv, tc.id, admission.Role(tc.role))
		peer := fakePeer(t)
		handle(wire{Type: "register", Role: tc.role, ID: tc.id, Country: "nl", Addr: tc.addr, Cred: cred}, peer.LocalAddr().(*net.UDPAddr))
		if m, ok := readReply(t, peer, 150*time.Millisecond); ok {
			t.Fatalf("%s register was rejected: %+v", tc.role, m)
		}
	}
	mu.Lock()
	_, gotRelay := relays["relay-A"]
	_, gotExit := exits["exit-C"]
	mu.Unlock()
	if !gotRelay || !gotExit {
		t.Fatalf("operator authority did not admit both roles: relay=%v exit=%v", gotRelay, gotExit)
	}
}

// setupAdmission's flag surface. -admission-pubkey keeps its exact meaning (one
// authority, every role) and -admission-authority is additive, so the migration
// is a flag an operator adds rather than a line they rewrite.
func TestSetupAdmissionFlagComposition(t *testing.T) {
	opPub, _, _ := ed25519.GenerateKey(nil)
	acPub, _, _ := ed25519.GenerateKey(nil)
	opHex, acHex := hex.EncodeToString(opPub), hex.EncodeToString(acPub)

	cases := []struct {
		name   string
		pubKey string
		specs  []string
		want   [][]admission.Role // the roles of each anchored authority, in order; empty means admission is off
	}{
		{
			name: "neither flag disables admission",
		},
		{
			name:   "-admission-pubkey alone is one authority for every role",
			pubKey: opHex,
			want:   [][]admission.Role{admission.AllRoles()},
		},
		{
			name:  "-admission-authority alone enables admission",
			specs: []string{"client:" + acHex},
			want:  [][]admission.Role{{admission.RoleClient}},
		},
		{
			name:   "the migration step: keep the old flag, add the account authority",
			pubKey: opHex,
			specs:  []string{"client:" + acHex},
			want:   [][]admission.Role{admission.AllRoles(), {admission.RoleClient}},
		},
		{
			name:  "the narrowed end state: both authorities scoped",
			specs: []string{"relay,exit:" + opHex, "client:" + acHex},
			want:  [][]admission.Role{{admission.RoleRelay, admission.RoleExit}, {admission.RoleClient}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel() // stop the revocation reload goroutine this starts
			v, anchors, _, err := setupAdmission(ctx, tc.pubKey, tc.specs, "")
			if err != nil {
				t.Fatalf("setupAdmission: %v", err)
			}
			if len(tc.want) == 0 {
				if v != nil {
					t.Fatal("admission was enabled with neither flag set")
				}
				return
			}
			if v == nil {
				t.Fatal("admission was disabled despite a configured anchor")
			}
			if len(anchors) != len(tc.want) {
				t.Fatalf("anchored %d authorities, want %d", len(anchors), len(tc.want))
			}
			for i, want := range tc.want {
				if !slices.Equal(anchors[i].Roles, want) {
					t.Fatalf("authority %d roles = %v, want %v", i+1, anchors[i].Roles, want)
				}
			}
		})
	}
}

// Every malformed anchor is fatal at startup rather than a skipped authority: a
// coordinator that came up looking configured while trusting a different set of
// keys than its unit file names is the failure this flag must not have.
func TestSetupAdmissionRejectsMalformedAnchors(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	keyHex := hex.EncodeToString(pub)
	other, _, _ := ed25519.GenerateKey(nil)

	cases := []struct {
		name   string
		pubKey string
		specs  []string
	}{
		{name: "bad -admission-pubkey", pubKey: "not-hex"},
		{name: "-admission-pubkey of the wrong length", pubKey: "abcd"},
		{name: "no colon", specs: []string{keyHex}},
		{name: "no roles", specs: []string{":" + keyHex}},
		{name: "unknown role", specs: []string{"courier:" + keyHex}},
		{name: "one unknown role among known ones", specs: []string{"relay,courier:" + keyHex}},
		{name: "key is not hex", specs: []string{"client:not-hex"}},
		{name: "key of the wrong length", specs: []string{"client:abcd"}},
		{name: "empty key", specs: []string{"client:"}},
		{name: "same key twice", specs: []string{"client:" + keyHex, "exit:" + keyHex}},
		{name: "-admission-pubkey repeated as an authority", pubKey: keyHex, specs: []string{"client:" + keyHex}},
		{
			name:   "one good anchor does not rescue a bad one",
			pubKey: hex.EncodeToString(other),
			specs:  []string{"client:" + keyHex, "courier:" + keyHex},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if _, _, _, err := setupAdmission(ctx, tc.pubKey, tc.specs, ""); err == nil {
				t.Fatal("setupAdmission succeeded, want a refusal — main log.Fatals on this, and anything it lets through becomes a running coordinator")
			}
		})
	}
}

// Whitespace around a spec's parts is tolerated: these come from unit files and
// shell quoting, where a stray space is a typo and not a different intent.
func TestParseAuthorityToleratesWhitespace(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	a, err := parseAuthority("  relay , exit : " + hex.EncodeToString(pub) + "  ")
	if err != nil {
		t.Fatalf("parseAuthority: %v", err)
	}
	if len(a.Roles) != 2 || a.Roles[0] != admission.RoleRelay || a.Roles[1] != admission.RoleExit {
		t.Fatalf("roles = %v, want [relay exit]", a.Roles)
	}
	if !a.Pub.Equal(pub) {
		t.Fatal("parsed key does not match")
	}
}

// The startup line names each authority's roles and only a prefix of its key.
// The roles are there because a wrong scope is the misconfiguration this flag
// makes newly possible and is invisible everywhere else; the key is truncated
// because a line an operator pastes into an issue needs to tell two anchors
// apart and nothing more.
func TestDescribeAuthorities(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	keyHex := hex.EncodeToString(pub)
	got := describeAuthorities([]admission.Authority{
		{Pub: pub, Roles: []admission.Role{admission.RoleRelay, admission.RoleExit}},
	})
	if want := "relay,exit=" + keyHex[:8] + "…"; got != want {
		t.Fatalf("describeAuthorities = %q, want %q", got, want)
	}
	if strings.Contains(got, keyHex) {
		t.Fatal("the full key reached the startup log line")
	}
}

// The repeatable flag accumulates in order, which is the order the anchors are
// then searched in.
func TestAuthorityFlagsAccumulate(t *testing.T) {
	var f authorityFlags
	for _, v := range []string{"client:a", "relay,exit:b"} {
		if err := f.Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	if len(f) != 2 || f[0] != "client:a" || f[1] != "relay,exit:b" {
		t.Fatalf("flags = %v, want both occurrences in order", f)
	}
	if got, want := f.String(), "client:a relay,exit:b"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
