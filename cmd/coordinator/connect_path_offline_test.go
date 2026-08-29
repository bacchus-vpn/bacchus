// The coordinator half of a claim the account service makes about itself
// (bacchus-payment#98, claim 1): that the coordinator never calls it on the
// connect path, so the network cannot link a connection to an account.
//
// # Why the claim needs a test on THIS side
//
// The other repository can prove the necessary half — its route tables are closed
// and none of their verbs is a connect-time query, so there is no endpoint to call.
// It cannot prove the sufficient half, because "the coordinator does not call out"
// is a statement about code in this module, which that one deliberately cannot
// import. This file is that half.
//
// # What is actually asserted, and in which of the two available currencies
//
// Two properties, and they are proved differently on purpose.
//
//  1. The DECISION cannot dial. admit (admission.go) resolves to
//     admission.Verifier.Verify, admitDevice (devicecred.go) to
//     devicecred.Verifier.Verify, and resolveTier (tier.go) to
//     policy.Policy.Limits. None of those three packages has `net` anywhere in its
//     transitive dependency graph, so an outbound call is not merely absent from
//     them — it is not expressible in them. That is a proof rather than a grep, and
//     it is the strongest form this claim can take.
//
//  2. The decision is REACHED and answered from held material alone. Structural
//     absence says nothing about whether the gate still runs, so the second test
//     drives real register, list and connect datagrams through handle() with an
//     admission root this test generated seconds earlier, and with no account
//     service configured at all — and every one of the six cases is decided
//     correctly anyway.
//
// # What this file deliberately does NOT claim
//
// Not "the coordinator process makes no outbound connection". It plainly does: this
// binary holds an http.Client in httpPolicySource, and two background loops
// (refreshPolicyLoop, refreshRevocationsLoop) use it to pull the signed policy and
// revocation bundles from an operator-configured -policy-source. Those run on
// tickers, carry no client identity, are not reachable from handle() — the source
// is a parameter of the refresh goroutine and never a package-level value a handler
// could see — and are not the account service. The claim is about the connect path
// and about that one service, and stating it narrowly is what makes it checkable.
//
// The coordinator also HOLDS account-service addresses, from -account-service, and
// publishes them in the signed cold-start directory (accountServiceEntries). Holding
// an address is not having a route to it: TestCoordinatorHoldsNoAccountServiceClient
// is what says there is nothing in this binary that could use one.

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core/admission"
)

// modulePath is this repository's Go module path.
const modulePath = "github.com/bacchus-vpn/bacchus"

// accountClientPkg is the one package in this repository that dials the account
// service (ADR-0056 §8). Its own dependency graph contains net, crypto/tls and
// net/http, which is what makes it a usable control below.
const accountClientPkg = modulePath + "/core/accountclient"

// connectPathDeciders are the packages that hold the register/list/connect
// decision itself, named by the coordinator function that reaches each:
//
//	admit        -> admission.Verifier.Verify        (core/admission)
//	admitDevice  -> devicecred.Verifier.Verify       (core/devicecred)
//	resolveTier  -> policy.Policy.Limits             (core/policy)
//
// Each verifies a signature chain against a root public key this coordinator was
// started with (-admission-pubkey / -admission-authority, -device-root-pubkey,
// -policy-root-pubkey) and a validity window against the local clock. Nothing in
// that list is a lookup.
var connectPathDeciders = []string{
	modulePath + "/core/admission",
	modulePath + "/core/devicecred",
	modulePath + "/core/policy",
}

// cannotDial is the deny list, and it is deliberately two entries rather than a
// pattern over "net/...".
//
// `net` is the package that owns every socket in Go: net/http, crypto/tls and every
// third-party client library reach a file descriptor through it, so a closure
// without `net` cannot open one by any route. Denying `net` alone therefore covers
// the whole transitive space, and it does so without false-positiving on net/netip
// and net/url, which are pure value types and parsers and import `net` not at all.
//
// os/exec is the second entry because it is the one way to make an outbound call
// without linking a network stack: shelling out. It does not import `net`, so it
// has to be named.
var cannotDial = []string{"net", "os/exec"}

// TestConnectPathVerificationCannotDial is claim 1's structural half: the packages
// that decide register, list and connect cannot make an outbound call to the
// account service or to anything else, because they cannot make one at all.
//
// A failure here does not necessarily mean a call was added. It means the decision
// gained the ABILITY to make one, which is the moment to look — the property the
// privacy statement rests on is that this is impossible rather than merely absent,
// and the two stop being the same thing the instant `net` appears.
func TestConnectPathVerificationCannotDial(t *testing.T) {
	for _, pkg := range connectPathDeciders {
		t.Run(shortPkg(pkg), func(t *testing.T) {
			deps := depsOf(t, pkg)

			// Non-vacuity: `go list -deps` names the package itself, so a set that
			// does not contain it is an answer about something else and every
			// assertion below would pass for the wrong reason.
			if !deps[pkg] {
				t.Fatalf("`go list -deps %s` did not name the package itself, so this test is measuring "+
					"something other than what it claims (it returned %d packages)", pkg, len(deps))
			}

			for _, banned := range cannotDial {
				if deps[banned] {
					t.Errorf("%s now has %q in its transitive dependency graph.\n\n"+
						"This package holds part of the register/list/connect decision, and the public "+
						"privacy statement's strongest sentence — that the network cannot link a "+
						"connection to an account — rests on that decision being a signature-and-expiry "+
						"check against a held root public key with no outbound call "+
						"(bacchus-payment#98 claim 1). While %q was absent, an outbound call was not "+
						"expressible here; it now is. If this dependency is deliberate, the account "+
						"model's \"offline verification is the load-bearing choice\" is what has to "+
						"change, not this test.", pkg, banned, banned)
				}
			}
		})
	}

	// The control, without which every assertion above could be passing because the
	// measurement is broken rather than because the property holds. This binary is a
	// UDP server, so `net` MUST be in its own graph; if it is not, depsOf is not
	// returning what this test thinks it is.
	own := depsOf(t, modulePath+"/cmd/coordinator")
	if !own["net"] {
		t.Fatal("the coordinator's own dependency graph does not contain `net`, which cannot be true of a " +
			"UDP server — the deny-list check above is therefore not detecting anything and the results " +
			"above are meaningless")
	}
}

// TestCoordinatorHoldsNoAccountServiceClient is claim 1 at the level the account
// service's README states it: not that the coordinator declines to call, but that
// it has no route to one even in principle.
//
// The coordinator does hold account-service ADDRESSES — -account-service collects
// them and accountServiceEntries publishes them in the signed cold-start directory,
// because the desktop client has no other channel for learning that the service
// moved (ADR-0061). An address is not a route. What would make it one is a client
// that speaks the service's protocol, and there is exactly one of those in this
// repository.
func TestCoordinatorHoldsNoAccountServiceClient(t *testing.T) {
	deps := depsOf(t, modulePath+"/cmd/coordinator")
	if !deps[modulePath+"/cmd/coordinator"] {
		t.Fatalf("`go list -deps` did not name the coordinator itself (%d packages returned)", len(deps))
	}
	if deps[accountClientPkg] {
		t.Errorf("%s is now linked into the coordinator.\n\n"+
			"That package exists to dial the account service. Linking it in gives this binary the route "+
			"the account model says it does not have, and it is the account model — not this test — that "+
			"would then be wrong (bacchus-payment#98 claim 1).", accountClientPkg)
	}

	// The control: prove the check would fire. accountclient is the package the
	// assertion above names, and it really is one that dials — if its own graph
	// stopped containing a network stack, "the coordinator does not import it" would
	// have stopped meaning anything.
	acct := depsOf(t, accountClientPkg)
	if !acct["net"] || !acct["net/http"] {
		t.Errorf("%s no longer imports a network stack (net=%v, net/http=%v), so the assertion above no "+
			"longer distinguishes a coordinator with a route to the account service from one without",
			accountClientPkg, acct["net"], acct["net/http"])
	}
}

// TestRegisterListConnectDecidedFromTheHeldRootKeyAlone is claim 1's behavioural
// half: the gate is still reached at all three verbs, and it answers every case
// from a root public key and a clock.
//
// The setup is the argument. The admission root is generated in this process
// microseconds before it is used, so no service anywhere has heard of it; the
// coordinator is configured with no account service at all (asserted, not assumed);
// and the six cases below still come out right. A gate that needed to ask something
// could not have answered any of them.
//
// The three refusal cases are what make the accepting ones worth anything. An
// expired credential is refused with no clock but the local one, and a credential
// signed by a DIFFERENT authority is refused with no key but the anchored one —
// between them, signature and expiry, which is the whole of what the claim says the
// check is.
func TestRegisterListConnectDecidedFromTheHeldRootKeyAlone(t *testing.T) {
	// No account service is configured on this coordinator. Stated as an assertion
	// rather than a comment: a future default that populated this would silently turn
	// "it never had one" into "it had one and chose not to use it", which is a much
	// weaker thing for the cases below to demonstrate.
	if len(accountServices) != 0 {
		t.Fatalf("this coordinator has account-service addresses configured (%v); the point of this test "+
			"is that register, list and connect are all decided without one", accountServices)
	}

	setPC(t)
	resetRegistry(t)

	anchored, anchoredPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate the anchored admission root: %v", err)
	}
	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate the unanchored root: %v", err)
	}
	setAdmission(t, anchored, nil)

	const exitID = "e-offline"
	const country = "NL"
	now := time.Now()

	// register — a node credential, bound to the id presenting it.
	t.Run("register", func(t *testing.T) {
		valid := issueAt(t, anchoredPriv, exitID, now.Add(-time.Minute), now.Add(time.Hour), admission.RoleExit)
		expired := issueAt(t, anchoredPriv, exitID, now.Add(-2*time.Hour), now.Add(-time.Hour), admission.RoleExit)
		stranger := issueAt(t, strangerPriv, exitID, now.Add(-time.Minute), now.Add(time.Hour), admission.RoleExit)

		for _, tc := range []struct {
			name, cred string
			wantAdmit  bool
		}{
			{"valid", valid, true},
			{"expired", expired, false},
			{"signed by an unanchored authority", stranger, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				resetRegistry(t)
				node := fakePeer(t)
				handle(wire{Type: "register", Role: "exit", ID: exitID, Country: country,
					Addr: "203.0.113.10:20000", Cred: tc.cred}, node.LocalAddr().(*net.UDPAddr))

				reply, replied := readReply(t, node, 200*time.Millisecond)
				mu.Lock()
				_, registered := exits[exitID]
				mu.Unlock()

				if tc.wantAdmit {
					if replied {
						t.Fatalf("a valid register drew a %q (%s); it should be admitted silently", reply.Type, reply.Reason)
					}
					if !registered {
						t.Fatal("a valid credentialed exit was not registered")
					}
					return
				}
				if !replied || reply.Type != "reject" {
					t.Fatalf("expected a reject, got %+v (replied=%v)", reply, replied)
				}
				if registered {
					t.Fatal("a refused exit was registered anyway")
				}
			})
		}
	})

	// list and connect — a client credential, bearer, no subject binding.
	//
	// They are driven together because they are the two verbs a CLIENT sends, and a
	// gate that had come loose on one of them is exactly the regression a
	// per-verb test would miss when the other still refuses.
	for _, verb := range []string{"list", "connect"} {
		t.Run(verb, func(t *testing.T) {
			valid := issueAt(t, anchoredPriv, "", now.Add(-time.Minute), now.Add(time.Hour), admission.RoleClient)
			expired := issueAt(t, anchoredPriv, "", now.Add(-2*time.Hour), now.Add(-time.Hour), admission.RoleClient)
			stranger := issueAt(t, strangerPriv, "", now.Add(-time.Minute), now.Add(time.Hour), admission.RoleClient)

			for _, tc := range []struct {
				name, cred string
				wantAdmit  bool
			}{
				{"valid", valid, true},
				{"expired", expired, false},
				{"signed by an unanchored authority", stranger, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					resetRegistry(t)
					// An exit has to exist for a connect to have something to assign;
					// registered directly rather than through handle() so this subtest's
					// subject stays the client gate.
					seedExit(t, exitID, country)

					client := fakePeer(t)
					src := client.LocalAddr().(*net.UDPAddr)
					if verb == "list" {
						handle(wire{Type: "list", Cred: tc.cred}, src)
					} else {
						dialConnect(wire{Country: country, Mode: "direct", Cred: tc.cred}, src)
					}

					reply, replied := readReply(t, client, time.Second)
					if !replied {
						t.Fatalf("no reply to %s at all", verb)
					}
					want := "countries"
					if verb == "connect" {
						want = "session"
					}
					if tc.wantAdmit {
						if reply.Type != want {
							t.Fatalf("a valid client credential got %q (%s), want %q", reply.Type, reply.Reason, want)
						}
						return
					}
					if reply.Type != "reject" {
						t.Fatalf("%s was answered %q (%s) for a credential that should have been refused; "+
							"the admission gate on this verb is not deciding", verb, reply.Type, reply.Reason)
					}
				})
			}
		})
	}
}

// issueAt mints one credential over an explicit window, so a caller can ask for an
// expired one. admission_test.go's issueCred is the always-valid case and is left
// alone; expiry is half of what claim 1 says the check is, so it needs a window a
// test controls.
func issueAt(t *testing.T, priv ed25519.PrivateKey, subject string, notBefore, notAfter time.Time, roles ...admission.Role) string {
	t.Helper()
	_, enc, err := admission.Issue(priv, subject, roles, notBefore, notAfter, "offline-path test")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return enc
}

// seedExit puts one live exit in the registry directly. registerExit drives a real
// register, which with admission enabled would need its own credential and would
// make the client subtests depend on the node gate they are not about.
func seedExit(t *testing.T, id, country string) {
	t.Helper()
	mu.Lock()
	defer mu.Unlock()
	exits[id] = &exitNode{
		id:            id,
		tcpAddr:       "203.0.113.10:20000",
		udp:           &net.UDPAddr{IP: net.IPv4(203, 0, 113, 10), Port: 20000},
		lastSeen:      time.Now(),
		country:       country,
		countrySource: countryObserved,
	}
}

// depsOf returns `go list -deps <pkg>` as a set.
//
// Test files are invisible to it — it reports the non-test package's imports — so
// this test cannot perturb what it measures.
func depsOf(t *testing.T, pkg string) map[string]bool {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH, so the dependency graph cannot be read: %v", err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	cmd := exec.Command("go", "list", "-deps", pkg)
	cmd.Dir = root
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, raw)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			set[line] = true
		}
	}
	return set
}

// shortPkg names a subtest after the package rather than its whole import path.
func shortPkg(pkg string) string { return strings.TrimPrefix(pkg, modulePath+"/") }
