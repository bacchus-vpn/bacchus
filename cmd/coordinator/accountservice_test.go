package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// stageAccountServices installs a -account-service list for one test and puts
// the previous one back afterwards. The value is package-level (it is written by
// flag parsing and read by buildSnapshot), so a test that left one behind would
// silently add an entry to every snapshot every later test builds.
func stageAccountServices(t *testing.T, addrs ...string) {
	t.Helper()
	prev := accountServices
	t.Cleanup(func() { accountServices = prev })
	accountServices = nil
	for _, a := range addrs {
		if err := accountServices.Set(a); err != nil {
			t.Fatalf("stage -account-service %q: %v", a, err)
		}
	}
}

// TestTheSignedDirectoryCarriesTheAccountService is the producer half of
// bacchus#193: a directory nothing populates changes nothing, however completely
// the client adopts it.
//
// The addresses go in the SIGNED bytes rather than only on the in-memory struct
// — the whole value of the artifact is that a client can tell the coordinator
// said it — so this round-trips the marshalled snapshot rather than reading the
// struct back.
func TestTheSignedDirectoryCarriesTheAccountService(t *testing.T) {
	resetRegistry(t)
	stageAccountServices(t, "https://account.example:8443", "https://spare.example:8443")

	snap := buildSnapshot("198.51.100.1:8080")
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var back coldstart.Snapshot
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}

	got := back.AddrsForRole("account")
	want := []string{"https://account.example:8443", "https://spare.example:8443"}
	if len(got) != len(want) {
		t.Fatalf("AddrsForRole(\"account\") = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AddrsForRole(\"account\") = %v, want %v — the operator's preference order is the client's rotation order", got, want)
		}
	}

	// The coordinator's own entry is untouched: the account service is an extra
	// record, not a replacement for the directory's original job.
	if coords := back.AddrsForRole("coordinator"); len(coords) != 1 || coords[0] != "198.51.100.1:8080" {
		t.Fatalf("AddrsForRole(\"coordinator\") = %v, want [198.51.100.1:8080]", coords)
	}

	// Each entry is referable: several records sharing one id is a directory
	// nobody can name an entry of.
	seen := map[string]bool{}
	for _, e := range back.Entries {
		if e.Role != "account" {
			continue
		}
		if e.ID == "" {
			t.Errorf("an account entry has no id: %+v", e)
		}
		if seen[e.ID] {
			t.Errorf("two account entries share the id %q", e.ID)
		}
		seen[e.ID] = true
	}
}

// TestNoAccountServiceFlagPublishesNoAccountEntry is the compatibility floor on
// this side: a network that runs no account service, or one whose coordinator
// has not been given the flag yet, publishes exactly the directory it always
// did. That is what lets the client half ship first — it falls back to the
// configured addresses when the directory names none.
func TestNoAccountServiceFlagPublishesNoAccountEntry(t *testing.T) {
	resetRegistry(t)
	stageAccountServices(t)

	snap := buildSnapshot("198.51.100.1:8080")
	if got := snap.AddrsForRole("account"); len(got) != 0 {
		t.Fatalf("AddrsForRole(\"account\") = %v with no -account-service set, want none", got)
	}
	for _, e := range snap.Entries {
		if e.Role == "account" {
			t.Fatalf("an account entry appeared with no flag set: %+v", e)
		}
	}
}

// TestAccountServiceFlagRefusesAnAddressNoClientCouldUse pins the validation to
// core/accountclient.New's own rules.
//
// It is fatal rather than skipped because of how the client meets a bad entry:
// accountclient validates the WHOLE list at construction, so one unusable
// address would cost every client that adopted this directory every address it
// was given — including the good ones beside it. The operator's terminal is the
// only place where a person is looking, so it is the only place being strict is
// cheap.
func TestAccountServiceFlagRefusesAnAddressNoClientCouldUse(t *testing.T) {
	for _, tc := range []struct{ in, why string }{
		{"", "empty"},
		{"   ", "whitespace only"},
		{"http://account.example:8443", "plain http, so the credential comes back in the clear"},
		{"account.example:8443", "no scheme"},
		{"https://", "no host"},
		{"https://account.example:8443/v1", "a path the verb routes would be concatenated onto"},
		{"https://account.example:8443?x=1", "a query"},
		{"https://user:pw@account.example:8443", "credentials in the URL"},
	} {
		t.Run(tc.why, func(t *testing.T) {
			var f accountServiceFlags
			if err := f.Set(tc.in); err == nil {
				t.Fatalf("Set(%q) was accepted (%s) — every client adopting this directory would be refused its whole address list", tc.in, tc.why)
			}
		})
	}
}

// TestAccountServiceFlagNormalizesWhatItAccepts: a trailing slash is the same
// location, the same address twice is not a second one, and what is published is
// what accountclient will parse back.
func TestAccountServiceFlagNormalizesWhatItAccepts(t *testing.T) {
	var f accountServiceFlags
	for _, a := range []string{
		"https://account.example:8443/",
		" https://account.example:8443 ",
		"https://spare.example:8443",
	} {
		if err := f.Set(a); err != nil {
			t.Fatalf("Set(%q): %v", a, err)
		}
	}
	want := []string{"https://account.example:8443", "https://spare.example:8443"}
	if strings.Join(f, " ") != strings.Join(want, " ") {
		t.Fatalf("collected %v, want %v — the same address twice is not a second location, and it would make one dead address consume two of a client's rotations", []string(f), want)
	}
}
