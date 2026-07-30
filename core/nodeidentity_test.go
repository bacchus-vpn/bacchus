package core

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bacchus-vpn/bacchus/core/coldstart"
)

// The tests below pin, at the New boundary, which node identities may be
// GENERATED and which must be configured — the split issue #96 is about.
//
// Everything here was already true of the code; what was missing was any test
// that said so at this level. setupRelayChaining's own table
// (TestSetupRelayChainingRefusesHalfConfiguration) calls that function directly,
// so it pins the check but not the WIRING: nothing failed if New stopped calling
// it, and nothing failed if the exit role's generate path was tightened to match
// the relay's. Both halves are load-bearing and both are now asserted through the
// real constructor.

// testHopDirectory returns a signed directory good enough for New to accept a
// node that forwards, plus the key that verifies it. The hop set does not matter
// here — these tests are about identity, not routing — only that it loads.
func testHopDirectory(t *testing.T) ([]byte, []byte) {
	t.Helper()
	pub, priv := testSnapKeys(t)
	signed := signTestSnapshot(t, priv, []coldstart.Entry{
		{Role: "exit", ID: hex.EncodeToString(make([]byte, 32)), Addr: "203.0.113.9:20001"},
	})
	return signed, pub
}

// TestNewRefusesAForwardingRelayWithoutAStableKey is the refusal itself, driven
// through New rather than through setupRelayChaining.
//
// A relay serving RelayIngress is authenticated by the client running Noise_NK
// against the key the SIGNED directory publishes as that hop's id. Generating that
// key would rotate the id at every restart, and the node would look perfectly
// healthy while doing it: it starts, it registers, it logs, it stays up, and it
// serves nobody, because every client holding the cached directory dials an id this
// process no longer has. The symptom lands on strangers' machines as chains that
// cannot be built, which is the hardest place to trace it back from. So it is a
// construction error.
func TestNewRefusesAForwardingRelayWithoutAStableKey(t *testing.T) {
	_, err := New(Config{
		Coordinators:   []string{"127.0.0.1:1"},
		Roles:          []string{"relay"},
		RelayIngress:   "127.0.0.1:0",
		RelayDirectory: []byte("x"), // never loaded; the key check refuses first
	})
	if err == nil {
		t.Fatal("a relay serving RelayIngress with no ExitKeyHex was constructed; want a refusal — it would carry a fresh node id into every restart and be unreachable as a hop, while looking healthy from inside the process")
	}
	// Naming the setting is the whole point of the message: the operator has to
	// know WHICH knob to reach for, and "invalid configuration" would not tell
	// them. Asserting only "some error" is what would let this pass for an
	// unrelated reason — an empty MeshPubKey, say, which the same config would
	// also trip if the check above it were deleted.
	if !strings.Contains(err.Error(), "ExitKeyHex") {
		t.Errorf("refused with %q, want it to name ExitKeyHex — an operator who cannot tell which setting is missing has not been helped by the refusal", err)
	}
}

// TestNewStillGeneratesForTheExitRole pins the OTHER half of the split, which is
// the half a well-meaning tightening would quietly delete.
//
// An exit with no configured key still gets one generated. That is the throwaway
// lab exit the behaviour was built for, and it stays supported because an exit's
// version of this mistake is loud: a client selects an exit out of the same
// snapshot that names its key, so a mismatch fails admission immediately and in
// front of the person who caused it. Two constructions of the SAME config yielding
// two DIFFERENT ids is what proves a key is being generated rather than derived.
func TestNewStillGeneratesForTheExitRole(t *testing.T) {
	cfg := Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{"exit"},
		Advertise:    "203.0.113.5:20000",
	}
	first, err := New(cfg)
	if err != nil {
		t.Fatalf("an exit with no ExitKeyHex was refused: %v — generating is deliberate for this role; see the comment above exitStaticKey", err)
	}
	second, err := New(cfg)
	if err != nil {
		t.Fatalf("New (second): %v", err)
	}
	if id, err := hex.DecodeString(first.cfg.ID); err != nil || len(id) != 32 {
		t.Fatalf("exit id = %q, want a 64-hex X25519 public key", first.cfg.ID)
	}
	if first.cfg.ID == second.cfg.ID {
		t.Errorf("two exits built from the same key-less config share id %s; the exit role is supposed to GENERATE here, so an id that repeats means this test no longer exercises the generate path at all", shortID(first.cfg.ID))
	}
}

// TestNewAcceptsAForwardingRelayWithAStableKey is the positive case the refusal
// must leave alone: give the same relay a key and it constructs, with its node id
// derived from that key rather than from anything random.
func TestNewAcceptsAForwardingRelayWithAStableKey(t *testing.T) {
	signed, dirKey := testHopDirectory(t)
	eng, err := New(Config{
		Coordinators:      []string{"127.0.0.1:1"},
		Roles:             []string{"relay"},
		RelayIngress:      "127.0.0.1:0",
		RelayDirectory:    signed,
		RelayDirectoryKey: dirKey,
		ExitKeyHex:        testExitKeyHex,
	})
	if err != nil {
		t.Fatalf("a correctly configured forwarding relay was refused: %v", err)
	}
	want, err := exitKeyFromSeed(mustHex(t, testExitKeyHex))
	if err != nil {
		t.Fatalf("exitKeyFromSeed: %v", err)
	}
	if got := hex.EncodeToString(want.Public); eng.cfg.ID != got {
		t.Errorf("hop id = %s, want %s — a hop's id must BE its X25519 public key or no client can run Noise_NK against it", shortID(eng.cfg.ID), shortID(got))
	}
}

// TestNewAcceptsARelayThatIsAlsoAnExit covers the combination the refusal must not
// catch by accident. A node holding both roles and serving an ingress is a normal
// deployment — one machine that both forwards other people's layers and terminates
// its own sessions — and it constructs.
//
// The second half pins a REMAINING gap rather than a desired property. With the
// exit role also set, an absent key is still generated, so this node's hop identity
// does churn across restarts with none of the loudness that makes it tolerable for
// a pure exit. Issue #96 deferred that on purpose: refusing it changes behaviour for
// a role that has generated since it existed, which is a call with a real user
// behind it and not one to fold into a fix for the relay case. The assertion is here
// so the deferral is visible in the test suite instead of only in the issue —
// tighten it, do not delete it, when that call is made.
func TestNewAcceptsARelayThatIsAlsoAnExit(t *testing.T) {
	signed, dirKey := testHopDirectory(t)
	base := Config{
		Coordinators:      []string{"127.0.0.1:1"},
		Roles:             []string{"relay", "exit"},
		Advertise:         "203.0.113.5:20000",
		RelayIngress:      "127.0.0.1:0",
		RelayDirectory:    signed,
		RelayDirectoryKey: dirKey,
	}

	keyed := base
	keyed.ExitKeyHex = testExitKeyHex
	eng, err := New(keyed)
	if err != nil {
		t.Fatalf("a relay-plus-exit serving an ingress was refused: %v — holding both roles is a normal deployment and the relay check must not catch it", err)
	}
	want, err := exitKeyFromSeed(mustHex(t, testExitKeyHex))
	if err != nil {
		t.Fatalf("exitKeyFromSeed: %v", err)
	}
	if got := hex.EncodeToString(want.Public); eng.cfg.ID != got {
		t.Errorf("relay-plus-exit id = %s, want %s", shortID(eng.cfg.ID), shortID(got))
	}

	// The deferred gap, pinned as it stands today.
	if _, err := New(base); err != nil {
		t.Fatalf("relay-plus-exit with no ExitKeyHex was refused: %v — that may well be the right end state, but it is a behaviour change issue #96 deliberately left out, so it needs its own ruling and its own release note rather than arriving as a side effect", err)
	}
}

// mustHex decodes a hex fixture or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}
