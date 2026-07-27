//go:build windows

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
)

func TestEventStatus(t *testing.T) {
	cases := []struct {
		name      string
		ev        core.Event
		lbl       string
		protected bool
		wantText  string
		wantShow  bool
	}{
		{
			name:      "error always shows, even while protected",
			ev:        core.Event{Kind: core.EventError, Message: "coordinator rejected handshake: peer protocol version 2 is newer than 1"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Error: coordinator rejected handshake: peer protocol version 2 is newer than 1",
			wantShow:  true,
		},
		{
			name:      "error shows pre-protected too",
			ev:        core.Event{Kind: core.EventError, Message: "[direct] dial: timeout"},
			protected: false,
			wantText:  "Error: [direct] dial: timeout",
			wantShow:  true,
		},
		{
			name:      "info shows pre-protected",
			ev:        core.Event{Kind: core.EventInfo, Message: "direct failed -> trying relay…"},
			protected: false,
			wantText:  "direct failed -> trying relay…",
			wantShow:  true,
		},
		{
			name:      "info is suppressed once protected",
			ev:        core.Event{Kind: core.EventInfo, Message: "direct failed -> trying relay…"},
			protected: true,
			wantShow:  false,
		},
		{
			name:      "ice is suppressed before protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: connected"},
			protected: false,
			wantShow:  false,
		},
		{
			name:      "ice disconnected reads as blocked once protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: disconnected"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Blocked — tunnel down (us exit1)",
			wantShow:  true,
		},
		{
			name:      "ice failed reads as blocked once protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: failed"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Blocked — tunnel down (us exit1)",
			wantShow:  true,
		},
		{
			name:      "ice closed reads as blocked once protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: closed"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Blocked — tunnel down (us exit1)",
			wantShow:  true,
		},
		{
			name:      "ice connected reads as protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: connected"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Protected — us exit1",
			wantShow:  true,
		},
		{
			name:      "ice completed reads as protected",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: completed"},
			lbl:       "us exit1",
			protected: true,
			wantText:  "Protected — us exit1",
			wantShow:  true,
		},
		{
			name:      "ice with an unrecognized state is ignored",
			ev:        core.Event{Kind: core.EventICE, Message: "peer1 ICE: checking"},
			protected: true,
			wantShow:  false,
		},
		{
			name:      "session is never shown live",
			ev:        core.Event{Kind: core.EventSession, Message: "[direct] session: abc123"},
			protected: false,
			wantShow:  false,
		},
		{
			name:      "connected is never shown live (connect() already narrates it)",
			ev:        core.Event{Kind: core.EventConnected, Message: "connected DIRECT to exit"},
			protected: false,
			wantShow:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotText, gotShow := eventStatus(tc.ev, tc.lbl, tc.protected)
			if gotShow != tc.wantShow {
				t.Fatalf("show = %v, want %v", gotShow, tc.wantShow)
			}
			if gotShow && gotText != tc.wantText {
				t.Fatalf("text = %q, want %q", gotText, tc.wantText)
			}
		})
	}
}

// TestRebuildRecoveryConfigReplacesOnlyCoordinatorsAndProof is the
// config-carrying-forward proof for issue #122's mid-session mesh-walk
// recovery: a rebuild must adopt the freshly rediscovered coordinators and
// proof but leave every other connect-time setting — ExitID, the transport
// pool, admission, OnUnderlayDial, … — exactly as connect() built it.
// Reverting rebuildRecoveryConfig to (say) also reset ExitID or drop
// AdmissionCRLPath would silently disable exit pinning or revocation
// checking on every mid-session recovery; this test catches that class of
// mistake without needing a running engine.
func TestRebuildRecoveryConfigReplacesOnlyCoordinatorsAndProof(t *testing.T) {
	base := core.Config{
		Coordinators:     []string{"203.0.113.1:51820"},
		Roles:            []string{core.RoleClient},
		SocksAddr:        "127.0.0.1:1080",
		ExitID:           "deadbeef",
		Geo:              "de",
		TransportPool:    []string{"reality", "webrtc"},
		SelectionDir:     `C:\selection`,
		STUNURL:          "stun:203.0.113.2:3478",
		TURNURL:          "turn:203.0.113.3:3478",
		TURNUser:         "u",
		TURNPass:         "p",
		ForceRelay:       true,
		AdmissionPubKey:  "abcd",
		AdmissionCRLPath: `C:\crl.bin`,
		MeshPeers:        []string{"198.51.100.9:3478"},
		MeshProof:        []byte("old-proof"),
	}
	dialCount := 0
	base.OnUnderlayDial = func(string) { dialCount++ }

	fresh := []string{"192.0.2.1:51820", "192.0.2.2:51820"}
	freshProof := []byte("new-proof")
	got := rebuildRecoveryConfig(base, fresh, freshProof)

	if !reflect.DeepEqual(got.Coordinators, fresh) {
		t.Fatalf("Coordinators = %v, want %v", got.Coordinators, fresh)
	}
	if !reflect.DeepEqual(got.MeshProof, freshProof) {
		t.Fatalf("MeshProof = %v, want %v", got.MeshProof, freshProof)
	}

	got.OnUnderlayDial("192.0.2.4") // proves the func value itself survived, not just its zero-ness
	if dialCount != 1 {
		t.Fatalf("OnUnderlayDial was not preserved across the rebuild")
	}

	// Blanket-check everything else: neutralize the func field (DeepEqual on a
	// non-nil func is always false, even for the identical value) and the two
	// fields already proven above, then the rest must be byte-for-byte
	// unchanged from base.
	got.OnUnderlayDial, base.OnUnderlayDial = nil, nil
	got.Coordinators, got.MeshProof = base.Coordinators, base.MeshProof
	if !reflect.DeepEqual(got, base) {
		t.Fatalf("rebuildRecoveryConfig altered a field it must preserve:\n got  = %+v\n want = %+v", got, base)
	}
}

// TestMeshRecoveryFields is issue #129's config-resolution proof: it does
// not mock file I/O or hex decoding, so it only passes if a real proof
// file's bytes and a real decoded pubkey actually reach the values connect()
// and switchExit() both build core.Config from.
func TestMeshRecoveryFields(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	proofPath := filepath.Join(t.TempDir(), "proof.bin")
	if err := os.WriteFile(proofPath, []byte("signed-snapshot-bytes"), 0o600); err != nil {
		t.Fatalf("write proof file: %v", err)
	}

	t.Run("all blank is valid (recovery off)", func(t *testing.T) {
		peers, proof, pk, err := meshRecoveryFields(Config{})
		if err != nil {
			t.Fatalf("meshRecoveryFields(zero value): %v", err)
		}
		if peers != nil || proof != nil || pk != nil {
			t.Fatalf("meshRecoveryFields(zero value) = (%v, %v, %v), want all nil", peers, proof, pk)
		}
	})

	t.Run("all three set resolves correctly", func(t *testing.T) {
		peers, proof, pk, err := meshRecoveryFields(Config{
			MeshPeers:     []string{"203.0.113.1:9000"},
			MeshProofPath: proofPath,
			MeshPubKey:    pubHex,
		})
		if err != nil {
			t.Fatalf("meshRecoveryFields: %v", err)
		}
		if !reflect.DeepEqual(peers, []string{"203.0.113.1:9000"}) {
			t.Fatalf("peers = %v, want the configured list", peers)
		}
		if string(proof) != "signed-snapshot-bytes" {
			t.Fatalf("proof = %q, want the proof file's contents", proof)
		}
		if !pk.Equal(pub) {
			t.Fatalf("pubKey = %x, want %x", []byte(pk), []byte(pub))
		}
	})

	t.Run("partial config is rejected", func(t *testing.T) {
		cases := []Config{
			{MeshPeers: []string{"203.0.113.1:9000"}},
			{MeshProofPath: proofPath},
			{MeshPubKey: pubHex},
			{MeshPeers: []string{"203.0.113.1:9000"}, MeshProofPath: proofPath}, // pubkey missing
		}
		for _, c := range cases {
			if _, _, _, err := meshRecoveryFields(c); err != meshConfigErr {
				t.Errorf("meshRecoveryFields(%+v) = %v, want meshConfigErr", c, err)
			}
		}
	})

	t.Run("missing proof file surfaces as an error", func(t *testing.T) {
		_, _, _, err := meshRecoveryFields(Config{
			MeshPeers:     []string{"203.0.113.1:9000"},
			MeshProofPath: filepath.Join(t.TempDir(), "does-not-exist.bin"),
			MeshPubKey:    pubHex,
		})
		if err == nil {
			t.Fatal("meshRecoveryFields with a missing proof file succeeded, want an error")
		}
	})

	t.Run("malformed pubkey hex is rejected", func(t *testing.T) {
		_, _, _, err := meshRecoveryFields(Config{
			MeshPeers:     []string{"203.0.113.1:9000"},
			MeshProofPath: proofPath,
			MeshPubKey:    "not-hex",
		})
		if err == nil {
			t.Fatal("meshRecoveryFields with malformed pubkey hex succeeded, want an error")
		}
	})

	t.Run("wrong-length pubkey is rejected", func(t *testing.T) {
		_, _, _, err := meshRecoveryFields(Config{
			MeshPeers:     []string{"203.0.113.1:9000"},
			MeshProofPath: proofPath,
			MeshPubKey:    "abcd", // valid hex, wrong length
		})
		if err == nil {
			t.Fatal("meshRecoveryFields with a wrong-length pubkey succeeded, want an error")
		}
	})
}

// TestSignalSwitchCoalescesABurst is issue #137's debounce proof: a burst of
// wakeups (mirroring a user clicking through several tray countries) must
// collapse to exactly one pending wakeup, not stack one per click.
func TestSignalSwitchCoalescesABurst(t *testing.T) {
	ch := make(chan struct{}, 1)
	signalSwitch(ch)
	signalSwitch(ch)
	signalSwitch(ch)

	select {
	case <-ch:
	default:
		t.Fatal("channel empty, want one pending wakeup")
	}
	select {
	case <-ch:
		t.Fatal("a second wakeup was pending, want exactly one after coalescing")
	default:
	}
}

// TestClientEngineConfigCarriesTheTransportPool pins the composition both
// connect() and switchCountry() now build through (issue #137's #183 review).
//
// This is a "feature-off mutation" guard, not a getter test. The bug it
// exists for was a *missing* field: the switch's own copy of the literal
// omitted Geo/TransportPool/SelectionDir, and every other check stayed green
// — the client built, vetted, connected and switched, it just quietly did so
// without the transport ladder, reality's TCP:443 camouflage or the learned-
// path store. Nothing observable in a unit test failed, because nothing
// asserted on the config a session is actually constructed from.
//
// The Geo/ExitID pair is asserted in both directions for a related reason. The
// first fix for that missing-field bug restored the pool but ALSO set ExitID,
// on the belief that ExitID still pinned the exit underneath the pool. It does
// not and never did (see clientEngineConfig's doc): the pin was ignored, the
// ladder raced the whole directory, and the tray reported a country the session
// was not necessarily in. Asserting only that Geo is set would not have caught
// that — the config was "correct plus one extra field" — so ExitID being empty
// is asserted as its own requirement.
func TestClientEngineConfigCarriesTheTransportPool(t *testing.T) {
	snap := Config{
		Coordinators:  []string{"coordinator.example:8080"},
		Geo:           "nl", // a stale saved preference: the ARGUMENT must win
		TransportPool: []string{"reality", "webrtc"},
		STUN:          "stun:stun.example:3478",
		TURN:          "turn:turn.example:3478",
		TURNUser:      "u",
		TURNPass:      "p",
	}
	var dialled string
	got, err := clientEngineConfig(snap, "de", func(a string) { dialled = a }, nil)
	if err != nil {
		t.Fatalf("clientEngineConfig: %v", err)
	}

	if !reflect.DeepEqual(got.TransportPool, []string{"reality", "webrtc"}) {
		t.Errorf("TransportPool = %v, want the sanitized configured order — an empty pool routes the session down core's single-transport path instead of the ladder", got.TransportPool)
	}
	// The country ASKED FOR, not snap.Geo: snap.Geo is only the persisted seed
	// for the picker (seedCountryFromConfig), and a live switch passes the newly
	// picked country while snap still holds the old one. Deriving Geo from snap
	// here would make every switch a no-op that still relabelled the tray.
	if got.Geo != "de" {
		t.Errorf("Geo = %q, want the requested country %q — snap.Geo (%q) is the persisted seed, not the session's country", got.Geo, "de", snap.Geo)
	}
	if got.SelectionDir == "" {
		t.Error("SelectionDir is empty with a pool configured — the learned-path store has nowhere to live, so per-network learning is lost")
	}
	if got.ExitID != "" {
		t.Errorf("ExitID = %q, want it never set: core ignores it since issue #146 and emits an EventError when a client sets it, so a pin here would neither pin anything nor stay quiet — Geo is what narrows the ladder (selection.Ladder's inScope)", got.ExitID)
	}
	if !got.ForceRelay {
		t.Error("ForceRelay is off — a post-ICE address could then race the tunnel's route setup (see the field's comment)")
	}
	if got.SocksAddr != socksAddr {
		t.Errorf("SocksAddr = %q, want the package's fixed %q that tun2socks dials", got.SocksAddr, socksAddr)
	}
	if got.OnUnderlayDial == nil {
		t.Fatal("OnUnderlayDial is nil — a reality underlay address would never be excluded from the tunnel it rides under (issue #109)")
	}
	got.OnUnderlayDial("203.0.113.7:443")
	if dialled != "203.0.113.7:443" {
		t.Errorf("OnUnderlayDial reached %q, want the address it was called with", dialled)
	}
	if got.STUNURL != snap.STUN || got.TURNURL != snap.TURN || got.TURNUser != "u" || got.TURNPass != "p" {
		t.Errorf("signalling endpoints not carried through: %+v", got)
	}
}

// TestClientEngineConfigWithoutAPoolLeavesSelectionDirUnset guards the other
// direction: a selection directory is only meaningful when there is a pool to
// learn about, so an unset pool must not create one.
func TestClientEngineConfigWithoutAPoolLeavesSelectionDirUnset(t *testing.T) {
	got, err := clientEngineConfig(Config{Coordinators: []string{"coordinator.example:8080"}}, "de", nil, nil)
	if err != nil {
		t.Fatalf("clientEngineConfig: %v", err)
	}
	if len(got.TransportPool) != 0 {
		t.Errorf("TransportPool = %v, want empty", got.TransportPool)
	}
	if got.SelectionDir != "" {
		t.Errorf("SelectionDir = %q, want empty with no pool configured", got.SelectionDir)
	}
}

// TestClientEngineConfigRejectsAnUnusableMeshTriad checks the resolution
// happens here rather than being left to core.New, so the failure surfaces at
// connect/switch time with a message naming the file.
func TestClientEngineConfigRejectsAnUnusableMeshTriad(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.snapshot")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("write empty proof: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	snap := Config{
		Coordinators:  []string{"coordinator.example:8080"},
		MeshPeers:     []string{"courier.example:7000"},
		MeshProofPath: empty,
		MeshPubKey:    hex.EncodeToString(pub),
	}
	if _, err := clientEngineConfig(snap, "de", nil, nil); err == nil {
		t.Fatal("a zero-byte mesh proof was accepted — core's meshRecoveryConfigured needs len(MeshProof) > 0, so recovery would be off for the whole session with no error anywhere")
	}
}

// TestSignalSwitchUnderConcurrentTrayClicks covers what the sequential
// coalescing test above structurally cannot: tray clicks arrive on different
// goroutines (onReady starts one per exit slot), so the mailbox is written
// concurrently, not in sequence.
//
// This is the test that drove the mailbox's design. An earlier version carried
// the chosen country as a channel value, which forced a drain-then-send pair to
// keep the newest, and that pair had two failure modes. The visible one was
// ordering: two enqueuers could both drain and both send, landing the OLDER
// request last, so the session switched to one country while the tray checkmark
// showed another. The worse one is what this asserts — with the slot refilled
// between a caller's drain and its own send, that send blocks on a full
// capacity-1 channel with nothing consuming it, and the tray-slot goroutine
// stops responding for good. Carrying no value removes both: there is nothing
// to keep, so the send never has to be paired with a drain, so it never blocks.
//
// A stress test, not a pinned interleaving, and stated as such: the
// value-carrying shape wedged here reliably but not on the first round (round 23
// of 200 when this was written against it). The round count is the margin; the
// failure itself — an enqueuer that never returns — is unambiguous.
func TestSignalSwitchUnderConcurrentTrayClicks(t *testing.T) {
	ch := make(chan struct{}, 1)
	const clickers, rounds = 8, 200
	for r := 0; r < rounds; r++ {
		var wg sync.WaitGroup
		start := make(chan struct{})
		for g := 0; g < clickers; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				signalSwitch(ch)
			}()
		}
		close(start)

		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("round %d: a caller never returned — a tray-slot goroutine is wedged on a blocking send into the debounce mailbox", r)
		}

		// Exactly one wakeup pending however many clickers ran: coalescing must
		// collapse the burst, and must not lose it entirely either.
		if got := len(ch); got != 1 {
			t.Fatalf("round %d: %d wakeups pending, want exactly 1", r, got)
		}
		<-ch
	}
}

// TestMeshRecoveryFieldsTrimsOnLoad covers the load-time TrimSpace the #183
// review flagged as correct but unproven (deleting it left the suite green).
//
// The Settings dialog trims on save, so the only way to get untrimmed values
// into a config is to hand-edit the JSON — and cmd/node hex-decodes
// strings.TrimSpace(pubkeyHex), so a client that did not trim would fail closed
// at connect time behind "must be a 32-byte ed25519 public key in hex", which
// describes a key that is in fact perfectly valid. Both surfaces have to agree
// about what a configured triad is.
func TestMeshRecoveryFieldsTrimsOnLoad(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	proofPath := filepath.Join(t.TempDir(), "proof.bin")
	if err := os.WriteFile(proofPath, []byte("signed-snapshot-bytes"), 0o600); err != nil {
		t.Fatalf("write proof file: %v", err)
	}

	// Whitespace on both fields, as a hand-edited config.json carries it.
	peers, proof, gotPub, err := meshRecoveryFields(Config{
		MeshPeers:     []string{"198.51.100.9:3478"},
		MeshProofPath: "  " + proofPath + "\t",
		MeshPubKey:    " " + hex.EncodeToString(pub) + "\n",
	})
	if err != nil {
		t.Fatalf("meshRecoveryFields with surrounding whitespace: %v — a hand-edited config fails closed behind a misleading error", err)
	}
	if len(peers) != 1 {
		t.Fatalf("peers = %v", peers)
	}
	// The proof bytes prove the PATH was trimmed: an untrimmed path does not
	// open, so reaching real content is the evidence.
	if string(proof) != "signed-snapshot-bytes" {
		t.Errorf("proof = %q, want the file's real content — the path was not trimmed before opening", proof)
	}
	if !gotPub.Equal(pub) {
		t.Errorf("pubkey did not round-trip — the hex was not trimmed before decoding")
	}
}

// TestSwitchCountryIsANoOpWithoutALiveTunnel pins the precondition switchCountry
// gained in the #183 review. A live country switch is defined as leaving the
// full-device tunnel untouched, which is only meaningful once there is one:
// during connect()'s own bring-up the engine exists but the tunnel does not,
// and connect() is about to install one from a poolExcluder switchCountry cannot
// see. Switching there would race a startTunnel already in flight.
//
// Uses an unstarted engine — the gate has to reject before anything is
// touched, so nothing needs to be running for the check to mean something.
func TestSwitchCountryIsANoOpWithoutALiveTunnel(t *testing.T) {
	eng, err := core.New(core.Config{
		Roles:        []string{core.RoleClient},
		Coordinators: []string{"coordinator.example:8080"},
		Geo:          "nl",
	})
	if err != nil {
		t.Fatalf("core.New: %v", err)
	}

	mu.Lock()
	engine, activeTunnel, liveCountry = eng, nil, "nl"
	selectedID, selectedLbl = "de", "de" // the user picked a different country mid-bring-up
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		engine, engineCancel, activeTunnel, liveCountry = nil, nil, nil, ""
		selectedID, selectedLbl = "", ""
		mu.Unlock()
	})
	setStatus("Bringing up tunnel…")

	switchCountry()

	mu.Lock()
	stillOld, stillCountry := engine == eng, liveCountry
	mu.Unlock()
	if !stillOld || stillCountry != "nl" {
		t.Errorf("switchCountry acted with no tunnel up: engine-replaced=%v liveCountry=%q", !stillOld, stillCountry)
	}
	if got := currentStatus(); got != "Bringing up tunnel…" {
		t.Errorf("switchCountry overwrote the in-progress connect's status with %q", got)
	}
}
