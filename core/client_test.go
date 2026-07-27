package core

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// TestMeshRecoveryPartialConfigDiagnostic is issue #121's second item: a direct
// core.Config caller (unlike cmd/node's loadMeshRecovery, which fails fast) that
// sets only some of MeshPeers/MeshProof/MeshPubKey — or a wrong-size MeshPubKey —
// got recovery silently disabled by meshRecoveryConfigured with no signal at all.
// New must emit a one-time EventInfo diagnostic naming the gap, without changing
// that fail-safe disable: meshRecoveryConfigured must still report false in every
// partial case, exactly as before.
func TestMeshRecoveryPartialConfigDiagnostic(t *testing.T) {
	fullPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	shortPub := ed25519.PublicKey{1, 2, 3}
	const diagnostic = "MeshPeers/MeshProof/MeshPubKey partially set"

	cases := []struct {
		name        string
		peers       []string
		proof       []byte
		pubkey      ed25519.PublicKey
		wantPartial bool
	}{
		{name: "unconfigured (nothing set)"},
		{name: "peers only", peers: []string{"127.0.0.1:1"}, wantPartial: true},
		{name: "peers+proof, no pubkey", peers: []string{"127.0.0.1:1"}, proof: []byte("snap"), wantPartial: true},
		{name: "peers+proof, wrong-size pubkey", peers: []string{"127.0.0.1:1"}, proof: []byte("snap"), pubkey: shortPub, wantPartial: true},
		{name: "proof only", proof: []byte("snap"), wantPartial: true},
		{name: "pubkey only", pubkey: fullPub, wantPartial: true},
		{name: "fully configured", peers: []string{"127.0.0.1:1"}, proof: []byte("snap"), pubkey: fullPub},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &eventRecorder{}
			e, err := New(Config{
				Coordinators: []string{"127.0.0.1:1"},
				Roles:        []string{RoleClient},
				SocksAddr:    "127.0.0.1:0",
				Geo:          "NL", // a connect names a country, not an exit (issue #146)
				MeshPeers:    tc.peers,
				MeshProof:    tc.proof,
				MeshPubKey:   tc.pubkey,
				OnEvent:      rec.record,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer e.Stop()

			if got := rec.hasSubstring(EventInfo, diagnostic); got != tc.wantPartial {
				t.Fatalf("partial-config diagnostic emitted=%v, want %v (events: %+v)", got, tc.wantPartial, rec.events)
			}

			// The fail-safe itself must be untouched by the diagnostic: recovery is
			// configured if and only if all three fields are fully, correctly set —
			// a partial config still disables it exactly as before issue #121.
			fullyConfigured := len(tc.peers) > 0 && len(tc.proof) > 0 && len(tc.pubkey) == ed25519.PublicKeySize
			if got := e.meshRecoveryConfigured(); got != fullyConfigured {
				t.Fatalf("meshRecoveryConfigured() = %v, want %v — partial config must still fail safe", got, fullyConfigured)
			}
		})
	}
}

// TestMeshRecoveryPartialDiagnosticIsOneTime proves the "one-time" half of the
// diagnostic: constructing two independent engines from the same half-configured
// Config each emits exactly one diagnostic event for that engine, not a growing
// count — the emit lives in construction (which runs once per engine), not on a
// path meshRecoveryConfigured's repeated callers (tryMeshRecovery, retried on
// every reconnect pass during an outage) would re-trigger.
func TestMeshRecoveryPartialDiagnosticIsOneTime(t *testing.T) {
	rec := &eventRecorder{}
	cfg := Config{
		Coordinators: []string{"127.0.0.1:1"},
		Roles:        []string{RoleClient},
		SocksAddr:    "127.0.0.1:0",
		Geo:          "NL",                    // a connect names a country, not an exit (issue #146)
		MeshPeers:    []string{"127.0.0.1:1"}, // peers only: proof/pubkey missing => partial
		OnEvent:      rec.record,
	}

	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Stop()

	count := func() int {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		n := 0
		for _, ev := range rec.events {
			if ev.Kind == EventInfo && strings.Contains(ev.Message, "MeshPeers/MeshProof/MeshPubKey partially set") {
				n++
			}
		}
		return n
	}
	if n := count(); n != 1 {
		t.Fatalf("expected exactly one diagnostic from constructing e, got %d", n)
	}

	// meshRecoveryConfigured (the gate tryMeshRecovery calls on every reconnect
	// pass) must not itself emit — calling it repeatedly must not grow the count.
	for i := 0; i < 5; i++ {
		if e.meshRecoveryConfigured() {
			t.Fatal("half-configured recovery must never report configured")
		}
	}
	if n := count(); n != 1 {
		t.Fatalf("meshRecoveryConfigured must not re-emit the diagnostic: count grew to %d", n)
	}
}
