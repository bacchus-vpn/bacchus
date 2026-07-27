package handshake

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLocalMatchesItself(t *testing.T) {
	ok, reason := Check(Local())
	if !ok {
		t.Fatalf("Check(Local()) should succeed, got reason %q", reason)
	}
	if reason != "" {
		t.Fatalf("expected no reason on success, got %q", reason)
	}
}

func TestCheckBadMagic(t *testing.T) {
	peer := Hello{Magic: "not-bacchus", Version: ProtocolVersion}
	ok, reason := Check(peer)
	if ok {
		t.Fatal("expected a bad-magic Hello to be rejected")
	}
	if !strings.Contains(reason, "magic") {
		t.Fatalf("expected reason to mention magic, got %q", reason)
	}
}

func TestCheckVersionTooOld(t *testing.T) {
	peer := Hello{Magic: Magic, Version: ProtocolVersion - 1}
	ok, reason := Check(peer)
	if ok {
		t.Fatal("expected an older peer version to be rejected")
	}
	if !strings.Contains(reason, "peer must update") {
		t.Fatalf("expected reason to say the peer must update, got %q", reason)
	}
}

func TestCheckVersionTooNew(t *testing.T) {
	peer := Hello{Magic: Magic, Version: ProtocolVersion + 1}
	ok, reason := Check(peer)
	if ok {
		t.Fatal("expected a newer peer version to be rejected")
	}
	if !strings.Contains(reason, "this side must update") {
		t.Fatalf("expected reason to say this side must update, got %q", reason)
	}
}

// Unrecognized capabilities must never fail the handshake — they are how a
// future feature stays backward compatible with older peers that only
// understand version + magic.
func TestCheckIgnoresUnknownCapabilities(t *testing.T) {
	peer := Hello{Magic: Magic, Version: ProtocolVersion, Capabilities: []Capability{"some-future-feature"}}
	ok, _ := Check(peer)
	if !ok {
		t.Fatal("an unrecognized capability must not fail the handshake")
	}
}

func TestHelloJSONRoundTrip(t *testing.T) {
	h := Hello{Magic: Magic, Version: ProtocolVersion, Capabilities: []Capability{"foo"}}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got Hello
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got.Magic != h.Magic || got.Version != h.Version || len(got.Capabilities) != 1 || got.Capabilities[0] != "foo" {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, h)
	}
}

func TestHelloOmitsEmptyCapabilities(t *testing.T) {
	b, err := json.Marshal(Local())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), "capabilities") {
		t.Fatalf("expected capabilities to be omitted when empty, got %s", b)
	}
}
