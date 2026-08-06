package core

import (
	"strings"
	"testing"
)

// TestSplitTransportName covers issue #176's parser. A bare name is version 1
// rather than "unversioned", so every configuration written before #176 keeps
// naming exactly the transport it always named.
func TestSplitTransportName(t *testing.T) {
	for _, tc := range []struct {
		in      string
		base    string
		version int
	}{
		{"", "", 1},
		{"webrtc", "webrtc", 1},
		{"reality", "reality", 1},
		{"reality/1", "reality", 1},
		{"reality/2", "reality", 2},
		{"webrtc/17", "webrtc", 17},
	} {
		base, version, err := splitTransportName(tc.in)
		if err != nil {
			t.Fatalf("splitTransportName(%q): %v", tc.in, err)
		}
		if base != tc.base || version != tc.version {
			t.Fatalf("splitTransportName(%q) = (%q, %d), want (%q, %d)", tc.in, base, version, tc.base, tc.version)
		}
	}
}

// TestSplitTransportNameRefusesAMalformedVersion is the one place #176's parser
// must NOT be forgiving. Reading "reality/two" as version 1 would hand an
// operator who typed a version the transport they were trying to move off, under
// the name of the one they asked for — the card's own failure produced by its fix.
func TestSplitTransportNameRefusesAMalformedVersion(t *testing.T) {
	for _, in := range []string{"reality/", "reality/two", "reality/0", "reality/-1", "reality/2.5", "reality/ 2"} {
		if _, _, err := splitTransportName(in); err == nil {
			t.Fatalf("splitTransportName(%q) must refuse a malformed version rather than silently defaulting", in)
		}
	}
}

// TestTransportNameRoundTrip pins that a version-1 transport renders BARE. A
// build that wrote "reality/1" back into a config would put a suffix on a name
// that arrived without one, and SanitizePoolOrder in the desktop client matches
// pool names by exact string.
func TestTransportNameRoundTrip(t *testing.T) {
	for _, in := range []string{"webrtc", "reality", "reality/2", "webrtc/9"} {
		base, version, err := splitTransportName(in)
		if err != nil {
			t.Fatalf("splitTransportName(%q): %v", in, err)
		}
		if got := transportName(base, version); got != in {
			t.Fatalf("transportName(splitTransportName(%q)) = %q, want %q", in, got, in)
		}
	}
}

// TestNewTransportAcceptsAVersionedName is decision B3's substance: a version
// this build does not implement is BUILT and reported, never refused. Refusing
// would be a fence, and #34 — the channel that would make a fence a repair tool
// rather than a kill switch — is unstarted.
func TestNewTransportAcceptsAVersionedName(t *testing.T) {
	var events []string
	tr, err := newTransport(Config{Transport: "webrtc/2"}, func(kind, msg string) {
		events = append(events, kind+": "+msg)
	})
	if err != nil {
		t.Fatalf("a transport version this build does not implement must not be refused: %v", err)
	}
	if tr == nil {
		t.Fatal("newTransport returned no transport and no error")
	}
	if len(events) != 1 {
		t.Fatalf("expected exactly one report of the version difference, got %d: %v", len(events), events)
	}
	e := events[0]
	for _, want := range []string{"webrtc/2", "version 2", "version 1", "#34"} {
		if !strings.Contains(e, want) {
			t.Fatalf("the report must name %q so the skew is diagnosable; got %q", want, e)
		}
	}
}

// TestNewTransportSaysNothingWhenTheVersionMatches keeps the report meaningful.
// A line on every ordinary startup is a line nobody reads, and #114's lesson is
// that the skew has to announce ITSELF rather than be buried in noise.
func TestNewTransportSaysNothingWhenTheVersionMatches(t *testing.T) {
	for _, name := range []string{"", "webrtc", "webrtc/1", "reality", "reality/1"} {
		var events []string
		if _, err := newTransport(Config{Transport: name}, func(kind, msg string) {
			events = append(events, kind+": "+msg)
		}); err != nil {
			t.Fatalf("newTransport(%q): %v", name, err)
		}
		if len(events) != 0 {
			t.Fatalf("newTransport(%q) must report nothing when the version matches, got %v", name, events)
		}
	}
}

// TestNewTransportStillRefusesAnUnknownBaseName pins that #176 widened the
// version, not the name set. An unknown transport is still a construction error,
// which is what makes setupPool's "a typo is a construction error, not a
// mid-connect surprise" still true.
func TestNewTransportStillRefusesAnUnknownBaseName(t *testing.T) {
	for _, name := range []string{"quic", "quic/2"} {
		_, err := newTransport(Config{Transport: name}, nil)
		if err == nil {
			t.Fatalf("newTransport(%q) must refuse an unknown transport", name)
		}
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("the error must name what was configured, got %v", err)
		}
	}
}

// TestNewTransportVersionedNameSurvivesNewNamedTransport is the property that
// makes the version worth carrying while nothing is fenced on it: the pool keys
// on the CONFIGURED string, so bumping a transport's version invalidates the
// learned winner for that path instead of trying a route validated against the
// old protocol shape first.
func TestNewTransportVersionedNameSurvivesNewNamedTransport(t *testing.T) {
	tr, err := newNamedTransport("reality/2", Config{}, func(string, string) {})
	if err != nil {
		t.Fatalf("newNamedTransport with a versioned name: %v", err)
	}
	if tr == nil {
		t.Fatal("newNamedTransport returned no transport")
	}
	// The concrete type must survive, or Engine.attachRealitySplice's type
	// assertion stops firing and #163's splice metering goes silently inert on
	// every pooled reality transport.
	if _, ok := tr.(*realityTransport); !ok {
		t.Fatalf("a versioned name must build the SAME concrete transport, got %T — "+
			"attachRealitySplice asserts on *realityTransport and would silently stop metering", tr)
	}
}

// TestTransportVersionsCoverEveryBuiltInName keeps the table honest: a transport
// added to newTransport's switch without an entry here would report "this build
// implements version 0", which reads as a skew that does not exist.
func TestTransportVersionsCoverEveryBuiltInName(t *testing.T) {
	for _, name := range []string{TransportWebRTC, TransportReality} {
		if v, ok := transportVersions[name]; !ok || v < 1 {
			t.Fatalf("transportVersions is missing a positive version for %q", name)
		}
	}
	if len(transportVersions) != 2 {
		t.Fatalf("transportVersions has %d entries; add the new transport to this test "+
			"so an unversioned one cannot ship", len(transportVersions))
	}
}
