package selection

import (
	"reflect"
	"testing"
	"time"
)

// The ladder's per-exit dimension became per-COUNTRY with country-only assignment
// (old #146, ADR-0042): a candidate must name something the client can ask the
// coordinator for, and it can no longer ask for an exit. These tests predate old #146,
// translated to that surface — same tier order, same learned-winner and cooling
// behaviour — plus the two properties the country dimension adds (busy countries, and
// a chosen geo that is honoured even when busy).

// at builds an assignable country with the given code and round-trip.
func at(code string, rttMs int) Country {
	return Country{Code: code, Available: 2, RTT: time.Duration(rttMs) * time.Millisecond}
}

// busy builds a country the coordinator has said it will refuse (old #147).
func busy(code string) Country {
	return Country{Code: code, Available: 0, Busy: true}
}

func direct(tr, country string) Candidate {
	return Candidate{Transport: tr, Country: country, Mode: ModeDirect}
}
func relay(tr, country string) Candidate {
	return Candidate{Transport: tr, Country: country, Mode: ModeRelay}
}

// TestLadderTierOrder pins the whole strategy: within a geo the primary transport
// tries every in-scope country fastest-first, then alternate transports, then relay.
func TestLadderTierOrder(t *testing.T) {
	got := Ladder(LadderInput{
		Countries: []Country{
			at("NL", 50),
			at("DE", 20),
			at("SE", 0), // unknown ping -> after the measured ones
		},
		Transports: []string{"reality", "webrtc"},
	})
	want := []Candidate{
		// Tier 1+2: primary (reality), countries by ping DE(20) < NL(50) < SE(unknown).
		direct("reality", "DE"), direct("reality", "NL"), direct("reality", "SE"),
		// Tier 3: alternate transport (webrtc), same country order.
		direct("webrtc", "DE"), direct("webrtc", "NL"), direct("webrtc", "SE"),
		// Tier 4: relay through nodes, primary transport, last.
		relay("reality", "DE"), relay("reality", "NL"), relay("reality", "SE"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ladder order:\n got %v\nwant %v", got, want)
	}
}

// TestLadderGeoRestrictsToOneCountry: a user who picked a country gets candidates only
// for that country — the rest of the network is not raced on their behalf.
func TestLadderGeoRestrictsToOneCountry(t *testing.T) {
	got := Ladder(LadderInput{
		Geo:        "NL",
		Countries:  []Country{at("NL", 50), at("DE", 5)},
		Transports: []string{"reality"},
	})
	if len(got) == 0 {
		t.Fatal("a chosen geo with an assignable country produced no candidates")
	}
	for _, c := range got {
		if c.Country != "NL" {
			t.Fatalf("geo NL produced a candidate for %s: %v", c.Country, got)
		}
	}
}

// TestLadderSkipsBusyCountriesWhenChoosingFreely: with no geo set, a country the
// coordinator has already said it will refuse is not raced (old #147). Dialing it would
// spend a whole candidate's stagger and timeout to be told what the list already said.
func TestLadderSkipsBusyCountriesWhenChoosingFreely(t *testing.T) {
	got := Ladder(LadderInput{
		Countries:  []Country{busy("NL"), at("DE", 30)},
		Transports: []string{"reality"},
	})
	if len(got) == 0 {
		t.Fatal("an assignable country was available but the ladder was empty")
	}
	for _, c := range got {
		if c.Country == "NL" {
			t.Fatalf("a busy country was raced anyway: %v", got)
		}
	}
}

// TestLadderHonoursAChosenBusyCountry is the deliberate exception to the rule above,
// and matters more than it looks.
//
// Silently substituting a different country for the one the user asked for would
// egress them somewhere they did not choose — the worst failure this feature has. So a
// user-chosen country is raced even when busy; the connect is refused, and the refusal
// (old #147's country-busy) reaches them as an answer rather than as a silent reroute.
func TestLadderHonoursAChosenBusyCountry(t *testing.T) {
	got := Ladder(LadderInput{
		Geo:        "NL",
		Countries:  []Country{busy("NL"), at("DE", 5)},
		Transports: []string{"reality"},
	})
	if len(got) == 0 {
		t.Fatal("a chosen country must still be attempted when busy, so the refusal reaches the user")
	}
	for _, c := range got {
		if c.Country != "NL" {
			t.Fatalf("a chosen busy country was silently swapped for %s: %v", c.Country, got)
		}
	}
}

// TestLadderLearnedFirst puts the remembered winner at the very front and does
// not repeat it later in its natural tier.
func TestLadderLearnedFirst(t *testing.T) {
	learned := direct("webrtc", "NL")
	got := Ladder(LadderInput{
		Countries:  []Country{at("NL", 50), at("DE", 20)},
		Transports: []string{"reality", "webrtc"},
		Learned:    &learned,
	})
	if got[0] != learned {
		t.Fatalf("learned winner should be first, got %v", got[0])
	}
	// It must appear exactly once (deduped from its later tier slot).
	n := 0
	for _, c := range got {
		if c == learned {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("learned winner appears %d times, want 1: %v", n, got)
	}
}

// TestLadderLearnedIgnoredWhenCountryGone drops a remembered winner whose country the
// coordinator no longer offers, so we never dial a country that has emptied out.
func TestLadderLearnedIgnoredWhenCountryGone(t *testing.T) {
	learned := direct("reality", "ZZ") // ZZ not offered
	got := Ladder(LadderInput{
		Countries:  []Country{at("NL", 20)},
		Transports: []string{"reality"},
		Learned:    &learned,
	})
	for _, c := range got {
		if c.Country == "ZZ" {
			t.Fatalf("stale learned country ZZ should be dropped, got %v", got)
		}
	}
}

// TestLadderCoolingLearnedNotFirst keeps a just-failed learned winner out of the
// front slot, so failover moves off the path that dropped instead of retrying it.
func TestLadderCoolingLearnedNotFirst(t *testing.T) {
	learned := direct("reality", "NL")
	got := Ladder(LadderInput{
		Countries:  []Country{at("NL", 20), at("DE", 50)},
		Transports: []string{"reality"},
		Learned:    &learned,
		Cooling:    func(c Candidate) bool { return c == learned }, // NL just dropped
	})
	if got[0] == learned {
		t.Fatalf("a cooling learned winner must not be tried first, got %v", got)
	}
	// The next healthy candidate (reality/DE) should lead instead.
	if got[0] != direct("reality", "DE") {
		t.Fatalf("expected reality/DE to lead when learned NL is cooling, got %v", got[0])
	}
}

// TestLadderCoolingSinksWithinTier moves a recently failed candidate to the back
// of its tier while keeping it a candidate (it may have recovered).
func TestLadderCoolingSinksWithinTier(t *testing.T) {
	cold := direct("reality", "DE")
	got := Ladder(LadderInput{
		Countries:  []Country{at("NL", 50), at("DE", 20), at("SE", 70)},
		Transports: []string{"reality"},
		Cooling:    func(c Candidate) bool { return c == cold },
	})
	// In the direct tier, healthy keep ping order (NL, SE) and the cooling direct/DE
	// sinks to the back. The relay tier is a different candidate per country (mode
	// differs), so relay/DE is not cooling and keeps its ping-first spot.
	want := []Candidate{
		direct("reality", "NL"), direct("reality", "SE"), direct("reality", "DE"),
		relay("reality", "DE"), relay("reality", "NL"), relay("reality", "SE"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cooling sink:\n got %v\nwant %v", got, want)
	}
}

// TestLadderNoGeoSelectsAcrossCountries selects across every assignable country when
// no geo is set, fastest first.
func TestLadderNoGeoSelectsAcrossCountries(t *testing.T) {
	got := Ladder(LadderInput{
		Countries:  []Country{at("NL", 50), at("DE", 10)},
		Transports: []string{"reality"},
	})
	if got[0].Country != "DE" {
		t.Fatalf("with no geo the fastest country should lead, got %v", got)
	}
}

// TestLadderEmptyWithoutTransports yields nothing to try when the pool is empty
// and there is no learned winner.
func TestLadderEmptyWithoutTransports(t *testing.T) {
	if got := Ladder(LadderInput{Geo: "NL", Countries: []Country{at("NL", 20)}}); len(got) != 0 {
		t.Fatalf("no transports and no learned winner should give an empty ladder, got %v", got)
	}
}
