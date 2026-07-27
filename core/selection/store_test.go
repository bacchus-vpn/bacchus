package selection

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func rec(net, geo, country, tr string, rttMs int, at time.Time) Record {
	return Record{Net: net, Geo: geo, Country: country, Tr: tr, Mode: ModeDirect, RTTms: int64(rttMs), At: at}
}

// TestStoreBestPicksFastest returns the lowest-RTT unexpired record for a
// network+geo — the winner to try first.
func TestStoreBestPicksFastest(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, _ := Open("")
	if err := s.Put(rec("net1", "RU", "RU", "webrtc", 80, now)); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(rec("net1", "RU", "BY", "reality", 25, now)); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Best("net1", "RU", now)
	if !ok || got.Country != "BY" || got.Transport != "reality" {
		t.Fatalf("Best = %+v ok=%v, want the reality/BY winner", got, ok)
	}
}

// TestStoreBestExpires stops trusting a record past the TTL, so a stale winner
// is re-raced instead of blindly reused.
func TestStoreBestExpires(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, _ := Open("")
	old := now.Add(-DefaultTTL - time.Hour)
	if err := s.Put(rec("net1", "RU", "RU", "webrtc", 25, old)); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Best("net1", "RU", now); ok {
		t.Fatal("an expired winner must not be returned")
	}
}

// TestStoreScopedByNetworkAndGeo keeps a winner from leaking across networks or
// geos — the whole point of per-network learning.
func TestStoreScopedByNetworkAndGeo(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, _ := Open("")
	_ = s.Put(rec("net1", "RU", "RU", "reality", 25, now))
	if _, ok := s.Best("net2", "RU", now); ok {
		t.Fatal("a winner on net1 must not apply to net2")
	}
	if _, ok := s.Best("net1", "US", now); ok {
		t.Fatal("a winner in RU must not apply to US")
	}
}

// TestStoreRTTWarmsRanking exposes the last measured round-trip per country so the
// ladder starts warm on reconnect.
func TestStoreRTTWarmsRanking(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s, _ := Open("")
	_ = s.Put(rec("net1", "RU", "RU", "reality", 42, now))
	if got := s.RTT("net1", "RU", now); got != 42*time.Millisecond {
		t.Fatalf("RTT = %v, want 42ms", got)
	}
	if got := s.RTT("net1", "ZZ", now); got != 0 {
		t.Fatalf("RTT of an unknown country = %v, want 0", got)
	}
}

// TestStorePersistRoundTrip proves the learning survives a restart: what one
// Store wrote, a fresh Store at the same path reads back.
func TestStorePersistRoundTrip(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	path := filepath.Join(t.TempDir(), "sub", "selection.json") // sub/ must be created by save
	s1, _ := Open(path)
	if err := s1.Put(rec("net1", "RU", "BY", "reality", 25, now)); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Best("net1", "RU", now)
	if !ok || got.Country != "BY" {
		t.Fatalf("reloaded Best = %+v ok=%v, want reality/BY", got, ok)
	}
}

// TestStoreDropsCountrylessRecords covers the one shape a file written before
// country-only assignment (issue #146) decodes to: it keyed on an exit id, so
// Country is absent and unmarshals empty.
//
// Such a record must not become a candidate. A connect naming no country is refused by
// the coordinator (refuseNoCountry), so resurfacing one as the learned winner would put
// a guaranteed-refused path at the FRONT of the ladder on every reconnect — a stale
// cache turning into a permanent first-attempt failure.
func TestStoreDropsCountrylessRecords(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	path := filepath.Join(t.TempDir(), "selection.json")
	// The pre-#146 on-disk shape: an "exit" key, no "country".
	old := `[{"net":"net1","geo":"RU","exit":"deadbeef","tr":"reality","mode":"direct","rttMs":25,"at":"2023-11-14T22:13:20Z"}]`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Best("net1", "RU", now); ok {
		t.Fatalf("a record with no country was offered as a candidate: %+v", got)
	}

	// Non-vacuity: the same file WITH a country loads fine, so the drop is about the
	// missing field and not about Open failing to read anything at all.
	fresh := `[{"net":"net1","geo":"RU","country":"BY","tr":"reality","mode":"direct","rttMs":25,"at":"2023-11-14T22:13:20Z"}]`
	if err := os.WriteFile(path, []byte(fresh), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, _ := Open(path)
	if got, ok := s2.Best("net1", "RU", now); !ok || got.Country != "BY" {
		t.Fatalf("a record with a country failed to load: %+v ok=%v", got, ok)
	}
}

// TestStoreResetForgets clears the learning and removes the file, so the user's
// reset control truly starts discovery fresh.
func TestStoreResetForgets(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	path := filepath.Join(t.TempDir(), "selection.json")
	s, _ := Open(path)
	_ = s.Put(rec("net1", "RU", "BY", "reality", 25, now))
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Best("net1", "RU", now); ok {
		t.Fatal("Best after Reset should be empty")
	}
	// A fresh store at the same path sees nothing either (file gone).
	s2, _ := Open(path)
	if _, ok := s2.Best("net1", "RU", now); ok {
		t.Fatal("Reset should have removed the persisted file")
	}
}
