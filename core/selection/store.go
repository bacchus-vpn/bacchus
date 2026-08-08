package selection

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core/atomicfile"
)

// DefaultTTL is how long a learned record stays trusted. Networks change — an
// operator lifts or adds a block, or the user moves — so a stale winner must not
// be trusted forever; past the TTL it is re-raced and the record refreshed.
const DefaultTTL = 14 * 24 * time.Hour

// Record is one validated success remembered on this device: on network Net, under
// the user's geo selection Geo, egressing in country Country, transport Tr in mode
// Mode sustained flow with round-trip RTTms.
//
// It holds nothing that identifies the user — Net is an opaque hash (see
// [NetworkKey]), and there is no destination, address, or user-traffic timing anywhere
// in it. The file it lives in never leaves the device.
//
// It no longer records WHICH EXIT served the session (issue #146). That is not merely
// a consequence of the client no longer choosing one: an exit id is the most granular
// thing this file ever held, and with selection unable to act on it there is nothing
// left to weigh against keeping a per-device history of the exits a user has been
// through. Country is what selection acts on, so country is what is kept.
type Record struct {
	Net     string    `json:"net"`     // opaque network fingerprint (hashed)
	Geo     string    `json:"geo"`     // the country the user selected ("" = any)
	Country string    `json:"country"` // the country this success egressed in
	Tr      string    `json:"tr"`      // transport name
	Mode    string    `json:"mode"`    // ModeDirect or ModeRelay
	RTTms   int64     `json:"rttMs"`   // measured round-trip at validation
	At      time.Time `json:"at"`      // when this success was recorded (for TTL)
}

func (r Record) candidate() Candidate {
	return Candidate{Transport: r.Tr, Country: r.Country, Mode: r.Mode}
}

// Store remembers which paths worked, per network+geo, so the winner is tried
// first next time (issue #15, "learn per-network"). It persists to a single JSON
// file on the device and is safe for concurrent use. The zero value (no path) is
// a fully working in-memory store — every method is safe on it — which is what
// tests and clients that opt out of persistence use.
type Store struct {
	mu   sync.Mutex
	path string
	ttl  time.Duration
	recs map[string]Record // recKey -> best-known record for that net+geo+exit
}

// Open loads the store persisted at path, or returns an empty one if the file is
// absent. A corrupt or unreadable file is treated as empty rather than fatal: a
// damaged cache must never stop a client from connecting — it just re-learns.
// path "" is an in-memory store that never touches disk.
func Open(path string) (*Store, error) {
	s := &Store{path: path, ttl: DefaultTTL, recs: map[string]Record{}}
	if path == "" {
		return s, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, nil // unreadable -> start empty, don't block the client
	}
	var recs []Record
	if json.Unmarshal(b, &recs) != nil {
		return s, nil // corrupt -> start empty
	}
	for _, r := range recs {
		if r.Country == "" {
			// A record with no country cannot be turned into a connect: the
			// coordinator refuses one that names none. Records written before
			// country-only assignment (issue #146) keyed on an exit id and decode to
			// exactly this shape, so they are dropped and re-learned rather than
			// resurfaced as a candidate that would be refused on every use. Dropped
			// silently, consistent with how this file already treats a corrupt or
			// unreadable cache: a damaged cache must never stop a client connecting.
			continue
		}
		s.recs[recKey(r.Net, r.Geo, r.Country)] = r
	}
	return s, nil
}

// recKey identifies one country's record within a network+geo bucket. The NUL
// separators keep fields that could otherwise concatenate ambiguously distinct.
func recKey(net, geo, country string) string {
	return net + "\x00" + geo + "\x00" + country
}

// Put records a validated success, replacing any prior record for the same
// network+geo+country with this newer truth, and persists. A network can shift
// under the client, so the most recent success for a path is the one to trust.
func (s *Store) Put(r Record) error {
	s.mu.Lock()
	s.recs[recKey(r.Net, r.Geo, r.Country)] = r
	s.mu.Unlock()
	return s.save()
}

// Best returns the winning candidate to try first for this network+geo: among
// unexpired records in that bucket, the one with the lowest measured round-trip.
// ok is false when nothing is remembered (or all of it has expired), in which
// case the caller runs the full ladder.
func (s *Store) Best(net, geo string, now time.Time) (Candidate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best Record
	found := false
	for _, r := range s.recs {
		if r.Net != net || r.Geo != geo || s.expired(r, now) {
			continue
		}
		if !found || r.RTTms < best.RTTms {
			best, found = r, true
		}
	}
	if !found {
		return Candidate{}, false
	}
	return best.candidate(), true
}

// RTT returns the last measured round-trip for a country on this network, so the
// ladder's ranking starts warm on reconnect instead of treating every country as
// unknown. Zero means no unexpired record.
//
// Per-country now, which is coarser than the per-exit figure it replaced and honestly
// so: the client cannot choose which exit inside a country it gets, so a round-trip
// attributed to one exit was never a prediction about the next session there. The
// country aggregate is the finest granularity selection can act on.
func (s *Store) RTT(net, country string, now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out time.Duration
	for _, r := range s.recs {
		if r.Net != net || r.Country != country || s.expired(r, now) {
			continue
		}
		d := time.Duration(r.RTTms) * time.Millisecond
		if out == 0 || d < out {
			out = d
		}
	}
	return out
}

// Reset forgets everything learned and clears the file, so a user who suspects a
// stale or wrong choice can start discovery fresh. The file is removed rather
// than left empty so nothing about past use lingers on disk.
func (s *Store) Reset() error {
	s.mu.Lock()
	s.recs = map[string]Record{}
	path := s.path
	s.mu.Unlock()
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *Store) expired(r Record, now time.Time) bool {
	return s.ttl > 0 && now.Sub(r.At) > s.ttl
}

// save installs the current records through core/atomicfile: a complete file is
// staged beside the target, flushed and renamed over it, so a crash mid-write
// leaves the previous cache rather than a truncated one. A no-path store is
// in-memory only.
//
// It used to stage under a FIXED name (path + ".tmp") and rename WITHOUT
// flushing — issue #188's two defects. The consequences are the mildest of the
// three writers that had them, and worth naming precisely rather than waving
// at: this file is a latency cache, Open discards it wholesale when it does not
// parse, and the cost of losing it is one round of discovery. What it is NOT is
// a file that can afford to be quietly wrong, and a fixed staged name left that
// to luck: two savers interleaving into one staged file almost always produce
// JSON that does not parse, and "almost always" is the objection — whether this
// cache stays trustworthy should not depend on how two writers' bytes happened
// to land.
func (s *Store) save() error {
	s.mu.Lock()
	if s.path == "" {
		s.mu.Unlock()
		return nil
	}
	recs := make([]Record, 0, len(s.recs))
	for _, r := range s.recs {
		recs = append(recs, r)
	}
	path := s.path
	s.mu.Unlock()

	// Stable order keeps the file diff-quiet and deterministic for tests.
	sort.Slice(recs, func(i, j int) bool {
		return recKey(recs[i].Net, recs[i].Geo, recs[i].Country) <
			recKey(recs[j].Net, recs[j].Geo, recs[j].Country)
	})
	b, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	// The parent directory is created here rather than by the writer: 0700 is
	// this store's choice, and it is what keeps a per-user cache per-user.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return atomicfile.Write(path, b, 0o600)
}
