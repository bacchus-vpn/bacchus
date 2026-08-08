package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// stateVersion is the on-disk state file's own format version, independent of the
// manifest's. A file written by a future build is refused rather than misread —
// but see Load, which treats that as "no usable state" while still recovering the
// sequence floor, because a floor that cannot be parsed must not silently become
// zero.
const stateVersion = 1

// Marker is the confirmation marker written beside a target before an apply and
// cleared once the new binary proves itself. See Apply and CheckStartup.
//
// It is small on purpose. Everything in it EXCEPT Started is for a human reading a
// log line after a demotion; nothing in it is trusted to make a decision beyond
// the two this package makes on it, because a marker is a file an attacker with
// write access could author — and both decisions only ever put a binary THIS build
// wrote back where it already was, or leave it alone.
type Marker struct {
	Release  string `json:"release"`
	Previous string `json:"previous"`
	Artifact string `json:"artifact"` // content-addressed name, for the log line

	// Started records that a process of the applied release has reached
	// CheckStartup. False means no process of it has ever run: either the apply's
	// handover has not happened yet, or the binary cannot execute at all.
	//
	// It is the field that makes the marker a PROBATION rather than a trap. Without
	// it the marker means only "an apply happened and was not confirmed", which the
	// applied release's own first start satisfies — so the first start would demote
	// every release, including every release that works. See CheckStartup.
	//
	// It is also the discriminator between the two watchdogs, and that is why it is
	// on disk rather than in memory. A started marker belongs to the in-process
	// check: a process reached main, so a crash loop puts it through CheckStartup
	// again and the demotion happens there. An UNSTARTED marker on a unit that has
	// given up restarting is the one case nothing in the process can reach — the
	// binary never got as far as main — and it is what deploy/bacchus-update-rollback.sh
	// acts on. Neither can act on the other's case, so they cannot fight.
	Started bool `json:"started"`
}

func writeMarker(path string, m Marker) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("update: marshal marker: %w", err)
	}
	if err := writeAtomic(path, b, 0o600); err != nil {
		return err
	}
	return nil
}

// readMarker reads the marker at path. A missing file is (zero, false, nil).
//
// A marker that cannot be parsed is reported as PRESENT with a zero body rather
// than as an error, because every decision a zero body drives is the safe one and
// the alternative is a build that refuses to start because a scratch file beside
// it is malformed. A zero body has Started false, so the applied release gets one
// trial start and is demoted on the next if it did not confirm — the same
// treatment a well-formed marker gets, with the unreadable file replaced by a
// well-formed one on the way past. The shell rollback reads the same file with a
// pattern and reaches the same conclusion for the same reason: it cannot match
// "started": true in bytes it cannot parse, so it treats the release as never
// started, which errs toward restoring a binary known to work.
func readMarker(path string) (Marker, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Marker{}, false, nil
		}
		return Marker{}, false, fmt.Errorf("update: read marker %s: %w", path, err)
	}
	var m Marker
	if err := json.Unmarshal(b, &m); err != nil {
		return Marker{}, true, nil
	}
	return m, true, nil
}

// Pending records an artifact that has been downloaded and verified but not yet
// published — the client's case, where an apply waits for a boundary the user is
// already at (ADR-0052 §4).
//
// The Artifact is recorded in full, not just its digest, because ApplyPending
// re-verifies the staged file against it. That re-verification is the whole reason
// this is a record rather than a path: the staging file has been sitting on disk,
// possibly across a reboot, in a directory whose permissions this code does not
// control.
type Pending struct {
	Release  string   `json:"release"`
	Seq      uint64   `json:"seq"`
	Artifact Artifact `json:"artifact"`
	Staged   string   `json:"staged"`
}

type stateFile struct {
	Version int `json:"version"`

	// MinSeq is the highest manifest sequence this peer has ever accepted. It is the
	// rollback floor, and persisting it is the entire reason this file exists: a peer
	// that kept the floor only in memory could be walked back onto a burned release
	// by anyone able to make it restart, using a genuinely signed, correctly
	// delegated, unexpired manifest from an older generation (ADR-0052 §7).
	MinSeq uint64 `json:"min_seq"`

	// AppliedRelease is the last release this peer published. Informational: what
	// decides whether an update is needed is the running build's own version, never
	// this field, because this field describes what was written to a path and the
	// question is what is executing.
	AppliedRelease string `json:"applied_release,omitempty"`

	Pending *Pending `json:"pending,omitempty"`
}

// State is a peer's persistent update state: the rollback floor it must never
// forget, and any staged-but-unpublished artifact.
//
// # The file is untrusted
//
// Nothing read back is acted on without re-verification: a pending artifact is
// re-hashed against its recorded row before it is published, and the recorded row
// only ever came from a manifest this build verified. The one thing that cannot be
// re-derived is MinSeq — it is this peer's own record of how far the ratchet has
// turned, and nothing in the signed data can confirm it. Write access to this file
// is therefore equivalent to the ability to roll this peer back one generation,
// which is why it is written 0600 and belongs beside the binary rather than in a
// world-writable spool. That is a deployment property, not something this code can
// enforce — the same statement core/policy.Cache makes about its own file.
type State struct{ path string }

// NewState returns a State backed by the file at path. A missing file is a cold
// start, not an error.
func NewState(path string) *State { return &State{path: path} }

// Path returns the state file's location, for logging.
func (s *State) Path() string { return s.path }

// Load reads the persisted state. A missing or unreadable file is a cold start:
// (0, nil, nil).
//
// err is non-nil only for a file that exists and cannot be understood at all, and
// even then the floor returned is the best value recoverable, never a silent zero.
func (s *State) Load() (minSeq uint64, pending *Pending, err error) {
	f, err := s.read()
	if err != nil {
		return f.MinSeq, nil, err
	}
	return f.MinSeq, f.Pending, nil
}

func (s *State) read() (stateFile, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return stateFile{}, nil
		}
		return stateFile{}, fmt.Errorf("update: read state %s: %w", s.path, err)
	}
	var f stateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return stateFile{}, fmt.Errorf("update: parse state %s: %w", s.path, err)
	}
	if f.Version != stateVersion {
		// The floor survives a format this build cannot use; nothing else does.
		return stateFile{MinSeq: f.MinSeq}, fmt.Errorf("update: state %s: unsupported version %d", s.path, f.Version)
	}
	return f, nil
}

// RaiseFloor records that a manifest at seq was accepted. The floor only ever
// RATCHETS: a lower seq is ignored rather than rejected, because re-reading the
// same manifest on every check is the steady state and must not be an error.
func (s *State) RaiseFloor(seq uint64) error {
	f, _ := s.read()
	if seq > f.MinSeq {
		f.MinSeq = seq
	}
	return s.write(f)
}

// SetPending records a staged artifact, raising the floor at the same time.
func (s *State) SetPending(p Pending) error {
	f, _ := s.read()
	if p.Seq > f.MinSeq {
		f.MinSeq = p.Seq
	}
	f.Pending = &p
	return s.write(f)
}

// ClearPending forgets a staged artifact, recording the release that was applied
// when one was. It does not lower the floor.
func (s *State) ClearPending(appliedRelease string) error {
	f, _ := s.read()
	f.Pending = nil
	if appliedRelease != "" {
		f.AppliedRelease = appliedRelease
	}
	return s.write(f)
}

func (s *State) write(f stateFile) error {
	f.Version = stateVersion
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("update: marshal state: %w", err)
	}
	return writeAtomic(s.path, b, 0o600)
}
