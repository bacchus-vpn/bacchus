package update

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/bacchus-vpn/bacchus/core/version"
)

// Config describes one binary's update path. The zero value is not usable;
// NewUpdater validates the combination and refuses a half-configured one loudly,
// because an update path that silently does nothing is the failure this whole card
// exists to remove.
type Config struct {
	// Root is the trust anchor. Usually Anchor(), the compiled-in one; an operator
	// flag may supply another for a test network.
	Root ed25519.PublicKey

	// Revoked reports whether a delegation serial has been revoked. Nil means no
	// revocation list is configured, which means nothing is revoked.
	Revoked func(serial string) bool

	// Source is where bytes come from. See Source: this is not a trust decision.
	Source Source

	// Target is the path to replace — the binary a supervisor executes, which is not
	// necessarily this process's own path. Empty uses os.Executable().
	Target string

	// Role is which artifact row this build is (RoleNode, RoleClient, …). Required:
	// there is no sensible default, and guessing would install the wrong binary.
	Role string

	// OS and Arch select the artifact row. Empty uses runtime.GOOS/GOARCH, which is
	// the only correct answer outside a test.
	OS, Arch string

	// StatePath is the persistent state file — the rollback floor and any staged
	// artifact. Required: a peer that forgets its floor on every restart can be
	// walked back onto a burned release by anyone who can make it restart.
	StatePath string

	// Defer stages and verifies but does not publish. The client sets it: a desktop
	// application that replaces itself while a tunnel is up is worse than one that
	// waits, and applying only at a disconnected boundary avoids the question rather
	// than managing it (ADR-0052 §4). Call ApplyPending at that boundary.
	Defer bool

	// Gate is checked BEFORE any byte is fetched. A non-nil error means no fetch
	// happens at all — not a fetch that fails, no fetch.
	//
	// It is how the client refuses to fetch while it is not routed (ADR-0065 §4): an
	// update fetch from a client's own link is a distinctive, well-timed request from
	// a machine whose whole design budget goes into not making any, while the same
	// fetch inside the tunnel is bytes in a session, which is what a session is for.
	Gate func() error

	// Now and Log are seams for tests and for a caller that owns its logging. Nil
	// uses time.Now and the standard logger.
	Now func() time.Time
	Log func(format string, args ...any)
}

// Updater checks a source for a newer release and, if there is one, downloads it,
// verifies it and either publishes it or stages it for a boundary.
//
// It does not poll. Nothing here has a ticker: WHEN to check is the caller's, and
// the two callers differ deliberately — cmd/node checks on an interval because a
// node is infrastructure whose traffic is not covert, clients/fyne checks when the
// coordinator's announcement changes and never otherwise. See ADR-0065 §3.
type Updater struct {
	cfg   Config
	v     *Verifier
	state *State
}

// NewUpdater validates cfg and builds an Updater.
func NewUpdater(cfg Config) (*Updater, error) {
	if cfg.Source == nil {
		return nil, errors.New("update: no source configured")
	}
	if cfg.StatePath == "" {
		return nil, errors.New("update: no state file configured (the rollback floor must survive a restart)")
	}
	switch cfg.Role {
	case RoleNode, RoleCoordinator, RoleNetd, RoleClient:
	default:
		return nil, fmt.Errorf("update: unknown artifact role %q", cfg.Role)
	}
	if cfg.Target == "" {
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("update: resolve this executable: %w", err)
		}
		cfg.Target = exe
	}
	if cfg.OS == "" {
		cfg.OS = runtime.GOOS
	}
	if cfg.Arch == "" {
		cfg.Arch = runtime.GOARCH
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = log.Printf
	}
	v, err := NewVerifier(cfg.Root, cfg.Revoked)
	if err != nil {
		return nil, err
	}
	return &Updater{cfg: cfg, v: v, state: NewState(cfg.StatePath)}, nil
}

// Outcome is what one Check did. Every field is a fact about this check; nothing
// here is advice.
type Outcome struct {
	// Release is the release the manifest describes, once one verified.
	Release string
	// UpToDate is set when the manifest's release is not newer than this build's.
	UpToDate bool
	// NoArtifact is set when the manifest carries no row for this build.
	NoArtifact bool
	// Staged is the staging file's path, when one was written.
	Staged string
	// Applied is set when the binary at the target path was replaced.
	Applied bool
	// Deferred is set when an artifact was staged and left for a boundary.
	Deferred bool
	// Gated is set when Gate refused and nothing was fetched.
	Gated bool
}

// Check performs one edge-triggered check: fetch the manifest, verify it, and act
// if it names a newer release with an artifact for this build.
//
// The order matters and is the order of what can be refused most cheaply. The gate
// comes first because it costs nothing and its whole purpose is that no packet
// leaves. The manifest comes next, so a release that is not news is discovered
// after a few hundred bytes rather than after a download. Only then is an artifact
// fetched.
//
// A refusal at any tier leaves the target path exactly as it was. That is not a
// promise this function keeps by being careful; it is a consequence of Apply being
// the only thing in this package that touches the target, and Apply running last.
func (u *Updater) Check(ctx context.Context) (Outcome, error) {
	if !version.Stamped() {
		// A build that cannot state its own release cannot tell whether a release is
		// newer than itself, and the answer it would compute — 0.0.0, below every
		// release — would have it replace a development binary with a shipped one at
		// the first opportunity. core/version's own doc records why the unstamped case
		// must stay representable rather than be given a plausible number; this is the
		// decision that falls out of it.
		return Outcome{}, errors.New("update: this build was not stamped with a release version, so it cannot tell whether a release is newer than itself")
	}
	if u.cfg.Gate != nil {
		if err := u.cfg.Gate(); err != nil {
			return Outcome{Gated: true}, nil
		}
	}

	minSeq, pending, err := u.state.Load()
	if err != nil {
		// A state file that cannot be read is reported and the check continues at the
		// floor that WAS recoverable. Refusing to update because a scratch file is
		// unreadable would turn a small local problem into an unpatchable node.
		u.cfg.Log("update: %v (continuing at floor %d)", err, minSeq)
	}

	raw, err := u.cfg.Source.Manifest(ctx)
	if err != nil {
		return Outcome{}, fmt.Errorf("update: fetch manifest from %s: %w", u.cfg.Source, err)
	}
	b, err := ParseBundle(raw)
	if err != nil {
		return Outcome{}, err
	}
	m, err := u.v.Verify(b, u.cfg.Now(), minSeq)
	if err != nil {
		return Outcome{}, err
	}
	// The ratchet turns on a VERIFIED manifest, whether or not it is acted on. A
	// release this build has no artifact for still establishes that generation N
	// exists, and re-offering N-1 afterwards is a rollback.
	if err := u.state.RaiseFloor(m.Seq); err != nil {
		u.cfg.Log("update: %v", err)
	}

	out := Outcome{Release: m.Release}
	self := version.Current()
	theirs, err := version.Parse(m.Release)
	if err != nil {
		// Unreachable through Verify — Validate has already checked the string more
		// strictly than Parse does — and checked anyway, because "unreachable" is a
		// claim about today's Validate.
		return out, fmt.Errorf("%w: release %q", ErrInvalid, m.Release)
	}
	if theirs.Compare(self) <= 0 {
		// Not newer. Never a downgrade, even from a perfectly signed manifest: the
		// operator's remedy for a bad release is a new, higher one, and walking a fleet
		// backwards is the attack the sequence floor exists to stop (ADR-0052 §7).
		out.UpToDate = true
		return out, nil
	}

	a, err := m.Find(u.cfg.OS, u.cfg.Arch, u.cfg.Role)
	if err != nil {
		out.NoArtifact = true
		return out, nil
	}

	staged := StagedPath(u.cfg.Target, a)
	if pending != nil && pending.Artifact.Name() == a.Name() && pending.Staged == staged {
		// Already downloaded on an earlier check and still waiting for a boundary.
		// Re-verified rather than trusted: it has been sitting on disk.
		if err := verifyFile(staged, a); err == nil {
			out.Staged, out.Deferred = staged, true
			if !u.cfg.Defer {
				return u.publish(out, staged, a, m.Release)
			}
			return out, nil
		}
		u.cfg.Log("update: the staged artifact no longer verifies; fetching it again")
	}

	staged, err = Stage(ctx, u.cfg.Source, a, u.cfg.Target)
	if err != nil {
		return out, err
	}
	out.Staged = staged

	if u.cfg.Defer {
		if err := u.state.SetPending(Pending{Release: m.Release, Seq: m.Seq, Artifact: a, Staged: staged}); err != nil {
			return out, err
		}
		out.Deferred = true
		u.cfg.Log("update: release %s staged and verified at %s; it is applied at the next disconnected boundary", m.Release, staged)
		return out, nil
	}
	if err := u.state.SetPending(Pending{Release: m.Release, Seq: m.Seq, Artifact: a, Staged: staged}); err != nil {
		return out, err
	}
	return u.publish(out, staged, a, m.Release)
}

// publish applies a staged artifact and records the result.
func (u *Updater) publish(out Outcome, staged string, a Artifact, release string) (Outcome, error) {
	if err := Apply(u.cfg.Target, staged, a, release); err != nil {
		return out, err
	}
	if err := u.state.ClearPending(release); err != nil {
		u.cfg.Log("update: %v", err)
	}
	out.Applied, out.Deferred = true, false
	u.cfg.Log("update: release %s applied at %s; the previous binary is kept at %s and is restored if this release never confirms",
		release, u.cfg.Target, PreviousPath(u.cfg.Target))
	return out, nil
}

// ApplyPending publishes a previously staged artifact. It is the client's other
// half: Check stages while the tunnel is up, and this runs at a boundary where
// nothing is connected — a start, or a clean exit.
//
// ErrNoPending means there was nothing staged, which is the ordinary case and not
// a failure.
//
// The staged file is re-verified against the recorded row before it is published.
// It has been on disk, possibly across a reboot, in a directory this code does not
// control the permissions of; the row it is checked against came from a manifest
// this build verified, and is held in a 0600 state file.
func (u *Updater) ApplyPending() (Outcome, error) {
	_, pending, err := u.state.Load()
	if err != nil {
		return Outcome{}, err
	}
	if pending == nil {
		return Outcome{}, ErrNoPending
	}
	out := Outcome{Release: pending.Release, Staged: pending.Staged}
	if err := verifyFile(pending.Staged, pending.Artifact); err != nil {
		// The staged bytes are gone or no longer match. Forget them: the next check
		// re-downloads, and keeping a record of a file that does not verify would make
		// every later boundary retry the same failure.
		_ = os.Remove(pending.Staged)
		if cerr := u.state.ClearPending(""); cerr != nil {
			u.cfg.Log("update: %v", cerr)
		}
		return out, err
	}
	return u.publish(out, pending.Staged, pending.Artifact, pending.Release)
}

// Confirm clears the confirmation marker for this updater's target. A caller
// invokes it once the running build has reached a state that proves it works.
func (u *Updater) Confirm() error { return Confirm(u.cfg.Target) }

// Target reports the path this updater publishes to.
func (u *Updater) Target() string { return u.cfg.Target }
