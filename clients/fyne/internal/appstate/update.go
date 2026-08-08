package appstate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core/update"
	"github.com/bacchus-vpn/bacchus/core/version"
)

// The client's half of the signed release channel (issue #34, ADR-0052,
// ADR-0065 §4).
//
// # Two rules, and everything here is one of them
//
// THE CLIENT NEVER POLLS THE NETWORK. There is no interval, because there is no
// interval to measure: the trigger is the release string a coordinator already
// stamps on every reply this client was already receiving, read out of memory
// (core.Engine.NetworkRelease). The ticker below touches nothing but two
// in-process values. A recurring update poll would be new, distinctive,
// well-timed behaviour on a device whose entire design budget goes into not
// having any (ADR-0018, ADR-0022, ADR-0032).
//
// THE CLIENT FETCHES ONLY THROUGH ITS OWN TUNNEL. The gate is Protected, and it
// is checked before a byte moves. The full-device tunnel excludes a fixed set of
// control-plane addresses from the split-default route and nothing else, so a
// fetch to any other destination egresses at the exit — indistinguishable from
// the browsing the session exists to carry. The same fetch made while
// disconnected would be a distinctive request from the client's own address, on
// the censor's side of the tunnel. That is the fingerprintable fetch this card
// forbids, and refusing to make it is one `if`.
//
// # And it applies only where nothing is connected
//
// ADR-0052 §4: a desktop application that replaces itself while a tunnel is up is
// worse than one that waits, and ADR-0014's default-block firewall means a client
// process that dies holding the lockdown leaves a machine that cannot reach the
// network. So Check STAGES and ApplyStaged publishes, at a start or a clean exit —
// boundaries where there is no session to interrupt and no kill-switch to strand.

// UpdateConfig is the client's release-channel configuration: one nested object
// in the config file, so the flat key space above it does not grow four entries
// for a feature most users never configure.
//
// The zero value is updates OFF, which is the correct default for a client that
// was installed by hand from a downloaded artifact and has never been told where
// releases live.
type UpdateConfig struct {
	// Source is where releases are fetched from: an https base URL, or a local
	// directory holding the manifest and blobs. The source is UNTRUSTED — the
	// manifest is signed and every artifact is named by its own digest — so this is
	// a convenience, not a trust decision. Empty disables updating.
	Source string `json:"source"`

	// RootPubKey is the release trust anchor, hex. Empty uses the one compiled into
	// this build, which is the normal case; a value here is for a test network.
	RootPubKey string `json:"rootPubKey"`

	// StatePath is where the rollback floor and any staged artifact are recorded.
	// Empty puts it beside the executable. It must persist across restarts: a client
	// that forgets its floor can be walked back onto a burned release by anyone who
	// can make it restart.
	StatePath string `json:"statePath"`
}

// Enabled reports whether this client has anywhere to fetch releases from.
func (u UpdateConfig) Enabled() bool { return strings.TrimSpace(u.Source) != "" }

// NetworkRelease returns the release the coordinator last advertised, or "" when
// this client has not been told one — because it has never connected, or because
// the coordinator it reached does not stamp one.
//
// It reads the live engine and nothing else. No network, no I/O, no wait.
func (c *Controller) NetworkRelease() string {
	c.mu.Lock()
	eng := c.eng
	c.mu.Unlock()
	if eng == nil {
		return ""
	}
	return eng.NetworkRelease()
}

// Protected reports whether a tunnel is up right now. It is the update path's
// gate: this client fetches through its own tunnel or not at all.
func (c *Controller) Protected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == Protected
}

// UpdateWatcher is the client's release-channel driver. It owns no network
// behaviour of its own: it watches two in-process values and, on an edge, hands
// off to core/update.
type UpdateWatcher struct {
	ctrl *Controller
	u    *update.Updater
	logf func(string, ...any)

	// seen is the last announcement acted on, so a steady-state advert — which
	// arrives on every reply — produces one check rather than one per reply.
	seen string
}

// watchInterval is how often the watcher looks at the two in-memory values. It is
// NOT a network interval and nothing leaves the machine on this tick: it is a
// cheap way to notice that the engine has come up or that the announcement has
// changed, in a package whose one state callback belongs to the UI.
const watchInterval = 30 * time.Second

// NewUpdateWatcher builds the client's updater, or returns nil when the config
// disables updating.
//
// A configuration that is present but unusable — an unparseable source, no anchor
// anywhere — is an ERROR rather than a silent no-op. A client that was told to
// keep itself updated and quietly does not is the failure this whole card exists
// to remove.
func NewUpdateWatcher(ctrl *Controller, cfg UpdateConfig, logf func(string, ...any)) (*UpdateWatcher, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	src, err := buildUpdateSource(cfg.Source)
	if err != nil {
		return nil, err
	}
	root, err := resolveUpdateAnchor(cfg.RootPubKey)
	if err != nil {
		return nil, err
	}
	target, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("update: resolve this executable: %w", err)
	}
	state := strings.TrimSpace(cfg.StatePath)
	if state == "" {
		state = target + ".update-state"
	}
	u, err := update.NewUpdater(update.Config{
		Root:      root,
		Source:    src,
		Target:    target,
		Role:      update.RoleClient,
		StatePath: state,
		// Stage now, publish at a boundary. See the file comment.
		Defer: true,
		// The gate. Checked before a byte moves, and a refusal is not a fetch that
		// fails — it is no fetch.
		Gate: func() error {
			if !ctrl.Protected() {
				return errors.New("not routed")
			}
			return nil
		},
		Log: logf,
	})
	if err != nil {
		return nil, err
	}
	return &UpdateWatcher{ctrl: ctrl, u: u, logf: logf}, nil
}

// buildUpdateSource turns the configured string into a Source: a URL if it has a
// scheme, a directory otherwise. The scheme rule — https, or http to loopback —
// is enforced inside core/update.
func buildUpdateSource(s string) (update.Source, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		return update.NewHTTPSource(s)
	}
	st, err := os.Stat(s)
	if err != nil {
		return nil, fmt.Errorf("update source %s is neither a URL nor a readable directory: %w", s, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("update source %s is a file; it must be the directory holding %s and %s/<digest>", s, update.ManifestName, update.BlobDir)
	}
	return update.NewDirSource(s), nil
}

// resolveUpdateAnchor prefers the configured key and falls back to the compiled-in
// one.
func resolveUpdateAnchor(hexKey string) ([]byte, error) {
	if strings.TrimSpace(hexKey) != "" {
		return update.ParseAnchor(hexKey)
	}
	pub, err := update.Anchor()
	if err != nil {
		return nil, fmt.Errorf("an update source is configured but this build carries no release trust anchor and none was configured, so nothing could be verified: %w", err)
	}
	return pub, nil
}

// ApplyStaged publishes a release staged by an earlier session. It is called at
// the two boundaries where nothing is connected — a start, before any connect,
// and a clean exit — and does nothing when there is nothing staged.
//
// Publishing does NOT restart this process. The running process keeps the inode
// it started from, so the release takes effect the next time the application is
// launched. That is one extra launch in the worst case and no self-exec at all,
// which is the trade ADR-0052 §4 makes deliberately: a GUI that re-execs itself
// is a class of bug this project does not need to own.
func (w *UpdateWatcher) ApplyStaged() {
	if w == nil {
		return
	}
	if w.ctrl != nil && w.ctrl.Protected() {
		// Never at a connected boundary, whatever the caller thought.
		return
	}
	out, err := w.u.ApplyPending()
	switch {
	case errors.Is(err, update.ErrNoPending):
		return
	case err != nil:
		w.logf("update: the staged release was refused and discarded: %v", err)
		return
	}
	w.logf("update: release %s installed; it takes effect the next time this application is started", out.Release)
}

// Run watches for an announcement worth acting on until ctx is done.
//
// Nothing here reaches the network on a tick. The check that does is entered only
// when the coordinator's announced release CHANGED, is newer than this build, and
// a tunnel is up.
func (w *UpdateWatcher) Run(ctx context.Context) {
	if w == nil {
		return
	}
	t := time.NewTicker(watchInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

// tick is one pass over the in-memory state. It is separated from Run so a test
// can drive it without a clock.
func (w *UpdateWatcher) tick(ctx context.Context) {
	announced := w.ctrl.NetworkRelease()
	if announced == "" || announced == w.seen {
		return
	}
	theirs, err := version.Parse(announced)
	if err != nil {
		// A garbled advert is not acted on. It IS remembered, so a coordinator stuck on
		// a bad string does not produce one line per tick.
		w.seen = announced
		return
	}
	if theirs.Compare(version.Current()) <= 0 {
		w.seen = announced
		return
	}
	if !w.ctrl.Protected() {
		// The announcement is worth acting on and the tunnel is not up. seen is
		// deliberately NOT recorded, so the first tick after the tunnel comes up
		// reconsiders this same announcement. That is the whole shape of the gate: the
		// fetch is not skipped, it is postponed until it has cover.
		return
	}
	w.seen = announced

	out, err := w.u.Check(ctx)
	switch {
	case err != nil:
		// Recorded, so this does not retry every tick. ADR-0052 §7: there is no retry
		// storm, because the next announcement is the next attempt — and a restart is
		// another, since seen starts empty in a new process.
		w.logf("update: release %s was refused: %v (this client is still %s)", announced, err, version.Current())
	case out.Gated:
		// The tunnel dropped between the check above and the gate inside Check.
		w.seen = ""
	case out.Deferred:
		w.logf("update: release %s downloaded and verified; it is installed when you next quit or start this application", out.Release)
	}
}
