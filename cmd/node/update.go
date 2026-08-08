package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/bacchus-vpn/bacchus/core/update"
	"github.com/bacchus-vpn/bacchus/core/version"
)

// The node's half of the signed release channel (issue #34, ADR-0052, ADR-0065).
//
// # Why a node POLLS and a client does not
//
// The anti-fingerprinting constraint on this card is a CLIENT constraint. A
// client performs no periodic network activity of its own — that is what
// ADR-0018, ADR-0022 and ADR-0032 spend their whole budget on — so a recurring
// update poll from one would be new, distinctive, well-timed behaviour on a
// machine designed to have none.
//
// A node is not that. It is infrastructure: it registers every ten seconds, it is
// listed in a signed directory clients dial, and its address is public by
// construction. ADR-0052 §2 says so directly — "a node is infrastructure whose
// conversation with a coordinator is already its normal traffic" and its fetch "is
// not covert in the way a client's must be".
//
// # And it polls rather than waiting to be told, because nothing tells it
//
// ADR-0052 §2 says a node "learns from the reply to a register it was already
// sending every ten seconds". THAT IS NOT TRUE OF THE CODE ON main, and the
// correction matters here because it decides the trigger. The coordinator's
// register handler replies only on a REJECT — a fenced node, a failed admission, a
// coordinator with no enforceable policy — and the success path sends nothing at
// all. `Release` is stamped on client replies (countries/session/error/challenge)
// and observed by Engine.observeNetworkVersion, which runs only for an engine with
// a client role.
//
// So a pure forwarder — the exact node this channel exists to repair, since a
// fenced one is the one running the burned release — has no announcement to be
// edge-triggered by. Giving it one is a coordinator change, and the coordinator is
// not this lane's to change. An interval here needs nobody else's file and is
// independently better in the case that matters: a node whose coordinators are all
// unreachable, or that every one of them has fenced, can still learn that a
// release exists and fix itself. See ADR-0065 §3.

// updateFlags is the node's update configuration. It is a struct rather than
// loose flags so main's flag block stays one line per concern.
type updateFlags struct {
	source   *string
	rootHex  *string
	state    *string
	target   *string
	interval *time.Duration
	stage    *bool
}

// registerUpdateFlags declares the update flags on the default flag set.
func registerUpdateFlags() updateFlags {
	return updateFlags{
		source:   flag.String("update-source", "", "signed release channel (issue #34, ADR-0052): where to fetch releases from — an https base URL, or a local directory holding "+update.ManifestName+" and "+update.BlobDir+"/<digest>. The source is UNTRUSTED: the manifest is signed by the offline root's update key and every artifact is named by its own SHA-256, so a mirror, a static host, a release page or a USB stick are all equally acceptable and none of them can substitute bytes. Empty disables updating entirely"),
		rootHex:  flag.String("update-root-pubkey", "", "the release trust anchor: the offline root's PUBLIC key, hex. Normally compiled in at release time and this flag is for a test network. Without one — stamped or given — this build refuses to apply any release, because a verifier with no anchor cannot verify anything and the only other option is admitting everything"),
		state:    flag.String("update-state", "", "file holding the update rollback floor and any staged artifact. Defaults to <target>.update-state beside the binary being updated. It MUST persist: a node that forgets its floor on every restart can be walked back onto a burned release by anyone who can make it restart, using a genuinely signed, unexpired manifest from an older generation"),
		target:   flag.String("update-target", "", "the binary path a release replaces. Empty uses this executable's own path, which is right unless a supervisor runs a copy from somewhere else"),
		interval: flag.Duration("update-interval", 6*time.Hour, "how often this node checks -update-source. A node is infrastructure and its fetch is not covert (ADR-0052 §2), which is why a node polls and a client never does. 0 checks once at startup and never again"),
		stage:    flag.Bool("update-stage-only", false, "download and verify a release but do not apply it. For an operator who wants the bytes on disk and the restart on their own schedule; the staged file is applied by the next start that is not stage-only"),
	}
}

// minUpdateInterval floors -update-interval at something a mirror can serve. A
// misconfigured 1s would hammer whoever is hosting the channel, and the shortest
// interval that is ever useful is far longer than this.
const minUpdateInterval = time.Minute

// startUpdates wires the update path and, when one is configured, starts the
// check loop. It returns the updater so the caller can confirm the running build
// once it is serving, or nil when updating is off.
//
// Every failure to CONFIGURE is fatal, and every failure to CHECK is not. A node
// told to update against a source it cannot parse is misconfigured and should say
// so at startup; a node that cannot reach its source this hour is a node that
// keeps running the release it has.
func startUpdates(ctx context.Context, f updateFlags, target string) *update.Updater {
	if strings.TrimSpace(*f.source) == "" {
		return nil
	}
	src, err := buildSource(*f.source)
	if err != nil {
		log.Fatalf("-update-source: %v", err)
	}
	root, err := resolveAnchor(*f.rootHex)
	if err != nil {
		log.Fatalf("%v", err)
	}
	state := *f.state
	if state == "" {
		state = target + ".update-state"
	}
	u, err := update.NewUpdater(update.Config{
		Root:      root,
		Source:    src,
		Target:    target,
		Role:      update.RoleNode,
		StatePath: state,
		Defer:     *f.stage,
	})
	if err != nil {
		log.Fatalf("update: %v", err)
	}
	log.Printf("update: checking %s for signed releases every %s; anchor %s, target %s (issue #34)",
		src, *f.interval, update.AnchorFingerprint(root), target)
	if !version.Stamped() {
		log.Print("update: this build carries no release stamp, so it cannot tell whether a release is newer than itself and will refuse every one. That is a build-path problem, not a configuration one — every shipped binary is stamped from the VERSION file")
	}

	go updateLoop(ctx, u, *f.interval)
	return u
}

// buildSource turns the flag into a Source. A value that parses as a URL with a
// scheme is remote; anything else is a directory. The scheme rule (https, or http
// to loopback) is enforced inside core/update.
func buildSource(s string) (update.Source, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "://") {
		return update.NewHTTPSource(s)
	}
	st, err := os.Stat(s)
	if err != nil {
		return nil, fmt.Errorf("%s is neither a URL nor a readable directory: %w", s, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is a file; a source is the DIRECTORY holding %s and %s/<digest>", s, update.ManifestName, update.BlobDir)
	}
	return update.NewDirSource(s), nil
}

// resolveAnchor prefers the flag and falls back to the compiled-in stamp.
func resolveAnchor(flagHex string) (anchor []byte, err error) {
	if strings.TrimSpace(flagHex) != "" {
		pub, perr := update.ParseAnchor(flagHex)
		return pub, perr
	}
	pub, aerr := update.Anchor()
	if aerr != nil {
		return nil, fmt.Errorf("-update-source is set but this build carries no release trust anchor and -update-root-pubkey was not given, so nothing could be verified: %w", aerr)
	}
	return pub, nil
}

// updateLoop checks once at startup and then on the interval. Once at startup
// because the case that matters most is a node that has just been restarted by an
// operator who noticed it was fenced.
func updateLoop(ctx context.Context, u *update.Updater, interval time.Duration) {
	checkOnce(ctx, u)
	if interval <= 0 {
		return
	}
	if interval < minUpdateInterval {
		interval = minUpdateInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			checkOnce(ctx, u)
		}
	}
}

// checkOnce runs one check and reports what happened. Nothing here is fatal: the
// binary that is running keeps running.
//
// The log line names version data only — no account identity, no address — which
// is ADR-0029's rule for a version reject and the reason a refusal here is safe to
// log at all.
func checkOnce(ctx context.Context, u *update.Updater) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	out, err := u.Check(cctx)
	switch {
	case err != nil:
		log.Printf("update: refused: %v (still running %s from %s)", err, version.Current(), u.Target())
	case out.Applied:
		log.Printf("update: release %s applied; exit to hand over to it — the supervisor re-execs the new binary, and if it never confirms, the previous one is restored", out.Release)
	case out.Deferred:
		log.Printf("update: release %s staged at %s and not applied (-update-stage-only)", out.Release, out.Staged)
	case out.NoArtifact:
		log.Printf("update: release %s carries no artifact for this build", out.Release)
	case out.UpToDate:
		// Silent-ish: this is the steady state and it happens on every interval.
	}
}

// checkStartupDemotion runs the demotion watchdog before anything else in main.
//
// It is unconditional — not gated on -update-source — because the marker it looks
// for was written by a PREVIOUS run that may have been configured differently, and
// because with no marker it is one stat.
//
// It demotes when a previous START OF THE APPLIED RELEASE did not confirm, which
// is not the same as "a release was applied and not confirmed" — an apply runs in
// the old binary, so this process's own start is the release's trial and returns
// nil. core/update.CheckStartup carries the whole argument; ADR-0069 records why
// the distinction is the difference between a channel that delivers a release and
// one that rolls every release back on the restart that hands over to it.
//
// A demotion exits with a distinct status. Under Restart=always the supervisor
// re-execs the restored binary two seconds later; continuing would mean the new
// release still running while the path claims the old one, which is the worst of
// both.
func checkStartupDemotion(target string) {
	err := update.CheckStartup(target)
	if err == nil {
		return
	}
	if errors.Is(err, update.ErrDemoted) {
		log.Printf("update: %v — the previous binary is back at %s and this process is exiting so the supervisor starts it", err, target)
		os.Exit(3)
	}
	log.Printf("update: startup check: %v", err)
}

// confirmProbation is how long a freshly applied release must keep running
// before it is confirmed and the demotion marker is cleared.
//
// "Reached a serving state" is core/update's phrase and deliberately the caller's
// to define. For a node it is operationalised as STILL RUNNING A MINUTE LATER, and
// the reason is what the marker is for: it exists to catch a crash loop, which
// under RestartSec=2 is a process that dies within seconds, over and over, looking
// exactly like a healthy restart in the log. A minute of uptime is what a crash
// loop cannot produce. It is not a claim that the node can serve — nothing here
// can make that claim, which is #114's problem and is recorded as such in
// ADR-0052 §7 and ADR-0065 §6.
const confirmProbation = time.Minute

// confirmAfter clears the demotion marker once the process has stayed up. A
// shutdown before then leaves the marker in place, which is correct: an operator
// stopping a node inside its first minute has told us nothing about whether the
// release works, and the next start re-runs the probation.
func confirmAfter(ctx context.Context, u *update.Updater, after time.Duration) {
	if u == nil {
		return
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(after):
	}
	if err := u.Confirm(); err != nil {
		log.Printf("update: %v", err)
	}
}

// updateTarget resolves the binary path a release replaces.
func updateTarget(flagPath string) string {
	if strings.TrimSpace(flagPath) != "" {
		return flagPath
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return exe
}
