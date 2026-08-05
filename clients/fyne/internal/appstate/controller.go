package appstate

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/clients/internal/enforcement"
	"github.com/bacchus-vpn/bacchus/core"
	"github.com/bacchus-vpn/bacchus/core/accountclient"
	"github.com/bacchus-vpn/bacchus/core/devicestore"
)

// Controller drives one core.Engine across a connect/disconnect lifecycle and
// republishes state as it changes, via OnState/OnDetail. It has no Fyne
// dependency at all - the outer package is the only place that touches widgets,
// and main.go wires OnState/OnDetail through fyne.Do (never fyne.DoAndWait) so
// updates always land on Fyne's UI goroutine regardless of which goroutine called
// them from here. That split is the seam issues
// #148/#149 spiked: it is what makes the state machine itself unit- and
// integration-testable with no display driver at all (controller_test.go
// exercises a real core.Engine over a loopback fake coordinator, driven
// exactly the way ui.go drives it).
//
// OnState/OnDetail are always invoked from a goroutine Controller itself
// spawned (Connect and Disconnect each start one), never synchronously from
// the caller's own stack - so a caller on the UI goroutine (a button's
// OnTapped) never re-enters itself through these callbacks.
type Controller struct {
	cfg Config

	OnState  func(ConnState)
	OnDetail func(Detail)

	// OnCountries republishes the country picker's model (issue #16) as a
	// refresh starts, succeeds or fails. Same threading contract as OnState —
	// always from a goroutine this Controller spawned, always under c.mu, so a
	// slow refresh landing after a fast one cannot leave the picker showing the
	// older answer. See publishLocked; the reasoning about ordering is the same,
	// even though a stale country list costs a wrong number rather than a false
	// "you are protected".
	OnCountries func(CountryListState)

	// Logf, if set, receives this client's own diagnostics and everything the
	// enforcement layer logs (route installs that failed, kill-switch
	// arming). Not the detail line: that is one calm user-facing sentence,
	// and OS-command failures are neither calm nor actionable by a user.
	// Whatever this points at, enforcement redacts addresses before writing
	// (issue #140).
	Logf func(format string, args ...any)

	// enf is this client's OS enforcement backend, or nil on a platform that
	// has none yet. Set once in NewController and never written again, so it
	// is safe to read without the lock — which matters, because the UI reads
	// it from inside an OnState callback that runs with c.mu held.
	enf enforcement.Enforcer

	mu     sync.Mutex
	eng    *core.Engine
	cancel context.CancelFunc
	sess   enforcement.Session
	state  ConnState

	// gen identifies the current connect attempt. Connect and Disconnect each bump
	// it, and an attempt may only install or abandon shared state while its own
	// generation is still current.
	//
	// It does not CANCEL an in-flight connect — nothing does; c.cancel is nil until an
	// attempt installs, so Disconnect has nothing to cancel yet and connectAsync runs
	// to completion regardless. What gen does is make that attempt's OUTCOME inert:
	// it finishes, finds itself stale, stops its own engine, and touches nothing.
	// That was survivable while SocksAddr was an ephemeral port, because two
	// attempts got two ports and never met. Pinning the port (see SocksAddr, and it
	// had to be pinned) made them collide: Connect -> Disconnect -> Connect leaves
	// two attempts racing to bind 1080, the loser's Start fails, and its abort would
	// nil out c.eng — orphaning the WINNER's live engine. The UI then reads
	// Disconnected with eng == nil, Disconnect is a no-op, 1080 is held forever by a
	// tunnel nothing is tracking, and every later Connect fails. Bricked until
	// restart, with a live session the user cannot see or stop.
	//
	// So the rule is: a stale attempt cleans up after ITSELF and touches nothing
	// else.
	gen uint64

	// countries is the picker's model and listGen is the refresh that owns it,
	// bumped by every RefreshCountries and by every config change. A refresh
	// whose generation has moved on discards its own result: the config it asked
	// under is gone, so its answer describes a coordinator pool this client may
	// no longer be pointed at. Same rule as gen above, one feature down — a
	// stale worker touches nothing.
	countries CountryListState
	listGen   uint64

	// cred is what this client currently knows about its own device credential
	// (bacchus#163, ADR-0056). Unlike everything above it, it OUTLIVES a connect
	// attempt and is deliberately not reset by Disconnect: a credential that
	// could not be renewed is still un-renewed after the user disconnects, and a
	// warning that vanished when they pressed the button would vanish exactly
	// when they had time to act on it.
	cred CredentialState
}

// CredentialState is what this client knows about its own device credential, and
// it exists because a failed renewal has to be something a user can be shown
// rather than a line in a log.
//
// The distinction matters more here than it looks. Renewal failing is not an
// error at the moment it happens — the device keeps connecting on the credential
// it already holds, and everything works. It becomes a failure hours later, all
// at once, when that credential expires and a gate-enabled coordinator starts
// refusing every connect for a reason the user has no way to connect back to a
// service outage they never saw. The whole point of surfacing this is that the
// warning has to arrive during the window where it is still only a warning.
type CredentialState struct {
	// Enrolled is whether this device holds a device credential at all.
	Enrolled bool
	// ExpiresAt is the stored credential's own claimed expiry, zero when there is
	// no credential or its expiry could not be read. It is READ, never verified —
	// a liveness question, not a trust one, and nothing admits or refuses on it.
	ExpiresAt time.Time
	// RenewalFailing is true from the first failed renewal until one succeeds.
	RenewalFailing bool
	// Attention is true when the user has something to do about it: the stored
	// credential is close enough to expiry that the next failure is the last one
	// with any slack left. It is what a UI should raise a badge on.
	Attention bool
	// Detail is the sentence to show, zero-valued when there is nothing to say.
	Detail Detail
}

// credentialWarnAt is how much life must be left in a credential before a failed
// renewal is merely noted rather than escalated to the user.
//
// It is deliberately much larger than core's own renewal margin. That margin is
// when a client STARTS trying; at the defaults a credential lives 48 hours and
// renewal begins 6 hours out, so a device that cannot reach the service has
// about six hours of retries before it goes dark. Waiting until the last of
// those to say anything would put the warning inside the window where the user
// can no longer do anything useful with it — reaching a support channel, moving
// to a network that is not being interfered with, paying an invoice — so this
// escalates at half the remaining slack rather than at its end.
const credentialWarnAt = 3 * time.Hour

// CredentialState returns what this client knows about its own device
// credential. Safe to call from any goroutine, including from inside an OnState
// callback.
func (c *Controller) CredentialState() CredentialState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cred
}

func NewController(cfg Config) *Controller {
	c := &Controller{cfg: cfg}
	// A platform with no Enforcer yet returns a NotImplementedError, and that
	// is not a failure to report — it is this client's pre-bacchus#59 posture,
	// which is proxy-only and says so (see DeviceEnforced). Windows has one
	// (bacchus#59); Linux has one as of bacchus#37; [E9] (macOS, bacchus#36) is
	// what gives the last platform theirs.
	if enf, err := enforcement.New(); err == nil {
		c.enf = enf
		// Parity item 3, at the only moment it works: a lockdown left behind by
		// a killed prior session has the user offline before they touch
		// anything, so this cannot wait until they press Connect.
		enf.Recover()
	}
	return c
}

// newProxyOnlyController is NewController with no Enforcer, which is the
// posture of a platform that has none — macOS today ([E9], bacchus#36).
//
// It exists because the tests that assert what "Protected" MEANS have to reach
// Protected, and on a platform with an Enforcer that now requires enforcement
// to actually come up. Before bacchus#37 those tests got this posture on Linux
// for free; the Linux Enforcer is exactly what took it away, so the seam that
// replaces it belongs in the same change.
//
// It is a narrowing, and the honest statement of what it costs is: these tests
// no longer exercise the enforced connect path on Linux. What they still
// exercise is the half they were written for — that reaching Protected means
// the SOCKS tunnel genuinely carries bytes — which is a real configuration on
// every platform and the only one on macOS. The enforced path is covered
// instead where it can be covered against a real kernel, in
// cmd/bacchus-netd's namespace tests — and, as of issue #112, at this seam by
// newEnforcedController below, which supplies a fake Enforcer. A
// controller-level test of the FULL enforced connect would still need a live
// helper, a network namespace and a real coordinator in one process; that is
// not built here and is named in the PR rather than implied.
func newProxyOnlyController(cfg Config) *Controller {
	return &Controller{cfg: cfg}
}

// newEnforcedController is NewController with the Enforcer supplied, so the
// enforced connect path — the one bacchus#37 gave Linux, and the one
// the Windows tray client had from bacchus#59 — can be driven at this seam with
// no live bacchus-netd. It mirrors NewController exactly, Recover() included,
// so what a test drives is the object production builds rather than a
// near-miss of it. The production path is NewController; nothing else calls
// this.
//
// It is the other half of newProxyOnlyController, and it is a narrowing too.
// The honest statement of what it costs is: the Enforcer is a fake, so nothing
// BELOW this seam is checked by it — no TUN, no routes, no kill-switch, and no
// evidence that a packet goes anywhere. That half is covered where it can be:
// against a real kernel in cmd/bacchus-netd's namespace tests, and against the
// real cmdlet sequences in clients/internal/enforcement.
//
// What this reaches that neither of those can is the CONTROLLER's own
// behaviour on the enforced path — a failed Start aborting the connect instead
// of leaving a working proxy under a banner (parity item 7), each helper
// failure keeping its own sentence, disconnect and reconnect unwinding and
// re-arming through here, and DeviceEnforced staying a property of the
// platform across a session that failed.
//
// Still not built, and named rather than implied: the FULL enforced connect,
// which needs a live helper, a network namespace and a real coordinator
// co-resident in one process. Issue #112 holds that as a separate judgement.
func newEnforcedController(cfg Config, enf enforcement.Enforcer) *Controller {
	c := &Controller{cfg: cfg, enf: enf}
	enf.Recover()
	return c
}

// DeviceEnforced reports whether a Protected session on this build routes the
// whole device, or only what is pointed at SocksAddr.
//
// It is a property of the platform, not of the moment, which is what makes it
// safe to call from an OnState callback (the caller holds c.mu; this touches
// no locked state). The per-session question collapses into it: when an
// Enforcer exists, connectAsync refuses to reach Protected unless enforcement
// actually came up — a failed Start aborts rather than falling back to
// proxy-only. That refusal is parity item 7. Silently degrading to
// unprotected is the single failure mode the whole bar exists to rule out,
// and "the user gets a working proxy instead" is exactly what that failure
// would look like from the inside.
//
// So: false means the UI must keep saying "Proxy ready" and naming what is
// and is not covered (ADR-0039's Scope). True means it has earned the word
// "Protected" — the same word the Windows tray client was always entitled to,
// through the same code.
func (c *Controller) DeviceEnforced() bool { return c.enf != nil }

// VolunteeringRefused reports whether the volunteer opt-ins must be refused on
// this build: it routes the whole device AND cannot carve a served role's own
// egress back out of the tunnel it installs (bacchus#109, ADR-0053).
//
// The two halves are asked separately because as of #109 they have different
// answers. Before it, "routes the device" implied "cannot serve", so
// DeviceEnforced() was the whole question — and once #37 gave Linux an
// Enforcer, that made the GUI volunteer toggles reachable on no platform that
// ships. Now Linux carves the egress out and Windows does not, so the question
// that decides the toggles is the second half, not the first.
//
// Like DeviceEnforced this is a property of the platform rather than of the
// moment, and for the same reason: the settings window asks it to decide
// whether to offer the checkboxes at all, and connectAsync asks it again
// against whatever is on disk. Two different answers to one user's one choice
// is how a box gets ticked that the connect then refuses.
func (c *Controller) VolunteeringRefused() bool {
	return c.enf != nil && !c.enf.ServesWhileRouted()
}

// servedSourceHook is what core asks, per served socket, for the local address
// to bind (core.Config.ServedSource). nil on a platform with no Enforcer, which
// core treats as "bind nothing" — the proxy-only case, where there is no tunnel
// for served traffic to be caught by and nothing to carve out of it.
func (c *Controller) servedSourceHook() func() string {
	if c.enf == nil {
		return nil
	}
	return c.enf.ServedSource
}

func (c *Controller) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// SocksAddr is where this client's SOCKS5 proxy listens, and it is FIXED rather
// than OS-assigned because the whole value of the tunnel is that something can
// reach it. This client does no OS-level routing — no TUN, no route flip, no
// system proxy configuration (see the ADR's Scope) — so the proxy address is the
// entire interface between the tunnel and the user's traffic. An ephemeral port
// (":0") would be unknowable: core exposes no accessor for the bound address, and
// even its own log line reports the *requested* address, so nothing and nobody
// could ever point an application at it. The engine would come up, the UI would
// say Protected, and every byte the user sent would leave in the clear.
//
// 1080 mirrors the Windows tray client (its socksAddr) deliberately: it is the
// conventional SOCKS port, it is what the Windows client's tun2socks already
// expects, and keeping both clients on one number means one sentence of
// documentation covers both. Loopback-only, so nothing off the machine can use it.
const SocksAddr = "127.0.0.1:1080"

// hasCoordinator reports whether cfg names at least one coordinator, counting
// them the way core.New counts them: it runs the pool through dedupNonEmpty
// before deciding, so a whitespace-only entry is not an address there and must
// not be one here either.
//
// Asking the same question rather than `len(...) == 0` is what keeps the
// answer this client's. A config carrying `"coordinators": [""]` — one
// keystroke from the empty template the release bundle ships beside the exe
// (bacchus#136), and exactly what deleting a host between the quotes leaves
// behind — has a non-zero length and no coordinator in it. It used to sail
// past this check and come back from core as "at least one coordinator address
// required": true, and naming neither the file to edit nor the key to put it
// in, which is the whole of bacchus#134.
//
// An UNEDITED placeholder counts as nothing configured too, for the same
// reason and a sharper one. Both seeded templates a user actually receives
// carry COORDINATOR_HOST rather than an empty list — deploy/install.sh's
// seed_client_config copies the example verbatim on Linux, and the Windows
// bundle ships that same example beside the exe. Without this, the one
// configuration mistake every fresh user makes produces a DNS failure against
// a hostname that does not resolve, which names neither the file nor the key
// and reads like a network problem rather than an unfinished setup. With it,
// they get the refusal below, which names both.
func hasCoordinator(addrs []string) bool {
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a != "" && !isTemplatePlaceholder(a) {
			return true
		}
	}
	return false
}

// templatePlaceholderHosts are the hostnames bacchus-fyne.config.example.json
// uses to mean "put your own here". They are matched exactly and only in the
// host position, so a real deployment that happens to run a host whose name
// merely CONTAINS one of these is unaffected.
//
// Hard-coding the example's own tokens here is the one thing about this that
// deserves an argument, because it teaches the client about a file it never
// reads. The alternative — seeding an empty list instead and leaving the
// client ignorant — was considered and declined: a placeholder tells someone
// editing the file by hand what shape of value belongs there, which `""` does
// not, and the same template serves both platforms (ADR-0054). Two templates
// that can drift is the worse trade. The knowledge is one string set, it is
// covered by a test that reads the example file itself, and that test fails if
// the example ever renames its placeholders.
var templatePlaceholderHosts = map[string]bool{
	"COORDINATOR_HOST":   true,
	"COORDINATOR_HOST_2": true,
}

// isTemplatePlaceholder reports whether addr is an untouched template entry
// rather than an address. addr is host:port by the time it reaches here; a
// value with no port is still checked, since a half-edited entry is exactly
// the case this exists for.
func isTemplatePlaceholder(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	return templatePlaceholderHosts[host]
}

// settingsMenuPath is how the Settings window is reached, spelled the way
// main.go's menu actually reads (File → Settings…). Named here because the
// message below has to be exact about what that window can and cannot do.
const settingsMenuPath = "File → Settings…"

// noCoordinatorsError is the refusal a client with nothing configured meets
// the first time it is asked to connect. The refusal itself has always been
// right; bacchus#134 is that its ADVICE was a dead end in three separate ways,
// all of which a downloaded binary meets at once and an install.sh install
// meets none of (install.sh seeds a config, which is why this never bit a
// Linux user):
//
//  1. It told the user to copy bacchus-fyne.config.example.json. That file
//     lives in the repository and is in no artifact, so it named something the
//     user does not have and has no reason to know exists.
//  2. It said to copy it "into place", which names no path. DefaultConfigPath
//     computes the real one and always has.
//  3. It did not mention the Settings window — and the reason that omission
//     was not simply a miss is that Settings CANNOT set Coordinators, STUN or
//     TURN. There is no widget for any of them. So a message pointing at
//     Settings for this would have been the same dead end wearing a menu item,
//     and one the user would search the whole window for before believing.
//
// So the sentence names the file, and names Settings only to rule it out.
// Whether those three fields should JOIN the Settings window is a live
// question and not settled here; if they ever do, this message is one of the
// two places that has to change (the other is Config's own doc comment).
//
// The path is resolved at each call rather than once at init: DefaultConfigPath
// stats the exe-adjacent candidate, and a user who creates that file while the
// app is running should be told about the file they actually have. Cheap
// enough — this runs only when a user pressed Connect on an empty config.
func noCoordinatorsError() error {
	const noCoordinators = "no coordinators configured"
	const settingsCaveat = settingsMenuPath + " covers the rest of that file, but not the coordinator, STUN and TURN addresses."

	path := DefaultConfigPath()
	if path == "" {
		// Neither candidate could be named: this OS reported no per-user
		// config directory AND no path for the running binary. SaveConfig
		// refuses an empty path for the same reason, so there is genuinely
		// nothing to point at but the file name.
		return fmt.Errorf("%s — put at least one in the \"coordinators\" list of a bacchus-fyne.config.json beside this program. %s",
			noCoordinators, settingsCaveat)
	}
	if _, err := os.Stat(path); err == nil {
		// The file is there — the release bundle ships one beside the exe with
		// the endpoint keys present and empty (bacchus#136), and that is the
		// case this branch is for. "Create" would be wrong and confusing
		// advice for a user looking straight at the file.
		return fmt.Errorf("%s — add at least one to the \"coordinators\" list in %s. %s",
			noCoordinators, path, settingsCaveat)
	}
	return fmt.Errorf("%s — create %s and put at least one in its \"coordinators\" list. %s",
		noCoordinators, path, settingsCaveat)
}

// Country is the country this client will ask to egress in, canonicalized, or
// CountryAutomatic when the user has expressed no preference. Read under the
// lock because SetCountry writes it from the UI goroutine while a connect may be
// reading it from its own.
func (c *Controller) Country() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return NormalizeCountry(c.cfg.Country)
}

// SetCountry records the user's choice for the next connect. code is
// canonicalized; CountryAutomatic (or anything that is not a country code)
// clears the choice back to "let core pick".
//
// It does NOT touch a live session, and that is the ruling rather than a
// limitation. core settles the country once per engine (resolveCountry) exactly
// so a reconnect cannot move a user to a different jurisdiction mid-session;
// honouring a change here would have to tear the session down and rebuild it,
// which is a thing the user should ask for by pressing Disconnect. The picker
// says so instead: it is inert while a session is up.
//
// PERSISTENCE IS THE CALLER'S. This package holds the running value; the config
// file's path, and whether the file on disk is safe to overwrite at all, are
// main.go's — a config that failed to parse leaves c.cfg at its zero value, and
// writing that back would turn a JSON typo into a wiped settings file.
func (c *Controller) SetCountry(code string) {
	cc := NormalizeCountry(code)
	c.mu.Lock()
	c.cfg.Country = cc
	c.mu.Unlock()
}

// SetConfig replaces the configuration the NEXT connect is built from, and
// invalidates any country refresh in flight against the old one.
//
// It closes a gap that predates the picker and that the picker makes visible:
// the Settings window wrote its result to disk and told main.go, and nothing
// told the Controller — so a coordinator, DNS server or kill-switch setting
// changed in Settings did not reach a connect until the app was restarted. With
// a country picker there is a second writer of the same file, and two stale
// copies of one config is how a user's choice silently reverts.
//
// It deliberately keeps the country this Controller already holds: SetCountry is
// the only thing that changes it, the Settings window has no widget for it, and
// a save from a window opened before the user picked would otherwise write the
// country back to whatever it was when that window opened.
func (c *Controller) SetConfig(cfg Config) {
	c.mu.Lock()
	cfg.Country = c.cfg.Country
	c.cfg = cfg
	// Any refresh in flight is now describing a coordinator pool this client may
	// no longer be pointed at, so its answer will be discarded when it lands.
	// The spinner is cleared HERE rather than left to that worker, because a
	// worker that has already decided to discard itself must not write anything
	// at all — and a picker left on "Looking for countries…" over a refresh
	// nobody is going to publish is a dead-looking window.
	c.listGen++
	c.countries.Loading = false
	c.publishCountriesLocked()
	c.mu.Unlock()
}

// Countries is the picker's current model, for a caller that needs it outside a
// callback (the first paint, before any refresh has published anything).
func (c *Controller) Countries() CountryListState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.countries
}

// RefreshCountries asks a coordinator for the country list, entirely off the
// calling goroutine, and republishes the picker's model as it goes.
//
// It is safe to call while connected. The list engine is separate from the
// session's, binds nothing, and asks a question whose answer changes as the
// network fills up, which is the whole reason a Refresh button exists.
//
// Concurrent refreshes are ordered rather than refused: the newest generation
// wins and every older answer is dropped. Refusing one while another is in
// flight was tried and is worse — the settings window changes the coordinator
// pool and immediately asks for a list, and that request must not be the one
// that gets swallowed because a refresh happened to be running. Not starting
// twenty engines is a UI concern and is handled where it belongs: the Refresh
// button disables itself while Loading.
func (c *Controller) RefreshCountries() {
	c.mu.Lock()
	c.listGen++
	gen := c.listGen
	cfg := c.cfg
	// Loading is published on top of whatever is already there: the previous
	// list stays on screen while this runs, because a list from a minute ago is
	// a better basis for choosing than an empty box.
	c.countries.Loading = true
	c.countries.Err = nil
	c.publishCountriesLocked()
	c.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), CountryListTimeout+2*time.Second)
		defer cancel()
		countries, err := FetchCountries(ctx, cfg, c.logf)

		c.mu.Lock()
		defer c.mu.Unlock()
		if c.listGen != gen {
			// The config moved under this refresh (Settings saved, or another
			// refresh started). Its answer describes a pool this client may no
			// longer be pointed at, so it is dropped whole — including the
			// Loading flag, which belongs to whichever refresh is current now.
			return
		}
		c.countries.Loading = false
		c.countries.Fetched = true
		c.countries.Unconfigured = !hasCoordinator(cfg.Coordinators)
		if err != nil {
			// The previous list is KEPT. Nothing about a coordinator being
			// unreachable makes the countries it named last time stop existing,
			// and emptying the picker would take the user's ability to choose
			// away at the exact moment the app is least able to explain itself.
			c.countries.Err = err
			c.logf("countries: %v", err)
		} else {
			c.countries.Err = nil
			c.countries.Countries = countries
		}
		c.publishCountriesLocked()
	}()
}

// publishCountriesLocked hands the picker's model to OnCountries. THE CALLER
// MUST HOLD c.mu, for the ordering reason publishLocked documents at length; the
// same "must not block, must not call back into Controller" contract applies,
// and main.go satisfies it the same way (fyne.Do).
func (c *Controller) publishCountriesLocked() {
	if c.OnCountries != nil {
		c.OnCountries(c.countries)
	}
}

// Connect resolves an exit and brings up a session, entirely off the calling
// goroutine. A no-op if a connect/connected session is already in flight. The
// re-entrancy guard below runs synchronously (so a rapid double-click is
// rejected immediately) but never itself invokes OnState/OnDetail - only the
// spawned goroutine does, preserving the "never from the caller's stack"
// contract documented on the Controller type.
func (c *Controller) Connect() {
	c.mu.Lock()
	if c.state != Disconnected {
		c.mu.Unlock()
		return
	}
	c.gen++
	gen := c.gen
	c.state = Connecting
	c.mu.Unlock()

	go func() {
		// Re-check under the lock rather than publishing Connecting unconditionally:
		// Disconnect may already have run and published Disconnected, and announcing
		// a stale Connecting on top of it strands the UI on "Connecting…" with
		// nothing connecting. See publishLocked.
		c.mu.Lock()
		if c.gen == gen && c.state == Connecting {
			c.publishLocked(Connecting)
		}
		c.mu.Unlock()
		c.connectAsync(gen)
	}()
}

func (c *Controller) connectAsync(gen uint64) {
	if !hasCoordinator(c.cfg.Coordinators) {
		c.abort(gen, noCoordinatorsError())
		return
	}

	// The country the picker chose (issue #16), or CountryAutomatic. Validated
	// before anything is built, and REFUSED rather than defaulted when it is not
	// a country code: silently treating an unreadable value as "let core choose"
	// would egress the user somewhere they did not ask for while their config
	// file still named a country, which is the failure the whole feature exists
	// to prevent. Only a hand-edited file can reach this — the picker offers
	// nothing but codes the coordinator itself sent.
	country, err := ValidateCountry(c.cfg.Country)
	if err != nil {
		c.abortWith(gen, Detail{
			Kind:    DetailCountryConfig,
			Country: strings.TrimSpace(c.cfg.Country),
			Text:    err.Error(),
		})
		return
	}

	// Read the relay directory before anything is built: a missing file or a
	// non-hex key is the user's to fix, and naming it here — as its own
	// message, from the field that caused it — is the whole reason this is not
	// left to core's construction-time refusal. Nothing is read at all below 2
	// hops, which is the default (see LoadRelayDirectory).
	relayDir, relayDirKey, err := LoadRelayDirectory(c.cfg.RelayHops, c.cfg.RelayDirectoryPath, c.cfg.RelayDirectoryKey)
	if err != nil {
		c.abort(gen, err)
		return
	}
	// Re-sanitized here and not only on save (settings.go), so a hand-edited
	// config file cannot put a transport into the pool that this client's
	// tunnel could not make safe. SelectionDir is meaningful only with a pool,
	// so it stays empty without one rather than creating a directory nothing
	// writes to.
	pool := SanitizePoolOrder(c.cfg.TransportPool)
	var selectionDir string
	if len(pool) > 0 {
		selectionDir = DefaultSelectionDir()
	}

	// Volunteering (issue #12). Re-validated here and not only on save
	// (settings.go), for the reason SanitizePoolOrder is: a hand-edited config
	// file must not reach core through a dialog it never opened. That matters
	// more here than for the pool, because the check this repeats is the one
	// that cannot be recovered from afterwards — a serving role on a build that
	// routes the whole device would carry other people's traffic out through
	// this machine's own tunnel while the settings window's disclosure claimed
	// it left under this machine's address (ErrVolunteerWhileRouted).
	//
	// VolunteeringRefused() is the same answer settings.go was given when the
	// user ticked the box, so the two agree by construction rather than by
	// comment. A refusal aborts the connect with its own sentence, exactly as
	// LoadRelayDirectory's does, rather than surfacing later as one of core's
	// construction errors naming a field the user never saw.
	volunteer, err := PlanVolunteer(c.cfg, c.VolunteeringRefused())
	if err != nil {
		c.abort(gen, err)
		return
	}
	// Warn-and-serve findings go to the log, not to the detail line: the detail
	// line is one calm user-facing sentence about the connection they are
	// waiting on, and "your advertised address is carrier-NAT" is neither about
	// that nor actionable in the moment. The settings window is where these are
	// shown to the user, at the point of choosing.
	for _, w := range volunteer.Warnings {
		c.logf("volunteer: %s", w)
	}

	// This device's own identity and entitlement (bacchus#163, ADR-0056). Read
	// before the engine is built, for the same reason the relay directory is: a
	// device-credential directory that cannot be opened, or an account-service
	// URL that is not a URL, is the user's to fix and is named here rather than
	// surfacing as one of core's construction errors about a field they never
	// set.
	dc, err := c.openDeviceCredential()
	if err != nil {
		c.abort(gen, err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Enrollment, if a claim code is waiting and this device holds nothing.
	// Inside the connect rather than at startup because this is the moment the
	// user asked for the network, and because it is bounded by the same context
	// the connect is: a Disconnect pressed during an enrollment cancels it.
	if abandon := c.enrollIfNeeded(ctx, dc); abandon != nil {
		cancel()
		c.abort(gen, abandon)
		return
	}
	c.publishCredentialFromStore(dc)

	eng, err := core.New(core.Config{
		Coordinators: c.cfg.Coordinators,
		// The client role, plus whichever serve roles were volunteered (issue
		// #12). Always includes RoleClient: a volunteer donates its connection
		// ALONGSIDE using it, so the serve roles add to the client role rather
		// than replacing it — the same shape cmd/node's volunteer flags have
		// against -role. The default, all-off plan is []string{RoleClient}
		// exactly, which is what this line said literally before #12.
		Roles:     volunteer.Roles,
		SocksAddr: SocksAddr,
		// Advertise/ListenAddr/ExitKeyHex are empty unless the EXIT opt-in is
		// on, and core reads all three only for the roles that need them.
		// ListenAddr is derived from Advertise's port rather than separately
		// configured, so the two cannot disagree; see VolunteerPlan.
		Advertise:  volunteer.Advertise,
		ListenAddr: volunteer.ListenAddr,
		ExitKeyHex: volunteer.ExitKeyHex,
		// No exit is named, and no client can name one: country-only assignment
		// (issue #146, ADR-0042) means the coordinator picks the exit inside the
		// country that was asked for. Geo is that country — the picker's choice
		// (issue #16), canonicalized above.
		//
		// Empty is not a fallback, it is the picker's "Automatic" row: core then
		// fetches the country list itself and takes the first assignable country
		// (resolveCountry/pickCountry), which is exactly what this client did
		// before it had a picker at all. A non-empty Geo is used VERBATIM by core
		// even when that country is busy or unknown — see Config.Country on why
		// substituting a working country for the one asked for is refused rather
		// than helpful.
		Geo:      country,
		STUNURL:  c.cfg.STUN,
		TURNURL:  c.cfg.TURN,
		TURNUser: c.cfg.TURNUser,
		TURNPass: c.cfg.TURNPass,
		// Passed through, not defaulted: unset means core verifies no exit
		// credential and checks no revocation (fail-open), so an operator with an
		// admission anchor loses ADR-0026/#60's backstop against a hostile
		// coordinator unless these actually reach the engine. See Config's doc.
		AdmissionPubKey:  c.cfg.AdmissionPubKey,
		AdmissionCRLPath: c.cfg.AdmissionCRLPath,
		// Config.AdmissionCred — this node's OWN admission credential, a
		// different thing from the two fields above — is deliberately NOT set.
		//
		// This client used to set it, reading the account service's admission
		// credential off disk on every connect, because the renewal seam could not
		// carry one and a long-lived engine would otherwise present the copy it
		// started with (ADR-0056 §7). bacchus#166 widened the seam, so core reads
		// the credential out of the device store it already owns and re-reads it
		// after every renewal. Setting the field here now would be strictly worse
		// than leaving it: a non-empty value WINS over the store, so this line
		// would pin the engine to a connect-time snapshot and reintroduce exactly
		// the lapse it was added to work around.
		// The device credential (bacchus#163, ADR-0056). Set here for the first
		// time: before this, clients/fyne set no DeviceCredDir under any
		// configuration, so the 1.0 desktop client generated a fresh device key
		// every launch, held no credential, and presented nothing to a
		// coordinator's device gate whether or not that gate was on.
		//
		// DeviceRenew is nil without an account service, which core reads as
		// renewal off — the client then runs on whatever it already holds until
		// that expires, which is what a deployment with no entitlement authority
		// should do.
		DeviceCredDir: dc.dir,
		DeviceRenew:   c.deviceRenewHook(dc),
		// Transport pool (issue #93). Empty reproduces the pre-#93
		// single-transport Connect exactly, so the default path is unchanged.
		TransportPool: pool,
		SelectionDir:  selectionDir,
		// ForceRelay pins every WebRTC candidate to the configured TURN server
		// — an address enforcement.Policy already excludes from the tunnel's
		// own default route — instead of letting ICE pick a direct P2P
		// candidate whose address is learned only after the fact.
		//
		// It is set only where this platform actually routes the whole device,
		// and that gate is the whole point. A full-device tunnel must be able
		// to exclude an underlay address BEFORE dialing it, or the underlay
		// follows the split-default back into the tunnel it is carrying (a
		// loop, and a Block once the kill-switch arms — clients/internal/
		// enforcement/poolroutes.go's file doc). reality is handled late, on
		// the dial path, by OnUnderlayDial below; webrtc has no such hook
		// because it is not supposed to need one — it is supposed to be pinned
		// here. The Windows tray client set this from issue #75 for exactly that
		// reason. This client did not, which left its webrtc underlay
		// unexcluded on the one platform where it enforces; #93 surfaced it
		// while wiring TransportPool, since a pool whose first member is
		// webrtc makes the omission load-bearing rather than latent.
		//
		// Not unconditional, unlike the Windows tray client: on a platform with no
		// Enforcer this client is proxy-only, there is no tunnel to loop into,
		// and forcing every session through TURN would spend an operator's
		// relay bandwidth and a round trip to fix a problem that platform does
		// not have.
		ForceRelay: c.enf != nil,
		// Relay chaining (ADR-0038, issue #93). RelayHops 0/1 with a nil
		// directory is pre-#93 behaviour exactly. RelayDirectoryPath is passed
		// alongside the bytes so the engine keeps the directory fresh for the
		// rest of the session rather than pinning the snapshot read above
		// (issue #27).
		RelayHops:          c.cfg.RelayHops,
		RelayDirectory:     relayDir,
		RelayDirectoryKey:  relayDirKey,
		RelayDirectoryPath: c.cfg.RelayDirectoryPath,
		OnEvent:            func(ev core.Event) { c.onEvent(gen, ev) },
		// Wired to the Enforcer, not to a Session: the transport pool's first
		// reality underlay is dialled inside Connect below, before enforcement
		// starts, so there is no Session yet to hand it to. The Enforcer
		// records it and bring-up installs it (issue #109). nil when this
		// platform has no Enforcer, which core treats as "no hook".
		OnUnderlayDial: c.underlayDialHook(),
		// The local address a served role's own sockets bind, so other
		// people's traffic leaves under THIS machine's address instead of
		// through the tunnel this machine is also using (bacchus#109,
		// ADR-0053). Wired to the Enforcer rather than the Session for the
		// same reason OnUnderlayDial is, and asked lazily rather than passed
		// as a value for a stronger version of it: enforcement has not started
		// yet on this line, so the address does not exist yet. nil when this
		// platform has no Enforcer, which core treats as "bind nothing".
		ServedSource: c.servedSourceHook(),
	})
	if err != nil {
		cancel()
		c.abort(gen, err)
		return
	}
	if err := eng.Start(ctx); err != nil {
		cancel()
		c.abort(gen, err)
		return
	}
	if err := eng.Connect(ctx); err != nil {
		eng.Stop()
		cancel()
		c.abort(gen, err)
		return
	}

	// Device-wide enforcement, once the SOCKS server it bridges into is
	// actually up (core.Engine.Connect started it). This is the step that
	// makes "Protected" mean the device rather than one proxy port.
	//
	// A failure here aborts the whole connect. It deliberately does NOT fall
	// back to leaving the engine running as a working SOCKS proxy, even
	// though that would look like the friendlier outcome and would leave the
	// user with something that works: the user asked to be protected, the app
	// would be unable to protect them, and a green banner over a proxy that
	// covers nothing they configured is this ADR's own Scope-section lie in
	// its original form. Parity item 7 names this exact failure — "silently
	// degrading to unprotected is the one failure mode this whole bar exists
	// to rule out" — and the overwhelmingly common cause is running
	// unelevated, which is fixable, but only by a user who is told.
	sess, err := c.startEnforcement(volunteer.Serving())
	if err != nil {
		eng.Stop()
		cancel()
		c.abort(gen, err)
		return
	}

	c.mu.Lock()
	// Disconnect (or a newer Connect) may have run while the above was in flight;
	// honor it rather than resurrecting a session nothing wants, or trampling an
	// engine a later attempt already installed. A stale attempt tears down only what
	// it built itself.
	if c.gen != gen || c.state != Connecting {
		c.mu.Unlock()
		if sess != nil {
			// Before eng.Stop(), mirroring the teardown order Disconnect uses
			// and tunnel.Close documents: the kill-switch is lifted and the
			// routes come out first, so egress is restored before the tunnel
			// carrying it goes away rather than after.
			sess.Close()
		}
		eng.Stop()
		cancel()
		return
	}
	c.eng, c.cancel, c.sess, c.state = eng, cancel, sess, Protected
	c.publishLocked(Protected)
	c.mu.Unlock()
}

// deviceCredential is everything the account service half of a connect needs:
// the on-device key and credential store (core.DeviceEnrollment), a client for
// the service's three verbs, and the directory both share.
//
// All three are nil/empty for a deployment that names no account service, which
// is a complete configuration and not a degraded one. openDeviceCredential
// returns that shape without error, so every caller's "is there one" test is a
// nil check rather than a config read repeated in four places.
type deviceCredential struct {
	dev    *core.DeviceEnrollment
	client *accountclient.Client
	dir    string
}

// openDeviceCredential loads this device's identity and, when the config names
// an account service, builds a client for it.
//
// The device enrollment is opened even with NO account service configured. That
// is deliberate: DeviceCredDir is where a credential provisioned by any other
// means already lives, core reads it whether or not anything here can renew it,
// and a client that only looked when it had a service to ask would ignore a
// credential sitting on disk. It is also what makes the device key stable across
// launches, which is what an enrollment is bound to.
//
// A malformed account-service configuration is a hard error rather than a
// silently skipped feature. Every one of accountclient.New's refusals is a value
// that cannot be defaulted — an empty audience binds assertions to nothing, an
// absent CA silently falls back to the public root pool — so a typo here has to
// stop the connect and name itself, not leave the user enrolled against
// whoever answered.
func (c *Controller) openDeviceCredential() (deviceCredential, error) {
	dir := c.cfg.EffectiveDeviceCredDir()
	dev, err := core.OpenDeviceEnrollment(dir)
	if err != nil {
		return deviceCredential{}, err
	}
	out := deviceCredential{dev: dev, dir: dir}
	if !c.cfg.AccountServiceConfigured() {
		return out, nil
	}
	cl, err := accountclient.New(accountclient.Config{
		BaseURL:      strings.TrimSpace(c.cfg.AccountServiceURL),
		Audience:     strings.TrimSpace(c.cfg.AccountServiceAudience),
		ServerCAFile: strings.TrimSpace(c.cfg.AccountServiceCA),
		Logf:         c.logf,
	})
	if err != nil {
		return deviceCredential{}, err
	}
	out.client = cl
	return out, nil
}

// enrollIfNeeded redeems a configured claim code, once, for a device that holds
// no credential yet. It reports whether the connect should be ABANDONED.
//
// The two answers are not the same failure, and telling them apart is the whole
// content of this function:
//
//   - The service REFUSED — a wrong claim code, a lapsed entitlement, no device
//     slots left. That answer will be identical in ten seconds and in ten hours,
//     the user has something to do about it, and continuing would take them to a
//     coordinator that refuses them for a reason two layers away from the one
//     that actually applies. So the connect is abandoned and the refusal is what
//     they are told.
//   - The service was UNREACHABLE. Then the connect continues, and that is not
//     leniency. A coordinator's device gate is off unless an operator turned it
//     on, so a client with no credential may well connect perfectly; making the
//     account service's reachability a precondition for connecting would put the
//     one service the deployment model allows to be blockable onto the critical
//     path of the thing it is allowed to be blockable because it is NOT on.
func (c *Controller) enrollIfNeeded(ctx context.Context, dc deviceCredential) (abandon error) {
	claim := strings.TrimSpace(c.cfg.ClaimCode)
	if dc.client == nil || claim == "" || dc.dev.Enrolled() {
		return nil
	}

	_, err := dc.client.Enroll(ctx, dc.dev, claim, c.cfg.EffectiveDeviceLabel())
	switch {
	case err == nil, errors.Is(err, accountclient.ErrAlreadyHaveCredential):
		// Erased before the connect proceeds, not after it succeeds: the code is
		// spent either way, and a client that kept it until the tunnel came up
		// would leave a spent bearer secret on disk for every connect that
		// failed for an unrelated reason.
		if cerr := appstateClearClaimCode(); cerr != nil {
			c.logf("enrollment: could not clear the spent claim code from the config file: %v", cerr)
		}
		c.logf("enrollment: this device now holds a device credential")
		c.notifyDetail(Detail{Text: "This device is now registered to your account."})
		return nil

	case accountclient.Terminal(err):
		return fmt.Errorf("%s", enrollmentRefusalText(err))

	default:
		// Unreachable, rate limited, or the service failed. Say so and keep
		// going: whatever this device already holds is what it will present.
		c.logf("enrollment: %v", err)
		c.notifyDetail(Detail{Text: "Could not reach your account service to register this device — connecting with what this device already has."})
		return nil
	}
}

// enrollmentRefusalText turns a coded refusal into the sentence a user reads.
//
// The mapping is small on purpose. Only three of these are things a user can act
// on, and the rest collapse into one honest sentence rather than being narrated
// individually — a code the user cannot do anything about is a code that should
// not become vocabulary they have to learn. bad_assertion in particular is NOT
// broken out: it means the signature failed or this device is not enrolled, the
// service refuses to say which, and inventing a client-side guess would tell the
// user the wrong one half the time.
func enrollmentRefusalText(err error) string {
	code, ok := accountclient.CodeOf(err)
	if !ok {
		return "Could not register this device: " + err.Error()
	}
	switch code {
	case accountclient.CodeMalformedSecret:
		return "That does not look like a Bacchus claim code — check what you entered."
	case accountclient.CodeClaimRejected:
		return "That claim code was not accepted. It may have been mistyped, or already used."
	case accountclient.CodeEntitlementExpired:
		return "Your subscription has expired, so this device cannot be registered."
	case accountclient.CodeNoSlots:
		return "Your plan has no device slots left. Remove a device, or add slots, and try again."
	default:
		return "Your account service refused to register this device."
	}
}

// deviceRenewHook is what fills core.Config.DeviceRenew — the seam ADR-0046 left
// open and nothing has ever filled.
//
// It wraps the account client's own renewal rather than passing it through, and
// the wrapper is the answer to the question ADR-0046 asked and nobody had:
// what a failed renewal looks like to a user rather than to a log line. core
// emits an event on failure and retries at the next tick, which is correct
// engine behaviour and invisible: the connection is fine, so nothing changes on
// screen, and it stays fine right up until the credential expires and every
// connect starts being refused. This records the failure as STATE, with the
// remaining life of the credential attached, so a UI can escalate on the way
// down rather than announce the arrival.
//
// nil when there is no account service, which core reads as renewal off — the
// pre-#163 posture exactly.
//
// What it no longer does is compensate for the seam. It used to wrap
// Client.RenewInto(dir) rather than Client.Renew, because the seam returned two
// strings and the response carried three, so the admission credential had to be
// written out of band by something that knew where this client's device
// directory was. bacchus#166 moved that into the seam, where every embedder gets
// it — which was the whole argument for fixing it rather than mitigating it
// again. What is left here is the part that is genuinely this client's: turning
// an outcome into something a user can see.
func (c *Controller) deviceRenewHook(dc deviceCredential) func(context.Context, core.DeviceRenewRequest) (devicestore.Credential, error) {
	if dc.client == nil {
		return nil
	}
	return func(ctx context.Context, req core.DeviceRenewRequest) (devicestore.Credential, error) {
		fresh, err := dc.client.Renew(ctx, req)
		// The expiry read is of the credential being REPLACED on failure and of
		// the fresh one on success, which is what makes the failure sentence
		// able to say how long is left.
		if err != nil {
			c.recordRenewalFailure(req.Current.Device, err)
		} else {
			c.recordRenewalSuccess(fresh.Device)
		}
		return fresh, err
	}
}

// recordRenewalFailure updates the credential state after a renewal that did not
// work, and tells the user when there is a reason to.
func (c *Controller) recordRenewalFailure(currentCred string, err error) {
	exp, _ := devicestore.Expiry(currentCred)
	left := time.Until(exp)
	attention := exp.IsZero() || left <= credentialWarnAt

	d := renewalFailureDetail(err, exp, left)

	c.mu.Lock()
	c.cred.Enrolled = currentCred != ""
	c.cred.ExpiresAt = exp
	c.cred.RenewalFailing = true
	c.cred.Attention = attention
	c.cred.Detail = d
	c.mu.Unlock()

	c.logf("device credential: renewal failed: %v", err)
	c.notifyDetail(d)
}

// recordRenewalSuccess clears a previously recorded failure.
//
// It notifies only when there was something to clear. A renewal succeeding is
// the normal case and happens every few hours forever; announcing it would make
// the detail line flicker with news that nothing is wrong, which is how a line
// that also carries real warnings stops being read.
func (c *Controller) recordRenewalSuccess(cred string) {
	exp, _ := devicestore.Expiry(cred)

	c.mu.Lock()
	wasFailing := c.cred.RenewalFailing
	c.cred = CredentialState{Enrolled: cred != "", ExpiresAt: exp}
	c.mu.Unlock()

	if wasFailing {
		c.logf("device credential: renewed")
		c.notifyDetail(Detail{
			Kind: DetailRenewalRecovered,
			Text: "Your subscription is up to date again.",
		})
	}
}

// renewalFailureDetail is the sentence a user reads when renewal fails, and it
// escalates rather than repeating.
//
// Chosen by how much slack is left rather than by what went wrong, because what
// went wrong is mostly not actionable and how much time is left always is. The
// one exception is a refusal about the ACCOUNT — an expired subscription or a
// revoked device — which no amount of waiting fixes and which therefore says so
// immediately whatever the clock says.
//
// It returns a whole Detail rather than a string (bacchus#171): every branch
// here is a fixed sentence this client wrote, so every branch has a DetailKind
// the outer package can render in the user's own language. Text is still filled
// in on all of them — a caller that does not translate, which is every test and
// anything reading this as a log, gets the whole sentence.
func renewalFailureDetail(err error, exp time.Time, left time.Duration) Detail {
	if code, ok := accountclient.CodeOf(err); ok {
		switch code {
		case accountclient.CodeEntitlementExpired:
			return Detail{
				Kind: DetailSubscriptionExpired,
				Text: "Your subscription has expired. This device will stop connecting when its current access runs out.",
			}
		case accountclient.CodeDeviceRevoked:
			return Detail{
				Kind: DetailDeviceRevoked,
				Text: "This device's access was withdrawn. It will stop connecting when its current access runs out.",
			}
		}
	}
	switch {
	case exp.IsZero():
		return Detail{
			Kind: DetailRenewalUnknownExpiry,
			Text: "Bacchus could not refresh this device's access, and cannot tell how long the current one lasts. If connecting starts failing, this is why.",
		}
	case left <= 0:
		return Detail{
			Kind: DetailRenewalExpired,
			Text: "This device's access has run out and could not be refreshed. Connecting will be refused until it is.",
		}
	case left <= credentialWarnAt:
		return Detail{
			Kind:      DetailRenewalUrgent,
			Remaining: left,
			Text:      fmt.Sprintf("Your subscription needs attention: Bacchus could not refresh this device's access, which runs out in about %s.", RoughDuration(left)),
		}
	default:
		return Detail{
			Kind: DetailRenewalFailing,
			Text: "Bacchus could not refresh this device's access and will keep trying. Your connection is unaffected for now.",
		}
	}
}

// DurationUnit is the coarse bucket RoughRemaining rounds a remaining lifetime
// into. It exists so the layer that owns the user's language can render the
// phrase itself: this package cannot import Fyne (see the package doc) and so
// cannot call lang.L, and handing the outer package a finished English fragment
// like "3 hours" would drop untranslated English into the middle of a
// translated sentence — the exact failure DetailKind exists to prevent.
type DurationUnit int

const (
	// DurationHours: Count is a number of hours, two or more.
	DurationHours DurationUnit = iota
	// DurationAnHour: about an hour. Count is 1 and is not worth printing —
	// "1 hour" reads as a precision this number does not have.
	DurationAnHour
	// DurationMinutes: Count is a number of minutes, two or more.
	DurationMinutes
	// DurationAMoment: less than a couple of minutes, or already gone. Count is 0.
	DurationAMoment
)

// RoughRemaining buckets a remaining lifetime the way a person would say it.
//
// Deliberately coarse. The precise number is a moving target the user cannot act
// on to the minute, and a countdown that reads "2h58m12s" invites watching it
// rather than doing the thing it is asking for.
func RoughRemaining(d time.Duration) (count int, unit DurationUnit) {
	switch {
	case d >= 2*time.Hour:
		return int(d.Round(time.Hour) / time.Hour), DurationHours
	case d >= time.Hour:
		return 1, DurationAnHour
	case d >= 2*time.Minute:
		return int(d.Round(time.Minute) / time.Minute), DurationMinutes
	default:
		return 0, DurationAMoment
	}
}

// RoughDuration renders RoughRemaining in English — the copy that goes in
// Detail.Text, which every kind carries so a caller that does not translate
// still gets the whole sentence. The outer package renders the same buckets
// through lang.L; both read the same rounding, so the two can differ in wording
// and never in what they claim.
func RoughDuration(d time.Duration) string {
	n, unit := RoughRemaining(d)
	switch unit {
	case DurationHours:
		return fmt.Sprintf("%d hours", n)
	case DurationAnHour:
		return "an hour"
	case DurationMinutes:
		return fmt.Sprintf("%d minutes", n)
	default:
		return "a moment"
	}
}

// Enroll redeems a claim code for this device on demand, outside a connect.
//
// It is the seam a claim-code dialog would call, and it is here rather than in
// the outer Fyne package for the same reason every other decision in this
// package is: this one is testable without a display driver, and the dialog that
// will eventually call it is not. ADR-0056 §3 records that the dialog is the
// intended shape and Config.ClaimCode is the interim; this method is what makes
// the two the same code path rather than two implementations of one exchange.
func (c *Controller) Enroll(ctx context.Context, claim, label string) error {
	dc, err := c.openDeviceCredential()
	if err != nil {
		return err
	}
	if dc.client == nil {
		return errors.New("no account service is configured, so this device cannot be registered")
	}
	if label == "" {
		label = c.cfg.EffectiveDeviceLabel()
	}
	if _, err := dc.client.Enroll(ctx, dc.dev, claim, label); err != nil {
		if errors.Is(err, accountclient.ErrAlreadyHaveCredential) {
			return nil
		}
		if accountclient.Terminal(err) {
			return fmt.Errorf("%s", enrollmentRefusalText(err))
		}
		return err
	}
	if cerr := appstateClearClaimCode(); cerr != nil {
		c.logf("enrollment: could not clear the spent claim code from the config file: %v", cerr)
	}
	c.publishCredentialFromStore(dc)
	return nil
}

// publishCredentialFromStore refreshes CredentialState from what is on disk,
// with no network call. Called after enrollment and at the start of every
// connect, so the state a UI reads describes this device rather than the last
// thing that happened to it.
func (c *Controller) publishCredentialFromStore(dc deviceCredential) {
	held, ok := dc.dev.Current()
	exp, _ := devicestore.Expiry(held.Device)

	c.mu.Lock()
	c.cred.Enrolled = ok
	c.cred.ExpiresAt = exp
	if ok {
		// A stored credential says nothing about whether renewal is currently
		// working, so a previously recorded failure is left standing. It is
		// cleared by a renewal that succeeds and by nothing else.
		c.cred.Attention = c.cred.RenewalFailing && (exp.IsZero() || time.Until(exp) <= credentialWarnAt)
	} else {
		c.cred.Attention = false
		c.cred.Detail = Detail{}
		c.cred.RenewalFailing = false
	}
	c.mu.Unlock()
}

// appstateClearClaimCode is ClearClaimCode behind a variable so a test can drive
// enrollment without writing to the real user's config file. Production never
// replaces it.
var appstateClearClaimCode = ClearClaimCode

// underlayDialHook returns the OnUnderlayDial callback, or nil when this
// platform has no Enforcer — core reads a nil hook as "no hook", and handing
// it a closure that dereferences a nil Enforcer would panic on the dial path.
func (c *Controller) underlayDialHook() func(string) {
	if c.enf == nil {
		return nil
	}
	return c.enf.ReserveUnderlay
}

// startEnforcement brings up device-wide routing for the session that just
// connected. Returns (nil, nil) — no session, no error — on a platform with
// no Enforcer, which is this client's documented proxy-only posture rather
// than a failure; see DeviceEnforced.
//
// serving is VolunteerPlan.Serving(): whether this session carries anybody
// else's traffic. It is passed in rather than re-derived from c.cfg because
// the plan is the validated answer and the config is only the request — a
// stored opt-in that PlanVolunteer refused must not turn into a carve-out
// here.
func (c *Controller) startEnforcement(serving bool) (enforcement.Session, error) {
	if c.enf == nil {
		return nil, nil
	}
	dns := c.cfg.DNS
	if dns == "" {
		dns = DefaultDNSUpstream
	}
	sess, err := c.enf.Start(enforcement.Policy{
		Coordinators: c.cfg.Coordinators,
		STUNURL:      c.cfg.STUN,
		TURNURL:      c.cfg.TURN,
		DNSUpstream:  dns,
		Bypass:       c.cfg.Bypass,
		BypassMode:   NormalizeBypassMode(c.cfg.BypassMode),
		KillSwitch:   !c.cfg.DisableKillSwitch,
		// Carve this node's own served egress out of the tunnel about to be
		// installed, when the volunteer plan says it is serving (bacchus#109).
		// PlanVolunteer has already refused this combination on a platform
		// that cannot honor it, so a true here is a platform that can — and
		// enforcement.Policy's contract makes Start fail rather than ignore
		// it if that is ever wrong.
		ServeEgress: serving,
		Logf:        c.logf,
	}, SocksAddr)
	if err != nil {
		return nil, fmt.Errorf("could not route this device: %w", err)
	}
	return sess, nil
}

// Disconnect tears the active session down, entirely off the calling
// goroutine. Safe to call with nothing connected (including mid-Connect, or
// twice in a row) - each is a harmless no-op past the first.
func (c *Controller) Disconnect() {
	go func() {
		c.mu.Lock()
		eng, cancel, sess := c.eng, c.cancel, c.sess
		c.eng, c.cancel, c.sess, c.state = nil, nil, nil, Disconnected
		// Any connect in flight is now stale and must not install its engine on top
		// of this: the user asked to be disconnected, and an attempt that finishes a
		// second later does not get to overrule them.
		c.gen++
		// Announced here — under the lock, and BEFORE the teardown below — rather
		// than after the engine is actually down. Both halves of that are load-bearing.
		//
		// Under the lock, because that is what stops a concurrent ICE event from
		// publishing Protected after this (publishLocked).
		//
		// Before the teardown, because Stop() is slow and must not run under the lock:
		// onEvent takes the same mutex, and the dying engine emits into it. Publishing
		// first is safe precisely because the state is already Disconnected: StateFor
		// only moves out of Protected/Blocked, so every event the engine emits on its
		// way down is inert by construction. Telling the user "disconnected" the
		// instant they asked, rather than when the last goroutine winds up, is also
		// simply the truth — the session is already unreachable.
		c.publishLocked(Disconnected)
		c.mu.Unlock()

		// Enforcement first, engine second (tunnel.Close's own order, and
		// ADR-0014's): the kill-switch is lifted and the routes come out
		// before the tunnel that was carrying traffic goes away. Reversed,
		// the machine spends the length of an engine teardown fail-closed
		// over a tunnel that is already gone — which is not a leak, but is
		// the user watching their network die for no reason they can see.
		if sess != nil {
			sess.Close()
		}
		if cancel != nil {
			cancel()
		}
		if eng != nil {
			eng.Stop()
		}
	}()
}

// onEvent is core.Config.OnEvent: called from whichever engine goroutine observed
// something (readLoop, the reconnect driver, pion's ICE callback, ...), never the
// goroutine that called Connect. See StateFor/DetailFor (state.go) for the pure
// decision logic this just applies and republishes.
//
// gen is the attempt whose engine emitted this, and an event from a stale one is
// DROPPED. Every attempt wires its own engine's OnEvent here, and a stale attempt's
// engine keeps running until it notices — Connect -> Disconnect -> Connect really does
// run two engines at once, briefly, and they both emit. Without this check a zombie's
// ICE ": closed", fired as it shuts down, moves the WINNER's state to Blocked, where
// it stays: the healthy engine has no reason to re-emit "connected", so no later event
// corrects it.
//
// It fails safe — a false Blocked over a live tunnel is the inverse of this app's
// defect, and it is not reachable over loopback, where a zombie always finishes before
// the winner starts. On a real network ICE timings swing enough to invert that, and
// "we could not make it happen locally" is not a guarantee.
func (c *Controller) onEvent(gen uint64, ev core.Event) {
	c.mu.Lock()
	if c.gen != gen {
		c.mu.Unlock()
		return
	}
	cur := c.state
	if next := StateFor(cur, ev); next != cur {
		c.state = next
		c.publishLocked(next)
	}
	c.mu.Unlock()

	// The detail line stays outside the lock: it is cosmetic prose, it makes no
	// safety claim, and a stale one costs a confusing sentence rather than a false
	// "you are protected".
	if d, show := DetailFor(ev, cur); show {
		c.notifyDetail(d)
	}
}

// abort ends a failed connect attempt: drop back to Disconnected and surface
// why. Never called once a session is up (past that point a drop is Blocked,
// not a failure - see onEvent/StateFor).
func (c *Controller) abort(gen uint64, err error) {
	c.abortWith(gen, Detail{Text: err.Error()})
}

// abortWith is abort for a failure this client itself diagnosed, where there is
// a fixed sentence to say rather than an error to relay — so it can be said in
// the user's own language (see DetailKind).
func (c *Controller) abortWith(gen uint64, d Detail) {
	// A stale attempt reports nothing and touches nothing. It lost a race it does not
	// know it was in — most concretely, it lost the bind on SocksAddr to the attempt
	// the user actually wants — and the state it would clear belongs to the winner.
	// Clearing it anyway is what orphans a live engine (see Controller.gen).
	c.mu.Lock()
	stale := c.gen != gen
	c.mu.Unlock()
	if stale {
		return
	}

	c.notifyDetail(d) // before the state, so the reason is on screen when it lands

	c.mu.Lock()
	// Re-checked: gen can move while the detail is being delivered, and the check
	// that matters is the one that guards the write.
	if c.gen == gen {
		// c.sess is nil here in every reachable path — abort is never called
		// once a session is up (see this function's doc), and enforcement is
		// installed in the same locked step as the engine. Cleared anyway so
		// the invariant is the code's, not a comment's.
		c.eng, c.cancel, c.sess, c.state = nil, nil, nil, Disconnected
		c.publishLocked(Disconnected)
	}
	c.mu.Unlock()
}

// publishLocked hands s to OnState. THE CALLER MUST HOLD c.mu, AND MUST STILL HOLD
// IT WHEN THIS RETURNS — that is the entire point, not an accident of where the
// call sits.
//
// Publishing outside the lock is a false-Protected bug, and this app's whole job is
// to not have one. Every mutator here used to set c.state under the lock and then
// publish after releasing it, which orders neither against the other: two goroutines
// could set A then B, and publish B then A, leaving the UI on A forever. That is not
// hypothetical — a reconnect (ADR-0030) fires ICE "connected" from a goroutine pion
// owns, which Engine.Stop's wg.Wait does not track, so it can be preempted between
// setting Protected and publishing it. The user presses Disconnect, the engine dies,
// Disconnected is published, and then the preempted goroutine publishes Protected on
// top of it. No further event can ever correct it, because the engine is gone. The
// band stays green on "you are protected" over a dead tunnel.
//
// Holding the lock across the callback makes the state change and its announcement
// one atomic step, so the last publish always carries the last state. A generation
// counter cannot do this: checking the counter and calling OnState are two steps, and
// a preemption between them reintroduces the same reorder.
//
// THE CONTRACT THIS REQUIRES: OnState must not block, and must not call back into
// Controller. main.go satisfies it — it wires OnState through fyne.Do, which queues
// onto Fyne's unbounded func channel and returns immediately, and its callback only
// assigns widget state. Never fyne.DoAndWait
// (that blocks until the UI goroutine runs the callback, and if the UI goroutine is
// itself inside a Connect/Disconnect button handler waiting on c.mu, that deadlocks).
// The Controller doc's "never from the caller's own stack" rule still holds: every
// publish happens on a goroutine Controller spawned.
func (c *Controller) publishLocked(s ConnState) {
	if c.OnState != nil {
		c.OnState(s)
	}
}

func (c *Controller) notifyDetail(d Detail) {
	if c.OnDetail != nil {
		c.OnDetail(d)
	}
}
