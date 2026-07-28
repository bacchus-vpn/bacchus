//go:build windows

// Bacchus Windows UI — tray client with exit picker, connection-strategy
// settings (settings.go, issue #75), and invite-QR display (invite.go, issue
// #32).
//
// Lists exits from the coordinator, lets you pick one, and Connect runs the
// core engine in-process (client role, forced through the TURN relay — see
// tunnel.go for why) and then routes the whole device through it: a wintun
// adapter + userspace netstack (tun2socks.go) replace the old browser-only
// PAC proxy.
//
// Build:  go mod tidy && go build -ldflags "-H=windowsgui" -o bacchus.exe .
// Needs:  bacchus.config.json alongside (see config.example.json), and
//
//	bacchus.exe.manifest alongside the built exe (Windows loads it
//	automatically; it's already in this directory, so building from here
//	is enough) — required for the settings/invite windows' Common
//	Controls v6 dependency (lxn/walk); see README.md's Build section and
//	ADR-0036. Must run
//
//	elevated (Administrator) — creating the TUN adapter and changing routes
//	both require it.
package main

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/getlantern/systray"
)

// socksAddr is the local SOCKS5 endpoint core.Engine.Connect runs; tun2socks
// dials it for every intercepted TCP flow and DNS query. Not sensitive.
const (
	socksAddr = "127.0.0.1:1080"
	maxExits  = 12
)

var (
	cfg     Config
	cfgPath string // where cfg was loaded from (loadConfig's 2nd return); saveConfig writes back here
)

// countryItem is one entry of the tray's country picker. A client picks a COUNTRY and
// the coordinator picks the exit inside it (issue #146, ADR-0042), so the picker offers
// places, not nodes; busy is the coordinator's own "nothing assignable here" (#147),
// shown rather than hidden so a full country is labelled instead of vanishing.
type countryItem struct {
	code      string
	exits     int
	available int
	busy      bool
}

// label renders one picker row.
func (c countryItem) label() string {
	if c.busy {
		return c.code + "  —  busy"
	}
	return fmt.Sprintf("%s  —  %d/%d available", c.code, c.available, c.exits)
}

var (
	mu           sync.Mutex
	engine       *core.Engine
	engineCancel context.CancelFunc
	activeTunnel *tunnel
	mStatus      *systray.MenuItem
	mSelected    *systray.MenuItem
	mConn        *systray.MenuItem
	mDisc        *systray.MenuItem
	exitSlots    []*systray.MenuItem
	slotCountry  []string // country code currently shown in each slot
	selectedID   string
	selectedLbl  string
)

func main() { systray.Run(onReady, onExit) }

func onReady() {
	if c, p, err := loadConfig(); err == nil {
		cfg = c
		cfgPath = p
	}
	// Undo any fail-closed lockdown left behind by a crashed prior session, so
	// the user isn't stuck offline after a hard exit.
	if !cfg.DisableKillSwitch {
		recoverKillSwitch()
	}
	systray.SetIcon(grapeIcon())
	systray.SetTitle("Bacchus")
	systray.SetTooltip("Bacchus VPN")

	mStatus = systray.AddMenuItem("Disconnected", "")
	mStatus.Disable()
	if len(cfg.Coordinators) == 0 {
		setStatus("No config — copy config.example.json to bacchus.config.json")
	}
	mSelected = systray.AddMenuItem("Exit: (none)", "")
	mSelected.Disable()
	systray.AddSeparator()
	mRefresh := systray.AddMenuItem("Refresh exits", "")

	slotCountry = make([]string, maxExits)
	for i := 0; i < maxExits; i++ {
		it := systray.AddMenuItem("", "")
		it.Hide()
		exitSlots = append(exitSlots, it)
		idx := i
		go func() {
			for range it.ClickedCh {
				selectExit(idx)
			}
		}()
	}
	systray.AddSeparator()
	mConn = systray.AddMenuItem("Connect", "")
	mDisc = systray.AddMenuItem("Disconnect", "")
	mDisc.Hide()
	systray.AddSeparator()
	mSettings := systray.AddMenuItem("Connection settings…", "")
	mInvite := systray.AddMenuItem("Show invite QR…", "")
	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Quit", "")

	go func() {
		for {
			select {
			case <-mRefresh.ClickedCh:
				go refreshExits()
			case <-mConn.ClickedCh:
				go connect()
			case <-mDisc.ClickedCh:
				disconnect()
			case <-mSettings.ClickedCh:
				go runOnUIThread(openSettingsDialog)
			case <-mInvite.ClickedCh:
				go runOnUIThread(openInviteDialog)
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}()

	refreshSelectedCountryLabel() // surface the selected country immediately, before the first refreshExits
	go refreshExits()
}

// uiWork feeds the one persistent UI worker goroutine (see uiWorkerLoop).
// Unbuffered: sending blocks the caller until the worker is free, which is
// exactly the serialization wanted — only one settings/invite window's
// worth of Win32 calls should ever be in flight at a time.
var (
	uiWork     = make(chan func())
	uiWorkOnce sync.Once
)

// runOnUIThread queues fn to run on the single persistent, OS-thread-locked
// UI worker (starting it on first use) and blocks until the worker picks it
// up. Callers wrap this in `go` (see the ClickedCh cases above) so the
// tray's own dispatch loop is never blocked by it.
//
// walk's Win32 windows are bound to whichever OS thread creates and pumps
// them, which is necessary but — confirmed by manually probing this, not
// just by Win32 folklore — not sufficient: lxn/walk only fully initializes
// its shared internal state (the dialog window class, common-controls setup)
// for the *first* thread that ever creates a walk window in the process. A
// second top-level Dialog created from a different locked thread
// reproducibly fails Win32 window creation, even though the identical
// dialog code succeeds every time when reused on the same locked thread. An
// earlier version of this code locked a fresh thread per dialog open, which
// worked for exactly one dialog per process lifetime and then silently
// broke on the second — see docs/design/client-connection-ui.md.
func runOnUIThread(fn func()) {
	uiWorkOnce.Do(func() { go uiWorkerLoop() })
	uiWork <- fn
}

func uiWorkerLoop() {
	runtime.LockOSThread()
	for fn := range uiWork {
		fn()
	}
}

func onExit() {
	disconnect()
	closeLog()
}

func setStatus(s string) {
	mStatus.SetTitle(s)
	systray.SetTooltip("Bacchus — " + s)
}

func selectExit(idx int) {
	mu.Lock()
	defer mu.Unlock()
	if slotCountry[idx] == "" {
		return
	}
	selectedID = slotCountry[idx]
	selectedLbl = slotCountry[idx]
	mSelected.SetTitle("Country: " + selectedLbl)
	for i, it := range exitSlots {
		if i == idx {
			it.Check()
		} else {
			it.Uncheck()
		}
	}
}

// shortLabel abbreviates a long id (an exit's 64-hex key) for display,
// mirroring core's own shortID (unexported, so not reusable directly here).
func shortLabel(id string) string {
	if len(id) <= 10 {
		return id
	}
	return id[:10] + "…"
}

// currentCountryLabel resolves the country connect() should ask for, and its label.
//
// There is no manual-pin precedence any more: naming an exact exit was removed for
// everyone (issue #146, ADR-0042), so the picker's country is the only input. A
// persisted cfg.ExitID from an older settings file is ignored — connect() says so out
// loud rather than letting a user believe a pin is still in force.
func currentCountryLabel() (code, lbl string) {
	mu.Lock()
	defer mu.Unlock()
	return selectedID, selectedLbl
}

// refreshSelectedCountryLabel updates the tray's "Country: …" line to match
// currentCountryLabel — called at startup and after the settings window saves (issue
// #75), so a change is visible right away rather than waiting on the next picker
// interaction.
func refreshSelectedCountryLabel() {
	_, lbl := currentCountryLabel()
	if lbl == "" {
		lbl = "(none)"
	}
	mSelected.SetTitle("Country: " + lbl)
}

func refreshExits() {
	countries := listCountries()
	mu.Lock()
	defer mu.Unlock()
	for i := 0; i < maxExits; i++ {
		if i < len(countries) {
			slotCountry[i] = countries[i].code
			exitSlots[i].SetTitle(countries[i].label())
			exitSlots[i].Show()
		} else {
			slotCountry[i] = ""
			exitSlots[i].Hide()
		}
	}
	if selectedID == "" && len(countries) > 0 { // auto-select the first assignable one
		pick := countries[0]
		for _, c := range countries {
			if !c.busy {
				pick = c
				break
			}
		}
		selectedID, selectedLbl = pick.code, pick.code
		mSelected.SetTitle("Country: " + selectedLbl)
		exitSlots[0].Check()
	}
}

// listCountries asks the coordinator which countries it will assign exits in, via a
// throwaway client-role engine (no SOCKS listener — just the list handshake).
func listCountries() []countryItem {
	// Snapshot cfg under mu: the "Connection settings" Save handler
	// (settings.go) writes the cfg global concurrently, and this runs on the
	// refreshExits goroutine, so an unlocked read would race that write.
	mu.Lock()
	snap := cfg
	mu.Unlock()
	if len(snap.Coordinators) == 0 {
		return nil
	}
	eng, err := core.New(core.Config{
		Coordinators:     snap.Coordinators,
		Roles:            []string{core.RoleClient},
		OnEvent:          onListEvent,
		AdmissionPubKey:  snap.AdmissionPubKey,
		AdmissionCRLPath: snap.AdmissionCRLPath,
	})
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		return nil
	}
	defer eng.Stop()

	countries, err := eng.ListCountries(ctx, 5*time.Second)
	if err != nil {
		return nil
	}
	out := make([]countryItem, 0, len(countries))
	for _, c := range countries {
		out = append(out, countryItem{code: c.Country, exits: c.Exits, available: c.Available, busy: c.Busy})
	}
	return out
}

func connect() {
	mu.Lock()
	if engine != nil {
		mu.Unlock()
		return
	}
	mu.Unlock()
	country, lbl := currentCountryLabel()
	if country == "" {
		setStatus("Pick a country first")
		return
	}

	setStatus("Connecting…")
	mConn.Hide()
	mDisc.Show()

	// Snapshot the whole cfg under mu once: the "Connection settings" Save
	// handler (settings.go) writes the cfg global concurrently, so every field
	// this connect reads must come from a single locked snapshot, not repeated
	// unlocked reads that could race — and, once Save can edit an endpoint
	// field, tear a slice header — mid-connect.
	mu.Lock()
	snap := cfg
	mu.Unlock()
	poolOrder := sanitizePoolOrder(snap.TransportPool)
	// A stale settings file may still carry an exit pin. It does nothing — naming an
	// exact exit was removed for everyone (issue #146, ADR-0042) — and saying so is
	// the point: a pin that is silently ignored leaves the user believing their
	// traffic leaves through one specific node when the coordinator is choosing.
	if snap.ExitID != "" {
		logLine("the saved exit pin %s is ignored: choosing a specific exit was removed (issue #146) — the coordinator picks the exit inside the country you select", shortLabel(snap.ExitID))
	}
	// The pool is always available now. It used to be switched off for a pinned
	// connect, because a pin and cross-exit selection contradict each other; with no
	// pin there is nothing to contradict.
	pool := poolOrder
	var selectionDir string
	if len(pool) > 0 {
		selectionDir = defaultSelectionDir()
	}

	// poolExcluder keeps the pool's dynamically-dialled reality underlay
	// addresses excluded from the full-device tunnel (issue #109). Wired as
	// OnUnderlayDial below so the excluder learns each address on the dial path,
	// before its connection is opened; startTunnel activates it (poolroutes.go).
	// Always created even when the pool is off or webrtc-only — it stays inert
	// (no reality dial ever calls reserve), which keeps startTunnel's signature
	// unconditional.
	pe := newPoolExcluder()

	// Named rather than inlined into core.New: a mid-session mesh-walk
	// recovery (issue #122, mirroring cmd/node's runNode in courier.go)
	// rebuilds the engine from this same config with only
	// Coordinators/MeshProof replaced (rebuildRecoveryConfig), so
	// watchMeshRecovery needs it to survive past this one construction.
	engCfg := core.Config{
		Coordinators: snap.Coordinators,
		Roles:        []string{core.RoleClient},
		SocksAddr:    socksAddr,
		// The country the user picked is the whole of what a connect names.
		Geo:           country,
		TransportPool: pool,
		SelectionDir:  selectionDir,
		STUNURL:       snap.STUN,
		TURNURL:       snap.TURN,
		TURNUser:      snap.TURNUser,
		TURNPass:      snap.TURNPass,
		// Full-device routing needs each session's underlay endpoint excluded
		// from the tunnel's default route before that route flips (see
		// tunnel.go). ForceRelay pins every WebRTC candidate to the one
		// configured TURN server — a fixed, already-excluded address —
		// regardless of which candidate.Mode the ladder picks, so a "direct"
		// P2P path's post-ICE address never races the route setup. Reality's
		// exit address isn't known until Dial time and so can't be pinned this
		// way; it is excluded late instead, via OnUnderlayDial (issue #109),
		// which is what now lets reality ride this client's pool at all.
		ForceRelay:     true,
		OnUnderlayDial: pe.reserve,
		OnEvent:        onEngineEvent(lbl),
		// Exit admission (issue #116): both no-ops (fail-open, pre-#116
		// behavior) when left unconfigured in Settings.
		AdmissionPubKey:  snap.AdmissionPubKey,
		AdmissionCRLPath: snap.AdmissionCRLPath,
		// Mesh-walk recovery (issue #115/#122): MeshPeers/MeshProof/MeshPubKey
		// are left unset — this client has no settings UI for them yet — so
		// Engine.meshRecoveryConfigured() stays false and NeedsRecovery() can
		// never fire. watchMeshRecovery below is wired unconditionally
		// anyway, so the day a future issue adds that UI, recovery works with
		// no further change here.
	}

	eng, err := core.New(engCfg)
	if err != nil {
		setStatus("Error: " + err.Error())
		mDisc.Hide()
		mConn.Show()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		cancel()
		setStatus("Error: " + err.Error())
		mDisc.Hide()
		mConn.Show()
		return
	}

	mu.Lock()
	engine = eng
	engineCancel = cancel
	mu.Unlock()

	if err := eng.Connect(ctx); err != nil {
		mu.Lock()
		stillActive := engine == eng
		mu.Unlock()
		if stillActive {
			setStatus("Failed to connect")
			disconnect()
		}
		return
	}

	// Mid-session mesh-walk recovery (issue #122): watch for the whole rest of
	// this session, not just the initial connect above — see
	// watchMeshRecovery's doc comment for why this is safe to start
	// unconditionally.
	go watchMeshRecovery(ctx, eng, engCfg, lbl)

	setStatus("Bringing up tunnel…")
	dns := snap.DNS
	if dns == "" {
		dns = defaultDNSUpstream
	}
	policy := newBypassPolicy(snap.BypassMode, snap.Bypass)
	t, err := startTunnel(snap.Coordinators, snap.STUN, snap.TURN, dns, socksAddr, policy, pe, !snap.DisableKillSwitch)
	if err != nil {
		mu.Lock()
		stillActive := engine == eng
		mu.Unlock()
		if stillActive {
			setStatus("Error: " + err.Error())
			disconnect()
		}
		return
	}

	mu.Lock()
	stillActive := engine == eng
	if stillActive {
		activeTunnel = t
	}
	mu.Unlock()
	if !stillActive {
		t.Close() // disconnected while the tunnel was coming up
		return
	}
	setStatus("Protected — " + lbl)
}

// rebuildRecoveryConfig returns base with only Coordinators and MeshProof
// replaced by a mid-session mesh-walk's rediscovered directory and fresher
// proof (issue #115/#122) — every other setting (ExitID, the transport pool,
// admission, OnUnderlayDial, the event sink, …) carries forward unchanged
// across a recovery rebuild, exactly as cmd/node's runNode carries its cfg
// forward across attempts. Pure and independent of any running engine, so
// it's testable without one (see main_test.go).
func rebuildRecoveryConfig(base core.Config, coordinators []string, proof []byte) core.Config {
	base.Coordinators = coordinators
	base.MeshProof = proof
	return base
}

// watchMeshRecovery runs for the lifetime of one connect() session, mirroring
// cmd/node's runNode supervisor loop (courier.go) so a mid-session
// all-coordinators-down event self-heals on Windows too (issue #122,
// ADR-0037's #115 update) — the same shape #116 already used to bring this
// client up to the node's CRL posture, just for recovery instead of
// revocation. It watches eng.NeedsRecovery() and, when a mesh-walk has
// rediscovered a live directory, stops eng and rebuilds against it
// (rebuildRecoveryConfig); base is the core.Config the watched engine was
// built from.
//
// Inert today: Windows never sets base.MeshPeers (no settings UI for it
// yet), so Engine.meshRecoveryConfigured() stays false and NeedsRecovery()
// can never close — this loop just sits on a channel that never fires,
// exactly as if it weren't here. It does not touch, and cannot regress, the
// ADR-0030 auto-reconnect loop living inside core.Engine itself: that keeps
// retrying a dropped path on its own, independent of this watcher, for as
// long as no mesh-walk directory is available to escalate to (ADR-0037's
// #115 update, "ADR-0030 is preserved, deliberately").
func watchMeshRecovery(ctx context.Context, eng *core.Engine, base core.Config, lbl string) {
	for {
		select {
		case <-eng.Done():
			return // engine stopped — a normal disconnect, or an unrecoverable failure elsewhere
		case <-eng.NeedsRecovery():
		}

		fresh, freshProof := eng.RecoveredDirectory()
		// Stop the old engine first (mirrors runNode): it frees the SOCKS
		// listener and drains its goroutines, so the rebuild below binds the
		// same address cleanly with no double-connect (ADR-0037: "no strand,
		// no double-connect").
		eng.Stop()

		mu.Lock()
		stillActive := engine == eng
		mu.Unlock()
		if !stillActive {
			return // disconnected concurrently with the recovery signal
		}

		next, err := core.New(rebuildRecoveryConfig(base, fresh, freshProof))
		if err != nil {
			abortMeshRecovery(eng, "Error: "+err.Error())
			return
		}
		if err := next.Start(ctx); err != nil {
			abortMeshRecovery(eng, "Error: "+err.Error())
			return
		}
		if err := next.Connect(ctx); err != nil {
			next.Stop()
			abortMeshRecovery(eng, "Failed to reconnect after mesh-walk recovery")
			return
		}

		mu.Lock()
		stillActive = engine == eng
		if stillActive {
			engine = next
		}
		mu.Unlock()
		if !stillActive {
			next.Stop() // disconnected while the rebuild was in flight
			return
		}
		logEvent(core.Event{Kind: core.EventInfo, Message: "mesh-walk: mid-session recovery rebuilt the engine (issue #115/#122)"})
		setStatus("Protected — " + lbl)
		eng = next // keep watching: a long session may recover more than once
	}
}

// abortMeshRecovery tears the session down when a mid-session mesh-walk
// rebuild (watchMeshRecovery) fails partway through — stopped is the engine
// watchMeshRecovery already stopped, now unrecoverable, so this mirrors
// connect()'s own failure handling (setStatus + disconnect()) rather than
// leaving the tray showing a stale "Protected" over a session that no longer
// exists. A no-op if the user disconnected concurrently — disconnect() has
// already torn everything down and replaced engine, so stopped no longer
// matches it.
func abortMeshRecovery(stopped *core.Engine, msg string) {
	mu.Lock()
	stillActive := engine == stopped
	mu.Unlock()
	if stillActive {
		setStatus(msg)
		disconnect()
	}
}

// eventStatus decides whether ev should update the live systray status line
// and, if so, with what text — given lbl (the exit label captured at connect
// time) and protected (whether a tunnel session is currently up). It has no
// side effects, so the routing decision is testable without a running
// systray (see main_test.go); onEngineEvent/onListEvent apply the result.
//
// EventError always surfaces: none of today's client-role error sources (a
// dial failure, a coordinator-rejected version handshake — see #8) fire once
// a session is protected, so there is no live "Protected" text an error
// could clobber. EventInfo narrates the connect attempt itself ("direct
// failed -> trying relay") and only shows pre-protected, for the same reason
// ICE only shows post-protected below: exactly one narrative owns the status
// line at a time — before the tunnel is up, connect() (and the info events
// alongside it) drive that line; once it's up, ICE state does. EventSession
// and EventConnected are deliberately never shown here — a session id is
// plumbing detail, and EventConnected's moment is already covered a beat
// later by connect()'s own "Bringing up tunnel…" — but every event still
// reaches logEvent regardless, for a complete history.
func eventStatus(ev core.Event, lbl string, protected bool) (text string, show bool) {
	switch ev.Kind {
	case core.EventError:
		return "Error: " + ev.Message, true
	case core.EventInfo:
		if protected {
			return "", false
		}
		return ev.Message, true
	case core.EventICE:
		if !protected {
			return "", false
		}
		switch {
		case strings.Contains(ev.Message, ": disconnected"), strings.Contains(ev.Message, ": failed"), strings.Contains(ev.Message, ": closed"):
			return "Blocked — tunnel down (" + lbl + ")", true
		case strings.Contains(ev.Message, ": connected"), strings.Contains(ev.Message, ": completed"):
			return "Protected — " + lbl, true
		}
		return "", false
	default: // EventSession, EventConnected: logged, never shown live
		return "", false
	}
}

// onEngineEvent turns the connect-flow engine's events into UI state: every
// event is appended to the log file (logEvent), and eventStatus decides
// whether it also updates the live status line. lbl is the human-readable
// exit label captured at connect time.
func onEngineEvent(lbl string) func(core.Event) {
	return func(ev core.Event) {
		logEvent(ev)
		mu.Lock()
		protected := activeTunnel != nil
		mu.Unlock()
		if text, show := eventStatus(ev, lbl, protected); show {
			setStatus(text)
		}
	}
}

// onListEvent handles events from a throwaway list engine (listCountries):
// there is no tunnel session for it to conflict with, so it always applies
// the pre-connect status rules — in practice that only ever means "surface
// an error" (a rejected handshake, most notably), since ListExits never
// drives ICE or the direct/relay fallback that produces EventInfo today.
func onListEvent(ev core.Event) {
	logEvent(ev)
	if text, show := eventStatus(ev, "", false); show {
		setStatus(text)
	}
}

func disconnect() {
	mu.Lock()
	eng, cancel, t := engine, engineCancel, activeTunnel
	engine, engineCancel, activeTunnel = nil, nil, nil
	mu.Unlock()

	if t != nil {
		t.Close()
	}
	if eng != nil {
		if cancel != nil {
			cancel()
		}
		eng.Stop()
	}
	setStatus("Disconnected")
	mDisc.Hide()
	mConn.Show()
}
