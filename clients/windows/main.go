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
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
	liveCountry  string // country code the current engine is actually built against; "" when disconnected (issue #137)
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
	mSelected = systray.AddMenuItem("Country: (none)", "")
	mSelected.Disable()
	systray.AddSeparator()
	mRefresh := systray.AddMenuItem("Refresh countries", "")

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

	seedCountryFromConfig()       // a persisted country preference is the picker's starting selection
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

// setStatus is a no-op before onReady has set mStatus up: getlantern/
// systray's package-level SetTooltip dereferences internal state that only
// exists once systray.Run has actually started (confirmed by reading
// systray_windows.go — it is not a benign nil-receiver no-op, it panics),
// so any call reaching here before then must not proceed. That can only
// happen from a test driving connect()/watchMeshRecovery()/switchCountry()
// directly without going through onReady() (issue #129's supervisor-level
// recovery test) — never in the real app, since nothing can trigger a
// connect before the tray it dispatches from exists.
//
// The text is recorded in lastStatus before that guard, so what the client
// currently *claims* to the user is readable independently of whether a tray
// exists to render it.
func setStatus(s string) {
	statusMu.Lock()
	lastStatus = s
	statusMu.Unlock()
	if mStatus == nil {
		return
	}
	mStatus.SetTitle(s)
	systray.SetTooltip("Bacchus — " + s)
}

// lastStatus is the most recent text handed to setStatus: the claim the tray
// is making to the user right now. Kept under its own leaf mutex rather than
// mu — setStatus is called from paths that have just released mu (connect,
// switchCountry, disconnect, onEngineEvent) and from paths that never take it,
// so folding it into mu would add a re-entrancy hazard for no benefit.
//
// "Protected" here while the full-device tunnel is down is the exact
// belief-safety failure ADR-0039 names, so the supervisor tests assert on it
// directly (currentStatus) rather than inferring it from engine/activeTunnel.
var (
	statusMu   sync.Mutex
	lastStatus string
)

// currentStatus returns the text setStatus last published.
func currentStatus() string {
	statusMu.Lock()
	defer statusMu.Unlock()
	return lastStatus
}

// trayHide and trayShow are nil-safe wrappers around a *systray.MenuItem's
// Hide/Show, for the same reason setStatus guards mStatus above: mConn/
// mDisc are nil until onReady has run, and connect()/disconnect()/
// switchCountry() are exercised directly (no onReady) by issue #129's
// supervisor-level recovery test.
func trayHide(item *systray.MenuItem) {
	if item != nil {
		item.Hide()
	}
}

func trayShow(item *systray.MenuItem) {
	if item != nil {
		item.Show()
	}
}

func selectExit(idx int) {
	mu.Lock()
	if slotCountry[idx] == "" {
		mu.Unlock()
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
	// Released explicitly rather than deferred: requestCountrySwitch reaches
	// switchCountry, which takes mu itself, so this must not still be held.
	mu.Unlock()

	// If a session is already live, switch it to the newly-picked country
	// instead of waiting for a manual Disconnect + Connect (issue #137). A
	// no-op pre-connect, or when idx is already the live country — see
	// switchCountry, which reads the selection just stored above rather than
	// being handed a copy of it.
	requestCountrySwitch()
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

// seedCountryFromConfig copies a persisted country preference (Config.Geo) into
// the tray picker's selection, so a returning user connects to the country they
// chose last time instead of whichever one the coordinator happens to list first.
//
// Seeding rather than reading Geo at connect time is what keeps ONE authority for
// the live country. Both the Settings geo box and the tray picker feed the same
// core.Config.Geo after country-only assignment (issue #146, ADR-0042); if
// connect() consulted both, one of them would silently lose, and a setting that
// quietly does nothing is the exact failure this client keeps being reviewed for.
// Instead the preference flows one way — config seeds picker, picker decides — and
// the Settings Save handler re-seeds it (settings.go), so changing the box is
// immediately visible in the tray.
//
// Only seeds an empty selection: it runs once at startup, before any picker
// interaction, so it can never overwrite a live user choice.
func seedCountryFromConfig() {
	mu.Lock()
	defer mu.Unlock()
	if selectedID != "" || cfg.Geo == "" {
		return
	}
	selectedID, selectedLbl = cfg.Geo, cfg.Geo
}

// adoptCountryPreference applies a country saved from the Settings window: it
// becomes the picker's selection and, if a session is live, the country that
// session switches to.
//
// Unconditional where seedCountryFromConfig is not, and for the opposite reason
// — saving Settings is a deliberate act, so it outranks an earlier tray click,
// whereas the startup seed must never overwrite one.
//
// code == "" is the "(any)" sentinel: no preference, so the picker keeps
// whatever it has (refreshExits' auto-select fills it in when it is still
// empty) and no switch is requested.
func adoptCountryPreference(code string) {
	if code == "" {
		return
	}
	mu.Lock()
	changed := selectedID != code
	selectedID, selectedLbl = code, code
	for i, it := range exitSlots {
		if i < len(slotCountry) && slotCountry[i] == code {
			it.Check()
		} else {
			it.Uncheck()
		}
	}
	mu.Unlock()
	if changed {
		requestCountrySwitch()
	}
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

// meshRecoveryFields resolves snap's mesh-walk recovery settings (issue
// #129) into the three core.Config fields they map to: reads
// MeshProofPath's file and hex-decodes MeshPubKey, mirroring cmd/node's own
// loadMeshRecovery validation (courier.go) — including matching error
// wording for the partial-triad case (meshConfigErr, settings.go) — so the
// two surfaces never disagree about what's valid.
//
// connect() and switchCountry() both call this: a live country switch must
// carry mesh recovery forward exactly like rebuildRecoveryConfig already does
// for a recovery-triggered rebuild, or switching country would silently and
// permanently turn recovery off for the rest of the session.
//
// Returns zero values with no error when recovery is unconfigured (all
// three settings fields blank) — core.Engine's own meshRecoveryConfigured
// then naturally stays false, exactly the pre-#129 state. Settings.go's
// validateMeshConfig already catches a half-configured triad and an invalid
// pubkey hex before either can be saved; this additionally reads
// proofPath's file — so a since-moved, deleted or truncated proof file
// surfaces as an error here, at connect/switch time, not silently.
//
// The empty-proof guard is not decoration: core.Engine's
// meshRecoveryConfigured requires len(MeshProof) > 0, so a zero-byte file
// (a truncated download, or a coldstart-bootstrap -cache run that created
// the file but never wrote it) would otherwise pass every check here and
// leave recovery off for the whole session, announced only by one EventInfo
// that the next event overwrites. cmd/node rejects exactly this
// (loadMeshRecovery's "-mesh-proof %s is empty"), and both surfaces have to
// agree about what "configured" means.
//
// Path and hex are trimmed on the way in, not only on the way out of the
// Settings dialog: cmd/node hex-decodes strings.TrimSpace(pubkeyHex), and a
// hand-edited config.json with a trailing space would otherwise fail closed
// at connect time behind a misleading "must be a 32-byte ed25519 public key
// in hex".
func meshRecoveryFields(snap Config) (peers []string, proof []byte, pubKey ed25519.PublicKey, err error) {
	proofPath := strings.TrimSpace(snap.MeshProofPath)
	pubKeyHex := strings.TrimSpace(snap.MeshPubKey)
	if len(snap.MeshPeers) == 0 && proofPath == "" && pubKeyHex == "" {
		return nil, nil, nil, nil
	}
	if len(snap.MeshPeers) == 0 || proofPath == "" || pubKeyHex == "" {
		return nil, nil, nil, meshConfigErr
	}
	proof, err = os.ReadFile(proofPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read mesh-recovery proof %s: %w", proofPath, err)
	}
	if len(proof) == 0 {
		return nil, nil, nil, fmt.Errorf("mesh-recovery proof %s is empty", proofPath)
	}
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, nil, nil, fmt.Errorf("mesh-recovery public key must be a %d-byte ed25519 public key in hex", ed25519.PublicKeySize)
	}
	return snap.MeshPeers, proof, ed25519.PublicKey(pub), nil
}

// clientEngineConfig assembles the core.Config for one client session from a
// settings snapshot and the country that session should egress in. Both entry
// points that build a client engine go through it — the initial connect() and a
// live country switch (switchCountry) — so the two cannot describe a session
// differently.
//
// That is the whole point of it existing rather than each caller writing the
// literal out. Issue #137's first version copied the field list and left out
// Geo/TransportPool/SelectionDir, which is not a cosmetic omission: an empty
// TransportPool routes the engine down core's single-transport path
// (serveReconnectSocks) instead of the pooled one (bindPoolSocks), so the
// switched session lost the transport ladder, reality's TCP:443 camouflage and
// the learned-path store. On a network where UDP is blocked and reality was the
// only thing carrying the session, changing country meant leaving the VPN.
//
// # Geo is what narrows the ladder, and ExitID never did
//
// country goes to Geo, and ExitID is never set — not even to the exit the
// session happens to be on. That is load-bearing, and an earlier version of this
// function got it exactly backwards: it set ExitID and justified doing so with
// "poolExits returns exactly the configured id as the only candidate". Core has
// never worked that way. ExitID is accepted-and-ignored since country-only
// assignment (issue #146, ADR-0042) and core.New emits an EventError when a
// client sets it, so setting it here would put a permanent "this setting has NO
// EFFECT" error in the user's log on every single connect.
//
// Geo does the narrowing instead, and does it properly. The ladder is built by
// selection.Ladder, whose first act is inScope(countries, geo): with geo set it
// keeps only the matching country, so every candidate raced belongs to the
// country asked for, across all four transport tiers. The learned-path store
// cannot smuggle the previous country back in either — Store.Best is keyed on
// (network, geo) and Store.RTT on (network, country), so a winner recorded for
// one country is invisible to a lookup for another. That is why a switch under
// the pool really switches: the pool is kept for the ladder, and the country
// bound is enforced inside it rather than alongside it.
//
// The mesh-recovery triad is resolved here (rather than left for core.New to
// reject) so a since-moved proof file or a hand-edited config's bad pubkey
// hex surfaces as a clear error at connect/switch time, the same way the
// admission fields' construction error already does.
//
// Pure apart from reading the mesh proof off disk, so the composition is
// testable without an engine (see main_test.go).
func clientEngineConfig(snap Config, country string, onUnderlayDial func(string), onEvent func(core.Event)) (core.Config, error) {
	pool := sanitizePoolOrder(snap.TransportPool)
	var selectionDir string
	if len(pool) > 0 {
		selectionDir = defaultSelectionDir()
	}
	meshPeers, meshProof, meshPubKey, err := meshRecoveryFields(snap)
	if err != nil {
		return core.Config{}, err
	}
	return core.Config{
		Coordinators: snap.Coordinators,
		Roles:        []string{core.RoleClient},
		SocksAddr:    socksAddr,
		// The country the user picked is the whole of what a connect names; see
		// the ExitID note above for why that field stays zero.
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
		OnUnderlayDial: onUnderlayDial,
		OnEvent:        onEvent,
		// Exit admission (issue #116): both no-ops (fail-open, pre-#116
		// behavior) when left unconfigured in Settings.
		AdmissionPubKey:  snap.AdmissionPubKey,
		AdmissionCRLPath: snap.AdmissionCRLPath,
		// Mesh-walk recovery (issue #115/#122/#129): unset (all three zero
		// values) when the Settings triad is blank, in which case
		// Engine.meshRecoveryConfigured() stays false and NeedsRecovery()
		// can never fire — watchMeshRecovery is wired unconditionally either
		// way.
		MeshPeers:  meshPeers,
		MeshProof:  meshProof,
		MeshPubKey: meshPubKey,
	}, nil
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
	trayHide(mConn)
	trayShow(mDisc)

	// Snapshot the whole cfg under mu once: the "Connection settings" Save
	// handler (settings.go) writes the cfg global concurrently, so every field
	// this connect reads must come from a single locked snapshot, not repeated
	// unlocked reads that could race — and, once Save can edit an endpoint
	// field, tear a slice header — mid-connect.
	mu.Lock()
	snap := cfg
	mu.Unlock()
	// A stale settings file may still carry an exit pin. It does nothing — naming an
	// exact exit was removed for everyone (issue #146, ADR-0042) — and saying so is
	// the point: a pin that is silently ignored leaves the user believing their
	// traffic leaves through one specific node when the coordinator is choosing.
	if snap.ExitID != "" {
		logLine("the saved exit pin %s is ignored: choosing a specific exit was removed (issue #146) — the coordinator picks the exit inside the country you select", shortLabel(snap.ExitID))
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
	engCfg, err := clientEngineConfig(snap, country, pe.reserve, onEngineEvent(lbl))
	if err != nil {
		setStatus("Error: " + err.Error())
		trayHide(mDisc)
		trayShow(mConn)
		return
	}

	eng, err := newCoreEngine(engCfg)
	if err != nil {
		setStatus("Error: " + err.Error())
		trayHide(mDisc)
		trayShow(mConn)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.Start(ctx); err != nil {
		cancel()
		setStatus("Error: " + err.Error())
		trayHide(mDisc)
		trayShow(mConn)
		return
	}

	// Publish only if nothing else claimed the session while this connect was
	// building one. The engine != nil check at the top of this function is a
	// cheap early-out, not the guard: the tray dispatches `go connect()` per
	// click and hides mConn only AFTER that check, so two rapid clicks both pass
	// it and then spend seconds apiece in core.New/Start.
	//
	// Assigning unconditionally here is the same check-then-act shape adoptEngine
	// exists to eliminate, and it fails the same way: the loser's disconnect()
	// clears the globals, the winner then sees engine != its own, closes its
	// tunnel and returns — leaving a live engine untracked and still holding
	// socksAddr, so every later Connect fails to bind for the life of the
	// process. Passing nil as `old` says "expect no session"; adoptEngine stops
	// this engine itself when that turns out to be false.
	if !adoptEngine(nil, eng, cancel, country) {
		cancel()
		// Deliberately no tray or status change: the connect that won owns both,
		// and "Connect"/"Disconnected" published from here would describe this
		// discarded attempt over the top of a session that is coming up fine.
		return
	}

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

// countrySwitchCh is issue #137's debounce mailbox: capacity 1, carrying no
// value — a bare "the selection changed, catch up" wakeup. A burst of tray
// clicks therefore collapses into at most one pending wakeup, and
// switchCountryLoop (started once, lazily) applies them one at a time: a switch
// already running when a new click lands finishes normally, then immediately
// re-reads the selection, rather than stacking a reconnect per click.
//
// The channel deliberately does NOT carry the chosen country. selectedID (under
// mu) is already the one authority for what the user picked, and switchCountry
// reads it at apply time, so the tray's checkmark and the country the session
// switches to cannot disagree — see signalSwitch for the bug that shape had.
var (
	countrySwitchCh   = make(chan struct{}, 1)
	countrySwitchOnce sync.Once
)

// requestCountrySwitch asks the live session, if any, to catch up with the
// picker's current selection (issue #137). Safe to call whether or not a
// session is connected, and safe to call repeatedly in quick succession —
// switchCountry itself is the no-op/staleness authority, this is purely the
// debounce.
func requestCountrySwitch() {
	countrySwitchOnce.Do(func() { go switchCountryLoop() })
	signalSwitch(countrySwitchCh)
}

// signalSwitch pokes ch (capacity 1) without ever blocking: if a wakeup is
// already pending, this one is redundant and dropped, because the waiter will
// read the selection fresh anyway. Split out from requestCountrySwitch so the
// coalescing itself is testable without a live switchCountryLoop or engine
// (see main_test.go).
//
// A non-blocking send with no drain is all that is needed, and that is a
// consequence of ch carrying no payload. An earlier version queued the
// requested country as a value, which forced a drain-then-send pair to keep
// the newest — and two tray-slot goroutines (one per slot, see onReady)
// interleaving on that pair could leave the OLDER request in the channel, so
// the tray showed one country checked while the session switched to another.
// Carrying no value removes the ordering question rather than answering it.
func signalSwitch(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default: // already pending — one wakeup is enough
	}
}

func switchCountryLoop() {
	for range countrySwitchCh {
		switchCountry()
	}
}

// switchCountry rebuilds the live engine against a newly-selected country
// (issue #137) without touching the full-device tunnel at all — the wintun
// adapter, routes, and kill-switch all stay exactly as startTunnel left
// them, armed the whole time. This is safe, not just convenient: tun2socks
// dials the fixed local socksAddr per-flow rather than holding a persistent
// connection to it (tun2socks.go), so as long as *some* engine is
// listening there by the time a flow needs it, the tunnel layer above
// never has to know which exit is underneath it. A flow that arrives in
// the gap between the old engine stopping and the new one's SOCKS listener
// coming up simply fails to dial — the same fail-closed "Blocked" the
// kill-switch already guarantees for any other transient drop, never a
// leak to the physical interface.
//
// A country, not an exit: country-only assignment (issue #146, ADR-0042)
// removed exact-exit pinning for everyone, so the only thing a user can change
// mid-session is which country they egress in. The coordinator picks the exit
// inside it, on this switch exactly as on the initial connect.
//
// engCfg is built from the same snapshot fields connect() uses, pool and
// selection directory included. Those are not optional decoration: an empty
// TransportPool sends the rebuilt engine down core's single-transport path
// (serveReconnectSocks) instead of the pooled one (bindPoolSocks), dropping
// the ladder, reality's TCP:443 camouflage and the learned-path store. On a
// network where UDP is blocked and reality was the only thing carrying the
// session, that turns "switch country" into "leave the VPN".
//
// The target country is read here, not passed in: the picker's selection is the
// single authority for it (see countrySwitchCh).
//
// A no-op unless a session is fully up: engine and activeTunnel both set, and
// the selection not already the live country. Requiring the tunnel is what
// makes "without touching the tunnel" true — during connect()'s own bring-up
// window the tunnel does not exist yet and connect() is still about to install
// one, so switching underneath it would race a startTunnel this function cannot
// see. A click in that window falls through to the normal path: the selection
// is already stored, so the next Connect uses it.
//
// On failure, ends the session exactly as a failed connect() would
// (abortSession) rather than trying to resurrect the country that was just torn
// down — the same "worst case: Blocked" the issue accepts, never a silent
// fall-back to a country the user no longer has selected.
func switchCountry() {
	mu.Lock()
	// engineCancel is deliberately NOT snapshotted here: retiring the replaced
	// context is adoptEngine's job, from the value live at the swap.
	old, t := engine, activeTunnel
	code, lbl := selectedID, selectedLbl
	sameCountry := code == liveCountry
	mu.Unlock()
	if old == nil || t == nil || code == "" || sameCountry {
		return
	}

	setStatus("Switching to " + lbl + "…")

	mu.Lock()
	snap := cfg
	mu.Unlock()

	// The live tunnel's own excluder, never a fresh one: exclusion routes and
	// kill-switch allow entries only get installed once goLive/armAllowlist
	// have run against a running tunnel (poolroutes.go), and only the
	// excluder the tunnel holds gets reaped by tunnel.Close(). A newly minted
	// one would sit at routesLive=false/armed=false forever — reserve()
	// silently installing nothing — so the new engine's reality underlay
	// address would never be carved out of the tunnel it is riding under.
	// startTunnel always stores the excluder connect() hands it, so this is
	// non-nil for any tunnel this client built; guarded anyway, exactly as
	// tunnel.Close() guards the same field, and core treats an unset
	// OnUnderlayDial as "nothing to exclude" (cmd/node never sets one).
	var onUnderlayDial func(string)
	if t.excluder != nil {
		onUnderlayDial = t.excluder.reserve
	}

	// The rebuilt engine's events are logged from the moment it is built, but
	// kept off the tray until the swap actually lands. Until then this engine
	// is a candidate, not the session: the status line belongs to
	// "Switching to <exit>…", and core emits its transport/fingerprint notice
	// from inside Start. Without the gate those notices overwrite that line
	// mid-switch, and — if the swap is then lost to a concurrent disconnect —
	// a transport diagnostic from a discarded engine becomes the last thing
	// the user is told, on top of the "Disconnected" that was true.
	var adopted atomic.Bool
	sink := onEngineEvent(lbl)
	engCfg, err := clientEngineConfig(snap, code, onUnderlayDial, func(ev core.Event) {
		if adopted.Load() {
			sink(ev)
			return
		}
		logEvent(ev)
	})
	if err != nil {
		setStatus("Country switch failed: " + err.Error())
		return // old engine/tunnel untouched — still connected, just not switched
	}

	// Stopping the old engine frees the SOCKS listener the replacement has to
	// bind, same reasoning as watchMeshRecovery's rebuild.
	//
	// Its context is NOT cancelled here, deliberately. The replacement runs on
	// its own, so the old one does have to be retired — but only once this
	// switch has actually won the session, and only from the value that is live
	// at that moment. adoptEngine does both, in the same critical section as the
	// swap; see its doc for the two ways cancelling it early went wrong.
	old.Stop()

	mu.Lock()
	stillActive := engine == old
	mu.Unlock()
	if !stillActive {
		return // a concurrent Disconnect already tore this session down
	}

	next, err := newCoreEngine(engCfg)
	if err != nil {
		abortSession(old, "Exit switch failed: "+err.Error())
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := next.Start(ctx); err != nil {
		cancel()
		abortSession(old, "Exit switch failed: "+err.Error())
		return
	}

	// The check above is stale by now: core.New and Start ran outside mu and
	// take seconds, and a Disconnect landing in that window has already
	// closed the tunnel and cleared engine. adoptEngine re-checks and assigns
	// in one critical section, so this can only publish an engine the session
	// still wants — and stops next itself when it doesn't, rather than
	// leaving it running unreferenced.
	if !adoptEngine(old, next, cancel, code) {
		cancel()
		return
	}
	adopted.Store(true) // this engine now owns the status line

	if err := connectEngine(ctx, next); err != nil {
		abortSession(next, "Country switch to "+lbl+" failed: "+err.Error())
		return
	}

	// Connect is the longest window of all, so re-check once more before
	// claiming success: a Disconnect during it has already stopped next and
	// torn the tunnel down, and "Protected — <country>" would overwrite
	// disconnect()'s own "Disconnected" with a claim nothing backs.
	mu.Lock()
	stillActive = engine == next
	mu.Unlock()
	if !stillActive {
		// Take the status line back first. next.Stop() below emits residual
		// events, and with the gate still open they would reach the tray and
		// republish this discarded engine's state over the "Disconnected" that
		// is true.
		adopted.Store(false)
		next.Stop() // idempotent — disconnect() has already done this
		return
	}

	// Re-arm mid-session mesh-walk recovery for the new engine (issue #129):
	// old's own watcher already observed old.Stop() via eng.Done() and
	// returned, so the session needs a fresh one watching next, exactly as
	// connect() spawns one for its own initial engine.
	go watchMeshRecovery(ctx, next, engCfg, lbl)
	setStatus("Protected — " + lbl)
}

// adoptEngine publishes next as the session's live engine, but only when old
// is still the live engine at that exact instant — the re-check and the
// assignment share ONE critical section. Every individual access to engine in
// this package is already guarded by mu; that is not the same property. A
// check released before the assignment leaves a window in which disconnect()
// can clear engine/engineCancel/activeTunnel and close the tunnel, after
// which an unconditional assignment resurrects a live engine over a
// torn-down tunnel: the tray reads "Protected", the device's traffic goes out
// in the clear, and connect() refuses to start a replacement session because
// engine is non-nil — no path back short of Quit. That is the ADR-0039
// belief-safety failure, reached through a different door.
//
// old is the engine the caller believes is live — or nil, meaning "expect no
// session at all", which is what connect() passes. The three callers are the
// three ways a session is ever PUBLISHED: an initial connect (nil -> eng), a
// live country switch (old -> next, new context, new country), and a mesh-walk
// rebuild (old -> next, same context, same country). Two writes to these globals
// are deliberately not publishes and do not come through here: disconnect()
// clears all four directly, and connect() assigns activeTunnel inside its own
// checking critical section once the tunnel exists. Say "publish" rather than
// "write" when adding the next one — an earlier revision of this comment claimed
// every write, which was already untrue when it was written. Every publish does
// go through here, so there is exactly one place where the session can
// change hands.
//
// cancel and country belong to a live country switch: it runs the new engine on
// its own context and changes which country is live, so both move with the
// engine. A mesh-walk rebuild (watchMeshRecovery) keeps the session's
// existing context and country and passes nil/"" to leave them alone.
//
// # Retiring the replaced context happens HERE, and only here
//
// When cancel replaces engineCancel, the context the session was running on is
// dropped at that instant and nothing will ever cancel it again — so this is the
// one place it can be cancelled safely, and it is done from the value read
// inside the winning critical section, never from a snapshot taken earlier.
//
// The earlier snapshot is exactly what made this wrong before. switchCountry
// used to read engineCancel at the top and fire it before re-checking ownership,
// on the stated belief that it could only belong to the engine being stopped.
// It cannot: watchMeshRecovery adopts with cancel == nil *deliberately*, so the
// session keeps its original context across a mesh-walk rebuild, and engineCancel
// therefore legitimately points at the context a currently-LIVE engine is running
// on. Cancelling it either killed a recovery mid-Connect (dropping the user off
// the VPN and blaming recovery) or left the adopted engine running on a cancelled
// context — SOCKS still bound, traffic flowing until the first path drop and then
// never recovering, with the tray still reading "Protected". Same check-then-act
// shape this function exists to eliminate, one level up.
//
// Returns false — having stopped next — when the session moved on, so a lost
// race can never strand a running engine.
func adoptEngine(old, next *core.Engine, cancel context.CancelFunc, country string) bool {
	mu.Lock()
	won := engine == old
	var retire context.CancelFunc
	if won {
		engine = next
		if cancel != nil {
			retire = engineCancel // about to be unreachable; see above
			engineCancel = cancel
		}
		if country != "" {
			liveCountry = country
		}
	}
	mu.Unlock()
	// Outside mu: a CancelFunc runs arbitrary registered work, and nothing about
	// the decision above depends on the cancellation having happened yet.
	if retire != nil {
		retire()
	}
	if !won {
		next.Stop()
	}
	return won
}

// newCoreEngine builds the engine a supervisor rebuild swaps in — a live
// country switch (switchCountry) or a mid-session mesh-walk recovery
// (watchMeshRecovery). Indirected through a var, the same way clients/fyne's
// runKeyPath is (autostart_windows.go), because it sits exactly inside the
// window both supervisors must survive a concurrent disconnect() in: a test
// that has to prove the window is handled correctly needs to pin the
// interleaving rather than race it and hope. Production always calls
// core.New.
var newCoreEngine = core.New

// connectEngine brings the rebuilt engine up. Indirected for the same reason
// newCoreEngine is, but for a different window: this one is the gap AFTER the
// session has been handed over and BEFORE the switch claims success, which is
// the longest of the three and the only one newCoreEngine's seam cannot park
// inside. Without a seam here the post-Connect re-check is unreachable from a
// test — deleting it left the whole suite green. Production always calls
// (*core.Engine).Connect.
var connectEngine = func(ctx context.Context, eng *core.Engine) error {
	return eng.Connect(ctx)
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
// Inert unless the Settings mesh-walk triad is filled in (issue #129): with
// base.MeshPeers unset, Engine.meshRecoveryConfigured() stays false and
// NeedsRecovery() can never close — this loop just sits on a channel that
// never fires, exactly as if it weren't here. It does not touch, and cannot
// regress, the ADR-0030 auto-reconnect loop living inside core.Engine
// itself: that keeps retrying a dropped path on its own, independent of
// this watcher, for as long as no mesh-walk directory is available to
// escalate to (ADR-0037's #115 update, "ADR-0030 is preserved,
// deliberately"). Re-spawned by switchCountry (issue #137) after a live
// switch, watching the new engine — a switch stops the old one, which this
// loop observes as a normal exit via eng.Done() and returns from cleanly.
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

		next, err := newCoreEngine(rebuildRecoveryConfig(base, fresh, freshProof))
		if err != nil {
			abortSession(eng, "Error: "+err.Error())
			return
		}
		if err := next.Start(ctx); err != nil {
			abortSession(eng, "Error: "+err.Error())
			return
		}
		if err := next.Connect(ctx); err != nil {
			next.Stop()
			abortSession(eng, "Failed to reconnect after mesh-walk recovery")
			return
		}

		// Same atomic swap switchCountry uses (see adoptEngine): the rebuild
		// above ran outside mu for seconds, so the earlier stillActive check
		// says nothing about the state now. The context and the exit are the
		// session's originals here — only the engine changes.
		if !adoptEngine(eng, next, nil, "") {
			return // disconnected while the rebuild was in flight
		}
		logEvent(core.Event{Kind: core.EventInfo, Message: "mesh-walk: mid-session recovery rebuilt the engine (issue #115/#122)"})
		setStatus("Protected — " + lbl)
		eng = next // keep watching: a long session may recover more than once
	}
}

// abortSession tears the session down when a rebuild fails partway through —
// a mid-session mesh-walk rebuild (watchMeshRecovery) or a live country switch
// (switchCountry, issue #137) alike. cur is whichever engine identifies the
// session the caller believes it still owns (the stopped predecessor, or the
// replacement already adopted in its place), so this is a no-op if the user
// disconnected concurrently: disconnect() has already torn everything down
// and cleared engine, so cur no longer matches it.
//
// msg is logged before the teardown and re-published as the status after it.
// Both halves matter: setStatus alone never reaches bacchus.log, and
// disconnect()'s own "Disconnected" would overwrite the live status line a
// beat later — so the reason a switch or a recovery failed used to land in
// neither of the two places README names as this client's only diagnostics
// surfaces.
func abortSession(cur *core.Engine, msg string) {
	mu.Lock()
	stillActive := engine == cur
	mu.Unlock()
	if !stillActive {
		return
	}
	logEvent(core.Event{Kind: core.EventError, Message: msg})
	disconnect()
	setStatus(msg)
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
	liveCountry = ""
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
	trayHide(mDisc)
	trayShow(mConn)
}
