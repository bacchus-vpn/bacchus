//go:build windows

// Connection settings window (issue #75, ADR-0036): the client-side surface
// over core's transport pool / per-user failover (ADR-0028) — a geo picker, a
// manual exit pin, transport-ladder reordering, a node-count control, and a
// "reset learned paths" button. It edits the package-level cfg (config.go)
// and calls only core's existing exported config API (Config.Geo/ExitID/
// TransportPool/SelectionDir, Engine.ResetSelection) — no selection logic is
// reimplemented here.
//
// allowedPoolTransports vs. knownPoolTransports: the full-device tunnel
// (tunnel.go) can only carry a transport whose underlay address it can exclude
// from its own default route (and, under the kill-switch, allow-list) before
// the pool dials it. WebRTC qualifies because ForceRelay pins every candidate
// to the one configured TURN server — a fixed, already-excluded address (see
// connect() in main.go, and transport_webrtc.go's use of cfg.ForceRelay).
// Reality's exit dial address is learned only at Dial time, over per-session
// coordinator signaling (core/transport_reality.go's Dial/answer), so it can't
// be pinned in advance — but it *is* now excluded late, on the dial path,
// before its underlay connection opens: connect() wires core.Config.
// OnUnderlayDial to the poolExcluder (poolroutes.go, issue #109), which is the
// structural gate that makes reality safe here. allowedPoolTransports may list
// reality precisely because that handler is always wired; a transport whose
// address the client could not make tunnel-safe this way would stay out of it.
// See docs/design/client-connection-ui.md, ADR-0036, and ADR-0028's #109
// amendment for the full reasoning.
package main

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bacchus-vpn/bacchus/core"
	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

var errNoCoordinators = errors.New("no coordinators configured")

// admissionConfigErr is returned by validateAdmissionConfig for a
// CRL-path-without-pubkey pair — the exact shape core/exit_admission.go's
// buildExitVerifier rejects as a construction error (issue #123): "CRL path
// set, pubkey blank" makes core.New fail, so connect() surfaces a raw
// "requires AdmissionPubKey" error and listCountries() silently returns none
// (both fail-closed, but confusing — see the issue). Checking this in the
// Settings dialog before it ever reaches core.Config turns that into a clear,
// in-place message instead.
var admissionConfigErr = errors.New("revocation list path requires the admission public key above")

// validateAdmissionConfig reports whether pubKey/crlPath describe an
// admission config core would accept at construction: crlPath is meaningless
// (and rejected by core) without pubKey also set. Both blank (admission off)
// and pubKey alone (verify but skip revocation) are valid. Trims both inputs
// first, mirroring core's buildExitVerifier (core/exit_admission.go) exactly
// — otherwise a whitespace-only pubkey (e.g. " ") paired with a real crlPath
// passes this check, and only core's own trim-then-reject turns it into the
// raw "requires AdmissionPubKey" error #123a set out to replace with this
// dialog's friendly message (issue #130). Returns the trimmed values so the
// caller persists what was actually validated, not the raw widget text. Pure,
// so it's testable without opening the dialog (see settings_test.go);
// saveBtn's handler is the only caller.
func validateAdmissionConfig(pubKey, crlPath string) (trimmedPubKey, trimmedCRLPath string, err error) {
	pubKey = strings.TrimSpace(pubKey)
	crlPath = strings.TrimSpace(crlPath)
	if crlPath != "" && pubKey == "" {
		return "", "", admissionConfigErr
	}
	return pubKey, crlPath, nil
}

// allowedPoolTransports is the set safe to actually enable for this client's
// full-device tunnel (see file doc comment) — both transports now, since
// reality's late underlay exclusion (issue #109) closed the gap that had held
// it to webrtc-only. knownPoolTransports is every transport the ladder UI
// displays, in its default order; it stays a separate list so a future
// transport can appear in the UI before it is proven tunnel-safe to enable.
var (
	allowedPoolTransports = []string{core.TransportWebRTC, core.TransportReality}
	knownPoolTransports   = []string{core.TransportWebRTC, core.TransportReality}
)

// geoAny is the ComboBox sentinel for "no geo preference" (Config.Geo == "").
const geoAny = "(any)"

// geoOptions returns the geo picker's model: every distinct country in items,
// sorted, prefixed with the "any geo" sentinel. Pure and independent of the live
// list's ordering so it's testable without a coordinator.
func geoOptions(items []countryItem) []string {
	seen := map[string]bool{}
	var countries []string
	for _, c := range items {
		if c.code == "" || seen[c.code] {
			continue
		}
		seen[c.code] = true
		countries = append(countries, c.code)
	}
	sort.Strings(countries)
	return append([]string{geoAny}, countries...)
}

// sanitizePoolOrder filters order down to allowedPoolTransports, preserving
// order's relative sequence and dropping duplicates/unknown entries. Applied
// both when the settings window saves the ladder and again in connect()
// before building core.Config, so a hand-edited config.json can't smuggle an
// unsafe transport into the pool either.
func sanitizePoolOrder(order []string) []string {
	allowed := map[string]bool{}
	for _, t := range allowedPoolTransports {
		allowed[t] = true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(order))
	for _, t := range order {
		if !allowed[t] || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// moveLadderItem returns a copy of order with the element at idx swapped with
// its neighbor in the direction dir (-1 up / +1 down). idx out of range, or a
// move that would run off either end, returns order unchanged — reordering a
// two-or-more item ladder is always a swap with an adjacent element, never a
// wrap-around or a clamp-and-move-to-the-end, so repeated clicks at an edge
// are inert instead of surprising.
func moveLadderItem(order []string, idx, dir int) []string {
	out := append([]string(nil), order...)
	j := idx + dir
	if idx < 0 || idx >= len(out) || j < 0 || j >= len(out) {
		return out
	}
	out[idx], out[j] = out[j], out[idx]
	return out
}

// defaultSelectionDir is where the pool's learned-path store persists
// (core.Config.SelectionDir) whenever the pool is on. Not user-configurable —
// issue #75 asks for the pool to be *usable*, not for every implementation
// detail to be a knob — so this mirrors eventlog.go's own APPDATA convention
// rather than adding a settings field nobody asked for.
func defaultSelectionDir() string {
	return filepath.Join(filepath.Dir(logPath()), "selection") // logPath: %APPDATA%\Bacchus\bacchus.log, or an exe-relative fallback
}

// settingsMu guards settingsOpen so a double-click on the tray item can't
// spawn two overlapping settings windows (mirrors the mu-guards-shared-state
// idiom already used for engine/activeTunnel in main.go).
var (
	settingsMu   sync.Mutex
	settingsOpen bool
)

// openSettingsDialog is the tray menu's "Connection settings…" handler. It
// must run on its own locked OS thread: walk's Win32 windows are bound to the
// thread that creates them, and the tray's ClickedCh is drained on a plain
// (unlocked, freely rescheduled) goroutine — see the doc comment on the
// caller in main.go for why LockOSThread is not optional here.
func openSettingsDialog() {
	settingsMu.Lock()
	if settingsOpen {
		settingsMu.Unlock()
		return
	}
	settingsOpen = true
	settingsMu.Unlock()
	defer func() {
		settingsMu.Lock()
		settingsOpen = false
		settingsMu.Unlock()
	}()

	countries := listCountries()

	mu.Lock()
	snap := cfg
	snap.TransportPool = append([]string(nil), cfg.TransportPool...)
	mu.Unlock()

	poolOn := len(snap.TransportPool) > 0
	ladder := ladderDisplayOrder(snap.TransportPool)

	var dlg *walk.Dialog
	var poolCheck *walk.CheckBox
	var geoCombo *walk.ComboBox
	var exitEdit *walk.LineEdit
	var ladderBox *walk.ListBox
	var admissionPubKeyEdit, admissionCRLPathEdit *walk.LineEdit
	var upBtn, downBtn, resetBtn, saveBtn, cancelBtn *walk.PushButton
	var statusLbl *walk.Label

	geoModel := geoOptions(countries)
	geoIdx := 0
	for i, g := range geoModel {
		if (g == geoAny && snap.Geo == "") || g == snap.Geo {
			geoIdx = i
			break
		}
	}

	err := Dialog{
		AssignTo:      &dlg,
		Title:         "Bacchus — Connection settings",
		DefaultButton: &saveBtn,
		CancelButton:  &cancelBtn,
		MinSize:       Size{Width: 440, Height: 560},
		Layout:        VBox{},
		Children: []Widget{
			CheckBox{
				AssignTo: &poolCheck,
				Text:     "Automatically find the best path (recommended)",
				Checked:  poolOn,
				ToolTipText: "Tries multiple exits and transports, validates each " +
					"actually carries traffic, and remembers what worked on this " +
					"network. Off keeps the simple single-transport behavior.",
			},
			GroupBox{
				Title:  "Exit selection",
				Layout: VBox{},
				Children: []Widget{
					Label{Text: "Preferred geo (used only with automatic path selection):"},
					ComboBox{
						AssignTo:     &geoCombo,
						Model:        geoModel,
						CurrentIndex: geoIdx,
					},
					Label{Text: "Manual exit ID (optional — overrides the tray picker; leave blank to auto-select):"},
					LineEdit{
						AssignTo: &exitEdit,
						Text:     snap.ExitID,
					},
				},
			},
			GroupBox{
				Title:  "Transport ladder (try-order)",
				Layout: VBox{},
				Children: []Widget{
					ListBox{
						AssignTo: &ladderBox,
						Model:    ladder,
					},
					Composite{
						Layout: HBox{MarginsZero: true},
						Children: []Widget{
							PushButton{AssignTo: &upBtn, Text: "Move up"},
							PushButton{AssignTo: &downBtn, Text: "Move down"},
							HSpacer{},
						},
					},
					Label{
						Text: "Both transports are used from the top of this list down; " +
							"each is tried until one carries traffic, then remembered for " +
							"this network. reality rides TCP :443 (camouflage TLS) and " +
							"webrtc rides UDP — keeping both covers networks where one is " +
							"blocked.",
					},
				},
			},
			GroupBox{
				Title:  "Relay hops",
				Layout: VBox{},
				Children: []Widget{
					NumberEdit{
						MinValue: 1,
						MaxValue: 1,
						Value:    1,
						Enabled:  false,
						Suffix:   " hop (multi-hop chaining not yet available — issue #76)",
					},
				},
			},
			GroupBox{
				Title:  "Exit admission (optional)",
				Layout: VBox{},
				Children: []Widget{
					Label{Text: "Admission authority public key, hex (verifies every exit end-to-end; leave blank to skip):"},
					LineEdit{
						AssignTo: &admissionPubKeyEdit,
						Text:     snap.AdmissionPubKey,
					},
					Label{Text: "Revocation list file path (optional, re-read periodically; requires the public key above):"},
					LineEdit{
						AssignTo: &admissionCRLPathEdit,
						Text:     snap.AdmissionCRLPath,
					},
				},
			},
			PushButton{
				AssignTo: &resetBtn,
				Text:     "Reset learned paths",
				ToolTipText: "Forgets which path won on this network before, so the " +
					"next connect re-discovers what works from scratch.",
			},
			Label{AssignTo: &statusLbl, Text: ""},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					HSpacer{},
					PushButton{AssignTo: &saveBtn, Text: "Save"},
					PushButton{AssignTo: &cancelBtn, Text: "Cancel"},
				},
			},
		},
	}.Create(nil)
	if err != nil {
		return
	}

	moveSelected := func(dir int) {
		idx := ladderBox.CurrentIndex()
		ladder = moveLadderItem(ladder, idx, dir)
		_ = ladderBox.SetModel(ladder)
		_ = ladderBox.SetCurrentIndex(idx + dir)
	}
	upBtn.Clicked().Attach(func() { moveSelected(-1) })
	downBtn.Clicked().Attach(func() { moveSelected(1) })

	resetBtn.Clicked().Attach(func() {
		resetBtn.SetEnabled(false)
		if err := resetLearnedPaths(snap); err != nil {
			statusLbl.SetText("Reset failed: " + err.Error())
		} else {
			statusLbl.SetText("Learned paths cleared.")
		}
		resetBtn.SetEnabled(true)
	})

	saveBtn.Clicked().Attach(func() {
		next := snap
		if poolCheck.Checked() {
			next.TransportPool = sanitizePoolOrder(ladder)
		} else {
			next.TransportPool = nil
		}
		g := geoCombo.Text()
		if g == geoAny {
			g = ""
		}
		next.Geo = g
		next.ExitID = exitEdit.Text()

		pubKey, crlPath, err := validateAdmissionConfig(admissionPubKeyEdit.Text(), admissionCRLPathEdit.Text())
		if err != nil {
			statusLbl.SetText(err.Error())
			return
		}
		next.AdmissionPubKey = pubKey
		next.AdmissionCRLPath = crlPath

		mu.Lock()
		cfg = next
		path := cfgPath
		mu.Unlock()
		if path == "" {
			path = configPaths()[0]
		}
		if err := saveConfig(path, next); err != nil {
			statusLbl.SetText("Save failed: " + err.Error())
			return
		}
		refreshSelectedCountryLabel()
		dlg.Accept()
	})
	cancelBtn.Clicked().Attach(func() { dlg.Cancel() })

	dlg.Run()
}

// ladderDisplayOrder returns saved (the persisted, already-sanitized
// TransportPool) followed by any knownPoolTransports entries it's missing —
// so a never-configured or partially-configured ladder still shows every
// transport the ladder control knows about, in a stable default order.
func ladderDisplayOrder(saved []string) []string {
	out := append([]string(nil), saved...)
	have := map[string]bool{}
	for _, t := range out {
		have[t] = true
	}
	for _, t := range knownPoolTransports {
		if !have[t] {
			out = append(out, t)
		}
	}
	return out
}

// resetLearnedPaths calls core.Engine.ResetSelection() through a throwaway
// engine, mirroring listCountries' "build one just for this call" pattern
// (main.go): ResetSelection needs an engine (it operates on the store
// setupPool opened), but nothing here needs a live connection.
func resetLearnedPaths(snap Config) error {
	if len(snap.Coordinators) == 0 {
		return errNoCoordinators
	}
	eng, err := core.New(core.Config{
		Coordinators:     snap.Coordinators,
		Roles:            []string{core.RoleClient},
		TransportPool:    allowedPoolTransports, // any non-empty pool opens the store; the list itself is irrelevant to Reset
		SelectionDir:     defaultSelectionDir(),
		AdmissionPubKey:  snap.AdmissionPubKey,
		AdmissionCRLPath: snap.AdmissionCRLPath,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := eng.Start(ctx); err != nil {
		return err
	}
	defer eng.Stop()
	return eng.ResetSelection()
}
