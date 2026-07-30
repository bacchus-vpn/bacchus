// Settings window (issue #152): split-tunnel bypass list, kill-switch, DNS,
// auto-connect, launch-on-boot — and, since issue #93, the connection-strategy
// half the walk client had and this one did not: the transport ladder, relay
// hop count and its directory pair, and the exit-admission anchor. One screen,
// reached from the main window's menu rather than competing with the single
// Connect/Disconnect button for attention - see ui.go's doc on the state
// indicator being the one thing a stressed user needs to read at a glance.
//
// Whether split-tunnel/kill-switch/DNS actually DO anything depends on the
// platform: they are enforced wherever there is an enforcement.Enforcer
// (Windows, bacchus#59) and saved-but-inert where there is not ([E9] macOS,
// [E10] Linux). This window says which, by asking
// appstate.Controller.DeviceEnforced rather than assuming either answer.
//
// Getting that wrong in either direction is a real failure. A settings screen
// that implies a kill-switch is armed when it cannot possibly be is exactly
// the failure mode ui.go's state indicator exists to prevent. The inverse —
// telling a Windows user their kill-switch does nothing while it is in fact
// holding their machine fail-closed — is how someone concludes the setting is
// decorative and stops thinking about it.
//
// The #93 controls carry no such caveat: they are core config, enforced by
// core on every platform, so they mean the same thing everywhere this client
// runs. Deliberately NOT ported from the walk client's dialog: its exit-ID
// pin, which ADR-0042/`old #146` made inert everywhere — see that dialog, from
// which #93 also deletes it.
//
// This file stays wiring. Every decision a wrong answer to which produces a
// broken config — what the hop control may offer, when a directory is
// required, what may enter the pool — is in internal/appstate (connection.go),
// which is the half a unit test can reach without a GUI toolchain. ADR-0039's
// Fyne-free/Fyne-touching split is the rule; #93's tests are why it matters.
package main

import (
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/widget"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

// settingsOpen guards against opening two windows onto the same file (e.g. a
// double-click on the menu item). Only ever read/written from the Fyne UI
// goroutine - menu actions and window-close callbacks both run there - so it
// needs no lock of its own, consistent with the rest of this package's UI
// state (Controller owns the only cross-goroutine state; see controller.go).
var settingsOpen bool

// splitTunnelModes is the Select widget's option list.
var splitTunnelModes = []string{appstate.BypassModeExclude, appstate.BypassModeInclude}

// showSettings opens the settings window seeded from cfg. onSaved is called
// with the new config and the path it was written to after a successful
// save, so main.go can update the config it holds for the next connect.
func showSettings(a fyne.App, cfg appstate.Config, cfgPath string, enforced bool, onSaved func(appstate.Config, string)) {
	if settingsOpen {
		return
	}
	settingsOpen = true

	w := a.NewWindow(lang.L("Bacchus — Settings"))
	w.SetOnClosed(func() { settingsOpen = false })

	noticeText := lang.L("Split-tunnel, kill-switch, and DNS below are saved for later use - this client has no device-wide tunnel yet, so they do not change traffic today.")
	if enforced {
		noticeText = lang.L("Split-tunnel, kill-switch, and DNS below take effect on the next connect. Bacchus routes this whole device, so these change what leaves it.")
	}
	notice := widget.NewLabel(noticeText)
	notice.Wrapping = fyne.TextWrapWord

	bypassEntry := widget.NewMultiLineEntry()
	bypassEntry.SetText(appstate.JoinBypassLines(cfg.Bypass))
	bypassEntry.Wrapping = fyne.TextWrapOff
	bypassEntry.SetMinRowsVisible(4)

	modeSelect := widget.NewSelect(splitTunnelModes, nil)
	modeSelect.SetSelected(appstate.NormalizeBypassMode(cfg.BypassMode))

	killSwitchCheck := widget.NewCheck(lang.L("Kill-switch (block traffic if the tunnel drops)"), nil)
	killSwitchCheck.SetChecked(!cfg.DisableKillSwitch)

	dnsEntry := widget.NewEntry()
	dnsEntry.SetText(cfg.DNS)
	dnsEntry.PlaceHolder = "1.1.1.1:53"

	autoConnectCheck := widget.NewCheck(lang.L("Connect automatically when Bacchus starts"), nil)
	autoConnectCheck.SetChecked(cfg.AutoConnect)

	launchOnBootCheck := widget.NewCheck(lang.L("Start Bacchus when you log in"), nil)
	launchOnBootCheck.SetChecked(cfg.LaunchOnBoot)

	// Transport ladder (issue #93). Seeded through SanitizePoolOrder as well as
	// LadderDisplayOrder — one step more than the walk client does — so a
	// transport a hand-edited config named but this client will not enable
	// never appears as a row the user can reorder and then watch silently
	// vanish on save. What is displayed is what can be saved.
	ladder := appstate.LadderDisplayOrder(appstate.SanitizePoolOrder(cfg.TransportPool))
	ladderSel := -1
	ladderList := widget.NewList(
		func() int { return len(ladder) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, o fyne.CanvasObject) { o.(*widget.Label).SetText(ladder[id]) },
	)
	ladderList.OnSelected = func(id widget.ListItemID) { ladderSel = id }
	ladderList.OnUnselected = func(widget.ListItemID) { ladderSel = -1 }
	// The same guard MoveLadderItem applies internally, repeated here because
	// the SELECTION must not follow a move that did not happen: a click at
	// either end is inert, and moving the highlight anyway would make it look
	// like something happened.
	moveLadder := func(dir int) {
		j := ladderSel + dir
		if ladderSel < 0 || j < 0 || j >= len(ladder) {
			return
		}
		ladder = appstate.MoveLadderItem(ladder, ladderSel, dir)
		ladderList.Refresh()
		ladderSel = j
		ladderList.Select(j)
	}
	ladderButtons := container.NewHBox(
		widget.NewButton(lang.L("Move up"), func() { moveLadder(-1) }),
		widget.NewButton(lang.L("Move down"), func() { moveLadder(1) }),
	)
	// A List sizes itself to its container, and this one sits inside the
	// form's own scroll, so it needs a definite height or it collapses to
	// nothing. Sized for one row more than knownPoolTransports has today, so a
	// third transport appears without the box needing to be resized here.
	ladderBox := container.NewGridWrap(fyne.NewSize(220, 96), ladderList)

	poolCheck := widget.NewCheck(lang.L("Automatically find the best path (recommended)"), nil)
	poolCheck.SetChecked(len(appstate.SanitizePoolOrder(cfg.TransportPool)) > 0)

	relayHopsSelect := widget.NewSelect(appstate.RelayHopChoices(), nil)
	relayHopsSelect.SetSelected(strconv.Itoa(appstate.NormalizeRelayHops(cfg.RelayHops)))

	relayDirPathEntry := widget.NewEntry()
	relayDirPathEntry.SetText(cfg.RelayDirectoryPath)

	relayDirKeyEntry := widget.NewEntry()
	relayDirKeyEntry.SetText(cfg.RelayDirectoryKey)

	admissionPubKeyEntry := widget.NewEntry()
	admissionPubKeyEntry.SetText(cfg.AdmissionPubKey)

	admissionCRLPathEntry := widget.NewEntry()
	admissionCRLPathEntry.SetText(cfg.AdmissionCRLPath)

	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord

	// The notice at the top of the window scopes itself to "split-tunnel,
	// kill-switch, and DNS below", and on a platform with no Enforcer it says
	// those are saved-but-inert. Everything from here down is core config,
	// enforced by core, and live on every platform — so without this line a
	// Linux user reads "saved for later use" above a relay hop count that
	// genuinely changes how they connect, and reasonably concludes it does
	// nothing. Shown unconditionally: it is true either way, and a sentence
	// that appears only sometimes is one more thing to get wrong.
	strategyNotice := widget.NewLabel(lang.L("The settings below change how Bacchus builds a connection. Unlike the ones above, they do not depend on this device being routed, and take effect everywhere."))
	strategyNotice.Wrapping = fyne.TextWrapWord

	relayHopsItem := widget.NewFormItem(lang.L("Relay hops"), relayHopsSelect)
	// Fail-closed is the part a user cannot guess and would otherwise learn
	// from a connect that simply stops working, so it is on the control itself
	// rather than in a paragraph above it.
	relayHopsItem.HintText = lang.L("1 is a single relay, which sees both you and your exit. 2 or more builds a chain — and fails the connection rather than quietly using fewer hops if one cannot be built.")

	relayDirPathItem := widget.NewFormItem(lang.L("Relay directory file"), relayDirPathEntry)
	relayDirPathItem.HintText = lang.L("A signed snapshot of relays to build chains from. Required at 2 or more hops.")

	relayDirKeyItem := widget.NewFormItem(lang.L("Relay directory public key (hex)"), relayDirKeyEntry)
	relayDirKeyItem.HintText = lang.L("Verifies the file above. Required at 2 or more hops.")

	admissionPubKeyItem := widget.NewFormItem(lang.L("Admission authority public key (hex)"), admissionPubKeyEntry)
	admissionPubKeyItem.HintText = lang.L("Verifies every exit end-to-end, independently of the coordinator. Blank does not check exits at all.")

	admissionCRLItem := widget.NewFormItem(lang.L("Revocation list file"), admissionCRLPathEntry)
	admissionCRLItem.HintText = lang.L("Optional, re-read while connected. Needs the public key above.")

	ladderItem := widget.NewFormItem(lang.L("Transport try-order"), ladderBox)
	ladderItem.HintText = lang.L("Each is tried from the top down until one carries traffic, then remembered for this network. reality rides TCP :443, webrtc rides UDP — keeping both covers networks where one is blocked.")

	form := widget.NewForm(
		widget.NewFormItem(lang.L("Split-tunnel bypass list (one per line: IP, CIDR, or domain)"), bypassEntry),
		widget.NewFormItem(lang.L("Split-tunnel mode"), modeSelect),
		widget.NewFormItem("", killSwitchCheck),
		widget.NewFormItem(lang.L("DNS upstream (host:port)"), dnsEntry),
		widget.NewFormItem("", autoConnectCheck),
		widget.NewFormItem("", launchOnBootCheck),
		widget.NewFormItem("", widget.NewSeparator()),
		widget.NewFormItem("", strategyNotice),
		widget.NewFormItem("", poolCheck),
		ladderItem,
		widget.NewFormItem("", ladderButtons),
		relayHopsItem,
		relayDirPathItem,
		relayDirKeyItem,
		admissionPubKeyItem,
		admissionCRLItem,
	)
	form.SubmitText = lang.L("Save")
	form.CancelText = lang.L("Cancel")
	form.OnCancel = func() { w.Close() }
	form.OnSubmit = func() {
		next := cfg
		next.Bypass = appstate.SplitBypassLines(bypassEntry.Text)
		next.BypassMode = appstate.NormalizeBypassMode(modeSelect.Selected)
		next.DisableKillSwitch = !killSwitchCheck.Checked
		next.DNS = strings.TrimSpace(dnsEntry.Text)
		next.AutoConnect = autoConnectCheck.Checked
		next.LaunchOnBoot = launchOnBootCheck.Checked

		// Validated BEFORE anything is written, and both checks before either
		// assignment: a config that fails one of these is refused whole rather
		// than half-saved. The error text doubles as its own translation key,
		// so lang.L returns Russian where translations/settings.ru.json has it
		// and the English sentence where it does not — the same silent-fallback
		// contract every other label in this window relies on.
		hops := appstate.ParseRelayHops(relayHopsSelect.Selected)
		dirPath, dirKey, err := appstate.ValidateRelayChainConfig(hops, relayDirPathEntry.Text, relayDirKeyEntry.Text)
		if err != nil {
			status.SetText(lang.L(err.Error()))
			return
		}
		pubKey, crlPath, err := appstate.ValidateAdmissionConfig(admissionPubKeyEntry.Text, admissionCRLPathEntry.Text)
		if err != nil {
			status.SetText(lang.L(err.Error()))
			return
		}
		next.RelayHops = hops
		next.RelayDirectoryPath = dirPath
		next.RelayDirectoryKey = dirKey
		next.AdmissionPubKey = pubKey
		next.AdmissionCRLPath = crlPath
		// Unchecking the pool clears the ladder rather than remembering it:
		// core reads a non-empty TransportPool as "the pool is on", so there is
		// no way to persist an off pool with an order still in it.
		if poolCheck.Checked {
			next.TransportPool = appstate.SanitizePoolOrder(ladder)
		} else {
			next.TransportPool = nil
		}

		path := cfgPath
		if path == "" {
			path = appstate.DefaultConfigPath()
		}
		if err := appstate.SaveConfig(path, next); err != nil {
			status.SetText(lang.L("Save failed:") + " " + err.Error())
			return
		}
		// Saved either way past this point - the file is the source of
		// truth, and main.go reconciles launch-on-boot against it at every
		// startup - but a failure here means it did not take effect
		// immediately, and the user should know that now rather than
		// discover it at the next login.
		if err := appstate.SetLaunchOnBoot(next.LaunchOnBoot); err != nil {
			status.SetText(lang.L("Saved, but launch-on-boot could not be set:") + " " + err.Error())
			onSaved(next, path)
			return
		}
		onSaved(next, path)
		w.Close()
	}

	top := container.NewVBox(notice, widget.NewSeparator())
	w.SetContent(container.NewBorder(top, status, nil, nil, container.NewVScroll(form)))
	w.Resize(fyne.NewSize(480, 520))
	w.Show()
}
