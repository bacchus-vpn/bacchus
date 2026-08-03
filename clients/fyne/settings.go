// Settings window (issue #152): split-tunnel bypass list, kill-switch, DNS,
// auto-connect, launch-on-boot — and, since issue #93, the connection-strategy
// half the walk client had and this one did not: the transport ladder, relay
// hop count and its directory pair, and the exit-admission anchor. Issue #12
// adds the one section that points the other way, at what this client GIVES
// rather than what it consumes: the relay and exit opt-ins. One screen,
// reached from the main window's menu rather than competing with the single
// Connect/Disconnect button for attention - see ui.go's doc on the state
// indicator being the one thing a stressed user needs to read at a glance.
//
// Whether split-tunnel/kill-switch/DNS actually DO anything depends on the
// platform: they are enforced wherever there is an enforcement.Enforcer
// (Windows since bacchus#59, Linux since bacchus#37) and saved-but-inert where
// there is not ([E9] macOS). This window says which, by asking
// appstate.Controller.DeviceEnforced rather than assuming either answer.
//
// One of the three carries a platform exception rather than a flat yes: Linux
// enforces split-tunnel and the kill-switch fully, but cannot yet capture DNS
// queries a systemd-resolved machine sends to 127.0.0.53 (bacchus#104). The
// enforced notice would otherwise claim all three "change what leaves it", so
// the exception is stated on the DNS field itself — see DNSCaptureIsComplete.
// Claiming more than is enforced is the same failure as claiming less, in the
// direction that gets somebody hurt.
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

// showSettings opens the settings window seeded from current(). onSaved is
// called with the new config and the path it was written to after a successful
// save, so main.go can update the config it holds for the next connect.
//
// current is a function rather than a value because this window is no longer the
// only thing that writes the config file: the country picker (bacchus#16) writes
// it too, from the main window, while this one may be open. Seeded from a copy
// taken at open time, a save half an hour later would carry every field back to
// what it was then - silently reverting a country the user chose in between, in
// a window that has no control for it and so cannot even show what it undid.
// Asking again at save time means this window overwrites only what it edits.
func showSettings(a fyne.App, current func() appstate.Config, cfgPath string, enforced, volunteeringRefused bool, onSaved func(appstate.Config, string)) {
	if settingsOpen {
		return
	}
	settingsOpen = true
	cfg := current()

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

	// Volunteering (issue #12). Two checkboxes rather than one, and the exit's
	// cost written next to the exit's own box rather than in a help page — both
	// of those are the ruling on the card, not layout preference. See
	// internal/appstate/volunteer.go's file doc for why the two costs cannot be
	// bundled behind one control, and why every message below is a fixed
	// sentence rather than a formatted one.
	volunteerNotice := widget.NewLabel(lang.L("Bacchus can also carry traffic for other people. These are two separate choices, both off unless you turn them on, and neither one turns on the other."))
	volunteerNotice.Wrapping = fyne.TextWrapWord

	volunteerRelayCheck := widget.NewCheck(lang.L("Carry other people's traffic as a relay"), nil)
	volunteerRelayCheck.SetChecked(cfg.VolunteerRelay)
	relayCost := widget.NewLabel(lang.L("Their traffic passes through you encrypted and blind-forwarded: a relay never learns where it is going and never sees anything in the clear. What this costs you is bandwidth. It does not make you an exit."))
	relayCost.Wrapping = fyne.TextWrapWord

	volunteerExitCheck := widget.NewCheck(lang.L("Let other people's traffic reach the internet through your connection"), nil)
	volunteerExitCheck.SetChecked(cfg.VolunteerExit)
	// THE DISCLOSURE. Bold and full-width rather than a form hint, because this
	// is the sentence that carries the legal exposure and it is the one thing in
	// this window a user must not be able to skim past on the way to a
	// checkbox. It sits directly under the control it describes: "at the point
	// of choosing" is the requirement, and a hint rendered small and grey
	// alongside four other hints is not that.
	exitDisclosure := widget.NewLabel(lang.L("Their traffic reaches the internet under YOUR OWN ADDRESS, IN YOUR OWN JURISDICTION. Your address is what every site they visit records in its logs, and abuse complaints, provider notices and legal demands arrive at you. What this costs you is legal exposure, not bandwidth — which is why this is a separate choice from the relay above."))
	exitDisclosure.Wrapping = fyne.TextWrapWord
	exitDisclosure.TextStyle = fyne.TextStyle{Bold: true}

	volunteerAdvertiseEntry := widget.NewEntry()
	volunteerAdvertiseEntry.SetText(cfg.VolunteerAdvertise)
	volunteerAdvertiseEntry.PlaceHolder = "203.0.113.4:20000"

	volunteerExitKeyEntry := widget.NewEntry()
	volunteerExitKeyEntry.SetText(cfg.VolunteerExitKey)
	// Generated here rather than documented as `openssl rand -hex 32`, which is
	// what cmd/node has to tell its operator. #12 is a discoverability card: a
	// donation gated behind a terminal is only nominally reachable, which is the
	// same complaint the card makes about `-role client,relay,exit`.
	generateExitKey := widget.NewButton(lang.L("Generate"), func() {
		k, err := appstate.NewExitKeyHex()
		if err != nil {
			status.SetText(lang.L("Could not generate an identity key:") + " " + err.Error())
			return
		}
		volunteerExitKeyEntry.SetText(k)
	})

	// A build that routes the whole device AND cannot carve a served role's
	// egress back out of it cannot serve, and says so on the controls
	// themselves rather than accepting the choice and failing at connect.
	// Disabled-with-a-reason is the honest state here: the refusal is not about
	// anything the user typed, so there is nothing for them to fix, and an
	// enabled checkbox that always errors on save would imply otherwise.
	// PlanVolunteer refuses the same combination anyway — this is the UI half of
	// one rule, not the rule itself, which is why a hand-edited config file is
	// still caught (Controller.connectAsync).
	//
	// volunteeringRefused rather than enforced, and the two are no longer the
	// same answer (bacchus#109, ADR-0053): Linux routes the device and CAN carve
	// the served egress out, so the toggles are live there; Windows routes it
	// and cannot, so they are not. Every other use of `enforced` in this window
	// still asks the old question, which is why both are parameters.
	if volunteeringRefused {
		// TextStyle before SetText: SetText is what triggers the Label's
		// Refresh, so assigning the style after it would leave the style out of
		// that refresh and rely on Show() rendering the widget fresh instead.
		volunteerNotice.TextStyle = fyne.TextStyle{Bold: true}
		volunteerNotice.SetText(lang.L(appstate.ErrVolunteerWhileRouted.Error()))
		for _, d := range []fyne.Disableable{
			volunteerRelayCheck, volunteerExitCheck,
			volunteerAdvertiseEntry, volunteerExitKeyEntry, generateExitKey,
		} {
			d.Disable()
		}
	}

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

	// Both of these belong to the EXIT choice alone. The relay choice needs
	// nothing beyond its own checkbox — behind a home NAT a relay serves as a
	// client's first hop, reached the way the client itself is, so it needs no
	// forwarded port and no fixed identity. Asking a bandwidth-only donor for an
	// exit's setup would put the exit's cost back on somebody who declined it.
	volunteerAdvertiseItem := widget.NewFormItem(lang.L("Your address for exiting (host:port)"), volunteerAdvertiseEntry)
	volunteerAdvertiseItem.HintText = lang.L("Only for exiting. The address the internet reaches you at, and a port you have forwarded to this computer — this is what relays dial to hand you traffic.")

	volunteerExitKeyItem := widget.NewFormItem(lang.L("Your exit identity key (hex)"), volunteerExitKeyEntry)
	volunteerExitKeyItem.HintText = lang.L("Only for exiting. Keep it: your exit is known by this key, and a new one makes you a new node other people cannot reach until the directory catches up.")

	ladderItem := widget.NewFormItem(lang.L("Transport try-order"), ladderBox)
	ladderItem.HintText = lang.L("Each is tried from the top down until one carries traffic, then remembered for this network. reality rides TCP :443, webrtc rides UDP — keeping both covers networks where one is blocked.")

	// The top-of-window notice says the settings in this section "change what
	// leaves" the device once there is an Enforcer. On Linux that is true of
	// split-tunnel and the kill-switch and only partly true of DNS, so the
	// exception is stated on the field itself rather than left to a paragraph
	// that would have to be wrong about one of the three. Empty (and so absent)
	// wherever the platform captures every query — see DNSCaptureCaveat.
	dnsItem := widget.NewFormItem(lang.L("DNS upstream (host:port)"), dnsEntry)
	if enforced && !appstate.DNSCaptureIsComplete() {
		dnsItem.HintText = lang.L("This applies to programs that ask for DNS directly. If this system uses systemd-resolved (the default on Ubuntu, Fedora and Debian), its own lookups go to 127.0.0.53, which no route can capture — with the kill-switch on they are blocked, and with it off they leave in the clear.")
	}

	form := widget.NewForm(
		widget.NewFormItem(lang.L("Split-tunnel bypass list (one per line: IP, CIDR, or domain)"), bypassEntry),
		widget.NewFormItem(lang.L("Split-tunnel mode"), modeSelect),
		widget.NewFormItem("", killSwitchCheck),
		dnsItem,
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
		widget.NewFormItem("", widget.NewSeparator()),
		widget.NewFormItem("", volunteerNotice),
		widget.NewFormItem("", volunteerRelayCheck),
		widget.NewFormItem("", relayCost),
		widget.NewFormItem("", volunteerExitCheck),
		widget.NewFormItem("", exitDisclosure),
		volunteerAdvertiseItem,
		volunteerExitKeyItem,
		widget.NewFormItem("", generateExitKey),
	)
	form.SubmitText = lang.L("Save")
	form.CancelText = lang.L("Cancel")
	form.OnCancel = func() { w.Close() }
	form.OnSubmit = func() {
		// Re-read rather than reuse the copy the widgets were seeded from, so a
		// field changed elsewhere while this window sat open survives the save.
		// See this function's doc.
		next := current()
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
		// The volunteer choice is validated against the config being saved
		// rather than against the widgets, so the one function that decides
		// this is the same one Controller.connectAsync runs — see PlanVolunteer.
		//
		// What is PERSISTED, though, is the trimmed widget text and not the
		// plan's values, which is the opposite of what unchecking the transport
		// pool does below. The pool has no choice: core reads a non-empty
		// TransportPool as "the pool is on". These two fields are read only for
		// the exit role, so keeping them costs nothing — and the identity key
		// especially must survive unticking the box, or a volunteer who turns
		// exiting off for a week comes back as a different node that nobody's
		// cached directory can reach.
		next.VolunteerRelay = volunteerRelayCheck.Checked
		next.VolunteerExit = volunteerExitCheck.Checked
		next.VolunteerAdvertise = strings.TrimSpace(volunteerAdvertiseEntry.Text)
		next.VolunteerExitKey = strings.TrimSpace(volunteerExitKeyEntry.Text)

		// Issue #101. On an enforcing build the two volunteer controls above are
		// disabled, and Disable() does not clear Checked — so a config that
		// already said "serve" reads back ticked from a control the user cannot
		// untick. PlanVolunteer then refuses, the save is blocked, and the only
		// widget that could fix it is greyed out: the whole window becomes
		// unsaveable, and every connect aborts with the same sentence, until
		// somebody hand-edits the JSON.
		//
		// It is a scheduled regression rather than an edge case. bacchus#37
		// gives Linux an Enforcer, so every Linux user who volunteered under the
		// proxy-only build has exactly this config on the day it lands — which
		// is this change. So the fix ships with it rather than after it.
		//
		// The disabled controls mean "this build cannot serve", so the save
		// writes THAT instead of reading back a stale widget. Deliberately not a
		// widget reset: the config is the thing being persisted, and clearing it
		// here is what makes the next launch consistent no matter which machine
		// the file came from.
		var volunteeringCleared bool
		next, volunteeringCleared = appstate.ClearVolunteeringIfRouted(next, volunteeringRefused)
		// VolunteerAdvertise and VolunteerExitKey are deliberately KEPT. #100's
		// reasoning applies unchanged and is stronger here than for the toggles:
		// they are read only for the exit role, so keeping them costs nothing,
		// and discarding the identity key would make a volunteer who returns to
		// a non-enforcing machine a NEW node that nobody's cached directory can
		// reach.
		//
		// Controller.connectAsync's refusal is untouched by all of this. It runs
		// PlanVolunteer against the config it loads from disk, which is the path
		// that genuinely must fail closed — a hand-edited file saying "serve" on
		// a build that routes the device must not connect.
		volunteer, err := appstate.PlanVolunteer(next, volunteeringRefused)
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
		// A warn-and-serve finding keeps this window OPEN with the warning on
		// screen, on exactly the reasoning the launch-on-boot failure above
		// uses: the save succeeded and onSaved has run, but the user has been
		// told something they would otherwise only discover as an exit nobody
		// ever dials. Closing on a warning would put it on screen for one frame.
		//
		// A cleared volunteer opt-in (#101) is announced through the same
		// mechanism, and announced rather than silent because the user did opt
		// in at some point on some machine. Turning a donation off without
		// saying so would leave them believing they are still carrying traffic
		// for other people. It is said only when something was actually
		// cleared, so it never appears for the ordinary case of a user who
		// never volunteered.
		notices := make([]string, 0, len(volunteer.Warnings)+1)
		if volunteeringCleared {
			notices = append(notices, lang.L("Volunteering has been turned off: this build routes your whole device, and it cannot carry other people's traffic at the same time."))
		}
		for _, wn := range volunteer.Warnings {
			notices = append(notices, lang.L(wn))
		}
		if len(notices) > 0 {
			status.SetText(lang.L("Saved.") + " " + strings.Join(notices, "\n\n"))
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
