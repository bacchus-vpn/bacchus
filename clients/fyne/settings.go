// Settings window (issue #152): split-tunnel bypass list, kill-switch, DNS,
// auto-connect, launch-on-boot. One screen, reached from the main window's
// menu rather than competing with the single Connect/Disconnect button for
// attention - see ui.go's doc on the state indicator being the one thing a
// stressed user needs to read at a glance.
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
package main

import (
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

	status := widget.NewLabel("")
	status.Wrapping = fyne.TextWrapWord

	form := widget.NewForm(
		widget.NewFormItem(lang.L("Split-tunnel bypass list (one per line: IP, CIDR, or domain)"), bypassEntry),
		widget.NewFormItem(lang.L("Split-tunnel mode"), modeSelect),
		widget.NewFormItem("", killSwitchCheck),
		widget.NewFormItem(lang.L("DNS upstream (host:port)"), dnsEntry),
		widget.NewFormItem("", autoConnectCheck),
		widget.NewFormItem("", launchOnBootCheck),
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
