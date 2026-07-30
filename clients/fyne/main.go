// Bacchus cross-platform client (issues #148/#149) - an all-Go Fyne app that
// calls the Go core in-process: no FFI bridge, one language, one binary per
// platform, no bundled webview (Fyne renders its own widgets - the smallest
// attack surface a security tool can have). See docs/adr for the seam this
// was spiked to prove.
//
// App shell, calm/trustworthy theme, Russian-first i18n, and the
// connection-state indicator. Settings (#152) covers
// split-tunnel/kill-switch/DNS/auto-connect/launch-on-boot; whether the first
// three do anything depends on the platform having an enforcement.Enforcer
// (Windows does, bacchus#59) - see settings.go's doc. Still no country picker
// (#150, blocked on #146): Connect auto-selects, exactly like
// clients/windows's own tray picker does before a user chooses.
//
// Build: go build -o bacchus-fyne .  (needs a C toolchain - see README.md)
package main

import (
	"embed"
	"errors"
	"log"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/widget"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

//go:embed translations
var translations embed.FS

const appID = "io.github.bacchus-vpn.bacchus"

func main() {
	if err := lang.AddTranslationsFS(translations, "translations"); err != nil {
		log.Println("translations:", err)
	}

	// A config file that exists but doesn't parse must be SEEN, not logged. This is
	// built with -H=windowsgui (see README): there is no console, so log.Println goes
	// nowhere at all — the same trap issue #50 fixed for clients/windows. Worse than
	// silent: cfg stays zero, so Connect then reports "no coordinators configured —
	// copy the example into place" at a user whose file IS in place and has a typo,
	// pointing them away from the one thing wrong. So it is carried to the UI and
	// shown on the detail line instead.
	cfg, cfgPath, err := appstate.LoadConfig()
	var cfgErr error
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		cfgErr = err
		log.Println("config:", err)
	}

	a := app.NewWithID(appID)
	a.Settings().SetTheme(newCalmTheme())
	w := a.NewWindow(appName)

	ctrl := appstate.NewController(cfg)
	// The enforcement layer's diagnostics (a route install that failed, the
	// kill-switch arming) go to the log, not to the detail line: that line is
	// one calm user-facing sentence, and a PowerShell error is neither calm
	// nor actionable by a user. Addresses are redacted before they get here
	// (issue #140).
	ctrl.Logf = log.Printf
	indicator := newStateIndicator()

	detail := widget.NewLabel("")
	detail.Wrapping = fyne.TextWrapWord

	action := widget.NewButton(lang.L("Connect"), nil)
	action.OnTapped = ctrl.Connect

	ctrl.OnState = func(s appstate.ConnState) {
		fyne.Do(func() {
			indicator.update(s, ctrl.DeviceEnforced())
			applyButtonState(action, ctrl, s)
		})
	}
	ctrl.OnDetail = func(text string) {
		fyne.Do(func() {
			detail.SetText(text)
		})
	}

	// Startup side effects driven by the loaded config, gated on cfgErr: a
	// config file that exists but fails to parse leaves cfg at its zero
	// value, and treating that as "AutoConnect/LaunchOnBoot are both off" -
	// rather than just skipping these entirely - would mean an unrelated
	// JSON typo silently unregisters autostart or dials nothing. Both wait
	// for a config we actually, successfully read.
	var bootErr error
	if cfgErr == nil {
		if cfg.AutoConnect {
			ctrl.Connect()
		}
		// Reconciled at every startup, not just from the Settings window:
		// the OS-side registration can drift from what the config says (the
		// user moved the binary, or deleted the autostart entry by hand),
		// and this is the one place guaranteed to run before anything else.
		if err := appstate.SetLaunchOnBoot(cfg.LaunchOnBoot); err != nil {
			bootErr = err
			log.Println("launch-on-boot:", err)
		}
	}

	switch {
	case cfgErr != nil:
		detail.SetText(lang.L("Your settings file could not be read:") + " " + cfgErr.Error())
	case bootErr != nil:
		detail.SetText(lang.L("Launch-on-boot could not be set:") + " " + bootErr.Error())
	}

	onConfigSaved := func(newCfg appstate.Config, path string) {
		cfg = newCfg
		cfgPath = path
	}
	settingsItem := fyne.NewMenuItem(lang.L("Settings…"), func() {
		showSettings(a, cfg, cfgPath, ctrl.DeviceEnforced(), onConfigSaved)
	})
	w.SetMainMenu(fyne.NewMainMenu(fyne.NewMenu(lang.L("File"), settingsItem)))

	w.SetContent(container.NewBorder(indicator.content, container.NewVBox(detail, action), nil, nil))
	w.SetCloseIntercept(func() {
		ctrl.Disconnect()
		w.Close()
	})
	w.Resize(fyne.NewSize(420, 340))
	w.ShowAndRun()
}

// appName is the window title. Deliberately not run through lang.L: a brand
// name is not translated (matching how "Bacchus" is treated everywhere else
// in the project, including the Russian tray-client strings).
const appName = "Bacchus"

// applyButtonState keeps the one action button in sync with the headline
// state: its label and behavior are exactly "the one thing you can do right
// now" (Connect, wait, or Disconnect) - never two competing controls.
func applyButtonState(b *widget.Button, ctrl *appstate.Controller, s appstate.ConnState) {
	switch s {
	case appstate.Connecting:
		b.SetText(lang.L("Connecting…"))
		b.OnTapped = nil
		b.Disable()
	case appstate.Protected, appstate.Blocked:
		b.SetText(lang.L("Disconnect"))
		b.OnTapped = ctrl.Disconnect
		b.Enable()
	default: // appstate.Disconnected
		b.SetText(lang.L("Connect"))
		b.OnTapped = ctrl.Connect
		b.Enable()
	}
}
