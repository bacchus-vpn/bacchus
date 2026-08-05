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
// (Windows does, bacchus#59) - see settings.go's doc. The window's centre is the
// country picker (bacchus#16, picker.go): the user chooses where they appear
// from, and Connect asks for that country and nothing else. Choosing nothing is
// still a choice the app supports - core then takes the coordinator's first
// assignable country, exactly as this client always did.
//
// Build: go build -o bacchus-fyne .  (needs a C toolchain - see README.md)
package main

import (
	"embed"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

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
	// nowhere at all — the same trap issue #50 fixed for the Windows tray client. Worse than
	// silent: cfg stays zero, so Connect then reports "no coordinators configured"
	// and sends the user to edit a file that is already there and already says what
	// it should — pointing them away from the one thing wrong, which is the typo.
	// So it is carried to the UI and shown on the detail line instead.
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

	// The country picker (bacchus#16). onChoose is where the choice becomes
	// durable: the Controller holds the running value and this file owns the
	// file it came from, which is the same split settings.go already uses.
	picker := newCountryPicker(cfg.Country, ctrl.RefreshCountries, func(code string) error {
		ctrl.SetCountry(code)
		if cfgErr != nil {
			// The config file exists and did not parse, so cfg is its zero
			// value. Writing that back would replace every setting the user has
			// with an empty file, over a typo they have already been told about
			// on the detail line. The choice still applies to this session.
			return errCountryConfigUnreadable
		}
		cfg.Country = code
		path := cfgPath
		if path == "" {
			path = appstate.DefaultConfigPath()
		}
		if err := appstate.SaveConfig(path, cfg); err != nil {
			log.Println("country:", err)
			return err
		}
		cfgPath = path
		return nil
	})

	ctrl.OnState = func(s appstate.ConnState) {
		fyne.Do(func() {
			indicator.update(s, ctrl.DeviceEnforced())
			applyButtonState(action, ctrl, s)
			picker.setConnState(s)
		})
	}
	ctrl.OnDetail = func(d appstate.Detail) {
		fyne.Do(func() {
			detail.SetText(detailText(d))
		})
	}
	ctrl.OnCountries = func(s appstate.CountryListState) {
		fyne.Do(func() {
			picker.update(s)
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
		// Populate the picker before the user looks at it. Off the UI goroutine
		// (RefreshCountries spawns its own), so a coordinator that never answers
		// costs a status line rather than a window that will not paint.
		//
		// Ordered before AutoConnect deliberately: both run, and a client that
		// dials on launch should still be able to show what else was on offer.
		ctrl.RefreshCountries()
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
		// Told to the Controller, not just kept here. Until the picker existed
		// nothing did this, so a coordinator, DNS or kill-switch setting changed
		// in Settings did not reach a connect until the app was restarted; with
		// two writers of one file that gap becomes a choice silently reverting.
		// SetConfig keeps the country the picker already chose - see its doc.
		ctrl.SetConfig(newCfg)
		// A new coordinator pool answers a different country list, and the one
		// on screen is now about a network this client is no longer pointed at.
		ctrl.RefreshCountries()
	}
	settingsItem := fyne.NewMenuItem(lang.L("Settings…"), func() {
		showSettings(a, func() appstate.Config { return cfg }, cfgPath, ctrl.DeviceEnforced(), ctrl.VolunteeringRefused(), onConfigSaved)
	})
	w.SetMainMenu(fyne.NewMainMenu(fyne.NewMenu(lang.L("File"), settingsItem)))

	w.SetContent(container.NewBorder(indicator.content, container.NewVBox(detail, action), nil, nil, picker.content))
	w.SetCloseIntercept(func() {
		ctrl.Disconnect()
		w.Close()
	})
	// Taller than the 420x340 the shell shipped with: that window had an empty
	// centre, and the centre is now a list somebody has to be able to read
	// several rows of without scrolling. The width is unchanged - a country code
	// and a short status fit in it, and a wider window would make the state band
	// above compete less well with nothing at all.
	w.Resize(fyne.NewSize(420, 540))
	w.ShowAndRun()
}

// errCountryConfigUnreadable is why a country choice was not written to disk:
// the config file on disk did not parse, so there is nothing safe to write back
// over it. The picker recognises it (errors.Is) and says so in its own words -
// this text is never shown, which is why it is not a translation key.
var errCountryConfigUnreadable = errors.New("the settings file could not be read, so the choice was not saved")

// detailText renders one detail-line message in the user's language.
//
// internal/appstate cannot import Fyne (ADR-0039's split) and so cannot call
// lang.L, but the sentences it classifies are fixed ones a user reads at the
// moment something did not work - which is exactly where an untranslated English
// line is worst. So appstate hands over a kind and its one variable part, and
// the literals live here where translations_test.go's AST walk can see them.
//
// The renewal ladder (bacchus#171) is the second group. It matters more than the
// country refusals rather than less: a country refusal arrives while the user is
// watching, and a renewal warning arrives while everything still works, carrying
// the only notice they will get before their access stops. Reading that in a
// language they do not speak is reading nothing.
//
// Everything else is relayed verbatim. That is not an oversight: core's errors
// are not fixed sentences, they have no translation to look up, and inventing a
// generic translated sentence to replace them would throw away the only
// diagnostic the user has.
func detailText(d appstate.Detail) string {
	switch d.Kind {
	case appstate.DetailCountryBusy:
		return fmt.Sprintf(lang.L("%s is busy right now — everything there is full. Choose another country, or try again in a moment."), d.Country)
	case appstate.DetailNoSuchCountry:
		return fmt.Sprintf(lang.L("Bacchus has nothing in %s to connect you through. Choose another country from the list."), d.Country)
	case appstate.DetailCountryConfig:
		return fmt.Sprintf(lang.L("Your settings file asks for \"%s\", which is not a country. Choose a country above, or put a two-letter code like DE in the \"country\" line of that file."), d.Country)
	case appstate.DetailRenewalFailing:
		return lang.L("Bacchus could not refresh this device's access and will keep trying. Your connection is unaffected for now.")
	case appstate.DetailRenewalUrgent:
		return fmt.Sprintf(lang.L("Your subscription needs attention: Bacchus could not refresh this device's access, which runs out in about %s."), roughRemainingText(d.Remaining))
	case appstate.DetailRenewalExpired:
		return lang.L("This device's access has run out and could not be refreshed. Connecting will be refused until it is.")
	case appstate.DetailRenewalUnknownExpiry:
		return lang.L("Bacchus could not refresh this device's access, and cannot tell how long the current one lasts. If connecting starts failing, this is why.")
	case appstate.DetailSubscriptionExpired:
		return lang.L("Your subscription has expired. This device will stop connecting when its current access runs out.")
	case appstate.DetailDeviceRevoked:
		return lang.L("This device's access was withdrawn. It will stop connecting when its current access runs out.")
	case appstate.DetailRenewalRecovered:
		return lang.L("Your subscription is up to date again.")
	}
	return d.Text
}

// roughRemainingText renders how long a device credential has left, in the
// user's language.
//
// The rounding is appstate's (RoughRemaining), so this and the English copy in
// Detail.Text cannot disagree about what they claim - only about how they say
// it. Only the phrasing lives here, because only the phrasing is a UI string.
func roughRemainingText(d time.Duration) string {
	n, unit := appstate.RoughRemaining(d)
	switch unit {
	case appstate.DurationHours:
		return fmt.Sprintf(lang.L("%d hours"), n)
	case appstate.DurationAnHour:
		return lang.L("an hour")
	case appstate.DurationMinutes:
		return fmt.Sprintf(lang.L("%d minutes"), n)
	default:
		return lang.L("a moment")
	}
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
