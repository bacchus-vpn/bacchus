// Bacchus cross-platform client (old #148/#149) - an all-Go Fyne app that
// calls the Go core in-process: no FFI bridge, one language, one binary per
// platform, no bundled webview (Fyne renders its own widgets - the smallest
// attack surface a security tool can have). See docs/adr for the seam this
// was spiked to prove.
//
// App shell, calm/trustworthy theme, Russian-first i18n, and the
// connection-state indicator. Settings (old #152) covers
// split-tunnel/kill-switch/DNS/auto-connect/launch-on-boot; whether the first
// three do anything depends on the platform having an enforcement.Enforcer
// (Windows does, bacchus#59) - see settings.go's doc. The window's centre is the
// country picker (bacchus#16, picker.go): the user chooses where they appear
// from, and Connect asks for that country and nothing else. Choosing nothing is
// still a choice the app supports - core then takes the coordinator's first
// assignable country, exactly as this client always did.
//
// # The process, as something somebody has to live with
//
// Three things a Windows hardware pass found (bacchus#185/#186/#187, ADR-0058)
// share this file because they are all about the client as a PROCESS rather
// than as a screen, and each of them was invisible to every test in the tree:
//
//   - Only one client may run (singleinstance). Two can arm at once, and the
//     kill-switch bookkeeping is machine-wide with no ownership check, so the
//     first to disconnect disarms the second's while it still says Protected.
//   - Closing the window tucks it into the tray instead of dropping the tunnel
//     (tray.go), and QUIT is the one gesture that disconnects — waited for, not
//     fired and forgotten.
//   - Everything this program logs goes to a file (clientlog), because on a
//     -H=windowsgui binary os.Stderr reaches nothing at all.
//
// Build: go build -o bacchus-fyne .  (needs a C toolchain - see README.md)
package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/widget"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/clientlog"
	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/singleinstance"
	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/tray"
	"github.com/bacchus-vpn/bacchus/clients/internal/enforcement"
	"github.com/bacchus-vpn/bacchus/core/version"
)

//go:embed translations
var translations embed.FS

const appID = "io.github.bacchus-vpn.bacchus"

func main() {
	if err := lang.AddTranslationsFS(translations, "translations"); err != nil {
		log.Println("translations:", err)
	}

	// THE LOG SINK GOES IN FIRST, before anything that can fail (bacchus#187).
	//
	// Until it existed, every line this program produced was discarded on
	// Windows: log.Printf writes to os.Stderr and the shipping binary is linked
	// -H=windowsgui, which gets no console, so os.Stderr had no destination. A
	// user on a hostile network could not produce a diagnostic log at all, and
	// the answer to "can you send me the log" was no.
	//
	// log.SetOutput rather than a sink passed to each writer, deliberately:
	// this client's diagnostics reach the standard logger from four directions
	// — this file's own lines, Controller.logf (which carries the enforcement
	// layer's and the account client's), Fyne's own fyne.LogError, and
	// fyne.io/systray's tray errors. Only the first two could be handed a sink;
	// redirecting the package logger catches the other two as well, and those
	// are exactly the ones that report a tray or a window failing to appear.
	//
	// Everything is redacted at the sink rather than per writer, which is what
	// makes the bar hold for a writer added later. See clientlog and
	// enforcement.RedactAddresses.
	logDir := clientlog.DefaultDir()
	logSink := clientlog.New(logDir, clientlog.Options{
		Redact: enforcement.RedactAddresses,
		Echo:   os.Stderr,
	})
	defer logSink.Close()
	log.SetOutput(logSink)
	log.Printf("bacchus-fyne %s starting; this log is capped at %d KiB, addresses are redacted, and Settings can turn it off and delete it",
		releaseLine(), clientlog.DefaultMaxBytes/1024)

	// ONE CLIENT PER MACHINE (bacchus#185). Before anything is armed, and
	// before a window exists.
	//
	// Two clients running at once is not untidy, it is unsafe: the kill-switch
	// is machine-wide and has no ownership check, so the first one to
	// disconnect disarms the second one's kill-switch while it is still
	// connected and still saying Protected.
	//
	// A guard that could not be ESTABLISHED is not treated as a free machine.
	// The three outcomes are kept apart — see singleinstance.Acquire — because
	// "another client holds it" and "I could not tell" want different answers,
	// and running anyway on the second would be assuming the safe one.
	release, err := singleinstance.Acquire(logDir)
	if err != nil {
		log.Println("single instance:", err)
		showRefusal(err, logSink.Path())
		return
	}
	defer release()

	// A config file that exists and does not parse STOPS THIS CLIENT (bacchus#255).
	//
	// It used to be carried to the detail line and started around: cfg stayed at
	// its zero value, the window came up, and the user got a client with no
	// coordinators, no account service, no country and no bypass list, looking
	// exactly like a fresh install. The sentence on the detail line was true and
	// nobody read it, because there was a working-looking app in front of it.
	//
	// That is fail-open on the one input that carries every setting this client
	// has, and the hardware pass reached it by following this repository's own
	// runbook: a config saved by `Set-Content -Encoding UTF8` acquired a byte
	// order mark, and the client ran three times with the whole file discarded.
	// The BOM itself is now tolerated (appstate.utf8BOM); this is the other half,
	// the one that holds for the next reason a file does not parse — a trailing
	// comma, a smart quote, half a paste.
	//
	// Refusing is not the harsh option here, it is the recoverable one. The user
	// keeps the file they wrote, is told which file and what is wrong with it, and
	// fixes it. Starting instead offers a Settings window whose Save would write
	// the zero value over their coordinators — losing the configuration to a typo
	// rather than merely suspending it.
	//
	// A file that cannot be READ (permissions, a busy handle) is deliberately not
	// this case: configPaths ranks two candidates and falling through to the next
	// one is the documented precedence rule (see configPaths, and issue #118 for
	// why the exe-adjacent candidate is so often not the user's file).
	cfg, cfgPath, err := appstate.LoadConfig()
	if bad, ok := appstate.ConfigUnreadable(err); ok {
		log.Println("config:", bad)
		showConfigRefusal(bad, logSink.Path())
		return
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Println("config:", err)
	}

	a := app.NewWithID(appID)
	a.Settings().SetTheme(newCalmTheme())
	a.SetIcon(appIcon())
	w := a.NewWindow(appName)

	ctrl := appstate.NewController(cfg)
	// The enforcement layer's diagnostics (a route install that failed, the
	// kill-switch arming) go to the log, not to the detail line: that line is
	// one calm user-facing sentence, and a PowerShell error is neither calm
	// nor actionable by a user. Addresses are redacted twice over — once by
	// enforcement itself (old #140) and again at the sink, which is what
	// covers every OTHER writer reaching this same logger.
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

	// The tray is decided here, before OnState is wired, because OnState has to
	// know whether there is one to update. tray.Available answers on the
	// mechanism that will actually be used rather than guessing — see that
	// package for why a guess is not good enough on Linux.
	trayOK := tray.Available()
	var trayUI *trayMenu

	// Whether a Protected session on this machine also cuts it off from its own
	// local network (bacchus#257, ADR-0073). Derived from cfg here rather than
	// asked of the Controller, because cfg is this file's copy and every writer
	// of it — the picker, the settings save — runs on the UI goroutine, which is
	// also the only goroutine that reads this. No lock, and no read of Controller
	// state from inside an OnState callback.
	lanBlocked := func() bool { return ctrl.DeviceEnforced() && !cfg.DisableKillSwitch }

	ctrl.OnState = func(s appstate.ConnState) {
		fyne.Do(func() {
			indicator.update(s, ctrl.DeviceEnforced(), lanBlocked())
			applyButtonState(action, ctrl, s)
			picker.setConnState(s)
			if trayUI != nil {
				trayUI.update(s, ctrl.DeviceEnforced())
			}
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

	// Startup side effects driven by the loaded config. They no longer need a
	// "did the config parse" gate: a config file that exists and does not parse
	// has already stopped this function above (bacchus#255), so cfg here is
	// either a file this client read or the zero value of a machine that has no
	// file at all — and on that machine "AutoConnect and LaunchOnBoot are both
	// off" is the truth rather than an artefact of a typo.
	//
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

	// One detail line, built from every startup finding rather than assigned by
	// whichever branch ran last. There used to be a switch here choosing ONE of
	// two, which was correct while the two could not both happen and is not a
	// shape to extend: a third finding added later would silently hide a second.
	var startup []string

	// Reconciled at every startup, not just from the Settings window:
	// the OS-side registration can drift from what the config says (the
	// user moved the binary, or deleted the autostart entry by hand),
	// and this is the one place guaranteed to run before anything else.
	if err := appstate.SetLaunchOnBoot(cfg.LaunchOnBoot); err != nil {
		log.Println("launch-on-boot:", err)
		startup = append(startup, lang.L("Launch-on-boot could not be set:")+" "+err.Error())
	}

	// Everything this client made of the configuration it just read, said once,
	// at the moment it is decided (bacchus#258). See appstate.CheckConfig: an
	// entry the client accepted, stored and then could not act on is the shape
	// all four of this wave's client cards share, and the answer is to say so
	// rather than to guess better.
	//
	// To the log as well as the line, one finding per line there: the line is
	// read now by whoever is looking at the window, and the log is read later by
	// whoever they ask for help — which for a bypass entry that does nothing is
	// the more likely of the two, since nothing about it looks broken.
	if findings := appstate.CheckConfig(cfg); len(findings) > 0 {
		for _, f := range findings {
			log.Println("config:", f)
		}
		startup = append(startup, lang.L("Some of your settings are not in force:")+" "+strings.Join(findings, " "))
	}

	if len(startup) > 0 {
		detail.SetText(strings.Join(startup, " "))
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
		showSettings(a, func() appstate.Config { return cfg }, cfgPath, ctrl.DeviceEnforced(), ctrl.VolunteeringRefused(), logSink, onConfigSaved)
	})

	// quit is the ONLY gesture that ends the session, and it is shared by the
	// tray and the File menu so there is exactly one definition of what leaving
	// means. See tray.go: it hides first, tears down and WAITS, then exits.
	//
	// DisconnectAndWait rather than Disconnect, and a.Quit through fyne.Do: the
	// teardown runs on a goroutine of quitAction's making, and touching the app
	// from one is what fyne.Do exists for (Fyne 2.6's threading rules).
	// The signed release channel (bacchus#34, ADR-0052, ADR-0065). Two boundaries
	// and one watcher:
	//
	//   - HERE, at startup, before anything connects: publish a release an earlier
	//     session staged. Nothing is connected, so there is no session to interrupt
	//     and no kill-switch to strand, which is the only kind of moment ADR-0052 §4
	//     permits an apply at.
	//   - inside quit, after the teardown has WAITED: the same call, at the other
	//     end of the same rule.
	//   - and updater.Run, which never touches the network on its own: it watches the
	//     release a coordinator already stamps on replies this client was already
	//     receiving, and fetches only while the tunnel is up.
	//
	// A configured-but-broken channel is reported and does not stop the client: a
	// user whose update source is a typo still wants their VPN.
	updater, err := appstate.NewUpdateWatcher(ctrl, cfg.Update, log.Printf)
	if err != nil {
		log.Println("update:", err)
	}
	updater.ApplyStaged()
	updateCtx, stopUpdates := context.WithCancel(context.Background())
	defer stopUpdates()
	go updater.Run(updateCtx)

	quit := quitAction(func() {
		ctrl.DisconnectAndWait()
		stopUpdates()
		// Disconnected by the line above, so this is a boundary by construction.
		updater.ApplyStaged()
	}, w.Hide, func() { fyne.Do(a.Quit) })

	// The File menu's Quit is explicit rather than left to Fyne. Fyne appends
	// one to any main menu that lacks it (addMissingQuitForMainMenu) and the one
	// it appends closes every window — which, now that closing hides, would
	// either hide the window or exit with the tunnel up depending on the tray.
	// Claiming the slot with IsQuit is what stops that, and it is also the
	// window's own guaranteed way out on a machine whose tray has gone away
	// since startup.
	quitItem := &fyne.MenuItem{Label: lang.L("Quit"), Action: quit, IsQuit: true}
	w.SetMainMenu(fyne.NewMainMenu(fyne.NewMenu(lang.L("File"), settingsItem, fyne.NewMenuItemSeparator(), quitItem)))

	w.SetContent(container.NewBorder(indicator.content, container.NewVBox(detail, action), nil, nil, picker.content))

	if trayOK {
		// RequestFocus as well as Show: a window restored behind everything else,
		// on a machine with a dozen others open, is one the user still has to go
		// and find — which is the complaint #186 is about, one step later.
		show := func() {
			w.Show()
			w.RequestFocus()
		}
		trayUI = newTrayMenu(ctrl, show, quit)
		if desk, ok := a.(desktop.App); ok {
			desk.SetSystemTrayMenu(trayUI.menu)
			// A left-click on the icon shows the window, which is what a user
			// tries first; the menu is the right-click. Fyne's own note is that
			// less compliant Linux panels ignore this, which is why "Show
			// Bacchus" is in the menu as well rather than instead.
			desk.SetSystemTrayWindow(w)
		} else {
			// tray.Available said yes and this build has no desktop.App to put
			// one on. Not reachable on either 1.0 platform, and if it ever is,
			// the close behaviour must fall back rather than hide into nothing.
			log.Println("tray: this build has no desktop app interface, so there is no tray to hide into")
			trayOK, trayUI = false, nil
		}
	}

	if trayOK {
		// X TUCKS AWAY; it does not disconnect (bacchus#186). Every desktop VPN
		// a user has met minimises to a tray, and the old behaviour dropped
		// their protection on a gesture that means the opposite.
		//
		// The notice is shown BEFORE the hide, once per run, because a user who
		// closes the window and finds the process still running goes looking for
		// a leak — and the window is the only place left to say anything at
		// all. Once per run rather than once per install on purpose: persisting
		// it would mean another file on the disk of somebody who is running this
		// software precisely to leave less behind, and the sentence is cheap.
		toldAboutTray := false
		w.SetCloseIntercept(func() {
			if toldAboutTray {
				w.Hide()
				return
			}
			toldAboutTray = true
			showTrayNotice(w)
		})
	} else {
		// No tray: keep exactly what this client has always done. Hiding here
		// would leave a running, connected, kill-switched client with no
		// surface at all, reachable only through the process list — where
		// killing it is bacchus#115's stranded machine.
		//
		// The teardown is now WAITED for, which the old two-liner only appeared
		// to do: Disconnect returns immediately and w.Close() took the process
		// down underneath it.
		w.SetCloseIntercept(quit)
	}
	// Taller than the 420x340 the shell shipped with: that window had an empty
	// centre, and the centre is now a list somebody has to be able to read
	// several rows of without scrolling. The width is unchanged - a country code
	// and a short status fit in it, and a wider window would make the state band
	// above compete less well with nothing at all.
	w.Resize(fyne.NewSize(420, 540))
	w.ShowAndRun()
}

// releaseLine is what the log's first line says this binary is.
//
// A support log that does not state its own version is a log whose reader has
// to ask a second question before they can use the first answer — and
// bacchus#114 is the case that makes it acute: a node on a stale binary
// registers, heartbeats and is assigned work while silently dropping every
// session, invisible in all three logs.
//
// Guarded by Stamped() rather than calling Current() outright, because Current
// panics on a MALFORMED stamp and the client already reaches it later, inside
// Engine.Start. An unstamped development build must not be made to panic here
// for the sake of a header line; a malformed one still panics, at connect,
// exactly where it did before.
func releaseLine() string {
	if !version.Stamped() {
		return "(no release stamp)"
	}
	return version.Current().String()
}

// showRefusal is what a second client does instead of arming a second
// machine-wide lockdown (bacchus#185).
//
// It is a window rather than a line on stderr, and that is the whole point of
// the card's "say so and exit, not die silently": a user double-clicks the
// desktop icon, and on a -H=windowsgui binary a message printed to a console
// that does not exist is indistinguishable from the program doing nothing. Three
// clients were running on the hardware pass before anybody noticed.
//
// It shares no state with the running client and takes no lock. It names the log
// file because "already running" is the first thing somebody will ask about, and
// the log is where the answer is.
func showRefusal(cause error, logPath string) {
	body := lang.L("Another copy of Bacchus is already running on this computer, so this one has stopped. Use the Bacchus icon in the notification area to open it.")
	if !errors.Is(cause, singleinstance.ErrAlreadyRunning) {
		// The other outcome: the guard could not be established at all, so
		// whether a client is running is unknown. Saying "already running"
		// would be a claim this process cannot make, and the user is the only
		// one who can check.
		body = lang.L("Bacchus could not check whether it is already running on this computer, and will not start a second copy: two of them can leave this machine unprotected while both say otherwise. Close any other Bacchus window and try again.")
	}
	showStopped(lang.L("Bacchus is already running"), body, "", logPath)
}

// showConfigRefusal is what this client does instead of starting with a config
// file it could not read (bacchus#255).
//
// Same window and same reasoning as showRefusal above, for a different refusal:
// on a -H=windowsgui binary there is no console, so a program that declines to
// start and says so anywhere but on screen has, from the user's side, done
// nothing at all.
//
// It names the FILE, which is the part the old detail line got wrong. This
// client reads from two candidates (appstate's configPaths) and the message a
// user saw — `invalid character 'ï»¿' looking for beginning of value` — named
// neither the file nor a cause anybody could act on. The parser's own text is
// still shown underneath, because for a trailing comma or a stray quote it is
// exactly the diagnostic, but it is no longer the whole message.
func showConfigRefusal(bad *appstate.ConfigUnreadableError, logPath string) {
	showStopped(
		lang.L("Bacchus could not read your settings file"),
		lang.L("Bacchus has stopped rather than start without the settings in this file, which would look like a fresh install and connect to nothing. Fix the file and start Bacchus again."),
		bad.Path+"\n"+bad.Err.Error(),
		logPath,
	)
}

// showStopped is the one window this client puts up when it will not start: a
// bold headline, one calm paragraph, an optional block of detail, and the log
// path. It runs its own Fyne app because it is used before — or instead of — the
// real one existing, and it shares no state with a running client.
func showStopped(headlineText, bodyText, detailText, logPath string) {
	a := app.NewWithID(appID)
	a.Settings().SetTheme(newCalmTheme())
	a.SetIcon(appIcon())
	w := a.NewWindow(appName)

	headline := widget.NewLabel(headlineText)
	headline.TextStyle = fyne.TextStyle{Bold: true}

	message := widget.NewLabel(bodyText)
	message.Wrapping = fyne.TextWrapWord

	rows := []fyne.CanvasObject{headline, message}
	if detailText != "" {
		detail := widget.NewLabel(detailText)
		detail.Wrapping = fyne.TextWrapWord
		detail.TextStyle = fyne.TextStyle{Monospace: true}
		rows = append(rows, detail)
	}
	if logPath != "" {
		where := widget.NewLabel(lang.L("Details are in:") + " " + logPath)
		where.Wrapping = fyne.TextWrapWord
		rows = append(rows, where)
	}

	w.SetContent(container.NewBorder(
		container.NewVBox(rows...),
		widget.NewButton(lang.L("Close"), a.Quit),
		nil, nil, nil,
	))
	w.Resize(fyne.NewSize(420, 260))
	w.ShowAndRun()
}

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
// Enrollment (bacchus#181) is the third, and it is the same argument reaching the
// two sentences #171 named but did not widen to. The second of them is the one
// that matters: it is what a user reads when enrollment cannot reach the account
// service, which is a moment they have something to act on and, until now, no way
// to read.
//
// enrollmentRefusalText's TERMINAL refusals (internal/appstate/controller.go) are
// deliberately not here. They are a different job — a coded refusal mapped to a
// sentence, in the package that owns the mapping — and widening to them is a
// decision rather than a follow-through, which is what #171 declined to make and
// #181 did not reopen.
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
	case appstate.DetailEnrolled:
		return lang.L("This device is now registered to your account.")
	case appstate.DetailEnrollUnreachable:
		return lang.L("Could not reach your account service to register this device — connecting with what this device already has.")
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
