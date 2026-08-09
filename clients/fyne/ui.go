package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/theme"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

// stateIndicator is the single most important widget in the app (old #149):
// a full-width color band carrying the headline state and a plain-language
// description, unmistakable at a glance for a non-technical, possibly
// stressed user. update must only be called from the Fyne UI goroutine -
// main.go is the only caller, via fyne.Do.
type stateIndicator struct {
	bg          *canvas.Rectangle
	headline    *canvas.Text
	description *canvas.Text
	content     fyne.CanvasObject
}

func newStateIndicator() *stateIndicator {
	bg := canvas.NewRectangle(theme.Color(theme.ColorNameDisabled))

	headline := canvas.NewText("", theme.Color(theme.ColorNameForeground))
	headline.TextSize = 28
	headline.TextStyle = fyne.TextStyle{Bold: true}
	headline.Alignment = fyne.TextAlignCenter

	description := canvas.NewText("", theme.Color(theme.ColorNameForeground))
	description.TextSize = 14
	description.Alignment = fyne.TextAlignCenter

	text := container.NewVBox(headline, description)
	s := &stateIndicator{
		bg:          bg,
		headline:    headline,
		description: description,
		content:     container.NewStack(bg, container.NewPadded(container.NewPadded(container.NewCenter(text)))),
	}
	s.update(appstate.Disconnected, false, false)
	return s
}

// update repaints the indicator for state s: fill, text color, and copy all
// come from the same (stateColorName, stateForegroundName) pair the theme
// defines (theme.go), so the indicator and the rest of the app's palette can
// never disagree about what "safe" looks like.
//
// enforced is Controller.DeviceEnforced: whether a Protected session on this
// build routes the whole device or only what is pointed at the proxy. It
// changes the two words a user reads first, so it is passed in rather than
// inferred here.
//
// lanBlocked is whether THIS session's lockdown also cuts the machine off from
// its own local network (ADR-0073, bacchus#257). Passed in for the same reason
// as enforced and one more: it depends on a setting, not on the platform, so
// nothing here could infer it.
func (s *stateIndicator) update(state appstate.ConnState, enforced, lanBlocked bool) {
	fg := theme.Color(stateForegroundName(state))
	s.bg.FillColor = theme.Color(stateColorName(state))
	s.headline.Color = fg
	s.description.Color = fg
	s.headline.Text = stateHeadline(state, enforced)
	s.description.Text = stateDescription(state, enforced, lanBlocked)
	s.bg.Refresh()
	s.headline.Refresh()
	s.description.Refresh()
}

// stateHeadline is the one or two words a user sees first. Plain language
// only - never protocol jargon (no "tunnel", "ICE", "handshake").
func stateHeadline(s appstate.ConnState, enforced bool) string {
	switch s {
	case appstate.Connecting:
		return lang.L("Connecting…")
	case appstate.Protected:
		// The headline is the glanceable layer — 28px, bold, on a success-green
		// band — and it is what a stressed user reads and acts on. A qualifier
		// at 14px underneath does not repair it: the colour and the type size
		// win, every time. So this word has to be true on its own.
		//
		// Which it is depends on the platform, not on the mood of the app. With
		// an Enforcer (Windows, bacchus#59) the device really is routed — TUN,
		// routes, kill-switch, the same code the Windows tray client shipped — and a
		// connect that could not do that aborts rather than arriving here, so
		// reaching Protected on such a build means it worked. That earns
		// "Protected", the word ADR-0039 said this would take back "the day
		// tun2socks lands and the app really does protect the device".
		//
		// Without one ([E9] macOS, [E10] Linux), nothing is routed and the
		// SOCKS port is the entire interface between the tunnel and the user's
		// traffic — so it keeps saying exactly that.
		if enforced {
			return lang.L("Protected")
		}
		return lang.L("Proxy ready")
	case appstate.Blocked:
		return lang.L("Blocked")
	default:
		return lang.L("Disconnected")
	}
}

// stateDescription is one calm sentence expanding on the headline.
//
// Two of these sentences used to say more than the app does, which is the worst
// thing a line in this particular app can do — a user who believes a false
// "you are safe" acts on it, in a country where acting on it is the risk.
//
// "Your connection is private and secure" described a device-wide VPN. This client
// routes nothing: no TUN, no route flip, no system proxy (ADR-0039's Scope). It
// offers a SOCKS5 proxy and protects exactly what is pointed at it, so that is what
// this says, address included — the address is not jargon here, it is the only
// instruction that makes the tunnel usable at all.
//
// "Nothing is exposed" described a kill switch. This client now has one on any
// platform with an Enforcer (bacchus#59) — ADR-0014's, the same code
// the Windows tray client armed — but the Blocked copy below still does not make that
// claim, deliberately. The kill-switch is a setting a user can turn off
// (Config.DisableKillSwitch), so "nothing is exposed" is true of an armed
// lockdown and false of a disabled one, and this function is handed the
// platform's capability, not that session's policy. Telling a user their
// traffic is contained when they themselves turned containment off is the
// same class of error as the two above. It reports that the path died, which
// is true either way, and leaves the stronger sentence to whoever is willing
// to plumb the actual armed state to it.
//
// # The local network (bacchus#257, ADR-0073)
//
// lanBlocked is that armed state finally plumbed, for the one claim that needed
// it. An armed kill-switch does not only stop leaks outward: the allowlist holds
// the tunnel adapter, the control plane, loopback and DHCP, and no RFC1918 range
// is in it, so every LAN destination falls to the default Block. The router's own
// page, a printer, a NAS, local SSH — all refused, measured on hardware, from the
// instant this band turns green.
//
// The block itself is kept, on the record (ADR-0073): a hole in the lockdown for
// "the local network" is a hole for whatever an attacker can reach from an
// address in that range. What was NOT defensible is that it happened without a
// word — the only visible change was this app saying Protected, so the
// conclusion available to the user was that Bacchus broke their network, and the
// action available to them was to turn off the one setting that must not be
// turned off for a bad reason.
//
// So it is said here, in the same breath as the good news, rather than in a
// document nobody reads before they need it. Only when it is TRUE: with the
// kill-switch off the LAN keeps working, because a directly connected subnet is
// an on-link route that the split-default (0.0.0.0/1 + 128.0.0.0/1) never
// overrides — it is the firewall that blocks it, not the routing.
func stateDescription(s appstate.ConnState, enforced, lanBlocked bool) string {
	switch s {
	case appstate.Connecting:
		return lang.L("Finding the safest way to connect…")
	case appstate.Protected:
		if enforced {
			if lanBlocked {
				return lang.L("All of this device's traffic goes through Bacchus. Other devices on your local network — printers, file shares, your router's own page — are not reachable while it is.")
			}
			return lang.L("All of this device's traffic goes through Bacchus.")
		}
		return lang.L("Apps set to use the proxy at 127.0.0.1:1080 are protected. Other apps are not.")
	case appstate.Blocked:
		return lang.L("The connection dropped — trying to reconnect…")
	default:
		return lang.L("You're not protected right now.")
	}
}
