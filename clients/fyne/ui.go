package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/theme"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

// stateIndicator is the single most important widget in the app (issue #149):
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
	s.update(appstate.Disconnected)
	return s
}

// update repaints the indicator for state s: fill, text color, and copy all
// come from the same (stateColorName, stateForegroundName) pair the theme
// defines (theme.go), so the indicator and the rest of the app's palette can
// never disagree about what "safe" looks like.
func (s *stateIndicator) update(state appstate.ConnState) {
	fg := theme.Color(stateForegroundName(state))
	s.bg.FillColor = theme.Color(stateColorName(state))
	s.headline.Color = fg
	s.description.Color = fg
	s.headline.Text = stateHeadline(state)
	s.description.Text = stateDescription(state)
	s.bg.Refresh()
	s.headline.Refresh()
	s.description.Refresh()
}

// stateHeadline is the one or two words a user sees first. Plain language
// only - never protocol jargon (no "tunnel", "ICE", "handshake").
func stateHeadline(s appstate.ConnState) string {
	switch s {
	case appstate.Connecting:
		return lang.L("Connecting…")
	case appstate.Protected:
		// NOT "Protected". The headline is the glanceable layer — 28px, bold, on a
		// success-green band — and it is what a stressed user reads and acts on. This
		// client routes nothing on its own (ADR-0039's Scope), so a device-wide
		// "Protected" at 28px with the scope in 14px underneath is a false claim
		// wearing a true footnote: the qualifier loses to the colour and the type
		// size, every time. It says what is actually true instead, and the day
		// tun2socks lands and the app really does protect the device, this earns the
		// stronger word back.
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
// "Nothing is exposed" described a kill switch. There is no kill switch in this
// client (ADR-0014 is the Windows client's). The state is named Blocked for the
// posture it will eventually enforce; today it reports that the path died, and it
// no longer tells the user what is or is not leaving their machine, because it has
// no way to know.
func stateDescription(s appstate.ConnState) string {
	switch s {
	case appstate.Connecting:
		return lang.L("Finding the safest way to connect…")
	case appstate.Protected:
		return lang.L("Apps set to use the proxy at 127.0.0.1:1080 are protected. Other apps are not.")
	case appstate.Blocked:
		return lang.L("The connection dropped — trying to reconnect…")
	default:
		return lang.L("You're not protected right now.")
	}
}
