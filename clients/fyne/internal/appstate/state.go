// Package appstate is the connection-state model and engine controller (issues
// #148/#149), kept deliberately free of any Fyne import. That split is what
// lets this package's tests run as plain `go test`, with no GUI toolchain
// (glfw/OpenGL need cgo - see the ADR) - only the outer main package touches
// fyne.* and needs that toolchain to build.
//
// ConnState is the single most important pixel in the app: a non-technical,
// possibly stressed user in a censored country must know their safety state
// at a glance, in plain language. Exactly one state is shown at a time; the
// outer ui.go binds it to a big icon+color+text indicator, never a jargon
// status line.
package appstate

import (
	"strings"

	"github.com/bacchus-vpn/bacchus/core"
)

// ConnState is the headline connection state. The zero value (Disconnected) is
// what the app starts and ends in.
type ConnState int

const (
	// Disconnected: no tunnel, nothing protected. Also where the app lands
	// after the user disconnects or a connect attempt fails outright.
	Disconnected ConnState = iota
	// Connecting: a connect attempt is in flight (dialing the coordinator,
	// negotiating the transport). Entered the moment the user presses Connect.
	Connecting
	// Protected: a session is up and traffic is flowing through it.
	Protected
	// Blocked: was Protected, and the live path just died. Named for the
	// kill-switch's fail-closed posture (ADR-0014): this app has no OS-level
	// enforcement of its own yet (out of scope for this skeleton - see the
	// ADR), but the *signal* is the same one the Windows tray client already
	// uses for the identical state (main.go's eventStatus) - a transport-level
	// drop while previously protected, not a firewall check.
	Blocked
)

// StateFor computes the next headline state given the state just prior and one
// core.Event. Every other transition (Disconnected->Connecting->Protected, or
// back to Disconnected on a failed attempt) is driven directly by
// Controller's own call sequence around Start/Connect/Stop, exactly as the
// Windows tray client's connect()/disconnect() drive its status line - those
// transitions have a corresponding blocking call that succeeds or fails right
// there. The one transition with no such call is a live path dying (or
// recovering) underneath an already-established session, which is only
// observable from the ICE event stream, so that is all this function
// handles. Mirrors eventStatus's ICE branch (clients/windows/main.go)
// exactly, typed as a state instead of a status string.
func StateFor(cur ConnState, ev core.Event) ConnState {
	if ev.Kind != core.EventICE || (cur != Protected && cur != Blocked) {
		return cur
	}
	switch {
	case strings.Contains(ev.Message, ": disconnected"), strings.Contains(ev.Message, ": failed"), strings.Contains(ev.Message, ": closed"):
		return Blocked
	case strings.Contains(ev.Message, ": connected"), strings.Contains(ev.Message, ": completed"):
		return Protected
	}
	return cur
}

// DetailFor decides whether ev should update the small secondary detail line
// beneath the headline state, and with what text. Mirrors eventStatus's own
// show/suppress rules (clients/windows/main.go): an error always surfaces,
// since no client-role error source fires once a session is protected; info
// narrates the connect attempt and only matters pre-protected; ICE detail is
// redundant with the headline state itself once protected, so it is never
// separately shown. EventSession/EventConnected are plumbing, logged
// elsewhere, never surfaced here.
func DetailFor(ev core.Event, cur ConnState) (text string, show bool) {
	switch ev.Kind {
	case core.EventError:
		return ev.Message, true
	case core.EventInfo:
		if cur == Protected {
			return "", false
		}
		return ev.Message, true
	default:
		return "", false
	}
}
