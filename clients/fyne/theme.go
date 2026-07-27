// Custom theme (issue #148): a calm, trustworthy palette, not Fyne's stock
// blue/orange. It overrides colors only - icons, fonts, and sizes fall through
// to theme.DefaultTheme() unchanged, since nothing about this app needs a
// different icon set or type scale, just different colors. Reusing Fyne's own
// semantic names (rather than inventing app-specific ones) means the same
// palette drives both ordinary widgets (buttons, links) and the connection-
// state indicator (issue #149, ui.go) for free - Protected reads
// theme.ColorNameSuccess, Blocked reads theme.ColorNameError, and so on.
package main

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

type calmTheme struct {
	fyne.Theme
}

func newCalmTheme() fyne.Theme {
	return &calmTheme{Theme: theme.DefaultTheme()}
}

func (t *calmTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return variantColor(variant, color.NRGBA{R: 0x2e, G: 0x6e, B: 0x8e, A: 0xff}, color.NRGBA{R: 0x5f, G: 0xa8, B: 0xc7, A: 0xff})
	case theme.ColorNameSuccess:
		return variantColor(variant, color.NRGBA{R: 0x2f, G: 0x85, B: 0x58, A: 0xff}, color.NRGBA{R: 0x59, G: 0xb9, B: 0x87, A: 0xff})
	case theme.ColorNameWarning:
		return variantColor(variant, color.NRGBA{R: 0xc9, G: 0x8a, B: 0x1b, A: 0xff}, color.NRGBA{R: 0xe0, G: 0xa8, B: 0x3e, A: 0xff})
	case theme.ColorNameError:
		return variantColor(variant, color.NRGBA{R: 0xb8, G: 0x3c, B: 0x34, A: 0xff}, color.NRGBA{R: 0xe0, G: 0x6f, B: 0x66, A: 0xff})
	case theme.ColorNameDisabled:
		return variantColor(variant, color.NRGBA{R: 0x9a, G: 0x9f, B: 0xa8, A: 0xff}, color.NRGBA{R: 0x6b, G: 0x70, B: 0x78, A: 0xff})
	case theme.ColorNameForegroundOnPrimary, theme.ColorNameForegroundOnSuccess, theme.ColorNameForegroundOnError:
		return color.White
	case theme.ColorNameForegroundOnWarning:
		return color.Black
	}
	return t.Theme.Color(name, variant)
}

func variantColor(variant fyne.ThemeVariant, light, dark color.Color) color.Color {
	if variant == theme.VariantDark {
		return dark
	}
	return light
}

// stateColorName maps a headline appstate.ConnState to the semantic color
// that represents it, so the indicator (ui.go) and the rest of the theme never
// disagree about what "safe" or "dangerous" looks like.
func stateColorName(s appstate.ConnState) fyne.ThemeColorName {
	switch s {
	case appstate.Protected:
		return theme.ColorNameSuccess
	case appstate.Blocked:
		return theme.ColorNameError
	case appstate.Connecting:
		return theme.ColorNamePrimary
	default: // appstate.Disconnected
		return theme.ColorNameDisabled
	}
}

// stateForegroundName is the readable-on-top-of counterpart to stateColorName.
func stateForegroundName(s appstate.ConnState) fyne.ThemeColorName {
	switch s {
	case appstate.Protected:
		return theme.ColorNameForegroundOnSuccess
	case appstate.Blocked:
		return theme.ColorNameForegroundOnError
	case appstate.Connecting:
		return theme.ColorNameForegroundOnPrimary
	default: // appstate.Disconnected
		return theme.ColorNameForeground
	}
}
