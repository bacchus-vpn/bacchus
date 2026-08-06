//go:build windows

package tray

// available is unconditionally true on Windows.
//
// The notification area is part of the shell rather than an optional component:
// there is no supported Windows configuration with a desktop and no taskbar
// notification area, and fyne.io/systray reaches it through Shell_NotifyIcon,
// which every Windows since XP answers. It also re-registers the icon on the
// TaskbarCreated broadcast, so an explorer.exe restart — the one way the icon
// can vanish under a running client — puts it back by itself.
//
// The user can HIDE the icon in the overflow chevron, and that is deliberately
// not treated as absence: the icon is still there, still clickable, and still
// found by a user who goes looking. Treating a collapsed overflow as "no tray"
// would take the close-to-hide behaviour away from most Windows machines.
func available() bool { return true }
