//go:build linux

package appstate

import (
	"fmt"
	"os"
	"path/filepath"
)

// autostartDesktopFileName identifies this client's own XDG autostart entry,
// distinct from any other Bacchus binary that might exist on the same
// machine (the walk client is Windows-only today, but the file name is
// deliberately specific rather than "bacchus.desktop" regardless).
const autostartDesktopFileName = "bacchus-fyne.desktop"

// autostartDesktopFilePath returns where the XDG autostart entry lives:
// $XDG_CONFIG_HOME/autostart (os.UserConfigDir, the same base
// configPaths uses for this client's own settings file) plus the standard
// "autostart" subdirectory every XDG-compliant desktop environment scans at
// login (GNOME, KDE, XFCE, and derivatives).
func autostartDesktopFilePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "autostart", autostartDesktopFileName), nil
}

// desktopEntryTemplate is the minimal XDG Desktop Entry this client needs:
// just enough for a desktop environment's autostart scanner to launch Exec
// at login. Exec is double-quoted per the Desktop Entry Specification's own
// quoting rule, since os.Executable's path can contain spaces.
const desktopEntryTemplate = "[Desktop Entry]\nType=Application\nName=Bacchus\nExec=\"%s\"\nX-GNOME-Autostart-enabled=true\n"

// LaunchOnBootActive reports whether this client's own XDG autostart file
// currently exists — used by main.go's startup reconcile (issue #170) to
// tell "never configured" apart from "configured, then removed outside the
// app" before deciding whether to recreate it. A hand-deleted entry is a
// real, common way a user turns this off (simpler than finding it in a
// desktop environment's own startup-apps settings, and the only way on a
// minimal window manager with no such settings UI at all) — silently
// recreating it on the next launch would be exactly backwards for a client
// whose whole point is doing only what it says it does.
func LaunchOnBootActive() (bool, error) {
	path, err := autostartDesktopFilePath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetLaunchOnBoot enables or disables starting this binary at login, via the
// XDG autostart mechanism (a .desktop file dropped in the per-user autostart
// directory). Idempotent both ways: enabling when already enabled overwrites
// the file (picks up a path change after the binary moved); disabling when
// never enabled is a no-op, not an error — matching SetLaunchOnBoot's other
// platform implementations. main.go's startup reconcile (issue #170) calls
// this to enable only when LaunchOnBootActive already reports true
// (refreshing a possibly-stale path) or to disable unconditionally — never
// to blindly recreate a file the user removed by hand; see
// LaunchOnBootActive's doc for why that matters.
func SetLaunchOnBoot(enabled bool) error {
	path, err := autostartDesktopFilePath()
	if err != nil {
		return err
	}

	if !enabled {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprintf(desktopEntryTemplate, exe)), 0o600)
}
