//go:build windows

package appstate

import (
	"os"

	"golang.org/x/sys/windows/registry"
)

// autostartValueName is the value this client owns under the Run key. Fixed
// and distinct from clients/windows's own product name only in that this is
// a separate binary; a machine could in principle run both clients, and each
// must be able to register/unregister itself without touching the other's
// entry — the walk client has no autostart entry of its own today, but there
// is no reason to couple this one to it.
const autostartValueName = "BacchusFyne"

// runKeyPath is the standard per-user autostart location: everything here
// launches once at login, no elevation required to read or write it (unlike
// HKEY_LOCAL_MACHINE's equivalent, which is machine-wide and admin-only). A
// var, not a const, so autostart_windows_test.go can redirect it to a
// private test key (issue #170) instead of exercising the real Run key.
var runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// LaunchOnBootActive reports whether this client's own Run value currently
// exists — used by main.go's startup reconcile (issue #170) to tell "never
// configured" apart from "configured, then removed outside the app" before
// deciding whether to recreate it. Presence alone, not enabled-ness: Windows
// tracks a Task Manager "Startup apps" disable via a separate, undocumented
// StartupApproved\Run binary flag this function does not read (its format
// isn't documented, varies across Windows versions, and there is no
// supported API to read it) — so disabling this entry from Task Manager
// rather than deleting it outright is a known gap this cannot detect, left
// as such rather than guessed at.
func LaunchOnBootActive() (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			return false, nil
		}
		return false, err
	}
	defer k.Close()
	_, _, err = k.GetStringValue(autostartValueName)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetLaunchOnBoot enables or disables starting this binary at login, via the
// per-user registry Run key. Idempotent both ways: enabling when already
// enabled overwrites the same value (picks up a path change after the binary
// moved); disabling when never enabled is a no-op, not an error — matching
// SetLaunchOnBoot's other platform implementations. main.go's startup
// reconcile (issue #170) calls this to enable only when LaunchOnBootActive
// already reports true (refreshing a possibly-stale path) or to disable
// unconditionally — never to blindly recreate an entry the user removed by
// hand; see LaunchOnBootActive's doc for why that matters.
func SetLaunchOnBoot(enabled bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if !enabled {
		if err := k.DeleteValue(autostartValueName); err != nil && err != registry.ErrNotExist {
			return err
		}
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// Quoted: os.Executable's path can contain spaces (e.g. under "Program
	// Files"), and the Run key's value is executed the same way a shell would
	// parse a typed command line — an unquoted space would split the path in
	// two.
	return k.SetStringValue(autostartValueName, `"`+exe+`"`)
}
