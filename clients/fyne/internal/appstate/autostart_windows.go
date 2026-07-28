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
// HKEY_LOCAL_MACHINE's equivalent, which is machine-wide and admin-only).
const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`

// SetLaunchOnBoot enables or disables starting this binary at login, via the
// per-user registry Run key. Idempotent both ways: enabling when already
// enabled overwrites the same value (picks up a path change after the binary
// moved); disabling when never enabled is a no-op, not an error — matching
// SetLaunchOnBoot's other platform implementations, and letting main.go call
// this unconditionally at startup to reconcile the OS state with whatever
// Config.LaunchOnBoot says, self-healing if the entry was ever removed by
// hand.
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
