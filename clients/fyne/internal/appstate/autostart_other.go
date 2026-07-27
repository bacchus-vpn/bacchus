//go:build !windows && !linux

package appstate

import "errors"

// ErrLaunchOnBootUnsupported is SetLaunchOnBoot's error on a platform with
// neither the Windows nor the Linux implementation (macOS today - the app
// itself still builds and runs there via Fyne, but nobody has implemented or
// verified a launchd LaunchAgent for it; see clients/fyne/README.md). This
// file exists so that omission is a clear, named error at the one call site
// that can hit it, not a missing-symbol build break on a platform this repo
// otherwise still compiles for.
var ErrLaunchOnBootUnsupported = errors.New("launch-on-boot is not supported on this platform yet")

// SetLaunchOnBoot enabled=false is always a safe no-op here: this platform
// has no autostart entry of this client's making to remove, on any of the
// platforms this build tag covers, since SetLaunchOnBoot(true) always failed
// on it and nothing else in this codebase creates one.
func SetLaunchOnBoot(enabled bool) error {
	if !enabled {
		return nil
	}
	return ErrLaunchOnBootUnsupported
}

// LaunchOnBootActive always reports false: SetLaunchOnBoot(true) always
// fails on this build tag (above), so there is never an entry of this
// client's making to find.
func LaunchOnBootActive() (bool, error) { return false, nil }
