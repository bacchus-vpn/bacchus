//go:build !windows && !linux

package tray

// available is false wherever this has not been answered.
//
// 1.0 is Windows plus Linux desktop, so the only platform reaching this today
// is macOS, which has a tray and would answer yes — but it also has no
// enforcement.Enforcer ([E9]) and is not built or run by anything here, so an
// unverified yes would be a claim nobody has tested standing between a user and
// their window.
//
// False is not a degradation: it is the client's pre-#186 behaviour, where
// closing the window disconnects and exits. That is a worse experience and a
// completely safe one.
func available() bool { return false }
