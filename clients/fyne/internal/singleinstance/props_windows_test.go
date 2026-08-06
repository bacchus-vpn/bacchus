//go:build windows

package singleinstance

// guarded and fileScoped describe this platform's implementation to the
// portable tests. The Windows guard is a kernel object name, so it spans the
// whole machine regardless of which directory any copy of the client was
// installed into — which is the scope #185 needs, since the kill-switch it
// protects is machine-wide.
const (
	guarded    = true
	fileScoped = false
)
