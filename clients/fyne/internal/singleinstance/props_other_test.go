//go:build !windows && !linux

package singleinstance

// guarded and fileScoped describe this platform's implementation to the
// portable tests. Both false: acquire is the documented stub, and the portable
// tests assert the stub's behaviour rather than skipping, so that a platform
// gaining an Enforcer has to come here and change an assumption on purpose.
const (
	guarded    = false
	fileScoped = false
)
