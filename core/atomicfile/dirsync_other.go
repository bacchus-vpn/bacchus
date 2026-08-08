//go:build !windows

package atomicfile

import "os"

// syncDirHandle fsyncs a directory, which POSIX defines and which is the only
// way to make a rename or a create in that directory survive a power loss.
func syncDirHandle(d *os.File) error { return d.Sync() }
