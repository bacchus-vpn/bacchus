package update

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// This package writes its own atomic-write helper rather than importing one.
//
// The sequence is core/policy.Cache.writeAtomic's — temp file in the SAME
// directory as the target, chmod, write, Sync, close, rename — which ADR-0052 §
// picked out as "the exact sequence this needs". What differs is the payload: that
// one writes a JSON cache and this one publishes an executable, so the mode is a
// parameter, the directory entry is fsynced after the rename, and the failure
// paths below care about leaving a running binary alone rather than about a
// reader seeing half a file.
//
// Same directory, not merely the same filesystem, so the final rename(2) cannot
// cross a mount boundary. That is the one real constraint this design adds, and it
// is the same one core/policy lives with.

// writeAtomic writes b to path via a temporary file in the same directory and a
// rename, so a reader never observes a partial file.
func writeAtomic(path string, b []byte, mode fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".bacchus-update-*")
	if err != nil {
		return fmt.Errorf("update: create temp in %s: %w", dir, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once the rename has succeeded
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("update: chmod temp: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("update: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("update: sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("update: close temp: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("update: install %s: %w", path, err)
	}
	return nil
}

// syncDir fsyncs a directory so a rename into it survives a power loss. Renaming
// is atomic with respect to a concurrent reader whether or not this runs; what it
// buys is that the new directory entry is durable, which for a binary published by
// rename is the difference between a crash losing the update and a crash losing
// the binary.
//
// A failure is reported but is never fatal to a caller that has already renamed:
// the rename happened, and some filesystems (and every Windows build, where
// opening a directory as a file is not a thing) simply will not answer this. The
// callers below log it rather than unwinding a successful publish.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
