//go:build linux

package singleinstance

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// acquire takes a non-blocking exclusive flock on <dir>/client.lock.
//
// flock rather than a PID file, for the reason the package doc gives: the lock
// belongs to the open file description, so the kernel drops it when the process
// dies by any route. A client killed mid-session — which bacchus#115 showed is
// a state this software really does reach — leaves nothing for the next launch
// to reason about or clean up.
//
// The file is NOT removed on release. Unlinking a flock'd path is a classic
// race: a second process can already be holding a lock on the same inode when
// the first unlinks it, and a third then creates a fresh inode and locks that,
// so two processes hold "the" lock at once. An empty 0600 file left behind
// inside the client's own directory costs nothing and is removed with the rest
// of it.
func acquire(dir string) (func(), error) {
	if dir == "" {
		return nil, errors.New("no per-user directory to keep the lock file in")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, LockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}
	return func() {
		// Closing the descriptor releases the lock; the explicit LOCK_UN is
		// there so the intent survives somebody later changing how the file is
		// held.
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
