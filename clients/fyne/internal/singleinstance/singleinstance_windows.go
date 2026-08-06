//go:build windows

package singleinstance

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// acquire creates the two named mutexes bacchus.iss's AppMutex looks for.
//
// windows.CreateMutex returns a VALID handle together with
// ERROR_ALREADY_EXISTS when the name is taken, which is what makes this a
// detector rather than a lock: nothing waits, nothing is acquired, and the
// question "is one already running" is answered by the error and not by the
// handle. The handle we get in that case is closed immediately — holding a
// second reference to somebody else's mutex would keep the name alive past
// their exit and make the NEXT launch believe a dead client is still there.
//
// The global name is tried first and its ERROR_ALREADY_EXISTS is decisive. Only
// a failure to CREATE it (privilege, in practice) falls through to the session
// name; a machine where the global namespace is reachable never consults the
// session one for the answer, it just also creates it so the installer finds
// either.
func acquire(string) (func(), error) {
	var handles []windows.Handle
	closeAll := func() {
		for _, h := range handles {
			_ = windows.CloseHandle(h)
		}
	}

	globalErr := createMutex(GlobalMutexName, &handles)
	if globalErr == ErrAlreadyRunning {
		closeAll()
		return nil, ErrAlreadyRunning
	}

	sessionErr := createMutex(SessionMutexName, &handles)
	if sessionErr == ErrAlreadyRunning {
		closeAll()
		return nil, ErrAlreadyRunning
	}

	if len(handles) == 0 {
		// Neither namespace would take the name for a reason that is not
		// "somebody else has it". The caller is told the guard is UNKNOWN
		// rather than told the machine is free.
		return nil, fmt.Errorf("could not create the single-instance mutex: %v; %v", globalErr, sessionErr)
	}
	return closeAll, nil
}

// createMutex creates one named mutex, appending its handle to out on success.
// Returns ErrAlreadyRunning if the name is taken, nil on success, or the
// underlying error.
//
// initialOwner is false deliberately. Nothing here ever waits on the mutex, so
// owning it buys nothing and costs the abandoned-mutex semantics that come with
// an owned one; existence of the NAME is the entire signal, and it is also the
// only thing Inno Setup's AppMutex checks.
func createMutex(name string, out *[]windows.Handle) error {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	h, err := windows.CreateMutex(nil, false, p)
	if h != 0 && err == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(h)
		return ErrAlreadyRunning
	}
	if err != nil && err != windows.ERROR_ALREADY_EXISTS {
		return err
	}
	if h == 0 {
		return fmt.Errorf("CreateMutex(%q) returned no handle", name)
	}
	*out = append(*out, h)
	return nil
}
