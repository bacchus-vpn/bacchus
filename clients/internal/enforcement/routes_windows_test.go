//go:build windows

package enforcement

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestNewPSCmdRunsWindowless guards the console-window fix: every powershell.exe
// the client spawns must carry CREATE_NO_WINDOW, or a -H=windowsgui process
// flashes a console window on each of the many calls runPS makes.
func TestNewPSCmdRunsWindowless(t *testing.T) {
	cmd := newPSCmd("Write-Output hi")
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Fatalf("newPSCmd must set CREATE_NO_WINDOW (%#x); got SysProcAttr=%+v", createNoWindow, cmd.SysProcAttr)
	}
}

// wrapLikeWintun reproduces the %w chain golang.zx2c4.com/wintun and
// golang.zx2c4.com/wireguard/tun put between the Win32 error and createTUN's
// caller, verbatim as of the versions in go.mod (wintun
// v0.0.0-20230126152724, wireguard v0.0.0-20260522210424):
//
//	tun.CreateTUNWithRequestedGUID: "Error creating interface: %w"
//	wintun lazyProc.Find:           "Error loading %v DLL: %w"   (load path only)
//	wintun lazyDLL.Load:            "Unable to load library: %w" (load path only)
//
// The load path goes through all three, because Find() runs before any syscall;
// anything the loaded DLL then does comes back through the first alone.
//
// What no synthetic error can check is that those layers keep using %w rather
// than %v. If a future bump drops the wrapping, errors.Is stops seeing the
// Errno and every failure lands on createTUNAdvice's default branch — which
// names both causes, so the client degrades to a vaguer message rather than a
// wrong one. That is the reason the default says both.
func wrapLikeWintun(errno windows.Errno, viaDLLLoad bool) error {
	if viaDLLLoad {
		load := fmt.Errorf("Unable to load library: %w", errno)
		find := fmt.Errorf("Error loading %v DLL: %w", "wintun.dll", load)
		return fmt.Errorf("Error creating interface: %w", find)
	}
	return fmt.Errorf("Error creating interface: %w", errno)
}

// TestCreateTUNAdviceNamesTheCauseThatHappened is bacchus#135's third point.
// Before this, a missing wintun.dll and an unelevated run produced the SAME
// sentence and it named only elevation — so the user who had the other problem
// was actively pointed away from their fix, which is the failure mode
// bacchus#115 hit on real hardware with the DLL in place and again with it
// removed.
//
// Mutation check: drop ERROR_MOD_NOT_FOUND from isDLLLoadFailure and the
// missing-DLL case falls to the both-causes default, which this names.
func TestCreateTUNAdviceNamesTheCauseThatHappened(t *testing.T) {
	const exe = "bacchus-fyne.exe"
	for _, tc := range []struct {
		name       string
		err        error
		wantDLL    bool // the sentence must talk about wintun.dll
		wantAdmin  bool // ...and/or about Administrator
		wantReason string
	}{
		{
			name:       "wintun.dll nowhere on the search path",
			err:        wrapLikeWintun(windows.ERROR_MOD_NOT_FOUND, true),
			wantDLL:    true,
			wantReason: "LoadLibraryEx could not find the module at all",
		},
		{
			name:       "wintun.dll of the wrong architecture",
			err:        wrapLikeWintun(windows.ERROR_BAD_EXE_FORMAT, true),
			wantDLL:    true,
			wantReason: "the wintun.net zip has one wintun.dll per arch and they share a name",
		},
		{
			name:       "a wintun.dll without the entry point",
			err:        wrapLikeWintun(windows.ERROR_PROC_NOT_FOUND, true),
			wantDLL:    true,
			wantReason: "GetProcAddress failed, so the file is not this wintun",
		},
		{
			name:       "a wintun.dll whose DllMain refused",
			err:        wrapLikeWintun(windows.ERROR_DLL_INIT_FAILED, true),
			wantDLL:    true,
			wantReason: "the load itself failed, so nothing the DLL does is implicated",
		},
		{
			name:       "not elevated",
			err:        wrapLikeWintun(windows.ERROR_ACCESS_DENIED, false),
			wantAdmin:  true,
			wantReason: "the driver install wintun performs is an administrator operation",
		},
		{
			name:       "not elevated, reported as a missing privilege",
			err:        wrapLikeWintun(windows.ERROR_PRIVILEGE_NOT_HELD, false),
			wantAdmin:  true,
			wantReason: "same cause, the other code wintun's refusal path can produce",
		},
		{
			// The honest default. wintun's refusal codes are not contractual,
			// so an unrecognised one must name both causes rather than pick.
			name:       "some other failure from the loaded DLL",
			err:        wrapLikeWintun(windows.ERROR_GEN_FAILURE, false),
			wantDLL:    true,
			wantAdmin:  true,
			wantReason: "nothing identifies which cause this is, so it may not claim one",
		},
		{
			// ERROR_FILE_NOT_FOUND deliberately does NOT mean "no wintun.dll":
			// LoadLibraryEx reports that as ERROR_MOD_NOT_FOUND, so a 2 here
			// came from the loaded DLL and must not send the user to
			// re-download a file they already have.
			name:       "a file-not-found from the loaded DLL is not a missing DLL",
			err:        wrapLikeWintun(windows.ERROR_FILE_NOT_FOUND, false),
			wantDLL:    true,
			wantAdmin:  true,
			wantReason: "not exclusive to the loader, so it may not be claimed as one",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := createTUNAdvice(tc.err, exe)
			gotDLL := strings.Contains(got, "wintun.dll")
			gotAdmin := strings.Contains(got, "Administrator")
			if gotDLL != tc.wantDLL {
				t.Errorf("advice %q: wintun.dll mentioned = %v, want %v — %s", got, gotDLL, tc.wantDLL, tc.wantReason)
			}
			if gotAdmin != tc.wantAdmin {
				t.Errorf("advice %q: Administrator mentioned = %v, want %v — %s", got, gotAdmin, tc.wantAdmin, tc.wantReason)
			}
			if !strings.Contains(got, exe) {
				t.Errorf("advice %q does not name the running binary %q — the user has to find that file to act on this", got, exe)
			}
		})
	}
}

// TestCreateTUNAdviceNamesNoRetiredBinary is bacchus#135's second point, kept
// as its own test because it is the part that failed silently for two
// releases: the text named `bacchus.exe`, which was correct until bacchus#59
// made this package shared and bacchus#138 deleted that client. Nothing broke
// — the advice simply started naming a file no user has.
//
// The guard is that the binary name comes from the CALLER, so there is no
// constant here that can go stale in the same way. runningExeName supplies it
// from os.Executable in production.
func TestCreateTUNAdviceNamesNoRetiredBinary(t *testing.T) {
	for _, err := range []error{
		wrapLikeWintun(windows.ERROR_MOD_NOT_FOUND, true),
		wrapLikeWintun(windows.ERROR_ACCESS_DENIED, false),
		wrapLikeWintun(windows.ERROR_GEN_FAILURE, false),
	} {
		got := createTUNAdvice(err, "whatever-the-user-launched.exe")
		if strings.Contains(got, "bacchus.exe") {
			t.Errorf("advice %q names bacchus.exe, the client retired in bacchus#138; it must name the running binary it was given", got)
		}
	}
}

// TestRunningExeNameIsAFileName covers the fallback path's contract rather
// than the happy one: whatever os.Executable says, this must hand
// createTUNAdvice something that reads as a file name in a sentence, never a
// full path, an empty string or a bare separator.
func TestRunningExeNameIsAFileName(t *testing.T) {
	got := runningExeName()
	if got == "" || got == "." || strings.ContainsAny(got, `\/`) {
		t.Fatalf("runningExeName() = %q, want a bare file name", got)
	}
}

// ---------------------------------------------------------------------------
// A route that is already there is not a failure (bacchus#259)
// ---------------------------------------------------------------------------

// TestEveryRouteAddToleratesAnExistingRoute is bacchus#259's second finding. One
// connect on real hardware logged
//
//	[tun] ps failed: New-NetRoute -DestinationPrefix "<ip>" … | New-NetRoute : Instance MSFT_NetRoute already exists
//
// at least fifteen times in nine seconds. Every one was the route table already
// holding what the call wanted, and every one spent part of a 256 KiB log budget
// that in the same session had no room left for the SOCKS bind failure the user
// was actually shown.
//
// All four route adds are covered rather than only the one in the report,
// because they are the same call with different arguments and a fix that reached
// three of them would be a fix somebody has to remember next time.
//
// Mutation check: put a bare `New-NetRoute … -ErrorAction Stop` back in any one
// of them and this names that one.
func TestEveryRouteAddToleratesAnExistingRoute(t *testing.T) {
	gw := gatewayInfo{nextHop: "192.0.2.1", nextHopV6: "2001:db8::1", ifIndex: 7, ifAlias: "Ethernet"}
	for _, tc := range []struct {
		name string
		call func(o *winOS)
	}{
		{"addExclusionRoutes", func(o *winOS) { o.addExclusionRoutes([]string{"198.51.100.4"}, gw) }},
		{"addExclusionRoutesV6", func(o *winOS) { o.addExclusionRoutesV6([]string{"2001:db8::2"}, gw) }},
		{"addInclusionRoutes", func(o *winOS) { o.addInclusionRoutes([]string{"203.0.113.0/24"}, tunIP) }},
		{"addSplitDefaultRoute", func(o *winOS) { _ = o.addSplitDefaultRoute(tunIP) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRecordingPS()
			tc.call(r.os())
			if len(r.scripts) == 0 {
				t.Fatal("no script ran")
			}
			for _, s := range r.scripts {
				if !strings.Contains(s, "New-NetRoute") {
					continue
				}
				if !strings.Contains(s, "NativeErrorCode") || !strings.Contains(s, "AlreadyExists") {
					t.Errorf("this route add still treats an existing route as a failure:\n%s", s)
				}
				if !strings.Contains(s, "throw") {
					t.Errorf("this route add swallows every error, not only an existing route:\n%s", s)
				}
			}
		})
	}
}

// TestAnAlreadyPresentSplitDefaultDoesNotFailTheConnect is the one place where
// this changes an OUTCOME rather than a log line. addSplitDefaultRoute's error
// aborts the whole connect, so a half-torn-down previous session leaving one of
// the two halves behind used to make every subsequent connect impossible until
// the route was removed by hand.
func TestAnAlreadyPresentSplitDefaultDoesNotFailTheConnect(t *testing.T) {
	r := newRecordingPS()
	r.answers["0.0.0.0/1"] = routeExistsMarker
	if err := r.os().addSplitDefaultRoute(tunIP); err != nil {
		t.Fatalf("addSplitDefaultRoute with the route already present = %v, want nil", err)
	}
}

// TestARealRouteFailureIsStillAFailure is the guard on the guard. The one thing
// this must never do is turn a genuine route-install failure into a quiet
// success — a missing exclusion route loops the session's own underlay back into
// the tunnel it is carrying.
func TestARealRouteFailureIsStillAFailure(t *testing.T) {
	r := newRecordingPS()
	r.fail["0.0.0.0/1"] = fmt.Errorf("exit status 1")
	if err := r.os().addSplitDefaultRoute(tunIP); err == nil {
		t.Fatal("addSplitDefaultRoute reported success over a failing New-NetRoute")
	}
}

// TestPSNewNetRouteKeepsTheCallersArguments guards the mechanical part of the
// wrapping: the arguments and -ErrorAction Stop have to survive being moved
// inside a try block, or the route installed is not the route asked for.
func TestPSNewNetRouteKeepsTheCallersArguments(t *testing.T) {
	s := psNewNetRoute(`-DestinationPrefix "198.51.100.0/24" -NextHop "192.0.2.1" -InterfaceIndex 7 -RouteMetric 1`)
	for _, want := range []string{
		`New-NetRoute -DestinationPrefix "198.51.100.0/24"`,
		`-NextHop "192.0.2.1"`,
		"-InterfaceIndex 7",
		"-RouteMetric 1",
		"-ErrorAction Stop",
		"Out-Null",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the wrapped script lost %q:\n%s", want, s)
		}
	}
}
