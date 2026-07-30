//go:build windows

package enforcement

import "testing"

// TestNewPSCmdRunsWindowless guards the console-window fix: every powershell.exe
// the client spawns must carry CREATE_NO_WINDOW, or a -H=windowsgui process
// flashes a console window on each of the many calls runPS makes.
func TestNewPSCmdRunsWindowless(t *testing.T) {
	cmd := newPSCmd("Write-Output hi")
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Fatalf("newPSCmd must set CREATE_NO_WINDOW (%#x); got SysProcAttr=%+v", createNoWindow, cmd.SysProcAttr)
	}
}
