//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bacchus-vpn/bacchus/core"
)

func TestLogPathPrefersAPPDATA(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)

	got := logPath()
	want := filepath.Join(dir, "Bacchus", "bacchus.log")
	if got != want {
		t.Fatalf("logPath() = %q, want %q", got, want)
	}
}

func TestLogPathFallsBackNextToExecutable(t *testing.T) {
	t.Setenv("APPDATA", "")

	got := logPath()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	want := filepath.Join(filepath.Dir(exe), "bacchus.log")
	if got != want {
		t.Fatalf("logPath() = %q, want %q", got, want)
	}
}

// formatEvent is the pure piece of logEvent (see eventlog.go for why the
// split exists): tested directly here rather than through the process-wide
// log singleton, which is a) global mutable state that can't be reset
// cleanly between tests and b) would otherwise write into the real user's
// %APPDATA%\Bacchus\ during `go test`. The singleton's own file-open/append
// mechanics (openLog/logEvent/closeLog) are plain os.OpenFile plus a stdlib
// log.Logger — verified by running the actual client, not re-tested here.
func TestFormatEvent(t *testing.T) {
	cases := []struct {
		name string
		ev   core.Event
		want string
	}{
		{
			name: "no session id",
			ev:   core.Event{Kind: core.EventError, Message: "coordinator rejected handshake: version mismatch"},
			want: "[error] coordinator rejected handshake: version mismatch",
		},
		{
			name: "with a session id",
			ev:   core.Event{Kind: core.EventSession, Session: "abc123", Message: "[direct] session: abc123"},
			want: "[session] abc123: [direct] session: abc123",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatEvent(tc.ev); got != tc.want {
				t.Fatalf("formatEvent() = %q, want %q", got, tc.want)
			}
		})
	}
}
