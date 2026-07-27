//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
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

// TestEventLogRedactsAddresses is the proof behind the README's claim that
// addresses do not reach bacchus.log. It is written against the REAL messages
// core emits and the client re-emits, not against invented strings, because the
// gap this closes was not a redaction bug — redactIPs was correct all along —
// but a coverage one: logSafe guarded runPS and nothing guarded the other two
// writers, so every address core put in an event message went in whole.
//
// Each case names where the string comes from, so a reader can check the source
// still produces that shape rather than trusting this list.
func TestEventLogRedactsAddresses(t *testing.T) {
	cases := []struct {
		name    string
		got     string
		wantNot []string
		want    string
	}{
		{
			// core/engine.go, when a pool member cannot be used. In Russia this is
			// the NORMAL case, and the address is the blocked coordinator's.
			name:    "skipped coordinator (core/engine.go)",
			got:     formatEvent(core.Event{Kind: core.EventError, Message: `skipping coordinator "203.0.113.9:51820": blocked`}),
			wantNot: []string{"203.0.113.9"},
			want:    `[error] skipping coordinator "<ip>:51820": blocked`,
		},
		{
			// core/client.go's mesh-peer dial error.
			name:    "mesh peer (core/client.go)",
			got:     formatEvent(core.Event{Kind: core.EventInfo, Message: "mesh-walk: peer 198.51.100.9:3478 did not answer"}),
			wantNot: []string{"198.51.100.9"},
			want:    "[info] mesh-walk: peer <ip>:3478 did not answer",
		},
		{
			// core/client.go's reality dial error names the exit's address.
			name:    "reality dial (core/client.go)",
			got:     formatEvent(core.Event{Kind: core.EventError, Message: "dial tcp 192.0.2.44:443: i/o timeout"}),
			wantNot: []string{"192.0.2.44"},
			want:    "[error] dial tcp <ip>:443: i/o timeout",
		},
		{
			// abortSession's own failure log (main.go). This one is the whole
			// configured pool at once, at the moment the client is failing under
			// censorship — the worst single line in the file before this fix.
			name:    "the whole coordinator pool (abortSession)",
			got:     formatEvent(core.Event{Kind: core.EventError, Message: "core: no usable coordinator in pool [203.0.113.1:51820 203.0.113.2:51820]"}),
			wantNot: []string{"203.0.113.1", "203.0.113.2"},
			want:    "[error] core: no usable coordinator in pool [<ip>:51820 <ip>:51820]",
		},
		{
			// IPv6 goes the same way; the alternation ordering that makes an
			// IPv4-mapped form redact whole is covered in routes_test.go.
			name:    "ipv6 literal",
			got:     formatEvent(core.Event{Kind: core.EventICE, Message: "candidate [2001:db8::5]:3478 failed"}),
			wantNot: []string{"2001:db8::5"},
			want:    "[ice] candidate [<ip>]:3478 failed",
		},
		{
			// logLine is the other writer: tunnel bring-up diagnostics.
			name:    "logLine formats then redacts (tunnel.go)",
			got:     redactIPs("excluding underlay 192.0.2.7:443 from the default route"),
			wantNot: []string{"192.0.2.7"},
			want:    "excluding underlay <ip>:443 from the default route",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, leak := range tc.wantNot {
				if strings.Contains(tc.got, leak) {
					t.Errorf("address %q reached the log line %q", leak, tc.got)
				}
			}
			if tc.got != tc.want {
				t.Errorf("= %q, want %q", tc.got, tc.want)
			}
		})
	}
}

// TestLogLineRedactsThroughTheRealSingleton closes the gap the case above
// cannot: it drives logLine and logEvent through the actual file writer and
// reads the bytes back, so a redaction applied to the formatting helper but not
// to the path that reaches the file would still fail here.
func TestLogLineRedactsThroughTheRealSingleton(t *testing.T) {
	redirectEventLogForTest(t)

	logLine("bringing up tunnel, excluding %s and %s", "203.0.113.4:51820", "198.51.100.8:3478")
	logEvent(core.Event{Kind: core.EventError, Message: "dial tcp 192.0.2.44:443: i/o timeout"})
	if logFile != nil {
		_ = logFile.Sync()
	}

	b, err := os.ReadFile(logPath())
	if err != nil {
		t.Fatalf("read back the event log: %v", err)
	}
	got := string(b)
	for _, leak := range []string{"203.0.113.4", "198.51.100.8", "192.0.2.44"} {
		if strings.Contains(got, leak) {
			t.Errorf("address %q reached the real log file:\n%s", leak, got)
		}
	}
	// Positive control: the surrounding diagnostic text must survive, or a
	// redaction that simply blanked the line would pass the checks above.
	for _, keep := range []string{"bringing up tunnel", "<ip>:51820", "dial tcp <ip>:443"} {
		if !strings.Contains(got, keep) {
			t.Errorf("expected %q in the log, got:\n%s", keep, got)
		}
	}
}
