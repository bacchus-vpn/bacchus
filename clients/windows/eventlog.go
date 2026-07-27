//go:build windows

// Bacchus is built with -H=windowsgui (see main.go), which means it has no
// console: writes to os.Stdout/os.Stderr go nowhere visible, ever. That
// includes core's own log.Println fallback for an engine with no OnEvent —
// so for this client, the systray status line and this file are the only
// two places a user can ever see what the engine is doing. The status line
// is live but ephemeral (the next event overwrites it); this file is what
// survives to be pasted into a bug report.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/bacchus-vpn/bacchus/core"
)

// logOnce is a *sync.Once rather than a value so the whole singleton can be
// reset — see logPath's doc for why a test needs that.
var (
	logOnce = new(sync.Once)
	logger  *log.Logger
	logFile *os.File
)

// logPath mirrors configPaths' fallback order (config.go): the per-user
// app-data directory first, next to the executable if APPDATA isn't set.
//
// Indirected through a var, the same way clients/fyne's runKeyPath is
// (autostart_windows.go): every path through connect()/switchCountry()/
// watchMeshRecovery() reaches logEvent or logLine, so a test driving those
// would otherwise append to the developer's own real
// %APPDATA%\Bacchus\bacchus.log. redirectEventLogForTest points this at a
// temp dir and restores the singleton afterwards.
var logPath = func() string {
	if ad := os.Getenv("APPDATA"); ad != "" {
		return filepath.Join(ad, "Bacchus", "bacchus.log")
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "bacchus.log")
	}
	return "bacchus.log"
}

// openLog opens (creating if needed) the append-only event log, once per
// process. Failure is not fatal — logEvent silently skips the file write;
// the systray status line still carries the live event either way.
func openLog() {
	logOnce.Do(func() {
		p := logPath()
		if dir := filepath.Dir(p); dir != "." {
			_ = os.MkdirAll(dir, 0o700)
		}
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		logFile = f
		logger = log.New(f, "", log.LstdFlags)
	})
}

// formatEvent renders one engine event as a single log line (no trailing
// newline — the logger adds one), with every IP literal redacted. Split out
// from logEvent so the formatting itself is testable without going through the
// process-wide log singleton.
//
// The redaction is not decorative and it does not belong at the call sites.
// core's event messages carry real addresses as a matter of course — a skipped
// coordinator, a mesh peer, a reality dial error all name one — and under
// censorship "the coordinator I could not reach" is exactly the address a user
// most needs kept out of a file they are about to paste into a bug report.
// Applying it here means a future event source cannot reintroduce the leak by
// forgetting a helper, which is precisely how abortSession's failure log came to
// write the entire configured coordinator list verbatim.
func formatEvent(ev core.Event) string {
	if ev.Session != "" {
		return redactIPs(fmt.Sprintf("[%s] %s: %s", ev.Kind, ev.Session, ev.Message))
	}
	return redactIPs(fmt.Sprintf("[%s] %s", ev.Kind, ev.Message))
}

// logEvent appends one engine event to the event log. Every kind is
// recorded, including ones the systray never shows live (see eventStatus),
// so the file has the full sequence even when the live status line doesn't.
// No rotation: this is lifecycle-event volume (connect/disconnect/ICE state
// changes), not per-packet, so unbounded growth is not a real concern for a
// personal desktop app.
func logEvent(ev core.Event) {
	openLog()
	if logger == nil {
		return
	}
	logger.Print(formatEvent(ev))
}

// logLine appends a plain diagnostic line to the event log — for client-side
// steps the engine event stream doesn't cover, notably the full-device tunnel
// bring-up (tunnel.go), which otherwise leaves no trace when a step blocks.
// Best-effort, same as logEvent, and redacted for the same reason: this and
// logEvent are the only two writers into bacchus.log, so redacting both is what
// makes "addresses do not reach the log" a property of the file rather than a
// habit of its callers.
//
// runPS additionally passes its command and output through logSafe (routes.go)
// before calling this. That is not redundant: logSafe also cuts to the first
// line and catches the partial dotted-quad a PowerShell hard wrap leaves behind,
// neither of which is an IP literal redactIPs can see. Redaction is idempotent,
// so the overlap costs nothing.
func logLine(format string, args ...any) {
	openLog()
	if logger == nil {
		return
	}
	logger.Print(redactIPs(fmt.Sprintf(format, args...)))
}

// closeLog flushes and closes the event log, best-effort, on shutdown.
func closeLog() {
	if logFile != nil {
		_ = logFile.Close()
	}
}
