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

var (
	logOnce sync.Once
	logger  *log.Logger
	logFile *os.File
)

// logPath mirrors configPaths' fallback order (config.go): the per-user
// app-data directory first, next to the executable if APPDATA isn't set.
func logPath() string {
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
// newline — the logger adds one). Split out from logEvent so the formatting
// itself is testable without going through the process-wide log singleton.
func formatEvent(ev core.Event) string {
	if ev.Session != "" {
		return fmt.Sprintf("[%s] %s: %s", ev.Kind, ev.Session, ev.Message)
	}
	return fmt.Sprintf("[%s] %s", ev.Kind, ev.Message)
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
// Best-effort, same as logEvent.
func logLine(format string, args ...any) {
	openLog()
	if logger == nil {
		return
	}
	logger.Printf(format, args...)
}

// closeLog flushes and closes the event log, best-effort, on shutdown.
func closeLog() {
	if logFile != nil {
		_ = logFile.Close()
	}
}
