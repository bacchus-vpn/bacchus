package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// What this coordinator's file paths RESOLVE to, said out loud at startup
// (issue #226).
//
// # The failure
//
// Nine of this binary's string flags default to a path under `secrets/`, and
// those defaults are relative ON PURPOSE: the binary should work from a working
// directory the operator chooses, and deploy/'s own unit files set one. The live
// coordinator's unit does not. For a system service `WorkingDirectory=` unset
// means `/`, so every flag left at its default resolves under the root directory,
// where nothing is staged.
//
// Two of those flags are `-device-revocations` and `-admission-revocations`,
// where **a missing file does not fail — it means nothing is revoked**. One is
// `-country-overrides`, ADR-0042 §8's correcting half, which is fatal on a
// present-but-unusable file and completely silent on an absent one, because
// absent is the ordinary "no corrections" case and is indistinguishable from
// "the path resolved somewhere unexpected".
//
// # Why the pin's check could not see it
//
// deploy/bacchus-pin.sh warns when `WorkingDirectory=` is unset AND `ExecStart`
// names a relative path. That reasoning is right and it reads the wrong surface:
// **a flag left at its default never appears in ExecStart at all**, so the
// warning stays silent precisely when the operator never thought about the path
// and fires only when they did. On the first real pin run every path written into
// the live ExecStart was absolute, the warning correctly stayed quiet, and the
// flags NOT written there were resolving under `/`.
//
// The script's half of the fix is to stop making the warning conditional on
// ExecStart. This is the other half, and the more useful one: the journal the pin
// already reads carries the answer, so nothing has to infer it — and it still
// carries it for somebody reading the journal without the pin.
//
// # What is in here and what is not
//
// Every flag naming a plain file or directory this process reads or writes.
// Deliberately NOT `-policy-source`, `-device-revocations-source` or
// `-admission-revocations-source`: each takes an http(s) URL *or* a filesystem
// path, and resolving a URL against the working directory would print a
// confident falsehood. They are reported by the loops that fetch them.

// pathFlagEntry is one flag whose value names a file or directory.
type pathFlagEntry struct {
	name  string
	value *string
	// absent is what a MISSING file means for this flag, in a few words. It is
	// the whole point of the line: "absent" is benign for a state file that is
	// written on first use and is a disabled security control for a revocation
	// list, and the two look identical from the path alone.
	absent string
}

// pathFlags is populated by pathFlag below, in main(), which runs once.
var pathFlags []pathFlagEntry

// pathFlag registers a string flag that names a file or directory, and records it
// so startup can state what it resolves to.
//
// Going through this rather than flag.String is what keeps the report from
// rotting: a new path flag declared the ordinary way is caught by
// TestEveryRelativePathDefaultGoesThroughPathFlag, which reads this file's own
// source. Issue #226 priced "enumerate the known relative defaults" as the option
// that would rot — correctly, for the shell script it was proposed in, where the
// list would sit a repository away from the flags. Here the list IS the flags.
func pathFlag(name, def, absent, usage string) *string {
	p := flag.String(name, def, usage)
	pathFlags = append(pathFlags, pathFlagEntry{name: name, value: p, absent: absent})
	return p
}

// statPath reports whether a path exists, separating "it is not there" from "this
// process cannot tell", which are different operator problems.
func statPath(p string) (exists bool, err error) {
	if _, err := os.Stat(p); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// describePaths renders the startup report: one line per path flag, plus the
// working directory it is all relative to, plus a warning when that working
// directory is the root directory and anything is still relative.
//
// It is a pure function of its inputs so a test can drive the exact live
// deployment — absolute paths in ExecStart, an empty WorkingDirectory, and flags
// left at their relative defaults — without a filesystem that looks like the box.
func describePaths(entries []pathFlagEntry, wd string, stat func(string) (bool, error)) []string {
	width := 0
	for _, e := range entries {
		if n := len(e.name) + 1; n > width {
			width = n
		}
	}

	lines := []string{fmt.Sprintf("paths: working directory %s", wd)}
	relative := 0
	for _, e := range entries {
		name := "-" + e.name
		v := *e.value
		if v == "" {
			lines = append(lines, fmt.Sprintf("paths: %-*s (empty — disabled)", width, name))
			continue
		}
		var notes []string
		resolved := v
		if !filepath.IsAbs(v) {
			resolved = filepath.Join(wd, v)
			relative++
			notes = append(notes, fmt.Sprintf("relative %q", v))
		}
		switch exists, err := stat(resolved); {
		case err != nil:
			notes = append(notes, fmt.Sprintf("CANNOT TELL whether it exists: %v", err))
		case exists:
			notes = append(notes, "present")
		case e.absent != "":
			notes = append(notes, "ABSENT — "+e.absent)
		default:
			notes = append(notes, "ABSENT")
		}
		lines = append(lines, fmt.Sprintf("paths: %-*s %s [%s]", width, name, resolved, strings.Join(notes, "; ")))
	}

	// The guard issue #226 asked for, on this side of the wire. `/` is what a
	// systemd unit with no WorkingDirectory= gives a system service, and it is
	// not a working directory anybody chose.
	if relative > 0 && filepath.Clean(wd) == "/" {
		lines = append(lines, fmt.Sprintf(
			"paths: WARNING: %d path(s) above are RELATIVE and this process's working directory is /, "+
				"so they resolve under the root directory, where nothing is normally staged. "+
				"A missing revocation file does not fail — it means NOTHING IS REVOKED. "+
				"Set WorkingDirectory= in the unit, or pass absolute paths (issue #226).", relative))
	}
	return lines
}

// logResolvedPaths writes the report to the journal the pin already reads.
func logResolvedPaths() {
	wd, err := os.Getwd()
	if err != nil {
		// Worth a line rather than a silent skip: without a working directory
		// every relative path below is unresolvable, which is exactly the
		// condition this report exists to make legible.
		log.Printf("paths: cannot read this process's working directory (%v), so no relative path below can be resolved (issue #226)", err)
		wd = "."
	}
	for _, line := range describePaths(pathFlags, wd, statPath) {
		log.Print(line)
	}
}
