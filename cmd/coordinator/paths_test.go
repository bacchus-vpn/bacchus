package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func entry(name, value, absent string) pathFlagEntry {
	v := value
	return pathFlagEntry{name: name, value: &v, absent: absent}
}

// The case that produced issue #226, reproduced exactly: the live deployment's
// unit writes ABSOLUTE paths into ExecStart for the three flags it sets, has
// `WorkingDirectory=` empty, and leaves the rest at their relative defaults. The
// pin's scan reads ExecStart, sees nothing relative, and stays silent — while
// `-device-revocations` resolves to `/secrets/device-revocations.json`, which is
// not there, which means nothing is revoked.
//
// MUTATION: resolve with filepath.Abs (the process's own cwd) instead of joining
// the working directory that was passed in — the resolved paths stop naming `/`
// and the first assertion goes red.
func TestResolvedPathsNameTheLiveMisSet(t *testing.T) {
	entries := []pathFlagEntry{
		entry("device-revocations", "secrets/device-revocations.json", "NOTHING IS REVOKED in the device namespace"),
		entry("country-overrides", "secrets/country-overrides.json", "no admin corrections take effect"),
		entry("operators", "/etc/bacchus/operators.json", "no operator tags"),
	}
	// Only the absolute one exists — the shape of the box this was found on.
	stat := func(p string) (bool, error) { return p == "/etc/bacchus/operators.json", nil }

	got := strings.Join(describePaths(entries, "/", stat), "\n")

	for _, want := range []string{
		"working directory /",
		"/secrets/device-revocations.json",
		"NOTHING IS REVOKED",
		"/secrets/country-overrides.json",
		"no admin corrections take effect",
		"/etc/bacchus/operators.json [present]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the report does not carry %q:\n%s", want, got)
		}
	}
	// And the summary an operator can act on without reading eleven lines.
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "2 path(s)") {
		t.Errorf("no warning that relative paths are resolving under the root directory:\n%s", got)
	}
	if !strings.Contains(got, "WorkingDirectory=") {
		t.Errorf("the warning does not name the unit setting that fixes it:\n%s", got)
	}
}

// A working directory the operator actually chose is not a finding. The warning
// exists for `/`, which is what a systemd unit with no WorkingDirectory= gives a
// system service — not for relative paths as such.
func TestResolvedPathsDoNotWarnUnderAChosenWorkingDirectory(t *testing.T) {
	entries := []pathFlagEntry{entry("device-revocations", "secrets/device-revocations.json", "NOTHING IS REVOKED")}
	stat := func(string) (bool, error) { return true, nil }

	got := strings.Join(describePaths(entries, "/opt/bacchus", stat), "\n")
	if !strings.Contains(got, "/opt/bacchus/secrets/device-revocations.json") {
		t.Errorf("the path is not resolved against the working directory:\n%s", got)
	}
	if strings.Contains(got, "WARNING") {
		t.Errorf("a chosen working directory drew a warning:\n%s", got)
	}
}

// An empty value is a DISABLED flag, not a path that resolved to the working
// directory — `-country-overrides ""` disables corrections, and `-geoip ""`
// disables derivation. Joining "" against "/" would print `/`, a file that
// always exists, and report the disabled flag as healthy.
func TestResolvedPathsReportAnEmptyValueAsDisabled(t *testing.T) {
	entries := []pathFlagEntry{entry("geoip", "", "")}
	stat := func(string) (bool, error) {
		t.Error("an empty path must not be stat'd — it names nothing")
		return true, nil
	}
	got := strings.Join(describePaths(entries, "/", stat), "\n")
	if !strings.Contains(got, "(empty — disabled)") {
		t.Errorf("an unset path flag is not reported as disabled:\n%s", got)
	}
	if strings.Contains(got, "WARNING") {
		t.Errorf("an unset flag counted as a relative path:\n%s", got)
	}
}

// "Not there" and "this process cannot tell" are different operator problems and
// must not render as the same line: a revocation file behind a directory this
// process cannot traverse is not a revocation file that is absent.
func TestResolvedPathsSeparateAbsentFromUnreadable(t *testing.T) {
	entries := []pathFlagEntry{entry("device-revocations", "/secrets/device-revocations.json", "NOTHING IS REVOKED")}
	stat := func(string) (bool, error) { return false, os.ErrPermission }

	got := strings.Join(describePaths(entries, "/", stat), "\n")
	if !strings.Contains(got, "CANNOT TELL") {
		t.Errorf("an unreadable path is reported as absent:\n%s", got)
	}
	if strings.Contains(got, "ABSENT") {
		t.Errorf("an unreadable path claims to be absent:\n%s", got)
	}
}

// The anti-rot guard, and the reason issue #226's option 3 is safe to take HERE
// and was not safe to take in a shell script a repository away from the flags.
//
// A new path flag declared the ordinary way would be missing from the startup
// report, silently, and the report would go on looking complete. This reads
// main.go's own source and fails on any flag.String whose default looks like a
// relative path — which is precisely the class that resolves under `/` when the
// unit sets no WorkingDirectory=.
//
// MUTATION: change any pathFlag call in main.go back to flag.String — this names
// it and goes red.
func TestEveryRelativePathDefaultGoesThroughPathFlag(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing main.go: %v", err)
	}

	var offenders []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "String" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "flag" {
			return true
		}
		name, okName := stringLit(call.Args[0])
		def, okDef := stringLit(call.Args[1])
		if !okName || !okDef {
			return true
		}
		if looksRelativePath(def) {
			offenders = append(offenders, "-"+name+" (default "+strconv.Quote(def)+")")
		}
		return true
	})

	if len(offenders) > 0 {
		t.Errorf("these flags default to a relative path and do not go through pathFlag: %s\n"+
			"A relative default never appears in the unit's ExecStart, so nothing outside this process can see it;\n"+
			"under a unit with no WorkingDirectory= it resolves under /, and a missing revocation file there does\n"+
			"not fail — it means nothing is revoked (issue #226). Declare it with pathFlag so startup states what\n"+
			"it resolves to.", strings.Join(offenders, ", "))
	}

	// The guard has to be able to see something, or it passes by finding nothing
	// for the wrong reason — an import rename, a moved main(), a parser change.
	if n := strings.Count(readSource(t, "main.go"), "pathFlag(\""); n < 9 {
		t.Errorf("only %d pathFlag declarations found in main.go; issue #226 counted nine relative-default flags alone, "+
			"so this test is no longer looking at what it thinks it is", n)
	}
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

// looksRelativePath is the same rule the failure has: something with a path
// separator in it that does not begin at the root. ":8080" and "bacchus" are not
// paths; "secrets/operators.json" is.
func looksRelativePath(v string) bool {
	return v != "" && !strings.HasPrefix(v, "/") && strings.ContainsRune(v, '/')
}

func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}
