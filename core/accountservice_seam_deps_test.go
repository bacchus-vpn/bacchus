// The check ADR-0046 §6 and ADR-0056 §2 rest on, in a form that measures the
// property they are actually about (issue #239).
//
// # What was wrong with the old form
//
// Both records phrased the property as an absolute claim about a grep:
// "`go list -deps ./core` names no HTTP client", and its concrete form, an
// operator running Bacchus with no account service who "imports no HTTP client".
//
// **That was false when it was written and it is false now.** `net/http` has
// always been in `core`'s dependency graph, by a route that has nothing to do
// with the account service:
//
//	core -> github.com/refraction-networking/utls -> github.com/andybalholm/brotli -> net/http
//
// utls is imported directly by `core` for the ClientHello fingerprint work
// (ADR-0018, ADR-0032), brotli is utls's own certificate-compression dependency,
// and brotli ships an http.Handler helper. None of that is a decision this
// project gets to make, and none of it dials anything.
//
// So the grep was worse than useless in both directions. It reported a breach
// that had not happened, and it would keep reporting the same breach on a build
// that really had grown a direct account-service client — the pattern that is
// supposed to catch the regression already matches.
//
// # What is actually being protected, and what this measures
//
// The property is a DIRECTION, not an absence: the dependency runs one way, from
// the account-service client to `core` and never back, so an operator with no
// account service imports nothing of it, configures nothing, and is not degraded.
// `Config.DeviceRenew` is the seam that keeps it that way (ADR-0056 §2).
//
// Two assertions below, and between them they say it without depending on a claim
// about the whole transitive set:
//
//  1. `core/accountclient` — the package that dials the account service — is not
//     in `go list -deps ./core`. The literal one-way claim.
//  2. No FIRST-PARTY package in `core`'s dependency graph imports `net/http` at
//     all. This is the form that survives the utls chain: third-party code may
//     bring in whatever it brings in, and what must not appear is a package in
//     THIS repository, reachable from `core`, that can make an outbound call.
//     A `core` that grew a built-in renewal client tomorrow would fail here on
//     the commit that added it.
//
// Test files are invisible to `go list -deps ./core`, which lists the non-test
// package's imports, so this test cannot perturb what it measures.

package core

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// firstPartyPrefix is this repository's module path. Everything under it is code
// this project writes and is therefore code this project is answerable for;
// everything else arrived through go.mod and is governed by ADR-0003.
const firstPartyPrefix = "github.com/bacchus-vpn/bacchus/"

// accountClientPackage is the one package in this repository that dials the
// account service (ADR-0056 §8).
const accountClientPackage = firstPartyPrefix + "core/accountclient"

func TestCoreImportsNothingThatDialsTheAccountService(t *testing.T) {
	deps := coreDeps(t)

	// A dependency set that does not contain `core` itself would mean the
	// command answered about something else, and every assertion below would be
	// vacuously true. `go list -deps` includes the named package.
	if !deps[strings.TrimSuffix(firstPartyPrefix, "/")+"/core"] {
		t.Fatalf("`go list -deps ./core` did not name core itself, so this test is measuring "+
			"something other than what it claims. It returned %d packages", len(deps))
	}

	if deps[accountClientPackage] {
		t.Fatalf("%s is in `go list -deps ./core`. The seam ADR-0056 §2 keeps is the DIRECTION of "+
			"this dependency: the account-service client imports core, and core imports nothing of "+
			"it, which is what lets an operator with no account service configure nothing and be "+
			"undegraded. That direction has been reversed", accountClientPackage)
	}

	// The regression the old grep was supposed to catch, expressed so that it
	// can be. utls -> brotli -> net/http is third-party and accounted for; a
	// package of OURS reachable from core that imports net/http is a new
	// outbound call from the package every embedder must import.
	var offenders []string
	for pkg := range deps {
		if !strings.HasPrefix(pkg, firstPartyPrefix) {
			continue
		}
		for _, imp := range directImports(t, pkg) {
			if imp == "net/http" || strings.HasPrefix(imp, "net/http/") {
				offenders = append(offenders, pkg+" imports "+imp)
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("packages in this repository are reachable from core and import net/http:\n  %s\n\n"+
			"ADR-0046 §6 and ADR-0056 §2 rest on core importing nothing that dials the account "+
			"service — core/devicecred's package doc says it \"never depends on, and never leaks to, "+
			"the closed account service\", and core's own import graph is what keeps that true rather "+
			"than a comment asserting it. If this is deliberate, those two records are what has to "+
			"change, not this test (issue #239).",
			strings.Join(offenders, "\n  "))
	}
}

// coreDeps returns `go list -deps ./core` as a set.
func coreDeps(t *testing.T) map[string]bool {
	t.Helper()
	out := goList(t, "-deps", "./core")
	set := make(map[string]bool, len(out))
	for _, p := range out {
		set[p] = true
	}
	return set
}

// directImports returns a package's own import list — not its transitive
// closure, which is the whole point: the question is which package in this
// repository holds the import, so that a failure names the file to look at.
func directImports(t *testing.T, pkg string) []string {
	t.Helper()
	return goList(t, "-f", "{{range .Imports}}{{.}}\n{{end}}", pkg)
}

// goList runs the toolchain from the repository root and returns its non-empty
// output lines.
func goList(t *testing.T, args ...string) []string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("no go toolchain on PATH, so the dependency graph cannot be read: %v", err)
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	cmd := exec.Command("go", append([]string{"list"}, args...)...)
	cmd.Dir = root
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list %s: %v\n%s", strings.Join(args, " "), err, raw)
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
