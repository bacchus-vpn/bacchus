package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The stamp has to REACH the binaries that claim it, and that is a different
// question from the one TestStampMatchesTheVersionFile answers.
//
// That test links `-X …core/version.current` into a test binary and reads the
// value back, so it catches a symbol path that no longer resolves: a renamed
// var, a moved package, a typo'd module path. What it cannot see is a binary
// that never references this package at all. `-X` naming a symbol the linker has
// no reference to is ignored just as silently and with the same zero exit, and
// no test that links THIS package can notice, because this package is linked.
//
// That is issue #223, found for real: `go list -deps ./cmd/bacchus-netd`
// contained no core/version, so deploy/install.sh, the builds in docs/RUNNING.md
// and CI all passed a stamp flag for it that did nothing, and every one of them
// reported success. ADR-0065's second correction records it. The cost was not
// the number — netd is socket-activated and nothing fences it — it was that
// three build paths asserted something false and nothing anywhere said so.

// stampedPackages returns the packages deploy/install.sh builds with the release
// stamp, read out of the script rather than listed here.
//
// install.sh is the derivation source because it is the build path that is both
// executable and complete: it builds every binary this project installs on
// Linux, and it passes one `-ldflags -X` to all of them from one variable
// (version_symbol). docs/RUNNING.md documents the same builds in prose and
// release.yml derives its own assertion from `go list -deps` already; a list
// written out here would be a fourth place to forget.
func stampedPackages(t *testing.T) map[string]string {
	t.Helper()
	const script = "../../deploy/install.sh"
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatalf("reading %s: %v", script, err)
	}
	// `netd_bin=$(resolve_binary bacchus-netd ./cmd/bacchus-netd)` — the installed
	// name and the package. Both captured: the name is what an operator sees on
	// disk and is what a failure message has to say.
	call := regexp.MustCompile(`resolve_binary +([A-Za-z0-9._-]+) +(\./[A-Za-z0-9._/-]+)`)
	out := map[string]string{}
	for _, m := range call.FindAllStringSubmatch(string(raw), -1) {
		out[m[2]] = m[1]
	}
	// A vacuous pass is the failure this whole file exists to prevent, so the
	// derivation asserts its own premise. If resolve_binary is renamed or its
	// call shape changes, this finds nothing and would otherwise report green
	// over an empty set — the same shape as a `-run` filter that matches no test,
	// or a `-X` that names no symbol.
	if len(out) < 4 {
		t.Fatalf("found only %d resolve_binary call(s) in %s, expected at least 4 (the coordinator, "+
			"the node, the netd helper and the GUI). Either a binary was dropped from the installer, "+
			"or the call shape changed and this test is now checking nothing", len(out), script)
	}
	return out
}

// Every package a build path stamps must link this one, or the stamp is a flag
// with no effect and the linker will not say so.
//
// The check is `go list -deps`, which is the same question release.yml asks
// before it asserts a stamp on a release artifact, and asking it here means a
// binary added to the installer is covered on the pull request that adds it
// rather than on the first tag afterwards.
func TestEveryStampedBuildLinksTheVersionPackage(t *testing.T) {
	const self = "github.com/bacchus-vpn/bacchus/core/version"
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	for pkg, name := range stampedPackages(t) {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("go", "list", "-deps", pkg)
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
			}
			for _, line := range strings.Split(string(out), "\n") {
				if strings.TrimSpace(line) == self {
					return
				}
			}
			t.Fatalf("deploy/install.sh builds %s (%s) with -ldflags -X %s.current, but %s does not "+
				"link that package, so the linker DROPS the flag — silently, with a zero exit. The build "+
				"succeeds, the install succeeds, and the binary can never state which release it is. Either "+
				"import %s and report Current() (which is what issue #223 did for bacchus-netd), or stop "+
				"passing the stamp for this binary in install.sh, docs/RUNNING.md, deploy/bacchus-pin.sh and "+
				"the release workflow. What must not persist is a build path asserting a stamp that does "+
				"not land", name, pkg, self, pkg, self)
		})
	}
}
