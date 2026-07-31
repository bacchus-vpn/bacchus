// Translation coverage. The only test in this package, and it is here rather
// than in internal/appstate because what it checks is a property of THIS
// package's source: every lang.L key it asks for.
//
// It exists because of how this failure mode behaves. Fyne's lang.L falls back
// to the key itself when a translation is missing, so an untranslated label
// renders as English, compiles, vets, passes every other test, and ships. The
// only signal is a Russian-speaking user reading an English sentence in the
// middle of a settings window — which is exactly the audience this client is
// for. Issue #93 called this out as "not optional and will not fail a build";
// this is the half that makes it fail a build.
//
// It deliberately does NOT check translation quality, only presence. A wrong
// translation is a review question; a missing one is a mechanical fact, and
// mechanical facts belong in a test.
package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"

	"github.com/bacchus-vpn/bacchus/clients/fyne/internal/appstate"
)

// loadTranslations reads every *.ru.json under translations/ into one key set.
// The files are split by window (settings/state) purely for editing
// convenience; lang.L looks in one merged catalogue at runtime, so the union is
// what "translated" actually means.
func loadTranslations(t *testing.T) map[string]string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("translations", "*.ru.json"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no translations/*.ru.json found — this test would pass vacuously")
	}
	all := map[string]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", p, err)
		}
		var m map[string]string
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s is not a flat string map: %v", p, err)
		}
		for k, v := range m {
			all[k] = v
		}
	}
	return all
}

// staticLangKeys collects every lang.L("...") literal in this package.
//
// Calls with a non-literal argument — lang.L(err.Error()) in settings.go — are
// invisible to this and are covered by TestValidationErrorsAreTranslated
// below, which asserts the exact error values those calls can produce. A new
// dynamic call site is therefore the one way to defeat this test; that is why
// the count of them is asserted rather than ignored.
func staticLangKeys(t *testing.T) (keys []string, dynamic int) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatalf("ParseDir: %v", err)
	}
	seen := map[string]bool{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "L" {
					return true
				}
				if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "lang" {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					dynamic++
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Errorf("unquote %s: %v", lit.Value, err)
					return true
				}
				if !seen[s] {
					seen[s] = true
					keys = append(keys, s)
				}
				return true
			})
		}
	}
	sort.Strings(keys)
	return keys, dynamic
}

// TestEveryUIStringIsTranslated is the guard itself.
//
// Mutation check: delete any entry from translations/settings.ru.json and this
// names that exact key. Add a lang.L("…") call for a new label without a
// translation and it names that one. Both are silent in every other check this
// repo runs, including the build.
func TestEveryUIStringIsTranslated(t *testing.T) {
	tr := loadTranslations(t)
	keys, dynamic := staticLangKeys(t)
	if len(keys) == 0 {
		t.Fatal("found no lang.L keys — the AST walk is broken, not the translations")
	}
	for _, k := range keys {
		if _, ok := tr[k]; !ok {
			t.Errorf("no Russian translation for %q — lang.L will silently render the English", k)
		}
	}

	// Five dynamic call sites exist today, all in settings.go, and every key
	// any of them can produce is covered by one of the two tests below:
	//
	//   - three lang.L(err.Error()) in the save handler (relay chaining,
	//     admission, volunteering)
	//   - lang.L(appstate.ErrVolunteerWhileRouted.Error()) on the notice shown
	//     when the volunteer section is disabled, which is the same sentinel the
	//     save handler can return, so it adds no new key
	//   - lang.L(w) over PlanVolunteer's warn-and-serve findings
	//
	// If this number moves, a call site was added whose key this test cannot
	// see: cover it below (or make it a literal) rather than only raising the
	// number.
	const knownDynamicCallSites = 5
	if dynamic != knownDynamicCallSites {
		t.Errorf("found %d lang.L calls with a non-literal key, expected %d — a new one is invisible to this test; see this test's doc",
			dynamic, knownDynamicCallSites)
	}
}

// TestValidationErrorsAreTranslated covers the keys the AST walk cannot see:
// settings.go passes err.Error() to lang.L, so each sentinel error's TEXT is
// itself a translation key. That makes the error strings part of the UI
// contract — renaming one without updating the catalogue silently reverts that
// message to English.
//
// Mutation check: reword either error in internal/appstate/connection.go
// without touching settings.ru.json and this goes red, naming the new text.
func TestValidationErrorsAreTranslated(t *testing.T) {
	tr := loadTranslations(t)
	for _, err := range []error{
		appstate.ErrRelayChainConfig,
		appstate.ErrAdmissionConfig,
	} {
		if _, ok := tr[err.Error()]; !ok {
			t.Errorf("no Russian translation for the error text %q — settings.go passes it to lang.L, so it is a UI string", err.Error())
		}
	}
}

// TestVolunteerMessagesAreTranslated is the same contract for issue #12's
// section, kept as its own test because its stake is different from every other
// string in this window.
//
// The exit disclosure and its refusals are where a user decides whether to
// accept legal exposure. lang.L falling back to English there does not
// inconvenience a Russian-speaking volunteer, it hands them a decision they
// cannot read — and this client's whole reason to be translated is that audience.
// So every sentence PlanVolunteer can put on screen is asserted, refusals and
// warn-and-serve findings alike, rather than only the ones a checkbox label
// happens to make static.
//
// Mutation check: drop any one of these entries from
// translations/settings.ru.json, or reword the sentinel in
// internal/appstate/volunteer.go without updating the catalogue, and this names
// the exact text that would silently revert to English.
func TestVolunteerMessagesAreTranslated(t *testing.T) {
	tr := loadTranslations(t)
	for _, err := range []error{
		appstate.ErrVolunteerWhileRouted,
		appstate.ErrVolunteerExitNeedsAddress,
		appstate.ErrVolunteerAddressForm,
		appstate.ErrVolunteerAddressUnreachable,
		appstate.ErrVolunteerExitNeedsKey,
		appstate.ErrVolunteerExitKeyForm,
	} {
		if _, ok := tr[err.Error()]; !ok {
			t.Errorf("no Russian translation for the volunteer refusal %q — settings.go passes it to lang.L, so it is a UI string", err.Error())
		}
	}
	for _, warning := range []string{
		appstate.WarnVolunteerAddressPrivate,
		appstate.WarnVolunteerAddressCGNAT,
		appstate.WarnVolunteerAddressName,
	} {
		if _, ok := tr[warning]; !ok {
			t.Errorf("no Russian translation for the volunteer warning %q — settings.go passes it to lang.L, so it is a UI string", warning)
		}
	}
}
