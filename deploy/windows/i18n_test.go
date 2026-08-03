// Language parity for the Windows distribution surface (bacchus#145).
//
// clients/fyne/translations_test.go fails the build when a lang.L key has no
// Russian, and says why: an untranslated label renders as English, compiles,
// vets, passes every other test, and ships, and the only signal is a
// Russian-speaking user reading an English sentence. Everything that user
// reads BEFORE the app opens — the installer's wizard, the README in the
// portable bundle — had no such discipline. This is that discipline for the
// two artifacts in this directory.
//
// Both languages are first-class, so every check here is symmetric: a message
// present in one language and absent in the other is the defect whichever way
// round it is, and each failure names which side is missing what.
//
// Deliberately NOT a Windows-only test, and deliberately not a step inside
// build-bundle.ps1.
//
// The compiler is not the check here, and could not be. release.yml's
// windows-bundle job does compile this installer on every pull request that
// touches deploy/windows/**, which catches a syntax error and an .isl that is
// not there — and catches NONE of what this file is about. Inno compiles a
// {cm:} key defined for one language and missing for the other perfectly
// cleanly; that is the entire premise. An unprefixed entry, a %1 dropped in
// translation, a russian. message holding English, a README section that only
// exists in one language: all of them produce a successful compile and a
// working installer that is wrong on somebody's screen.
//
// So this walks the committed files with the standard library, on any
// platform, in milliseconds, and it also covers the two cases the Windows job
// structurally cannot: a push straight to main (release.yml has no push
// trigger for a branch) and a contributor with no Windows at all. It is the
// manifest_test.go shape: a Go test that reads a non-Go build artifact.
//
// What it does NOT check is translation quality — the same line
// translations_test.go draws. A wrong translation is a review question; a
// missing one is a mechanical fact, and mechanical facts belong in a test.
//
// This package has no non-test files on purpose. It exists so that these two
// artifacts have somewhere to be checked from; there is nothing here to
// import.
package windows

import (
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

const (
	issFile    = "bacchus.iss"
	buildFile  = "build-bundle.ps1"
	readmeEN   = "README.en.txt"
	readmeRU   = "README.ru.txt"
	langEnFile = "english"
	langRuFile = "russian"
)

// vouchedLanguages is an allowlist, not a mirror of what Inno Setup ships.
//
// A MessagesFile naming an .isl that is not there does fail the compile, and
// release.yml's windows-bundle job runs that compile on every pull request
// touching this directory. What it does NOT fail on is an .isl that exists and
// is the wrong one — Ukrainian.isl typed where Russian.isl was meant compiles
// perfectly and ships a wizard in the wrong language — and it does not run at
// all on a push straight to main, or on the machine of anyone without Windows.
//
// So this is a second, cheaper, differently-shaped guard rather than the only
// one: adding a language is a deliberate edit here as well as in the script,
// which is the point at which somebody has to have checked the file exists.
//
// Both of these are stock: Default.isl sits in the compiler's own directory
// and Russian.isl in its Languages subdirectory, so neither is fetched,
// vendored or shipped by us. Confirmed compiling: the windows-bundle job on
// this branch's own pull request built the installer from these two entries.
var vouchedLanguages = map[string]string{
	langEnFile: `compiler:Default.isl`,
	langRuFile: `compiler:Languages\Russian.isl`,
}

// stockCustomMessages are the [CustomMessages] entries every stock .isl
// defines, so a {cm:} reference to one resolves in every language without this
// script defining anything. Confirmed present in both Default.isl and
// Russian.isl.
//
// They are listed so that a reference to a key that is NEITHER stock NOR
// defined in bacchus.iss is caught here rather than by a user meeting a broken
// wizard page. Inno resolves {cm:} at runtime, and CustomMessage() in [Code]
// raises rather than falling back.
var stockCustomMessages = map[string]bool{
	"NameAndVersion":                   true,
	"AdditionalIcons":                  true,
	"CreateDesktopIcon":                true,
	"CreateQuickLaunchIcon":            true,
	"ProgramOnTheWeb":                  true,
	"UninstallProgram":                 true,
	"LaunchProgram":                    true,
	"AssocFileExtension":               true,
	"AssocingFileExtension":            true,
	"AutoStartProgramGroupDescription": true,
	"AutoStartProgram":                 true,
	"AddonHostProgramNotFound":         true,
}

var (
	issNameRe     = regexp.MustCompile(`(?i)\bName:\s*"([^"]*)"`)
	issMsgFileRe  = regexp.MustCompile(`(?i)\bMessagesFile:\s*"([^"]*)"`)
	issSourceRe   = regexp.MustCompile(`(?i)\bSource:\s*"[^"]*[\\/]([^"\\/]+)"`)
	issSectionRe  = regexp.MustCompile(`^\[([A-Za-z]+)\]\s*$`)
	cmEntryRe     = regexp.MustCompile(`^(?:([A-Za-z0-9_]+)\.)?([A-Za-z0-9_]+)=(.*)$`)
	cmConstRe     = regexp.MustCompile(`\{cm:([A-Za-z0-9_]+)`)
	cmCallRe      = regexp.MustCompile(`CustomMessage\(\s*'([A-Za-z0-9_]+)'\s*\)`)
	cmArgRe       = regexp.MustCompile(`%([1-9])`)
	headingRe     = regexp.MustCompile(`^([0-9]+)\.\s+(.*\S)\s*$`)
	placeholderRe = regexp.MustCompile(`\{\{[A-Za-z0-9_]+\}\}`)
	psReplaceRe   = regexp.MustCompile(`\.Replace\('(\{\{[A-Za-z0-9_]+\}\})'`)
	psBundleRe    = regexp.MustCompile(`(?s)\$BundleFiles\s*=\s*@\((.*?)\n\)`)
	psQuotedRe    = regexp.MustCompile(`'([^']+)'`)
)

// utf8BOM is what makes bacchus.iss version-independent. Inno Setup stopped
// requiring it for a non-ASCII UTF-8 script in 6.3; on 6.0 through 6.2 a
// BOM-less script is read in the build machine's ANSI codepage instead, which
// turns every Russian message in it into mojibake inside a shipped installer,
// silently. build-bundle.ps1 accepts any "Inno Setup 6" it finds.
const utf8BOM = "\xef\xbb\xbf"

// -------------------------------------------------------------------------
// bacchus.iss
// -------------------------------------------------------------------------

// issLine is one non-comment line, tagged with the section it fell in.
//
// Comment syntax in an .iss file depends on the section: ";" starts a comment
// everywhere except [Code], which is Pascal and uses "//" — and where ";" is a
// statement terminator instead. Getting that backwards would either read the
// prose in the header as script or read half the uninstall procedure as
// comment, so it is tracked rather than guessed.
type issLine struct {
	Section string // lower-case, "" before the first section header
	N       int    // 1-based, for failure messages a reader can jump to
	Text    string
}

type issScript struct {
	Lines []issLine

	// LanguageNames in declaration order, and their MessagesFile.
	LanguageNames []string
	MessagesFile  map[string]string

	// Messages[language][key] = value. Unprefixed maps to "".
	Messages map[string]map[string]string

	// Refs are every custom-message name referenced, from {cm:Name} anywhere
	// and from CustomMessage('Name') in [Code].
	Refs map[string]bool

	// StagedFiles are the base names [Files] copies out of the staging
	// directory.
	StagedFiles map[string]bool
}

func loadISS(t *testing.T) *issScript {
	t.Helper()
	raw, err := os.ReadFile(issFile)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", issFile, err)
	}
	body := strings.TrimPrefix(string(raw), utf8BOM)

	s := &issScript{
		MessagesFile: map[string]string{},
		Messages:     map[string]map[string]string{},
		Refs:         map[string]bool{},
		StagedFiles:  map[string]bool{},
	}
	section := ""
	for i, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if m := issSectionRe.FindStringSubmatch(trimmed); m != nil {
			section = strings.ToLower(m[1])
			continue
		}
		if trimmed == "" {
			continue
		}
		if section == "code" {
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
		} else if strings.HasPrefix(trimmed, ";") {
			continue
		}
		s.Lines = append(s.Lines, issLine{Section: section, N: i + 1, Text: trimmed})
	}

	for _, l := range s.Lines {
		switch l.Section {
		case "languages":
			name := issNameRe.FindStringSubmatch(l.Text)
			file := issMsgFileRe.FindStringSubmatch(l.Text)
			if name == nil || file == nil {
				t.Fatalf("%s:%d: [Languages] entry has no Name: or no MessagesFile:\n\t%s", issFile, l.N, l.Text)
			}
			s.LanguageNames = append(s.LanguageNames, name[1])
			s.MessagesFile[name[1]] = file[1]
		case "custommessages":
			m := cmEntryRe.FindStringSubmatch(l.Text)
			if m == nil {
				t.Fatalf("%s:%d: [CustomMessages] line is not lang.Key=value\n\t%s", issFile, l.N, l.Text)
			}
			lang, key, val := m[1], m[2], m[3]
			if s.Messages[lang] == nil {
				s.Messages[lang] = map[string]string{}
			}
			s.Messages[lang][key] = val
		case "files":
			if m := issSourceRe.FindStringSubmatch(l.Text); m != nil {
				s.StagedFiles[m[1]] = true
			}
		}
		for _, m := range cmConstRe.FindAllStringSubmatch(l.Text, -1) {
			s.Refs[m[1]] = true
		}
		for _, m := range cmCallRe.FindAllStringSubmatch(l.Text, -1) {
			s.Refs[m[1]] = true
		}
	}
	if len(s.LanguageNames) == 0 {
		t.Fatalf("%s has no [Languages] entries — the parser found nothing, which is a broken parser and not an English-only installer", issFile)
	}
	return s
}

// TestInstallerDeclaresBothLanguages is bacchus#145 at the [Languages] line: the
// installer has to offer Russian and English, and the .isl behind each has to
// be one this project has actually checked.
//
// Mutation check: delete the russian line and this names it — which the
// compile does not, because an installer offering one language is a valid
// installer. Typo the MessagesFile path and this names that too, in
// milliseconds on any platform rather than eight minutes into a Windows job.
func TestInstallerDeclaresBothLanguages(t *testing.T) {
	s := loadISS(t)

	seen := map[string]bool{}
	for _, name := range s.LanguageNames {
		if seen[name] {
			t.Errorf("%s declares the language %q twice — Inno takes the internal name as a key, so the second entry shadows the first", issFile, name)
		}
		seen[name] = true
		want, ok := vouchedLanguages[name]
		if !ok {
			t.Errorf("%s declares the language %q, which is not in vouchedLanguages. The compile catches an .isl that is absent but not one that is present and wrong: confirm the file ships with Inno Setup and is the language meant, then add it to vouchedLanguages deliberately", issFile, name)
			continue
		}
		if got := s.MessagesFile[name]; got != want {
			t.Errorf("%s: language %q reads its messages from %q, want %q", issFile, name, got, want)
		}
	}
	for _, want := range []string{langEnFile, langRuFile} {
		if !seen[want] {
			t.Errorf("%s does not declare the language %q. Both are first-class: every wizard page a user reads before the app opens comes from the .isl of the language they picked, and a missing entry means that language is simply not offered", issFile, want)
		}
	}
	if len(s.LanguageNames) < 2 {
		t.Errorf("%s declares %d language(s). With one, Inno shows no language dialog and this whole file is single-language again", issFile, len(s.LanguageNames))
	}
}

// TestInstallerCustomMessagesMatchInEveryLanguage is the enforcement itself,
// and it is symmetric on purpose: it reports a key English has and Russian does
// not, AND a key Russian has and English does not, as two distinct failures.
//
// Nothing in Inno catches either. An unprefixed entry silently applies to every
// language, so one language's sentence is shown to the other's reader; a
// prefixed entry present for only one language compiles cleanly and raises on
// the user's machine when the other language reaches it.
//
// Mutation check: delete either ru. line from [CustomMessages] and this names
// that key and that language. Delete the en. line instead and it names that
// one. Drop the "en."/"ru." prefix from a line and it names the entry as
// applying to every language at once.
func TestInstallerCustomMessagesMatchInEveryLanguage(t *testing.T) {
	s := loadISS(t)

	declared := map[string]bool{}
	for _, name := range s.LanguageNames {
		declared[name] = true
	}

	if shared, ok := s.Messages[""]; ok {
		for _, key := range sortedKeys(shared) {
			var forms []string
			for _, lang := range s.LanguageNames {
				forms = append(forms, lang+"."+key+"=")
			}
			t.Errorf("%s: [CustomMessages] entry %q has no language prefix, so Inno applies it to every language. That is one language's text shown to the other's reader, which is the exact failure this file is here to prevent — write it once per language (%s) even if the two are identical", issFile, key, strings.Join(forms, " and "))
		}
	}

	union := map[string]bool{}
	for lang, msgs := range s.Messages {
		if lang == "" {
			continue
		}
		if !declared[lang] {
			t.Errorf("%s: [CustomMessages] has entries prefixed %q, which is not a language declared in [Languages]. Nothing will ever read them", issFile, lang)
			continue
		}
		for key := range msgs {
			union[key] = true
		}
	}

	for _, key := range sortedSet(union) {
		for _, lang := range s.LanguageNames {
			val, ok := s.Messages[lang][key]
			if !ok {
				t.Errorf("%s: [CustomMessages] defines %s.%s but not %s.%s. Inno compiles this; {cm:%s} then raises on the machine of whoever picked %s", issFile, otherLangWith(s, key, lang), key, lang, key, key, lang)
				continue
			}
			if strings.TrimSpace(val) == "" {
				t.Errorf("%s: %s.%s is empty. A blank message is not a translation, and it renders as a blank line in the dialog", issFile, lang, key)
			}
		}
		// %1..%9 are the arguments the caller passes. Losing one in a
		// translation does not fail anything — it silently drops the value
		// (the path, the program name) out of the sentence that was written
		// around it.
		var reference string
		var refLang string
		for _, lang := range s.LanguageNames {
			val, ok := s.Messages[lang][key]
			if !ok {
				continue
			}
			args := argSet(val)
			if refLang == "" {
				reference, refLang = args, lang
				continue
			}
			if args != reference {
				t.Errorf("%s: %s.%s takes the arguments [%s] but %s.%s takes [%s]. The one that is missing an argument silently drops the value it was written around", issFile, refLang, key, reference, lang, key, args)
			}
		}
	}
}

// otherLangWith names a language that DOES define key, so the failure above
// reads as "defined here, missing there" rather than only "missing".
func otherLangWith(s *issScript, key, missing string) string {
	for _, lang := range s.LanguageNames {
		if lang == missing {
			continue
		}
		if _, ok := s.Messages[lang][key]; ok {
			return lang
		}
	}
	return "another language"
}

// TestInstallerCustomMessageReferencesResolve closes the other half: a {cm:}
// name that resolves to nothing at all, and a translated pair nothing uses.
//
// Inno resolves these at runtime. A mistyped {cm:} in [Tasks] or [Icons] is a
// broken wizard page; CustomMessage() in [Code] raises outright. Neither is
// visible until the installer runs, which nothing here can do.
//
// Mutation check: rename RemoveSettingsPrompt in [CustomMessages] without
// touching [Code] and this names both halves — the reference that resolves to
// nothing, and the pair nothing references.
func TestInstallerCustomMessageReferencesResolve(t *testing.T) {
	s := loadISS(t)

	local := map[string]bool{}
	for lang, msgs := range s.Messages {
		if lang == "" {
			continue
		}
		for key := range msgs {
			local[key] = true
		}
	}

	for _, ref := range sortedSet(s.Refs) {
		if local[ref] || stockCustomMessages[ref] {
			continue
		}
		t.Errorf("%s references {cm:%s}, which is neither defined in [CustomMessages] nor one of the messages every stock .isl carries. It resolves to nothing at run time — in [Code] that raises, elsewhere it is a broken wizard string", issFile, ref)
	}
	for _, key := range sortedSet(local) {
		if s.Refs[key] {
			continue
		}
		t.Errorf("%s: [CustomMessages] defines %s in every language and nothing uses it. Either a reference was renamed and these were left behind, or a string was translated for a page that was never written", issFile, key)
	}
}

// TestInstallerMessagesAreInTheLanguageTheyClaim catches the copy-and-rename:
// a ru. line holding the English sentence. It is the same failure
// translations_test.go exists for, one artifact earlier, and it is invisible to
// every other check here because such a file is perfectly well-formed.
//
// Strict on purpose in both directions. A ru. value with no Cyrillic in it is
// not a Russian message, and an en. value with Cyrillic in it is not an English
// one. If a message ever has to be brand-only ("Bacchus" and nothing else),
// that is a stock .isl message or an [Icons] literal, not a custom message —
// reconsider the string rather than loosening this.
func TestInstallerMessagesAreInTheLanguageTheyClaim(t *testing.T) {
	s := loadISS(t)

	for _, key := range sortedKeys(s.Messages[langRuFile]) {
		if !hasCyrillic(s.Messages[langRuFile][key]) {
			t.Errorf("%s: ru.%s holds no Cyrillic at all (%q). That is the English string under a Russian prefix — it compiles, it ships, and a Russian speaker reads English", issFile, key, s.Messages[langRuFile][key])
		}
	}
	for _, key := range sortedKeys(s.Messages[langEnFile]) {
		if hasCyrillic(s.Messages[langEnFile][key]) {
			t.Errorf("%s: en.%s holds Cyrillic (%q) — the two prefixes are the wrong way round", issFile, key, s.Messages[langEnFile][key])
		}
	}
}

// TestInstallerScriptEncoding is the one thing about this file that cannot be
// seen by reading it.
//
// Inno Setup 6.3 dropped the BOM requirement for a UTF-8 script holding
// non-ASCII characters. Before 6.3 a BOM-less script is decoded in the build
// machine's ANSI codepage, so every Russian message in [CustomMessages]
// becomes mojibake in the compiled installer with no warning at any stage.
// build-bundle.ps1 accepts any "Inno Setup 6" it locates, so the compiler
// version is not something this repository pins — the BOM is what makes the
// result the same on all of them, and it costs nothing on 6.3 and later.
//
// The allowed set is the same one build-bundle.ps1 enforces on the staged
// READMEs: it catches a smart quote or a stray em dash pasted in from a
// document, and text in a script neither language uses.
//
// Mutation check: strip the BOM and this fails naming the codepage risk. Paste
// a typographic apostrophe into a message and it names the character.
func TestInstallerScriptEncoding(t *testing.T) {
	raw, err := os.ReadFile(issFile)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", issFile, err)
	}
	if !utf8.Valid(raw) {
		t.Fatalf("%s is not valid UTF-8", issFile)
	}
	body := strings.TrimPrefix(string(raw), utf8BOM)
	hasBOM := len(raw) != len(body)
	nonASCII := strings.IndexFunc(body, func(r rune) bool { return r > unicode.MaxASCII }) >= 0

	switch {
	case nonASCII && !hasBOM:
		t.Errorf("%s holds non-ASCII characters and does not start with a UTF-8 BOM. Inno Setup only stopped needing one in 6.3; on 6.0-6.2 this file is read in the build machine's ANSI codepage and every Russian message ships as mojibake, with no error anywhere", issFile)
	case !nonASCII && hasBOM:
		t.Errorf("%s is pure ASCII and carries a UTF-8 BOM. Harmless, but it means the Russian messages went missing — check [CustomMessages]", issFile)
	}
	reportDisallowed(t, issFile, body)
}

// -------------------------------------------------------------------------
// README.en.txt / README.ru.txt
// -------------------------------------------------------------------------

// readme is one language's copy, cut into sections at its numbered headings.
type readme struct {
	Path     string
	Body     string
	Preamble string
	Numbers  []int
	Titles   []string
	Bodies   []string
}

// loadREADME parses the shape both files are written in: numbered, upper-case
// headings at column zero.
//
// The numbering is what makes the two comparable at all. Their heading TEXT is
// in different languages and cannot be compared, and prose has no keys — so the
// section number is the key, and it is one a reader uses too ("see section 3
// below" replaced "see SETTING IT UP below", which does not survive
// translation).
//
// A line that looks like a heading but is not upper-case is refused rather than
// ignored. Left ignored it would be a section this test cannot see, which is
// how a parity check goes quietly vacuous; refusing it costs one reflowed line
// in the file.
func loadREADME(t *testing.T, path string) *readme {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", path, err)
	}
	if !utf8.Valid(raw) {
		t.Fatalf("%s is not valid UTF-8", path)
	}
	// The committed sources are LF and carry no BOM; build-bundle.ps1 converts
	// to CRLF and adds the BOM the Russian one needs at package time. A BOM
	// here would be staged into the middle of nothing useful and would show up
	// in the title line a user reads first.
	body := string(raw)
	if strings.HasPrefix(body, utf8BOM) {
		t.Errorf("%s starts with a UTF-8 BOM. The committed sources carry none — build-bundle.ps1 is what adds it to the staged Russian copy, so one here would be doubled", path)
		body = strings.TrimPrefix(body, utf8BOM)
	}
	if strings.Contains(body, "\r") {
		t.Errorf("%s has CRLF line endings. .gitattributes normalises the sources to LF and build-bundle.ps1 converts at package time", path)
	}

	r := &readme{Path: path, Body: body}
	// -1 while still accumulating the preamble; the index of the section being
	// filled once the first heading is met.
	cur := -1
	var parts []*strings.Builder
	pre := &strings.Builder{}
	for i, line := range strings.Split(body, "\n") {
		m := headingRe.FindStringSubmatch(line)
		if m != nil && strings.ToUpper(m[2]) != m[2] {
			t.Errorf("%s:%d starts with %q at column zero but is not an upper-case heading:\n\t%s\nThis file's sections are numbered upper-case headings, and a line that only looks like one is a section this check cannot see. Reflow the line so the number is not first", path, i+1, m[1]+".", line)
			m = nil
		}
		if m == nil {
			b := pre
			if cur >= 0 {
				b = parts[cur]
			}
			b.WriteString(line)
			b.WriteString("\n")
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("%s:%d: %q is not a section number: %v", path, i+1, m[1], err)
		}
		r.Numbers = append(r.Numbers, n)
		r.Titles = append(r.Titles, m[2])
		parts = append(parts, &strings.Builder{})
		cur = len(parts) - 1
	}
	r.Preamble = pre.String()
	for _, b := range parts {
		r.Bodies = append(r.Bodies, b.String())
	}
	return r
}

// TestBundleREADMEsExistInBothLanguages is the file-level half of the same rule,
// and
// the one that would go wrong first: a README added, renamed or dropped in one
// language while the other three places that name it stay as they were.
//
// The bundle is one flat folder, so the file NAME is the language chooser a
// user actually uses. That only works if every README on disk is in the zip
// and in the installer — a Russian file that exists in this directory and in
// neither artifact is a translation nobody receives.
//
// Mutation check: remove README.ru.txt from $BundleFiles and this names the
// zip. Remove its [Files] line and this names the installer.
func TestBundleREADMEsExistInBothLanguages(t *testing.T) {
	for _, p := range []string{readmeEN, readmeRU} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s is not in this directory: %v", p, err)
		}
	}

	onDisk := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "README.") && strings.HasSuffix(e.Name(), ".txt") {
			onDisk[e.Name()] = true
		}
	}

	iss := loadISS(t)
	staged := bundleFileSet(t)

	for _, name := range sortedSet(onDisk) {
		if !staged[name] {
			t.Errorf("%s is in this directory but not in $BundleFiles in %s, so the portable zip does not carry it. build-bundle.ps1 asserts that set twice and would refuse a staged file it does not list, so this is also a broken build", name, buildFile)
		}
		if !iss.StagedFiles[name] {
			t.Errorf("%s is in this directory but has no [Files] entry in %s, so the installer does not place it in {app}", name, issFile)
		}
	}
	for _, name := range sortedSet(staged) {
		if strings.HasPrefix(name, "README.") && !onDisk[name] {
			t.Errorf("$BundleFiles in %s lists %s, which is not in this directory. build-bundle.ps1 would fail at staging", buildFile, name)
		}
	}
	// Each copy names the other. In a flat folder the alternative to a
	// bilingual file is two files a reader can find, and the cross-reference is
	// what makes a reader who opened the wrong one one line away from the right
	// one.
	for _, pair := range [][2]string{{readmeEN, readmeRU}, {readmeRU, readmeEN}} {
		b, err := os.ReadFile(pair[0])
		if err != nil {
			t.Fatalf("ReadFile %s: %v", pair[0], err)
		}
		if !strings.Contains(string(b), pair[1]) {
			t.Errorf("%s never names %s. Two files instead of one bilingual file only works if a reader who opened the wrong one is told where the right one is", pair[0], pair[1])
		}
	}
}

// TestBundleREADMEsAreStructurallyParallel is the prose half of the
// enforcement, and its granularity is the section rather than the sentence.
//
// That limit is deliberate and worth stating: no mechanical check can tell that
// a paragraph inside a translated section was not translated, any more than
// translations_test.go can tell that a Russian string says the right thing. The
// section is the largest unit that can be keyed without putting markup into a
// file a user reads in Notepad, and a section added on one side and not the
// other is the failure that actually happens when someone edits one copy.
//
// Mutation check: add a ninth section to one file and this names the mismatch
// in both directions. Copy an English section into the Russian file without
// translating it and the Cyrillic check names that section number.
func TestBundleREADMEsAreStructurallyParallel(t *testing.T) {
	en := loadREADME(t, readmeEN)
	ru := loadREADME(t, readmeRU)

	if len(en.Numbers) == 0 || len(ru.Numbers) == 0 {
		t.Fatalf("found %d sections in %s and %d in %s — the heading rule is broken, not the files", len(en.Numbers), readmeEN, len(ru.Numbers), readmeRU)
	}
	for _, r := range []*readme{en, ru} {
		for i, n := range r.Numbers {
			if n != i+1 {
				t.Errorf("%s: section headings run %v, which is not 1..%d in order. Contiguous numbering is what makes a column-zero \"N.\" unambiguous in a plain-text file", r.Path, r.Numbers, len(r.Numbers))
				break
			}
		}
	}
	if len(en.Numbers) != len(ru.Numbers) {
		t.Errorf("%s has %d sections and %s has %d. The two are kept section for section: whichever gained one, the other is missing it",
			readmeEN, len(en.Numbers), readmeRU, len(ru.Numbers))
	}

	// Language, per section. This is what catches the copy-and-forget: a
	// section present in both files, structurally identical, and English in
	// both.
	if !hasCyrillic(ru.Preamble) {
		t.Errorf("%s: the text before section 1 holds no Cyrillic", readmeRU)
	}
	for i, body := range ru.Bodies {
		if !hasCyrillic(ru.Titles[i]) {
			t.Errorf("%s: the heading of section %d (%q) holds no Cyrillic — it was not translated", readmeRU, i+1, ru.Titles[i])
		}
		if !hasCyrillic(body) {
			t.Errorf("%s: section %d (%q) holds no Cyrillic anywhere in its body — it is the English section copied across", readmeRU, i+1, ru.Titles[i])
		}
	}
	for i, title := range en.Titles {
		if hasCyrillic(title) || hasCyrillic(en.Bodies[i]) {
			t.Errorf("%s: section %d (%q) holds Cyrillic — the two files are the wrong way round", readmeEN, i+1, title)
		}
	}

	// The encodings build-bundle.ps1 will stage them under, asserted here so a
	// stray character fails on every push and on every platform, rather than
	// only on the Windows job that runs the packaging script.
	if i := strings.IndexFunc(en.Body, func(r rune) bool { return r > unicode.MaxASCII }); i >= 0 {
		t.Errorf("%s is not pure ASCII (first offender at byte %d: %q). It is staged as UTF-8 with NO BOM precisely because it can stay inside ASCII; a non-ASCII character there renders wrong in a first-run reader's Notepad", readmeEN, i, string([]rune(en.Body[i:])[0]))
	}
	reportDisallowed(t, readmeRU, ru.Body)
}

// TestBundleREADMEPlaceholdersAreSubstitutedInEveryLanguage is the trap this
// change walks straight into: build-bundle.ps1 templates {{VERSION}} and
// {{WINTUN_VERSION}}, and a second README nobody remembered to run through the
// substitution ships the literal braces to a user.
//
// The known set is READ OUT OF build-bundle.ps1 rather than hardcoded, so a
// placeholder invented in a README and never substituted, or a substitution
// dropped from the script, both fail here.
//
// Mutation check: add {{CHANNEL}} to either README and this names it. Remove
// the .Replace('{{WINTUN_VERSION}}'...) call from build-bundle.ps1 and it names
// both files.
func TestBundleREADMEPlaceholdersAreSubstitutedInEveryLanguage(t *testing.T) {
	script, err := os.ReadFile(buildFile)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", buildFile, err)
	}
	substituted := map[string]bool{}
	for _, m := range psReplaceRe.FindAllStringSubmatch(string(script), -1) {
		substituted[m[1]] = true
	}
	if len(substituted) == 0 {
		t.Fatalf("found no .Replace('{{...}}') calls in %s — the parser is broken, not the script", buildFile)
	}

	used := map[string]map[string]bool{}
	for _, p := range []string{readmeEN, readmeRU} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile %s: %v", p, err)
		}
		used[p] = map[string]bool{}
		for _, ph := range placeholderRe.FindAllString(string(b), -1) {
			used[p][ph] = true
			if !substituted[ph] {
				t.Errorf("%s uses %s, which %s never substitutes. It would ship to a user with the braces still in it", p, ph, buildFile)
			}
		}
	}
	for _, ph := range sortedSet(used[readmeEN]) {
		if !used[readmeRU][ph] {
			t.Errorf("%s uses %s and %s does not. Whatever that value tells a reader — the release they are holding, the driver version — one language is not being told it", readmeEN, ph, readmeRU)
		}
	}
	for _, ph := range sortedSet(used[readmeRU]) {
		if !used[readmeEN][ph] {
			t.Errorf("%s uses %s and %s does not. Whatever that value tells a reader, one language is not being told it", readmeRU, ph, readmeEN)
		}
	}
}

// -------------------------------------------------------------------------
// helpers
// -------------------------------------------------------------------------

// bundleFileSet reads $BundleFiles out of build-bundle.ps1 — the list the
// script asserts against the staging directory and then again against the
// finished zip.
func bundleFileSet(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(buildFile)
	if err != nil {
		t.Fatalf("ReadFile %s: %v", buildFile, err)
	}
	m := psBundleRe.FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("no $BundleFiles = @( ... ) array in %s — the parser is broken, not the script", buildFile)
	}
	set := map[string]bool{}
	for _, q := range psQuotedRe.FindAllStringSubmatch(m[1], -1) {
		set[q[1]] = true
	}
	if len(set) == 0 {
		t.Fatalf("$BundleFiles in %s parsed as empty", buildFile)
	}
	return set
}

// allowedRune is the character set both languages are written in: ASCII, the
// Cyrillic block, and the two punctuation marks Russian typography uses that
// ASCII has no equivalent for. Kept in step with Write-WindowsText in
// build-bundle.ps1, which enforces the same set on the staged files.
func allowedRune(r rune) bool {
	switch {
	case r <= unicode.MaxASCII:
		return true
	case r >= 0x0400 && r <= 0x04FF: // Cyrillic
		return true
	case r == '«' || r == '»': // guillemets
		return true
	case r == '—': // em dash
		return true
	}
	return false
}

func reportDisallowed(t *testing.T, path, body string) {
	t.Helper()
	seen := map[rune]bool{}
	for i, r := range body {
		if allowedRune(r) || seen[r] {
			continue
		}
		seen[r] = true
		t.Errorf("%s holds %q (U+%04X) at byte %d, which is outside ASCII, Cyrillic, the guillemets and the em dash. A typographic quote or a stray dash from a pasted document renders wrong on a user's machine, and text in a third script is in neither of this project's languages", path, string(r), r, i)
	}
}

func hasCyrillic(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cyrillic, r) {
			return true
		}
	}
	return false
}

// argSet renders the %1..%9 arguments a message uses as a stable string, so two
// languages' argument use can be compared. "%%" is Inno's escape for a literal
// percent and is removed first.
func argSet(v string) string {
	seen := map[string]bool{}
	for _, m := range cmArgRe.FindAllStringSubmatch(strings.ReplaceAll(v, "%%", ""), -1) {
		seen[m[1]] = true
	}
	return strings.Join(sortedSet(seen), " ")
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
