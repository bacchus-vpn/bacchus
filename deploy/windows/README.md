# Windows release artifacts

What ships to a Windows user, and how it is built. The Linux equivalent is
[`deploy/install.sh`](../install.sh); this is deliberately not that script's
Windows port, because Windows does not want one — see "Two artifacts" below.

> `README.en.txt` and `README.ru.txt` in this directory are not documentation
> *about* the bundle. They are the files that **ship inside** it and are the
> first thing a user reads. `build-bundle.ps1` substitutes
> `{{VERSION}}`/`{{WINTUN_VERSION}}` into both, converts both to CRLF, and
> refuses to ship either if its characters are outside the set its language
> uses.

| File | What it is |
|---|---|
| `build-bundle.ps1` | Builds both artifacts. The whole packaging step. |
| `bacchus.iss` | Inno Setup 6 script for the installer. |
| `README.en.txt`, `README.ru.txt` | Ship inside both artifacts. |
| `i18n_test.go` | Fails when the two languages disagree — see "Two languages" below. |
| `.github/workflows/release.yml` | When the above runs, and what happens to the result. |

## Two artifacts, and the zip is the primary one

**`bacchus-fyne-<version>-windows-amd64.zip`** — portable. Unzip, run. Nothing
registered, nothing to uninstall, no trace, runs from removable media, and it is
a single file that moves through any channel in
[`docs/distribution.md`](../../docs/distribution.md). For this product those
properties are the point rather than a compromise, which is why this one ships
first and is what the release notes lead with.

**`bacchus-fyne-setup-<version>-windows-amd64.exe`** — the installer, for users
who expect one: Start menu entry, uninstaller, a normal-looking install.

Both are built from one staging directory in one run, so they cannot drift.

### The bundle layout is fixed

```
bacchus-fyne-<version>-windows-amd64/
    bacchus-fyne.exe
    wintun.dll
    LICENSE.txt             this program's, AGPL-3.0
    LICENSE.wintun.txt      wintun's, which is a different licence
    bacchus-fyne.config.json
    README.en.txt
    README.ru.txt
```

Seven files, flat, one directory. `build-bundle.ps1` asserts the set twice —
once on the staging directory and again by reading the finished zip back — so
changing it fails the build rather than silently changing what other work
depends on. The installer places the same set in `{app}`, minus the config,
which goes elsewhere for the reason below.

**`LICENSE.txt` is compliance, not decoration.** Conveying a binary under
GPL-family terms means giving the recipient a copy of the licence along with
the work; a link is a pointer, not that copy. It is deliberately not wired to
Inno's `LicenseFile=`, which would make the user click "I accept" — the AGPL is
not an agreement acceptance is conditioned on, and gating on it would
misrepresent it. wintun's licence is copied out of its archive byte for byte;
this one is converted to CRLF like the READMEs, because it is ours.

Neither licence is translated, and that is not an omission. A licence is
translated by whoever stewards it or not at all; a translation made here would
be a text nobody has agreed to. Both READMEs say so in their last paragraph.

### They seed the config in opposite places, on purpose

This is the one thing to understand before changing either artifact.

* **The zip seeds `bacchus-fyne.config.json` beside the exe.** Correct: the
  directory belongs to whoever unzipped it, and
  `appstate.configPaths` ranks an exe-adjacent config first, so a portable copy
  carries its own settings and stays portable.
* **The installer seeds `%APPDATA%\Bacchus\fyne-client.json` and puts nothing
  beside the exe.** Under Program Files an exe-adjacent config would be found
  on load, reported as the save target by
  [`appstate.DefaultConfigPath`](../../clients/fyne/internal/appstate/config.go),
  and every Settings save would then fail on permissions — which is
  `bacchus-vpn/bacchus#118` arriving from the other side. With nothing beside
  the exe, the same function picks the per-user path, which is the mirror of
  what `install.sh` does on Linux and the reason `#134` never bit a Linux user.

Getting this backwards does not fail the build. It fails on a user's machine,
once, the first time they change a setting.

Both copy `clients/fyne/bacchus-fyne.config.example.json` verbatim, placeholder
hosts and all, rather than generating a file with the endpoint keys present and
empty. One template serving both platforms is worth more than two that can
drift, and `COORDINATOR_HOST`/`CHANGE_ME` tell someone editing the file by hand
what shape of value belongs there in a way `""` does not. `install.sh` reaches
for its empty-key form only when the example is not beside it.

### Which `%APPDATA%` — a limitation to confirm on hardware

The paragraph above says "the per-user path" as if there were only one. On a
machine where the person using the client is **not** an administrator, there may
be two, and this project has not yet run the case that would tell us.

The mechanism: the client asks Windows for elevation itself, so it always runs
under an administrator's token. Where a standard user borrows an
administrator's credentials to grant that ("over-the-shoulder" elevation), the
elevated process is given the *elevating* account's environment, and
`os.UserConfigDir` on Windows is a read of the `AppData` environment variable
(`os/file.go`) rather than a lookup against the calling user. So the client's
per-user config, its `selection\` cache, and anything the Settings window saves
land in the **administrator's** profile, not in the profile of the person
sitting at the machine.

What follows from that, and how confident each part is:

* **The installer stays consistent with the client** — believed, not measured.
  An admin-mode install resolves `{userappdata}` through the same account that
  will later elevate the client, so both sides land in the same profile. This is
  why `bacchus.iss` sets `PrivilegesRequired=admin` with no per-user override: a
  per-user install would seed the standard user's profile and the elevated
  client would read the administrator's, which is a guaranteed mismatch for
  exactly the user who has the least room to work around it.
* **It breaks if the two accounts differ** — install under one administrator,
  elevate the client under another, and the seeded config is in a third place
  nobody reads. Rare, and it fails legibly ("no coordinator configured") rather
  than dangerously.
* **The portable zip is immune.** It loads exe-adjacent first, and that path
  does not depend on which token is running.

**None of this has been run on hardware.** It is reasoned from the Go source and
Inno Setup's documentation on a machine with a single administrator account, and
the two sides resolve the path by different mechanisms (an environment variable
on one, a known-folder lookup on the other), which is precisely the kind of
difference that does not show up until it is measured. The case to run is a
standard user, a separate administrator account, an installer run with
over-the-shoulder elevation, and then Settings → Save.

There is one alternative worth recording, **not** implemented here: the
installer could seed the config **beside the exe** under Program Files, which is
token-independent because the load order puts it first whatever account is
running. `#118`'s objection to that — the directory is unwritable — does not
hold on Windows the way it does on Linux, because the client runs elevated on
every launch rather than only during install. `DefaultConfigPath`'s own comment
rejects a writability probe on the grounds that "the same user's next ordinary
launch could read it but never save it again", and on Windows there is no
ordinary launch. The costs are real and are why it is not the default:

* one config for the whole machine — two users of one PC cannot have different
  settings, and
* `turnPass` sits in a world-readable directory. `SaveConfig`'s `0600` does not
  protect it there: on Windows Go's file mode controls the read-only attribute
  and not the ACL, so what keeps that file private today is the profile
  directory around it.

That is the trade to weigh if the hardware run shows the per-user path is worse
than it looks. Do not implement both — two config files is the state
`configPaths` permanently shadows one of, which is worse than either.

### `AppMutex`, and what a running client does to Setup (bacchus#185)

`[Setup]` names both mutexes the client creates —
`Global\BacchusVpnClient,BacchusVpnClient` — so Setup and Uninstall stop and ask
the user to close Bacchus rather than proceeding over a running one. Before this
line existed the uninstaller ran straight through a live client and left `{app}`
holding a locked exe; Setup had the same hole from the other side, replacing a
binary that was currently routing the machine.

`CloseApplications=no` goes with it, and is the more interesting half.
Inno's default is to use the Restart Manager, whose graceful close is a
window-close message — which since `bacchus#186` **hides** this client to the
notification area instead of exiting it. So the graceful path always fails and
Inno falls back to terminating the process, which is `bacchus#115`'s stranded
machine: kill-switch armed, firewall profiles at `Block`, and no client left to
lift them. `AppMutex` refusing and sending the user through the client's own Quit
is the only route that disarms the machine first.

The two names must match
`clients/fyne/internal/singleinstance`'s constants exactly, and nothing in either
file would notice a rename. `installer_test.go` in that package asserts it — the
`.iss` is not Go, Inno compiles an `AppMutex` naming a mutex nobody creates
perfectly cleanly, and at runtime the failure looks exactly like a machine with no
client open.

**Not run on hardware.** The cases to run, all of which need a compiled
installer and a real client:

* uninstall with the client running — Setup should name Bacchus and refuse;
* upgrade-install with the client running — same;
* quit the client from the tray, then uninstall — should proceed;
* start a second client from the Start menu while one runs — should show the
  "already running" window and stop, and the first client's kill-switch should
  still be armed afterwards (`Get-NetFirewallProfile | Select Name,
  DefaultOutboundAction` all `Block`, and
  `Get-NetFirewallRule -Group BacchusKillSwitch` still returning four rules).

## Two languages, and the check that keeps them in step

Russian and English, both first-class, from the installer's first screen
onward. Not Russian with an English fallback and not the reverse: a message
present in one language and missing in the other is the defect, whichever way
round it is.

This is an inconsistency being closed rather than a new policy.
`clients/fyne/translations_test.go` already **fails the build** when a `lang.L`
key has no Russian, and gives the reason: an untranslated label renders as
English, compiles, vets, passes every other test, and ships, and the only
signal is a Russian-speaking user reading an English sentence — which is
exactly the audience this client is for. Everything the same user read *before*
the app opened was English with nothing checking it.

**The wizard.** `bacchus.iss` declares both languages, and Inno shows a
language dialog before the first page. `ShowLanguageDialog=yes` is set
explicitly even though it is the default, because with two languages it stops
being a default: `auto` would pick by the machine's UI language and show
nothing, and there is no language switch anywhere else in the wizard, so the
user it gets wrong — a Russian speaker on an English-locale Windows — would
have no way back. `/LANG=russian` still suppresses it for a silent install.

**The README ships twice, once per language, rather than once bilingually.**
The bundle is one flat folder, so both files are in front of a reader at the
same moment and the name is the chooser. A single file would have to put one
language above the other, and whichever went second is the one a reader scrolls
past. Two files also keep `README.en.txt` inside ASCII — `README.ru.txt` cannot
be, so the guarantee is available for one of them and is worth keeping there.
Each names the other, so a reader who opened the wrong one is one line away.

**Encoding differs between them, and has to.** `README.en.txt` is staged as
UTF-8 with **no** BOM, because a file that can stay inside ASCII should:
without a BOM a stray smart quote renders wrong somewhere, and with one the
file opens with visible junk in an editor that does not expect it.
`README.ru.txt` is staged as UTF-8 **with** a BOM, because Notepad before
Windows 10 1903 does not detect BOM-less UTF-8 and renders the whole file in
the ANSI codepage — for Cyrillic that is total, and against it a leading marker
costs nothing.

**`bacchus.iss` itself is UTF-8 with a BOM**, and must stay that way while it
holds any non-ASCII character. Inno Setup only stopped requiring one in 6.3;
on 6.0–6.2 a BOM-less script is read in the *build machine's* ANSI codepage, so
the Russian messages ship as mojibake with no error at any stage.
`build-bundle.ps1` accepts any "Inno Setup 6" it locates, so the compiler
version is not something this repository pins.

### `i18n_test.go`

An ordinary Go test in this directory, on the `clients/fyne/manifest_test.go`
model: it reads non-Go build artifacts, on every platform, and needs neither
Inno Setup nor Windows.

**The compile is not this check, and could not be.** `release.yml`'s
`windows-bundle` job does build both artifacts — `iscc` included — on every
pull request that touches `deploy/windows/**`, which is a real check and
catches a syntax error or an `.isl` that is not there. It catches none of what
this test is about: Inno compiles a `{cm:}` key defined for one language and
missing for the other perfectly cleanly, which is the entire premise. An
unprefixed entry, a `%1` dropped in translation, a `russian.` message holding
English, a README section that exists in one language only — every one of those
produces a successful compile and a working installer that is wrong on
somebody's screen. The Go test also covers two cases the Windows job
structurally cannot: a push straight to `main` (`release.yml` has no branch
push trigger) and a contributor with no Windows at all.

It fails, symmetrically and by name, when:

* `[Languages]` loses either language, or names an `.isl` outside the allowlist
  of pairs this project has actually confirmed ship with Inno Setup;
* a `[CustomMessages]` key exists for one language and not the other, **in
  either direction**, or carries no language prefix at all (an unprefixed entry
  applies to every language, which is one language's sentence shown to the
  other's reader);
* the two languages' versions of a message use different `%1`–`%9` arguments —
  the translation that drops one silently loses the value it was written
  around;
* a `{cm:}` reference resolves to neither a local key nor a stock `.isl`
  message, or a translated pair is referenced by nothing;
* a `russian.` message holds no Cyrillic, or an `english.` one holds some;
* the two READMEs have different numbered sections, or a Russian section holds
  no Cyrillic (the English one copied across);
* a README uses a `{{PLACEHOLDER}}` that `build-bundle.ps1` does not
  substitute, or one language uses a placeholder the other does not;
* a README exists here but is missing from `$BundleFiles` or from the
  installer's `[Files]`;
* `bacchus.iss` holds non-ASCII without a BOM, or any file holds a character
  outside ASCII, Cyrillic, the guillemets and the em dash.

Its limit is worth stating: **the section is the smallest unit it can key
prose by.** No mechanical check can tell that a paragraph inside a translated
section was left untranslated, any more than `translations_test.go` can tell
that a Russian string says the right thing. Presence is a mechanical fact and
belongs in a test; quality is a review question.

The READMEs are written in the shape that makes this possible: sections are
numbered, upper-case headings at column zero, and cross-references say "see
section 3" rather than naming a heading that does not survive translation. A
line that looks like a heading but is not upper-case is **refused** rather than
ignored, because ignoring it would be a section the parity check cannot see.

### What is not translated

The AGPL, wintun's licence, and the name "Bacchus". Licences are translated by
their stewards or not at all. The brand is treated as a brand everywhere else
in this project, including in the existing Russian strings under
`clients/fyne/translations/`, which are also the register and vocabulary the
Russian README is written to match.

## wintun

The bundle **carries** `wintun.dll` and its licence. It is never fetched at
install time.

The licence constraint this project has reasoned from is about the **source
repo**, not the release: `wintun.net` states that the signed DLLs are the only
supported way of distributing it and that they are released under a more
permissive licence than GPL 2.0, which is permission to redistribute them as
downloaded. What does not belong in an AGPL source tree is a *committed* copy —
hence `*.dll` in `.gitignore`, and hence a fetch at **build** time into a
directory that is also ignored.

The second reason is the one that decides it: an install step that fetched from
`wintun.net` would need a foreign third-party host reachable from the user's
machine, and the people this exists for are behind the apparatus
`docs/distribution.md` exists to route around. A dependency that fails exactly
where the product must work is not a dependency to take.

The pinned version tracks `golang.zx2c4.com/wintun` in `go.mod` — that module is
the loader, this is the driver it loads. `build-bundle.ps1` checks the archive
against wintun.net's published SHA-256 **before extracting anything**, and then
checks the DLL's Authenticode signature, so a swapped upstream file fails the
build instead of shipping.

## Version

**From the git tag, and from nothing else.** `release.yml` derives two values:

* the **display** version (`1.0.0`, `1.0.0-rc1`) — file names, the
  Programs-and-Features entry, both shipped READMEs;
* the bare **`MAJOR.MINOR.PATCH`**, stamped into the binary through
  `-ldflags -X …core/version.current` (ADR-0052 §5).

The second is validated hard in two places. `core/version.Parse` takes exactly
three numeric components and `Current()` **panics** on anything else, so a tag
that cannot be read that way fails the release immediately rather than producing
a client that dies at its first connect. An unstamped build would report the
source default — `0.1.0` — to every coordinator it meets, and ADR-0015's node
fence and client-update policy both turn on that number.

### The `VERSION` gate, and why it is a job

`release.yml`'s first job compares the tag against the repository's `VERSION`
file and refuses if they differ. `ci.yml` asserts the same thing on a tag push;
that copy stays, and it is deliberately not what this relies on. Two workflows
triggered by one push run **in parallel**, and there is no native way to order
them — `needs:` is intra-workflow, `workflow_run` solves a different problem. So
`ci.yml`'s assertion can go red *beside* a release that has already been
published. A check that cannot stop the thing it checks gates nothing.

Ordering the jobs `verify-version → windows-bundle → publish` makes it a
precondition instead: **a refusal happens before the build.** Nothing is
compiled, no artifact is uploaded, and no release object is created — not even a
draft.

The two version checks are not the same check and neither covers the other. The
gate asks whether the tag **equals** what the repository claims; the rule inside
the build asks whether `MAJOR.MINOR.PATCH` can be **read out of** the tag at all.
A `v1.5.0` pushed while `VERSION` still says `1.0.0` passes the second cleanly
and builds a perfectly self-consistent 1.5.0 bundle that the repository knows
nothing about.

One consequence to know rather than discover: while `VERSION` is a bare
`MAJOR.MINOR.PATCH`, a pre-release tag (`v1.0.0-rc1`) cannot pass the gate, so
the `--prerelease` path is presently unreachable. That is the two checks
agreeing rather than an oversight — `ci.yml`'s copy would refuse the same tag —
and it is the thing to revisit if release candidates are ever wanted.

## Building it by hand

On a Windows machine with Go, a mingw-w64 `gcc` on `PATH` (see
[`clients/fyne/README.md`](../../clients/fyne/README.md), "Build") and Inno
Setup 6:

```powershell
pwsh deploy\windows\build-bundle.ps1 -Version 1.0.0
```

Artifacts land in `dist\` (git-ignored). `-SkipInstaller` builds the zip alone,
for a machine with no Inno Setup. `-OutDir` moves the output. The script builds
the exe itself rather than taking a prebuilt one, so the link flags — including
the version stamp — exist in exactly one place.

## What is not here

* **Signing.** `bacchus-vpn/bacchus#38` is deferred to the end of 1.0 by ruling.
  Both artifacts are unsigned and both raise SmartScreen's "Windows protected
  your PC"; both READMEs tell the user so in as many words. ADR-0052 §6 also
  requires that the update signing key never sit on a build machine, so signing
  will not become a step in this pipeline even once `#38` lands — it is a
  deliberate act performed afterwards on the artifacts CI produced.
* **winget**, ruled out for now as a consequence: it needs a signed installer,
  and its manifest repository is Microsoft-hosted and therefore pullable, which
  is the wrong property for this product's distribution model.
* **Anything but `amd64`.** No 32-bit and no ARM64 build: CI builds neither, and
  the bundle carries only the amd64 DLL. `bacchus.iss` refuses to install on
  anything else rather than placing a DLL the loader cannot use.
* **Any third language.** Adding one means an entry in `[Languages]`, a matching
  `[CustomMessages]` pair, a third README, an entry in `$BundleFiles`, an
  `[Files]` line, and a deliberate addition to `vouchedLanguages` in
  `i18n_test.go`. Everything but the translation itself is checked. The point of
  that last one is that nobody here can compile the installer, so an `.isl` name
  taken on trust fails during a release rather than in CI.
* **A wizard anybody has looked at.** `release.yml`'s `windows-bundle` job
  *builds* both artifacts on every pull request touching this directory, so
  `build-bundle.ps1` runs for real and `iscc` compiles `bacchus.iss` for real —
  but nothing runs the installer. What still needs a person at a Windows
  machine: that the Select Language dialog appears and the wizard renders in
  Russian; that the uninstall prompt resolves its custom messages in the
  language the *install* ran in (Inno records the chosen language with the
  uninstall data, and a missing key raises rather than falling back, so this
  fails loudly if it fails); and that `README.ru.txt` opens as Russian in
  Notepad out of the extracted zip. These sit alongside the `%APPDATA%`
  question above.
