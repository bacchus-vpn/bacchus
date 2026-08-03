# 54. The Windows distribution artifact: a bundle that carries `wintun.dll` and a config template and elevates itself, shipped as a portable zip first and an installer second

- Status: accepted
- Date: 2026-08-02

## Context

There is no way to install Bacchus on Windows. `deploy/install.sh` says so in its
own first line — it installs *"a Bacchus **Linux** client or a Bacchus server
node"* — and it places systemd units and needs `groupadd`/`usermod`. There is no
MSI, no Inno Setup, no NSIS, no winget manifest and no `.ps1` installer anywhere
in this repository. #18 `[G3]`, the closed installer card, was the Linux
one-liner. Nothing ever asked for the Windows equivalent, so nothing noticed it
was missing — on a platform that is half of the 1.0 desktop scope (ADR-0052 §8).

The consequence is sharper than a missing convenience. **On Windows the
bare-downloaded-binary route is not one route among several; it is the only one**,
every user is on it, and it does not work. #115's hardware pass found two
independent defects within minutes of running the CI binary the way a user would:

- **#134** — the app points at a config example that is not in the artifact, and
  the Settings window cannot set a coordinator, so there is no way to configure it
  at all.
- **#135** — `wintun.dll` is a runtime dependency that is deliberately not in the
  repository and not in the artifact. Without it bring-up fails with `create
  wintun adapter`, which is *the same message an unelevated run produces*, so the
  two causes are indistinguishable to the person in front of the screen.

Fixing each individually still leaves a user hand-editing JSON and hand-fetching a
DLL from a foreign site — a reasonable ask of a developer and not of the
population #34's release channel is meant to reach. #136 is the root card. Its
four sub-decisions were ruled on 2026-08-02, and this record is those rulings.
**It decides what the artifact contains and how many artifacts there are; it
builds neither.** #136 stays open for that.

## What is in the tree today

Verified against `main` at `d26a772`, because three of the four rulings below turn
on it:

- **No application manifest, no `.syso` and no `.rc` anywhere in the repository.**
  `clients/fyne` has never asked Windows for elevation, by any mechanism.
- **`golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2`** in `go.mod`
  (indirect). `clients/fyne/README.md` documents fetching the matching wintun.net
  release into the git-ignored `clients/fyne/wintun/` staging directory, and
  already states the packaging rule this record adopts: *"In any release bundle,
  ship `wintun.dll` **and its `LICENSE.txt`** alongside the exe."*
- **`configCandidates` (`clients/fyne/internal/appstate/config.go:244`) names
  exactly two paths**: `bacchus-fyne.config.json` beside the executable, and
  `<os.UserConfigDir()>/Bacchus/fyne-client.json`, which on Windows is
  `%AppData%\Bacchus\fyne-client.json`. `configPaths` **loads** exe-adjacent
  first; `DefaultConfigPath` **saves** per-user first *unless an exe-adjacent file
  already exists*, in which case it keeps using it. That asymmetry is #118's fix,
  and §4 below is entirely about respecting it.
- **`deploy/install.sh:565` seeds the per-user file** from
  `bacchus-fyne.config.example.json`, which is precisely why #134 has never bitten
  a Linux user.
- **CI's `windows-fyne-client` job** builds `bacchus-fyne.exe` with `-ldflags
  "-H=windowsgui"` and uploads it, and its own comment calls the result *a test
  artifact, not a release*. Nothing places a DLL or a config beside it.

## Decision

### 1. The bundle carries `wintun.dll`. It is not fetched at install time.

`wintun.dll` and its `LICENSE.txt` ship inside the artifact, beside the exe. The
version must match `golang.zx2c4.com/wintun` in `go.mod`, and the file must be the
binary **as downloaded from wintun.net** rather than one rebuilt from source.

Two reasons, and the second is the one that decides it.

**The licence constraint everyone has reasoned from is about the source repo, not
about the release.** `wintun.dll` is proprietary — © WireGuard LLC, "licensed, not
sold" — which is why it is not committed to an AGPL source tree and why
`clients/fyne/wintun/` is git-ignored. But wintun's own guidance is to distribute
the binary as downloaded rather than rebuilt, and that is a permission to
redistribute, not a prohibition on it. The retired `clients/windows/README.md`
said so outright, and `clients/fyne/README.md` still does. The rule is "do not
vendor it into the repository", and shipping it in a release bundle does not
violate that rule.

**An install-time fetch needs a foreign third-party host reachable from the user's
machine.** That is the reason this is not a close call. The target population is
behind the apparatus `docs/distribution.md` exists to route around; every channel
in that document is chosen for surviving a censor, and a first-run step that
reaches out to a single foreign domain is a dependency that fails exactly where
the product must work. A tool whose first launch requires the open internet has
made the open internet a prerequisite for getting to the tunnel.

The bundle is therefore **self-contained by design**: everything needed to reach a
working tunnel travels in the one file that travels through the channels.

### 2. The exe requests elevation itself

`clients/fyne` gains an application manifest declaring
`requestedExecutionLevel level="requireAdministrator"`, embedded into the binary
as a `.syso` at build time.

This is a new file, not a restored one. **The manifest deleted with
`clients/windows` (`bacchus.exe.manifest`) declared a dependency on Common
Controls v6 for `lxn/walk` and nothing else** — verified: it contains one
`dependentAssembly` element and no `requestedExecutionLevel` at all. It was
unrelated to elevation and was correctly deleted; Fyne needs none of it.

The client must run as Administrator to bring the tunnel up, and today nothing
arranges for that. A double-click produces the `create wintun adapter` failure
with no hint that privilege is the cause — the ambiguity #135 is about. With the
manifest, Windows raises the UAC prompt at launch and that entire failure class
disappears, because the process either has the privilege or the user declined a
prompt they can see and understand.

Asking the OS beats documenting the requirement. "Right-click, Run as
administrator" is an instruction that has to reach the user through the same
channels the binary did, in a language they read, and be remembered on every
launch. A manifest is asked and answered by the operating system on the machine.

### 3. The bundle carries a config template

`bacchus-fyne.config.json` ships beside the exe with the endpoint keys present and
empty. That is the file name `configCandidates` looks for exe-adjacent, so the
template is loaded, not ignored.

This is the Windows form of what `deploy/install.sh:565` already does on Linux —
seed a config the user can actually edit — and it is why #134 has never been a
Linux problem. A user with a file full of empty keys can fill them in; a user with
no file at all, and a Settings window that does not offer the fields, has nothing
to act on.

**Left open deliberately: whether `Coordinators`/`STUN`/`TURN` also get fields in
the Settings window.** ADR-0039 separates operator configuration from user
preference, and that separation is right when an operator installs for someone
else. But the user of a downloaded binary *is* the operator, which is the case
that separation did not have in view. Shipping the template does not foreclose the
fields, and the fields would not remove the need for the template — a first launch
still needs somewhere to write. It is a separate decision and is not made here.

### 4. Both a portable zip and an installer, with the zip primary — and they seed config in opposite places

Not either/or.

**The portable zip is the primary artifact and ships first.** For this product its
properties are the point rather than a compromise: nothing registered, nothing to
uninstall, no trace left on the machine, runs from removable media, and it is a
**single file that moves through every channel in `docs/distribution.md`** —
including the ones that are hardest to enumerate, a Telegram handout and a copy
passed between two people. It also sidesteps #118's writability problem entirely,
because the directory it unpacks into is the user's own.

**The installer follows**, for users who expect one: a Start-menu entry, an
uninstaller, an install that looks like every other install on the machine. That
is not a small audience, and the zip does not serve it.

**The trap, and the one constraint the installer must respect.** The two artifacts
have to seed the config in **opposite** places, and getting this backwards walks
straight back into #118 from the other side:

| artifact | exe lands in | config seeded at |
|---|---|---|
| portable zip | a directory the user chose and owns | `bacchus-fyne.config.json` **beside the exe** |
| installer | Program Files, typically | `%AppData%\Bacchus\fyne-client.json`, **never beside the exe** |

The mechanism is `configPaths`/`DefaultConfigPath`. Load order ranks an
exe-adjacent config **first**, and `DefaultConfigPath` keeps saving to an
exe-adjacent config that already exists — deliberately, because a save that landed
elsewhere would write a second file that the load order then permanently shadows,
so the user's edits would appear to save and never take effect. Under Program
Files that same rule is a trap: a seeded exe-adjacent file is unwritable, wins the
load order anyway, and makes every subsequent save fail. Seeding `%AppData%`
instead leaves the exe-adjacent candidate absent, which is exactly the condition
under which `DefaultConfigPath` prefers the per-user path — the mirror of what
`install.sh` does on Linux.

The zip does the opposite, and is correct to: there the exe's directory belongs to
the user, an exe-adjacent config is what makes the install genuinely portable
(config travels with the binary on the stick), and an existing exe-adjacent file
is precisely the "deliberate act that should win" the load order was written for.

`wintun.dll` and its `LICENSE.txt` go beside the exe in **both**.

### 5. Neither artifact is signed, and winget is ruled out as a consequence

Code signing is #38, deferred to the end of 1.0 by ruling. Both artifacts are
therefore unsigned and both will produce a SmartScreen interstitial on first run.
**That is the accepted state**, not an oversight, and it is the first-install cost
ADR-0052 §8 already priced: SmartScreen fires on Mark-of-the-Web, which the
downloading application applies, so it is acquisition that pays it and not the
update path.

One note for whoever builds the zip, because it decides *what* the interstitial
fires on. Mark-of-the-Web is applied to the downloaded container, and Explorer
propagates the zone identifier to the files it extracts from one — so the
interstitial is expected to land on `bacchus-fyne.exe` itself rather than only on
the zip, while an extraction tool that does not propagate the stream would produce
no prompt at all. That makes the prompt partly a property of how the user
unpacked, not only of what was shipped. *Stated as the documented mechanism and
flagged to confirm on real Windows during the build half, in the same terms
ADR-0052 §8 flags its own Mark-of-the-Web claim.*

**winget is ruled out for now**, and it falls out of the same deferral rather than
being a separate judgement. It needs a signed installer, which does not exist yet.
And its manifest repository is Microsoft-hosted and therefore pullable on request
— the same property that made the Apple and Google storefronts unreliable for this
app category in `docs/distribution.md` §2, arriving one layer down. A channel that
can be removed centrally is a channel to add on top of a distribution model, never
one to build it on.

## Consequences

- **+** A Windows user gets a working first run from one download: the exe, the
  driver it needs, a config it can find, and a privilege prompt instead of a
  cryptic failure. #134 and #135 stop being reachable through the supported path.
- **+** The primary artifact is a single self-contained file, which is the shape
  `docs/distribution.md`'s asymmetric channels carry best and the shape that
  survives being copied from a stick.
- **+** First run depends on no foreign host. The censored-network failure mode
  that an install-time DLL fetch would have introduced never exists.
- **+** #34's release channel gains the starting state it assumed. It replaces a
  binary that is already installed; on Windows, until now, nothing put the first
  one there.
- **−** The release bundle now redistributes a proprietary binary. Permitted, and
  it makes the release something more than "our own AGPL output": the version must
  be tracked against `go.mod`, and a wintun update becomes a release step someone
  has to perform.
- **−** Two artifacts is twice the packaging, twice the release checklist, and a
  standing invariant that the two seed config in opposite places — a rule that is
  invisible in the artifacts themselves and is only enforced by whoever builds
  them.
- **−** Requiring Administrator at launch is coarse. The whole GUI runs elevated
  for the whole session, which is the same trade Windows enforcement already makes
  and is *not* the boundary ADR-0049 drew on Linux, where the privileged half is a
  separate helper behind a peer-credential socket. Windows keeps the coarser
  arrangement in 1.0.
- **−** A UAC prompt at every launch is friction, and on an unsigned binary it is
  friction that names an unknown publisher.
- **−** Elevation and the per-user config path can disagree on a standard-user
  machine, which is where §2 and §4 meet. `requireAdministrator` on an account
  without administrator rights produces an over-the-shoulder UAC prompt, and the
  process then runs under *that administrator's* token — so `os.UserConfigDir()`
  resolves to their `%AppData%` rather than the installing user's, and the config
  the installer seeded is not the one the elevated client reads. The portable zip
  is unaffected, because an exe-adjacent config does not depend on whose token
  opened the process, which is one more reason it is the primary artifact.
  *Stated as the documented mechanism and flagged for #136's build half to confirm
  on real Windows rather than to assume in a build script.*
- **−** Both artifacts trip SmartScreen until #38 lands, on a population that has
  every reason to be suspicious of a download that the operating system says it
  does not trust.

> **Update (2026-08-03):** the distribution surface speaks Russian and English,
> both first-class, and something fails when it stops doing so (#145).
>
> This record decided *what the artifact contains* and never asked what language
> it contains it in. The answer it shipped with was English: `[Languages]` in
> `bacchus.iss` held one entry, every wizard page and the uninstall prompt were
> English, and so was the whole of `README.txt`. That is an inconsistency rather
> than a policy — `clients/fyne/translations_test.go` **fails the build** when a
> `lang.L` key has no Russian, and says why in its own header: an untranslated
> label renders as English, compiles, vets, passes every other test, and ships,
> and the only signal is a Russian-speaking user reading an English sentence,
> *which is exactly the audience this client is for*. Everything that user read
> **before** the app opened had no such discipline.
>
> **Ruled (owner, 2026-08-03): two languages from the start, Russian and
> English, both first-class.** Not Russian with an English fallback and not the
> reverse. A message present in one and missing in the other is the defect
> whichever way round it is, so the check is symmetric.
>
> Three things follow, and the third is the one with teeth:
>
> - **The installer declares both.** Inno Setup ships `Russian.isl`, and
>   `ShowLanguageDialog` stays at `yes`: `auto` picks by the machine's UI
>   language and shows nothing, and there is no language switch anywhere else
>   in the wizard, so the user it gets wrong has no way back.
> - **§4's bundle layout changes for the first time.** It is now **seven**
>   files, not six: `README.txt` becomes `README.en.txt` and `README.ru.txt`.
>   Two files rather than one bilingual file, because the bundle is one flat
>   folder — both are in front of a reader at once and the name is the chooser,
>   where a single file would have to put one language above the other and
>   whichever went second is the one a reader scrolls past. It also keeps the
>   English copy inside ASCII, which is a guarantee the packaging script can
>   make about it and cannot make about a file carrying Cyrillic.
> - **The enforcement, which is the point.** `deploy/windows/i18n_test.go` is
>   an ordinary Go test on the `manifest_test.go` model — it reads non-Go build
>   artifacts on every platform and needs neither Inno Setup nor Windows. It
>   fails, by name and in both directions, on a `{cm:}` key present for one
>   language and absent for the other, an unprefixed `[CustomMessages]` entry
>   (which silently applies to all languages), a `%1`–`%9` argument dropped in
>   translation, a `russian.` message with no Cyrillic in it, a section present
>   in one README and not the other, a `{{PLACEHOLDER}}` the build script does
>   not substitute, and a README missing from either artifact's file list. Its
>   granularity for prose is the section and not the sentence, which is the same
>   line `translations_test.go` draws: presence is a mechanical fact and belongs
>   in a test, quality is a review question.
>
> **§5 is untouched and so is the AGPL's place in this record.** The licences
> are *not* translated — translated by their stewards or not at all — and
> `LICENSE.txt` remains deliberately unwired from `LicenseFile=`, because that
> page conditions the install on clicking "I accept" and the AGPL is not an
> agreement acceptance is conditioned on. "Bacchus" stays untranslated as a
> brand, as it is everywhere else including `clients/fyne/translations/`.
>
> **Not verified on hardware, and it cannot be here.** There is no Inno Setup
> compiler, no PowerShell and no Windows machine in this development
> environment, so neither `bacchus.iss` nor `build-bundle.ps1` has been
> executed. The static check is a check on their text. What a real machine still
> owes: that the wizard renders Russian, that the uninstall prompt resolves its
> custom messages in the language the *install* ran in, and that
> `README.ru.txt` opens as Russian in Notepad out of the extracted zip. Listed
> with the other hardware items in `deploy/windows/README.md`.

## Scope: what this record does not decide

- **The artifacts themselves.** No zip is built, no installer is chosen, no
  manifest is written and no `.syso` is generated by this record. That is #136's
  build half, which stays open.
- **Which installer technology.** Inno Setup, NSIS, MSI or WiX — the constraint in
  §4 binds whichever is picked, and nothing else here does.
- **Whether `Coordinators`/`STUN`/`TURN` join the Settings window** (§3). Open on
  purpose.
- **Code signing** (#38), and with it the SmartScreen interstitial and any winget
  listing.
- **How the artifact reaches a user, and how they check it.**
  `docs/distribution.md` owns acquisition; this record owns what is acquired.
- **Anything about Linux or macOS packaging.** Linux has #18's installer; macOS is
  outside the 1.0 scope (ADR-0050).
- **Any Go, and any build-system change.** Design half only.
