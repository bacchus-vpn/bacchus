# Windows release artifacts

What ships to a Windows user, and how it is built. The Linux equivalent is
[`deploy/install.sh`](../install.sh); this is deliberately not that script's
Windows port, because Windows does not want one — see "Two artifacts" below.

> `README.txt` in this directory is not documentation *about* the bundle. It is
> the file that **ships inside** the bundle and is the first thing a user reads.
> `build-bundle.ps1` substitutes `{{VERSION}}`/`{{WINTUN_VERSION}}` into it,
> converts it to CRLF, and refuses to ship it if it is not pure ASCII.

| File | What it is |
|---|---|
| `build-bundle.ps1` | Builds both artifacts. The whole packaging step. |
| `bacchus.iss` | Inno Setup 6 script for the installer. |
| `README.txt` | Ships inside both artifacts. |
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
    LICENSE.wintun.txt
    bacchus-fyne.config.json
    README.txt
```

Five files, flat, one directory. `build-bundle.ps1` asserts the set twice —
once on the staging directory and again by reading the finished zip back — so
adding a file here fails the build rather than silently changing what other
work depends on.

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
  Programs-and-Features entry, the shipped `README.txt`;
* the bare **`MAJOR.MINOR.PATCH`**, stamped into the binary through
  `-ldflags -X …core/version.current` (ADR-0052 §5).

The second is validated hard in two places. `core/version.Parse` takes exactly
three numeric components and `Current()` **panics** on anything else, so a tag
that cannot be read that way fails the release immediately rather than producing
a client that dies at its first connect. An unstamped build would report the
source default — `0.1.0` — to every coordinator it meets, and ADR-0015's node
fence and client-update policy both turn on that number.

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
  your PC"; `README.txt` tells the user so in as many words. ADR-0052 §6 also
  requires that the update signing key never sit on a build machine, so signing
  will not become a step in this pipeline even once `#38` lands — it is a
  deliberate act performed afterwards on the artifacts CI produced.
* **winget**, ruled out for now as a consequence: it needs a signed installer,
  and its manifest repository is Microsoft-hosted and therefore pullable, which
  is the wrong property for this product's distribution model.
* **A localised installer and `README.txt`.** Both are English only, in a
  product whose UI is Russian-first. Inno Setup ships a Russian message file, so
  the wizard is cheap; the user-facing text is a translation decision rather than
  a packaging one.
* **Anything but `amd64`.** No 32-bit and no ARM64 build: CI builds neither, and
  the bundle carries only the amd64 DLL. `bacchus.iss` refuses to install on
  anything else rather than placing a DLL the loader cannot use.
