<#
.SYNOPSIS
    Builds the Windows release artifacts: the portable zip and the installer.

.DESCRIPTION
    This is the whole packaging step for bacchus-vpn/bacchus#136, and it is a
    script rather than steps inside a workflow for the same reason
    deploy/install.sh is a script: the release path must be runnable by hand on
    the machine that will actually be used to check it, not only by CI. A
    tag-triggered workflow cannot be rehearsed by pushing a branch, so anything
    that lives only in YAML gets its first execution during a real release.

    It produces, in -OutDir:

      bacchus-fyne-<version>-windows-amd64.zip        the portable bundle
      bacchus-fyne-setup-<version>-windows-amd64.exe  the installer
      SHA256SUMS.txt                                  hashes over both

    The zip contains exactly one directory holding exactly five files:

      bacchus-fyne.exe  wintun.dll  LICENSE.wintun.txt
      bacchus-fyne.config.json  README.txt

    That layout is fixed. Do not add a sixth file without checking what else
    depends on it - see deploy/windows/README.md.

    The installer builds from the SAME staging directory and deliberately does
    NOT install bacchus-fyne.config.json beside the exe; bacchus.iss explains
    why at length (it is issue #118 seen from the other side).

.PARAMETER Version
    The display version: what appears in file names, in the installer's
    Programs-and-Features entry, and in the shipped README. Normally the git
    tag with any leading "v" removed. May carry a pre-release suffix
    ("1.0.0-rc1"); may not contain anything that is not safe in a file name.

.PARAMETER SemVer
    The bare MAJOR.MINOR.PATCH stamped into the binary via
    core/version.current. Defaults to the numeric head of -Version. This one is
    validated hard: core/version.Current() PANICS on a malformed value
    (core/version/version.go), so a sloppy stamp does not produce a build that
    reports the wrong number, it produces a build that dies at the first
    connect.

.PARAMETER OutDir
    Where the artifacts land. Defaults to <repo>/dist, which is git-ignored.

.PARAMETER SkipInstaller
    Build the zip only. Useful when Inno Setup is not installed and you only
    want to check the bundle.

.PARAMETER Iscc
    Path to Inno Setup's command-line compiler. Located automatically when not
    given.

.EXAMPLE
    pwsh deploy\windows\build-bundle.ps1 -Version 1.0.0

.EXAMPLE
    pwsh deploy\windows\build-bundle.ps1 -Version 0.0.0-dev -SkipInstaller
#>
# PowerShell 7 (pwsh), not Windows PowerShell 5.1: Get-Content -AsByteStream and
# Invoke-WebRequest's retry parameters are both 6.0+. windows-latest ships pwsh.
#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter()] [string] $Version = '0.0.0-dev',
    [Parameter()] [string] $SemVer,
    [Parameter()] [string] $OutDir,
    [Parameter()] [switch] $SkipInstaller,
    [Parameter()] [string] $Iscc
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest is glacial with it on

# --------------------------------------------------------------------------
# wintun
#
# CARRIED, not fetched at install time (issue #136's first ruling). Two
# reasons, and the second is the one that decides it:
#
#   - The licence constraint this project has reasoned from is about the SOURCE
#     REPO, not the release. wintun's own download page states that the signed
#     DLLs are the only supported way of distributing it, and that they are
#     released under a more permissive licence than GPL 2.0 - which is
#     permission to redistribute them as downloaded. What does not belong in an
#     AGPL source tree is a committed copy, which is why *.dll is git-ignored
#     and why this fetches at BUILD time into a directory that is also ignored.
#   - An install step that fetches from wintun.net needs a foreign third-party
#     host reachable from the user's machine. The people this product exists for
#     are behind the apparatus docs/distribution.md exists to route around. A
#     dependency that fails exactly where the product must work is not a
#     dependency to take.
#
# The version tracks golang.zx2c4.com/wintun in go.mod: that module is the
# loader, this is the driver it loads, and a mismatch is an ABI mismatch. 0.14.1
# is the current wintun.net release and matches the pseudo-version pinned there.
#
# The hash is wintun.net's own published SHA2-256 for this file. It is checked
# before anything is extracted, so a swapped upstream file fails the build
# rather than shipping.
# --------------------------------------------------------------------------
$WintunVersion = '0.14.1'
$WintunUrl     = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"
$WintunSha256  = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'

# The exact set the bundle ships. Asserted after staging and again inside the
# finished zip, because "the artifact contains what we think it contains" is the
# one thing a packaging script must not take on trust.
$BundleFiles = @(
    'bacchus-fyne.exe',
    'wintun.dll',
    'LICENSE.wintun.txt',
    'bacchus-fyne.config.json',
    'README.txt'
)

function Step { param([string] $Text) Write-Host "==> $Text" }
function Note { param([string] $Text) Write-Host "    $Text" }

function Invoke-Native {
    # & alone does not fail a script on a non-zero exit code, and a build that
    # kept going after a failed `go build` would package a stale exe.
    param([string] $Exe, [string[]] $Arguments, [string] $What)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed (exit $LASTEXITCODE): $Exe $($Arguments -join ' ')"
    }
}

# --------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------

if ($Version -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') {
    throw "-Version '$Version' is not usable in a file name. Expected something like 1.0.0 or 1.0.0-rc1."
}
# Tolerate a tag handed over verbatim.
$Version = $Version -replace '^v', ''

if (-not $SemVer) {
    # Anchored at both ends of the numeric head - "1.2.3" or "1.2.3-rc1" and
    # nothing else - so that "1.2.3.4" is refused rather than silently read as
    # 1.2.3. Same rule as release.yml's, which self-tests it.
    $m = [regex]::Match($Version, '^(\d+\.\d+\.\d+)($|-)')
    if (-not $m.Success) {
        throw @"
cannot derive MAJOR.MINOR.PATCH from -Version '$Version'.
core/version.Parse accepts exactly three numeric components and core/version.Current()
panics on anything else, so this must not be guessed. Pass -SemVer explicitly.
"@
    }
    $SemVer = $m.Groups[1].Value
}
if ($SemVer -notmatch '^\d+\.\d+\.\d+$') {
    throw "-SemVer '$SemVer' is not MAJOR.MINOR.PATCH; core/version.Current() would panic on it at runtime."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
if (-not $OutDir) { $OutDir = Join-Path $RepoRoot 'dist' }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$OutDir = (Resolve-Path $OutDir).Path

$BundleName = "bacchus-fyne-$Version-windows-amd64"
$SetupName  = "bacchus-fyne-setup-$Version-windows-amd64"
$StageRoot  = Join-Path $OutDir 'stage'
$StageDir   = Join-Path $StageRoot $BundleName
$WorkDir    = Join-Path $OutDir 'work'

Step "Bacchus Windows bundle $Version (binary stamped $SemVer)"
Note "repo:   $RepoRoot"
Note "output: $OutDir"

foreach ($d in @($StageRoot, $WorkDir)) {
    if (Test-Path $d) { Remove-Item -Recurse -Force $d }
}
New-Item -ItemType Directory -Path $StageDir | Out-Null
New-Item -ItemType Directory -Path $WorkDir  | Out-Null

# --------------------------------------------------------------------------
# 1. The binary
# --------------------------------------------------------------------------

Step 'building bacchus-fyne.exe'

# clients/fyne is the only package in this repo needing a C toolchain: Fyne's
# desktop driver renders through OpenGL via cgo (ADR-0039). CGO_ENABLED=0 does
# not fail as "you have no C compiler" - go-gl's files drop out on a build
# constraint and the error names a package no reader connects to the cause, so
# check it here rather than reading it out of the wreckage later.
$env:CGO_ENABLED = '1'
$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
if (-not (Get-Command gcc -ErrorAction SilentlyContinue)) {
    throw @"
no gcc on PATH. clients/fyne needs a mingw-w64 GCC (clients/fyne/README.md, "Build").
On a workstation: install MSYS2's mingw-w64-x86_64-gcc and put its bin directory on PATH.
"@
}
Note "gcc:    $((Get-Command gcc).Source)"
Note "go:     $((Get-Command go).Source)"

$exeOut = Join-Path $StageDir 'bacchus-fyne.exe'

# -H=windowsgui is what clients/fyne/README.md documents for the shipping
# binary: no console window behind the GUI.
#
# -X core/version.current is how a release build states its own release number
# (core/version/version.go:28, ADR-0052 section 5). Unstamped, this binary would
# report the source default - 0.1.0 - to every coordinator it talks to, and
# ADR-0015's node fence and client-update policy both turn on that number.
#
# -trimpath keeps the build machine's directory layout out of the shipped
# binary. It does not make this build reproducible - ADR-0052 section 5 says
# plainly that clients/fyne is not, because reproducing it means pinning an
# entire C toolchain and sysroot - but there is no reason to ship the paths.
$ldflags = "-H=windowsgui -X github.com/bacchus-vpn/bacchus/core/version.current=$SemVer"
Push-Location $RepoRoot
try {
    Invoke-Native 'go' @('build', '-trimpath', '-ldflags', $ldflags, '-o', $exeOut, './clients/fyne') 'go build'
} finally {
    Pop-Location
}

$exe = Get-Item $exeOut
Note ("bacchus-fyne.exe: {0:N1} MB" -f ($exe.Length / 1MB))
# A Fyne binary with the GL stack linked in is tens of megabytes. A few hundred
# KB means something got stubbed out, which is exactly the failure that must not
# reach a release.
if ($exe.Length -lt 5MB) {
    throw "bacchus-fyne.exe is only $($exe.Length) bytes - too small to have the GL stack linked in"
}
$mz = Get-Content $exeOut -AsByteStream -TotalCount 2
if (($mz[0] -ne 0x4D) -or ($mz[1] -ne 0x5A)) { throw 'bacchus-fyne.exe is not a PE image' }

# --------------------------------------------------------------------------
# 2. wintun
# --------------------------------------------------------------------------

Step "fetching wintun $WintunVersion"

$wintunZip = Join-Path $WorkDir "wintun-$WintunVersion.zip"
Invoke-WebRequest -Uri $WintunUrl -OutFile $wintunZip -UseBasicParsing -MaximumRetryCount 3 -RetryIntervalSec 3

$got = (Get-FileHash $wintunZip -Algorithm SHA256).Hash.ToUpperInvariant()
if ($got -ne $WintunSha256) {
    throw @"
wintun-$WintunVersion.zip does not match its published hash.
  expected $WintunSha256
  got      $got
Nothing was extracted. Do not work around this: check https://www.wintun.net for the
current published SHA2-256 and update `$WintunSha256 in this script deliberately.
"@
}
Note "sha256 matches the published value"

$wintunDir = Join-Path $WorkDir 'wintun'
Expand-Archive -Path $wintunZip -DestinationPath $wintunDir -Force

# Discovered rather than hardcoded. The archive's internal layout is upstream's
# to change, and a wrong guess here would fail during a real release; a search
# that fails loudly, with the tree printed, is answerable from the log alone.
$dll = Get-ChildItem -Path $wintunDir -Recurse -File -Filter 'wintun.dll' |
    Where-Object { $_.FullName -match '[\\/]bin[\\/]amd64[\\/]wintun\.dll$' } |
    Select-Object -First 1
if (-not $dll) {
    Get-ChildItem -Path $wintunDir -Recurse -File | ForEach-Object { Write-Host "    $($_.FullName)" }
    throw "no bin/amd64/wintun.dll in wintun-$WintunVersion.zip - the archive layout above is not what this expects"
}

$lic = Get-ChildItem -Path $wintunDir -Recurse -File |
    Where-Object { $_.Name -match '^LICENSE.*\.txt$' } |
    Sort-Object { $_.FullName.Length } |
    Select-Object -First 1
if (-not $lic) {
    Get-ChildItem -Path $wintunDir -Recurse -File | ForEach-Object { Write-Host "    $($_.FullName)" }
    throw "no LICENSE*.txt in wintun-$WintunVersion.zip - it must ship beside the DLL, so this is fatal"
}

Copy-Item $dll.FullName (Join-Path $StageDir 'wintun.dll')
# Renamed on the way in: LICENSE.txt beside an AGPL program would read as the
# program's licence, and this one covers the DLL only.
Copy-Item $lic.FullName (Join-Path $StageDir 'LICENSE.wintun.txt')
Note "wintun.dll from $($dll.FullName.Substring($wintunDir.Length + 1))"
Note "licence    from $($lic.FullName.Substring($wintunDir.Length + 1))"

# The zip hash proves we got the bytes wintun.net published. The Authenticode
# signature proves those bytes are WireGuard LLC's, independently of the host
# that served them - worth checking for the one proprietary binary this project
# redistributes.
$sig = Get-AuthenticodeSignature (Join-Path $StageDir 'wintun.dll')
if ($sig.Status -ne 'Valid') {
    throw "wintun.dll's Authenticode signature is '$($sig.Status)', not Valid - refusing to ship it"
}
Note "signed by $($sig.SignerCertificate.Subject)"

# --------------------------------------------------------------------------
# 3. The config template
# --------------------------------------------------------------------------

Step 'staging the config template'

# Issue #134: the app told a Windows user to copy a config example that was in
# no artifact. This is the same thing deploy/install.sh:565 does on Linux with
# the same file, which is exactly why #134 never bit a Linux user - one template,
# one source of truth, both platforms.
#
# In the ZIP it lands beside the exe, which is right: a portable copy's
# directory belongs to whoever unzipped it, and appstate.configPaths ranks an
# exe-adjacent config first. The INSTALLER does the opposite; bacchus.iss says
# why.
$example = Join-Path $RepoRoot 'clients/fyne/bacchus-fyne.config.example.json'
if (-not (Test-Path $example)) {
    throw "missing $example - the bundle's config template comes from it"
}
Copy-Item $example (Join-Path $StageDir 'bacchus-fyne.config.json')

# --------------------------------------------------------------------------
# 4. README.txt
# --------------------------------------------------------------------------

Step 'staging README.txt'

$readmeSrc = Join-Path $PSScriptRoot 'README.txt'
$readme = Get-Content -Raw -Path $readmeSrc
$readme = $readme.Replace('{{VERSION}}', $Version).Replace('{{WINTUN_VERSION}}', $WintunVersion)

# Kept ASCII on purpose. Written without a BOM (so it does not start with
# visible junk in editors that do not expect one) and read on Windows by
# whatever the user has, which for a first-run reader is Notepad. ASCII is the
# one encoding every one of those agrees on; the moment a smart quote or an
# em dash gets in, the file needs a BOM or it renders wrong somewhere. Fail
# rather than ship an unreadable first-run instruction.
$nonAscii = [regex]::Matches($readme, '[^\x00-\x7F]')
if ($nonAscii.Count -gt 0) {
    throw "deploy/windows/README.txt contains $($nonAscii.Count) non-ASCII character(s), e.g. '$($nonAscii[0].Value)'. Keep it ASCII - see the comment here."
}
# CRLF: it is a .txt read on Windows, and the repo normalises to LF
# (.gitattributes). Convert at package time so the source file stays normal.
$readme = ($readme -replace "`r`n", "`n") -replace "`n", "`r`n"
[System.IO.File]::WriteAllText((Join-Path $StageDir 'README.txt'), $readme, (New-Object System.Text.UTF8Encoding($false)))

# --------------------------------------------------------------------------
# 5. Check the staged bundle, then zip it
# --------------------------------------------------------------------------

Step 'checking the staged bundle'

$staged = Get-ChildItem -Path $StageDir -Recurse | ForEach-Object { $_.Name } | Sort-Object
$want = $BundleFiles | Sort-Object
if (($staged -join '|') -ne ($want -join '|')) {
    throw "staged bundle is wrong.`n  want: $($want -join ', ')`n  got:  $($staged -join ', ')"
}
foreach ($f in $BundleFiles) {
    $i = Get-Item (Join-Path $StageDir $f)
    Note ("{0,-26} {1,12:N0} bytes" -f $i.Name, $i.Length)
}

Step 'building the portable zip'

$zipPath = Join-Path $OutDir "$BundleName.zip"
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
# Present by default under pwsh; the load is for the case where it is not, and
# it must not be able to take the script down when it is unnecessary.
try { Add-Type -AssemblyName 'System.IO.Compression.FileSystem' } catch { }
# includeBaseDirectory: unzipping gives one folder, not five loose files in
# whatever directory the user happened to be in.
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $StageDir, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $true)

# Read the finished artifact back rather than trusting the call above.
$zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
try {
    $entries = $zip.Entries | ForEach-Object { $_.FullName } | Sort-Object
} finally {
    $zip.Dispose()
}
$wantEntries = ($BundleFiles | ForEach-Object { "$BundleName/$_" }) | Sort-Object
if (($entries -join '|') -ne ($wantEntries -join '|')) {
    throw "the zip does not contain what it should.`n  want: $($wantEntries -join ', ')`n  got:  $($entries -join ', ')"
}
Note "$BundleName.zip: $($entries.Count) entries under $BundleName/"

# --------------------------------------------------------------------------
# 6. The installer
# --------------------------------------------------------------------------

$setupPath = Join-Path $OutDir "$SetupName.exe"

if ($SkipInstaller) {
    Step 'skipping the installer (-SkipInstaller)'
    $setupPath = $null
} else {
    Step 'building the installer'

    if (-not $Iscc) {
        $cmd = Get-Command 'iscc' -ErrorAction SilentlyContinue
        if ($cmd) {
            $Iscc = $cmd.Source
        } else {
            $Iscc = @(
                "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
                "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
            ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        }
    }
    if (-not $Iscc) {
        throw @"
Inno Setup's compiler (ISCC.exe) was not found. Install Inno Setup 6
(https://jrsoftware.org/isinfo.php, or: choco install innosetup), or pass -Iscc,
or pass -SkipInstaller to build the portable zip only.
"@
    }
    Note "iscc:   $Iscc"

    Invoke-Native $Iscc @(
        '/Qp',
        "/DAppVersion=$Version",
        "/DSemVer=$SemVer",
        "/DStageDir=$StageDir",
        "/DOutputDir=$OutDir",
        "/DOutputBase=$SetupName",
        (Join-Path $PSScriptRoot 'bacchus.iss')
    ) 'iscc'

    if (-not (Test-Path $setupPath)) { throw "iscc reported success but $setupPath is not there" }
    Note ("$SetupName.exe: {0:N1} MB" -f ((Get-Item $setupPath).Length / 1MB))
}

# --------------------------------------------------------------------------
# 7. Hashes
#
# Published with the release and printed here. This is not ceremony: these
# artifacts are meant to travel by mirror, messenger and USB stick
# (docs/distribution.md), so the only thing a recipient can check is the bytes
# against a hash they got another way. sha256sum's own format, so `sha256sum -c
# SHA256SUMS.txt` works as-is on the receiving end.
#
# It is also the shape #34 will want: ADR-0052's signed manifest names a size
# and a SHA-256 per artifact and deliberately names no location.
# --------------------------------------------------------------------------

Step 'hashing the artifacts'

$artifacts = @($zipPath)
if ($setupPath) { $artifacts += $setupPath }

$lines = foreach ($a in $artifacts) {
    $h = (Get-FileHash $a -Algorithm SHA256).Hash.ToLowerInvariant()
    Note "$h  $(Split-Path -Leaf $a)"
    "$h  $(Split-Path -Leaf $a)"
}
$sumPath = Join-Path $OutDir 'SHA256SUMS.txt'
[System.IO.File]::WriteAllText($sumPath, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

Step 'done'
foreach ($a in $artifacts) { Write-Host "    $a" }
Write-Host "    $sumPath"

# Left for the caller: these artifacts are UNSIGNED. Issue #38 is deferred to
# the end of 1.0 by ruling, so both of them raise SmartScreen on a user's
# machine, and README.txt tells the user that in as many words. ADR-0052 also
# requires that the update signing key never sits on a build machine, so
# signing does not belong in this script even once #38 lands - it is a
# deliberate act performed afterwards on the artifacts this produced.
