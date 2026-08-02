; Bacchus Windows installer (Inno Setup 6).
;
; Built by deploy/windows/build-bundle.ps1, which passes every value below that
; changes between releases. Compile it by hand with, e.g.:
;
;   iscc /DAppVersion=1.0.0 /DSemVer=1.0.0 /DStageDir=<dist\stage\...> \
;        /DOutputDir=<dist> /DOutputBase=bacchus-fyne-setup-1.0.0-windows-amd64 \
;        deploy\windows\bacchus.iss
;
; This is the SECOND artifact. The portable zip is the primary one and ships
; first (issue #136, ruling 4): nothing registered, nothing to uninstall, no
; trace, runs from removable media, one file that moves through any channel in
; docs/distribution.md. This exists for users who expect an installer -
; Start menu entry, an uninstaller, a normal-looking install - and it must not
; take anything away from the other one.
;
; UNSIGNED. Issue #38 is deferred to the end of 1.0 by ruling, so this raises
; SmartScreen's "Windows protected your PC" on a user's machine. That is the
; accepted state and is not to be worked around; README.txt tells the user
; about it in as many words. It is also why winget is ruled out for now - it
; needs a signed installer, and its manifest repository is Microsoft-hosted and
; therefore pullable, which is the wrong property for this product.

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif
#ifndef SemVer
  #define SemVer "0.0.0"
#endif
#ifndef StageDir
  #error StageDir must be passed with /DStageDir=... - it is the directory build-bundle.ps1 staged
#endif
#ifndef OutputDir
  #define OutputDir "."
#endif
#ifndef OutputBase
  #define OutputBase "bacchus-fyne-setup-windows-amd64"
#endif

[Setup]
; Never change AppId. It is what Windows uses to recognise an existing install,
; so a new one here turns every upgrade into a second entry in Programs and
; Features that cannot uninstall the first.
AppId={{81FBC362-0A57-47A1-A60C-4FC3F2499592}
AppName=Bacchus
AppVersion={#AppVersion}
; Must be numeric; SemVer is validated as MAJOR.MINOR.PATCH by build-bundle.ps1
; and Inno pads the fourth component. AppVersion above may carry a pre-release
; suffix, which this field cannot.
VersionInfoVersion={#SemVer}
AppPublisher=Bacchus
AppPublisherURL=https://github.com/bacchus-vpn/bacchus
AppSupportURL=https://github.com/bacchus-vpn/bacchus/issues
DefaultDirName={autopf}\Bacchus
DefaultGroupName=Bacchus
DisableProgramGroupPage=yes
UninstallDisplayName=Bacchus
UninstallDisplayIcon={app}\bacchus-fyne.exe
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBase}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
; 64-bit only. The bundle carries the amd64 wintun.dll and CI builds no other
; architecture; installing on x86 would place a DLL the loader cannot use.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Administrator only, and NOT overridable into a per-user install. That is a
; decision about where the config ends up, not about where the exe ends up.
;
; The client asks Windows for elevation itself, so it always runs under an
; administrator's token. Where a standard user has to borrow an administrator's
; credentials to do that ("over-the-shoulder" elevation), the elevated client's
; %AppData% is the ADMINISTRATOR's, not theirs - os.UserConfigDir reads the
; AppData environment variable (os/file.go), and an elevated process is given
; the elevating account's environment.
;
; An admin-mode install resolves {userappdata} through that same account, so
; the file this seeds and the file the client reads are the same file. A
; per-user install would resolve it through the standard user instead - and
; then the one user who most needs the seeded config, the one who is not an
; administrator, is the one guaranteed not to get it. Offering that mode would
; be offering an install that cannot read what it just installed.
;
; NOT CONFIRMED ON HARDWARE. The reasoning above is from the Go source and
; Inno's own documentation, on a machine with a single administrator account
; and no separate standard user. See deploy/windows/README.md, "Which %APPDATA%".
PrivilegesRequired=admin
; Suppresses Inno's compile-time warning about touching {userappdata} from an
; admin-mode install. It is deliberate here and the [Files] comment below is the
; whole reason this installer exists in the shape it does.
UsedUserAreasWarning=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; The program, and the two files that must sit next to it.
;
; wintun.dll is not optional and is not a nicety: without it, bring-up fails
; with "create wintun adapter" - the same message an unelevated run produces,
; which is why issue #135 was so easy to misread. It ships beside the exe in
; both artifacts.
;
; LICENSE.txt is this program's own, AGPL-3.0, and it ships for compliance
; rather than for form: conveying a binary under GPL-family terms means giving
; the recipient a copy of the licence along with the work. Deliberately NOT
; wired to LicenseFile= - that page makes the user click "I accept" before the
; install proceeds, and the AGPL is not an agreement acceptance is conditioned
; on. Shipping the file is the requirement; gating on it would misrepresent it.
Source: "{#StageDir}\bacchus-fyne.exe";     DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\wintun.dll";           DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\LICENSE.txt";          DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\LICENSE.wintun.txt";   DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\README.txt";           DestDir: "{app}"; Flags: ignoreversion

; The config goes to %APPDATA%, NOT next to the exe. This is the one constraint
; that separates this installer from the portable zip, and getting it backwards
; walks straight back into issue #118:
;
;   - appstate.configPaths ranks an exe-adjacent config FIRST on load, and
;     appstate.DefaultConfigPath (config.go:371) returns the exe-adjacent path
;     when a file is ALREADY there - otherwise the per-user one.
;   - Under Program Files that directory is not writable by the user running
;     the app. So a config seeded beside the exe here would be found on load,
;     reported as the save target, and every Settings save would fail on
;     permissions - which is #118 exactly, arriving from the other side.
;   - With nothing beside the exe, the same code picks
;     %APPDATA%\Bacchus\fyne-client.json, which the user owns. Seeding that file
;     is the mirror of what deploy/install.sh:565 does on Linux, and it is why
;     issue #134 - "the app tells you to copy an example that is not in the
;     artifact" - never bit a Linux user.
;
; The portable zip does the opposite, correctly: there the exe's directory
; belongs to whoever unzipped it.
;
; onlyifdoesntexist: never overwrite a config the user already has.
; uninsneveruninstall: removal is the [Code] section's decision below, together
; with the rest of %APPDATA%\Bacchus, rather than half of it happening here.
Source: "{#StageDir}\bacchus-fyne.config.json"; DestDir: "{userappdata}\Bacchus"; \
    DestName: "fyne-client.json"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{group}\Bacchus"; Filename: "{app}\bacchus-fyne.exe"
Name: "{group}\{cm:UninstallProgram,Bacchus}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Bacchus"; Filename: "{app}\bacchus-fyne.exe"; Tasks: desktopicon

[Run]
; shellexec so this goes through ShellExecuteEx: the exe asks Windows for
; elevation itself, and a per-user (unelevated) install could not start it with
; a plain CreateProcess.
Filename: "{app}\bacchus-fyne.exe"; Description: "{cm:LaunchProgram,Bacchus}"; \
    Flags: nowait postinstall skipifsilent shellexec

[Code]
procedure CurUninstallStepChanged(CurStep: TUninstallStep);
var
  Dir: String;
begin
  // %APPDATA%\Bacchus holds the config (endpoints, TURN password) and, if the
  // transport pool was ever enabled, the learned-path cache under selection\.
  //
  // Removing it is the default, and that is the considered choice rather than
  // tidiness: deploy/install.sh makes exactly the same call on Linux and states
  // the reason there - a client config holds no identity worth preserving, and
  // a user of a circumvention tool who uninstalls it usually means the residue
  // to be gone too. A leftover file naming the coordinators they used is
  // precisely the thing they were removing.
  //
  // install.sh's --keep-config is the prompt here. SuppressibleMsgBox so a
  // silent uninstall takes the default (remove) instead of hanging on a dialog
  // nobody can see.
  if CurStep = usPostUninstall then
  begin
    Dir := ExpandConstant('{userappdata}\Bacchus');
    if DirExists(Dir) then
    begin
      if SuppressibleMsgBox('Also remove your Bacchus settings?' + #13#10 + #13#10 +
           Dir + #13#10 + #13#10 +
           'This holds the endpoints and password you configured. Choose No to keep them '
           + 'for a later install.', mbConfirmation, MB_YESNO, IDYES) = IDYES then
        DelTree(Dir, True, True, True);
    end;
  end;
end;
