#define MyAppName "wing"
#ifndef MyAppVersion
#define MyAppVersion "1.0.6"
#endif
#ifndef MyAppFileVersion
#define MyAppFileVersion "1.0.6.0"
#endif
#define MyAppPublisher "Ethan-Wanng"
#define MyAppURL "https://github.com/Ethan-Wanng/high-mae"
#define MyAppExeName "wing.exe"
#define SourceRoot "..\build\bin"
#define OutputRoot "..\dist"

[Setup]
AppId={{7D7D9ED8-AC02-47E4-9F88-3C0DF53E9C1E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={localappdata}\Programs\wing
DefaultGroupName=wing
AllowNoIcons=yes
DisableProgramGroupPage=no
OutputDir={#OutputRoot}
OutputBaseFilename=wing-{#MyAppVersion}-windows-x64-setup
SetupIconFile=..\assets\icon.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\icon.ico
VersionInfoVersion={#MyAppFileVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=wing Windows installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppFileVersion}
CloseApplications=force
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加图标："; Flags: unchecked

[Files]
Source: "{#SourceRoot}\wing.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\assets\icon.ico"; DestDir: "{app}"; DestName: "icon.ico"; Flags: ignoreversion
Source: "{#SourceRoot}\libcronet.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\flutter_ui\*"; DestDir: "{app}\flutter_ui"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\wing"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\icon.ico"; AppUserModelID: "EthanWanng.wing"
Name: "{group}\卸载 wing"; Filename: "{uninstallexe}"; IconFilename: "{app}\icon.ico"
Name: "{autodesktop}\wing"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\icon.ico"; AppUserModelID: "EthanWanng.wing"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "启动 wing"; Flags: nowait postinstall skipifsilent

[Code]
function PowerShellString(Value: String): String;
begin
  StringChangeEx(Value, '''', '''''', True);
  Result := '''' + Value + '''';
end;

procedure StopInstalledWingProcesses;
var
  ResultCode: Integer;
  InstallRoot: String;
  Script: String;
begin
  InstallRoot := ExpandConstant('{app}');
  Script :=
    '$root = [System.IO.Path]::GetFullPath(' + PowerShellString(InstallRoot) + ').TrimEnd(''\'') + ''\''; ' +
    'Get-Process -Name ''wing'',''wing_ui'' -ErrorAction SilentlyContinue | Where-Object { ' +
    '$processPath = $null; try { $processPath = $_.Path } catch { $processPath = $null }; ' +
    'if ($processPath) { $fullProcessPath = [System.IO.Path]::GetFullPath($processPath); ' +
    '$fullProcessPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase) } else { $false } ' +
    '} | ForEach-Object { $targetId = $_.Id; ' +
    'Stop-Process -Id $targetId -Force -ErrorAction SilentlyContinue; ' +
    'try { Wait-Process -Id $targetId -Timeout 10 -ErrorAction SilentlyContinue } catch {} }';

  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ' + AddQuotes(Script),
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    StopInstalledWingProcesses;
  end;
end;
