#define MyAppName "wing"
#ifndef MyAppVersion
#define MyAppVersion "1.0.4.7.2"
#endif
#ifndef MyAppFileVersion
#define MyAppFileVersion "1.0.4.72"
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
CloseApplications=yes
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
