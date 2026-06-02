#define MyAppName "wing"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Ethan-Wanng"
#define MyAppExeName "wing.exe"
#define SourceRoot "..\build\bin"
#define OutputRoot "..\dist"

[Setup]
AppId={{7D7D9ED8-AC02-47E4-9F88-3C0DF53E9C1E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={localappdata}\Programs\wing
DefaultGroupName=wing
AllowNoIcons=yes
DisableProgramGroupPage=no
OutputDir={#OutputRoot}
OutputBaseFilename=wing-setup
SetupIconFile=..\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加图标："; Flags: unchecked

[Files]
Source: "{#SourceRoot}\wing.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\libcronet.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceRoot}\flutter_ui\*"; DestDir: "{app}\flutter_ui"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\wing"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\卸载 wing"; Filename: "{uninstallexe}"
Name: "{autodesktop}\wing"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "启动 wing"; Flags: nowait postinstall skipifsilent
