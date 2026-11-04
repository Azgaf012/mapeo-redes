#define AppVersion "1.0.0"
[Setup]
AppId={{D8E50B33-C649-4A85-BA4E-675B15F73121}
AppName=NetMap Escolar
AppVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\NetMapEscolar
DefaultGroupName=NetMap Escolar
PrivilegesRequired=lowest
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=NetMapEscolar-Instalador-{#AppVersion}-Windows-x64
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\NetMapEscolar.exe
SetupLogging=yes
CloseApplications=yes
[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
[Files]
Source: "..\dist\NetMapEscolar\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "LEEME.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme
[Tasks]
Name: "desktopicon"; Description: "Crear un acceso directo en el escritorio"; Flags: checkedonce
[Icons]
Name: "{group}\NetMap Escolar"; Filename: "{app}\NetMapEscolar.exe"
Name: "{autodesktop}\NetMap Escolar"; Filename: "{app}\NetMapEscolar.exe"; Tasks: desktopicon
[Run]
Filename: "{app}\NetMapEscolar.exe"; Description: "Abrir NetMap Escolar"; Flags: nowait postinstall skipifsilent
