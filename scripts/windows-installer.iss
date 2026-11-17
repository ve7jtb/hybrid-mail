#ifndef TargetArch
#define TargetArch "x64"
#endif
[Setup]
AppId=HybridMail-{#TargetArch}
AppName=PQ Mail
AppVersion=1.2.0
AppPublisher=PQ Mail
DefaultDirName={localappdata}\Programs\PQ Mail
DefaultGroupName=PQ Mail
PrivilegesRequired=lowest
#if TargetArch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif
OutputDir=..\dist\windows
OutputBaseFilename=PQ-Mail-1.2.0-Windows-{#TargetArch}-Setup
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\PQ Mail.exe
[Files]
Source: "..\build\windows-image\PQ Mail\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{group}\PQ Mail"; Filename: "{app}\PQ Mail.exe"
Name: "{userdesktop}\PQ Mail"; Filename: "{app}\PQ Mail.exe"
[Run]
Filename: "{app}\PQ Mail.exe"; Description: "Launch PQ Mail"; Flags: nowait postinstall skipifsilent
