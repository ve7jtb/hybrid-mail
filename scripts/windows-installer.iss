#ifndef TargetArch
#define TargetArch "x64"
#endif
[Setup]
AppId=HybridMail-{#TargetArch}
AppName=Hybrid Mail
AppVersion=1.2.0
AppPublisher=Hybrid Mail
DefaultDirName={localappdata}\Programs\Hybrid Mail
DefaultGroupName=Hybrid Mail
PrivilegesRequired=lowest
#if TargetArch == "arm64"
ArchitecturesAllowed=arm64
ArchitecturesInstallIn64BitMode=arm64
#else
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#endif
OutputDir=..\dist\windows
OutputBaseFilename=Hybrid-Mail-1.2.0-Windows-{#TargetArch}-Setup
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\Hybrid Mail.exe
[Files]
Source: "..\build\windows-image\Hybrid Mail\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{group}\Hybrid Mail"; Filename: "{app}\Hybrid Mail.exe"
Name: "{userdesktop}\Hybrid Mail"; Filename: "{app}\Hybrid Mail.exe"
[Run]
Filename: "{app}\Hybrid Mail.exe"; Description: "Launch Hybrid Mail"; Flags: nowait postinstall skipifsilent
