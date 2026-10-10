[Setup]
AppName=OptiRadar
AppVersion=6.16.0
DefaultDirName={pf}\OptiRadar
OutputBaseFilename=optiradar-setup
ArchitecturesInstallIn64BitMode=x64

[Dirs]
Name: "{app}\data"
Name: "{app}\logs"

[Files]
Source: "out\*"; DestDir: "{app}"; Flags: recursesubdirs

[Run]
Filename: "{app}\jre\bin\java.exe"; Parameters: "-jar ""{app}\tracker-server.jar"" --install .\conf\optiradar.xml"; Flags: runhidden

[UninstallRun]
Filename: "{app}\jre\bin\java.exe"; Parameters: "-jar ""{app}\tracker-server.jar"" --uninstall"; Flags: runhidden
