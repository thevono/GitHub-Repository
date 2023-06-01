MD C:\Windows\EndpointApps
MD C:\Windows\EndpointApps\CustomExplorer
ECHO Making Directory > C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt
ECHO Successfully created Customer Explorer directory >> C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt

ECHO Copy registry file to Custom Explorer directory >> C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt
COPY "%~dp0Win11-RightClick-Reg.bat" C:\Windows\EndpointApps\CustomExplorer /Y
COPY "%~dp0Win11-RightClick-Reg.ps1" C:\Windows\EndpointApps\CustomExplorer /Y
ECHO Successfully copied files to Custom Explorer directory >> C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt

ECHO CD into Custom Explorer Directory >> C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt
PUSHD C:\Windows\EndpointApps\CustomExplorer
ECHO Successfully CD into Custom Explorer Directory >> C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt

ECHO Run the batch file >> C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt
PUSHD %AppData%\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\
START "Windows PowerShell.exe" "C:\Windows\EndpointApps\CustomExplorer\Win11-RightClick-Reg.ps1"
ECHO Successfully imported Win11-RightClick-Reg.bat file >> C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt

ECHO Delete file >> C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt

ECHO Script ran successfully >> C:\Windows\EndpointApps\CustomExplorer\rightclicklog.txt

PAUSE >nul

