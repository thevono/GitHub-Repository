MD C:\Windows\EndpointApps
MD C:\Windows\EndpointApps\CustomExplorer
ECHO Making Directory > C:\Windows\EndpointApps\CustomExplorer\log.txt
ECHO Successfully created Customer Explorer directory >> C:\Windows\EndpointApps\CustomExplorer\log.txt

ECHO Copy registry file to Custom Explorer directory >> C:\Windows\EndpointApps\CustomExplorer\log.txt
COPY "Windows-Custom-Explorer-Reg.bat" C:\Windows\EndpointApps\CustomExplorer /Y
ECHO Successfully copied bat file to Custom Explorer directory >> C:\Windows\EndpointApps\CustomExplorer\log.txt

ECHO CD into Custom Explorer Directory >> C:\Windows\EndpointApps\CustomExplorer\log.txt
PUSHD C:\Windows\EndpointApps\CustomExplorer
ECHO Successfully CD into Custom Explorer Directory >> C:\Windows\EndpointApps\CustomExplorer\log.txt

ECHO Run Windows-Custom-Explorer-Reg.bat file >> C:\Windows\EndpointApps\CustomExplorer\log.txt
CALL "Windows-Custom-Explorer-Reg.bat"
ECHO Successfully ran Windows-Custom-Explorer-Reg.bat file >> C:\Windows\EndpointApps\CustomExplorer\log.txt

ECHO Delete file >> C:\Windows\EndpointApps\CustomExplorer\log.txt
DEL C:\Windows\EndpointApps\CustomExplorer\Windows-Custom-Explorer-Reg.bat
ECHO Script ran successfully >> C:\Windows\EndpointApps\CustomExplorer\log.txt

EXIT

