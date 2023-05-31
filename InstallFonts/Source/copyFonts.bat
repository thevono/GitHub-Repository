if not exist "C:\Windows\EndpointApps\InstallFonts" md "C:\Windows\EndpointApps\InstallFonts"

copy "%~dp0FONTS\*.ttf" C:\Windows\EndpointApps\InstallFonts\ /y
copy "%~dp0FONTS\*.otf" C:\Windows\EndpointApps\InstallFonts\ /y
copy "%~dp0InstallFonts.ps1" C:\Windows\EndpointApps\InstallFonts\ /y

Powershell.exe -Executionpolicy bypass -File "C:\Windows\EndpointApps\InstallFonts\InstallFonts.ps1"




