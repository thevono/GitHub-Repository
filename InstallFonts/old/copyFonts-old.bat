if not exist "C:\ProgramData\InstallFonts" md "C:\ProgramData\InstallFonts"
robocopy . *.ttf C:\ProgramData\InstallFonts

Powershell.exe -Executionpolicy bypass -File "%~dp0InstallFonts.ps1
Exit
