if exist c:\driversupdate (
	/S /Q "c:\driversupdate"
)
xcopy "%~dp0*" "c:\driversupdate\" /y /f
Powershell.exe -executionpolicy bypass -File  "c:\driversupdate\dell-dcu-check.ps1"

