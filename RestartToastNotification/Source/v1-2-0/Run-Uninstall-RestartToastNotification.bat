
Powershell.exe -windowstyle hidden -executionpolicy bypass -File  ".\Uninstall-RestartToastNotification.ps1"

SCHTASKS /DELETE /TN "Restart Toast Notification" /F

