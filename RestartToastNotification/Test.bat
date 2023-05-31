if exist C:\Windows\EndpointApps\ToastRestartNotification (
	DEL /S /Q "C:\Windows\EndpointApps\ToastRestartNotification\"
)
pause


-executionpolicy bypass -File  "C:\Windows\EndpointApps\ToastRestartNotification\New-ToastNotification.ps1"

/ru "NT AUTHORITY\SYSTEM"