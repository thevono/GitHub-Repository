if exist C:\Windows\EndpointApps\RestartToastNotification\ (
	DEL /S /Q "C:\Windows\EndpointApps\RestartToastNotification"
)
xcopy "%~dp0*" "C:\Windows\EndpointApps\RestartToastNotification\*" /E /H /C /I /y /f
schtasks /create /xml "C:\Windows\EndpointApps\RestartToastNotification\RestartToastNotification6.xml" /tn "Restart Toast Notification" /F


