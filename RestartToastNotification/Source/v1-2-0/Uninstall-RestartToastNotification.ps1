
$CheckInstalled = Test-Path -Path "C:\Windows\EndpointApps\RestartToastNotification"

if ($CheckInstalled)
{
    try {
        Write-Host "Deleting existing files"
        Start-Sleep 2
        Remove-Item -Path "C:\Windows\EndpointApps\RestartToastNotification\config-toast.xml" -ErrorAction SilentlyContinue
        Start-Sleep 2
        Remove-Item -Path "C:\Windows\EndpointApps\RestartToastNotification\RestartToastNotification-Log.log" -ErrorAction SilentlyContinue
        Start-Sleep 2
        Remove-Item -Path "C:\Windows\EndpointApps\RestartToastNotification\RestartToastNotification.ps1" -ErrorAction SilentlyContinue
        Start-Sleep 2
        Remove-Item -Path "C:\Windows\EndpointApps\RestartToastNotification\RestartToastNotification5.xml" -ErrorAction SilentlyContinue
        Start-Sleep 2
        #Remove-Item -Path "C:\Windows\EndpointApps\RestartToastNotification\Images" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\EndpointApps\RestartToastNotification\Run-RestartToastNotification.bat" -ErrorAction SilentlyContinue
        Start-Sleep 2
        #Unregister-ScheduledTask -TaskName Restart Toast Notification -Confirm:$false -Force
    }
    catch {
        Write-Host "Failed to remove old files"
    }
}

