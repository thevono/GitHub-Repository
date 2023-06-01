

<#
    Detection Rule for detecting any old version of DELL COMMAND UPDATE
    Created by Von Ouch
#>


$AllRegApp = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object {Get-ItemProperty -Path $_.pspath}

ForEach($App in $AllRegApp) {
    if ($App.name -like "*Dell Command*"){
        Write-Output "DELL COMMAND UPDATE FOUND"
        
        $DCUExist = $true
        #$GetVersion = $App | Select-Object {$_.DisplayVersion}
        #$GetVersion

        Break
    }
    else {
        Write-Output "Searching ..."
    }
    Start-Sleep 1
    
}


$NOTLatitudeFolder = Test-Path "C:\driversupdate\NOTLatitude"
try {
    $GetNewVersion = ((Get-ItemProperty -Path "C:\Program Files (x86)\Dell\CommandUpdate\DellCommandUpdate.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion)
}
catch {
    throw "Failed to locate DCU in 32bit"
}


Write-Output "Comparing versions"
if (($DCUExist -eq $true) -and ($App.DisplayVersion -lt "4.6.0"))
{
    Write-Host "OLD EXIST"
    Exit 15
}
elseif ($NOTLatitudeFolder -eq $true)
{
    Write-Host "THIS IS NOT A LATITUDE SYSTEM"
    Exit 0
}
elseif ($GetNewVersion -ge "4.6.0")
{
    Write-Host "New version installed successfully"
    Exit 0
}
else {
    Write-Host "Not Exist"
    Exit 15
}










