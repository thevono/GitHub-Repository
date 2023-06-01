<#
    This will check if ANY old version of DELL COMMAND UPDATE exist, if so uninstall it, and install the lastest version 4.6

    1. Scans the system if there are any old versions of Dell Command Update
    2. Then uninstalls the old version
    3. Launches the new Dell Command Update install

    Created by Von Ouch

#>



function RunUninstall {

    $uniRegArg = @(
            "/x" 
            $UApp.IdentifyingNumber 
            "/qn"
            "REBOOT=Reallysupress"
        )
    Start-Process "msiexec.exe" -ArgumentList $uniRegArg -Wait -NoNewWindow
    Start-Sleep 10
}

function uninstallDCU {
    try {
        Write-Output "Uninstalling old version"

        <#
        $uninstallReg = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object {Get-ItemProperty -Path $_.pspath}

        ForEach($UApp in $uninstallReg) {
        if (($UApp.DisplayName -match "Dell Command | Update for Windows Universal") -or ($App.DisplayName -match "Dell Command | Update")) {
            Write-Output "DELL COMMAND UPDATE FOUND"
            
            #$DCUExist = $true
            RunUninstall
            Start-Sleep 2

        Break
        }
        else {
            Write-Output "Searching ..."
        }
        Start-Sleep 1
        
    }
    #>
        
        $oldDCUUni = Get-WmiObject win32_product | `
        Where-Object{$_.name -like "*Dell Command*"}
        $oldDCUUni
        $oldDCUUni.Uninstall()

        Start-Sleep 5

        <#
        $uniRegArg = @(
            "/x" 
            $oldDCUUni.IdentifyingNumber 
            "/qn"
            "REBOOT=Reallysupress"
        )
        Start-Process "msiexec.exe" -ArgumentList $uniRegArg -Wait -NoNewWindow
        #>
    }
    catch {
        throw "Failed to uninstall DCU"
    }
    
}



function installNewDCU {
    Start-Sleep 2
    #try {
        Write-Output "Installing new version"
        #Start-Sleep 1

        #Push-Location "C:\driversupdate"
        #Start-Sleep 1
        $PathArgs = {.\Dell-Command-Update-4.6.0.exe /s /f}
        #Start-Process -Wait -FilePath .\Dell-Command-Update-4.6.0.exe -ArgumentList "/s", "/f" -PassThru -NoNewWindow 
        Invoke-Command -ScriptBlock $PathArgs
        Start-Sleep 1
        Register-ScheduledTask -xml (Get-Content 'C:\driversupdate\Dell-Driver-Update.xml' | Out-String) -TaskName "Dell Driver Update" -TaskPath "\driverupdates\" -User "System" -Force
        
        Start-Sleep 5

        $GetNewVersion = (Get-ItemProperty -Path "C:\Program Files (x86)\Dell\CommandUpdate\DellCommandUpdate.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
        if ($GetNewVersion -ge "4.6.0")
        {
            Write-Output "New version installed successfully"
            #Exit 0
        }

    #}
    #catch {
    #    throw "Failed to install new version of DCU"
    #}
    
}

$latitudeModel = Get-CimInstance -ClassName Win32_ComputerSystem | Where-Object {$_.Model -match "Latitude*"}

if ($latitudeModel)
{
    Write-Output "This system is a Dell Latitude"



    $NOTLatitudeFolder = Test-Path "C:\driversupdate\NOTLatitude"


    $AllRegApp = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | ForEach-Object {Get-ItemProperty -Path $_.pspath}

    ForEach($App in $AllRegApp) {
        if (($App.DisplayName -match "Dell Command | Update for Windows Universal") -or ($App.DisplayName -match "Dell Command | Update")) {
            Write-Output "DELL COMMAND UPDATE FOUND"
            
            $DCUExist = $true

            Break
        }
        else {
            Write-Output "Searching ..."
        }
        Start-Sleep 1
        
    }

    $NOTLatitudeFolder = Test-Path "C:\driversupdate\NOTLatitude"
    $GetNewVersion = (Get-ItemProperty -Path "C:\Program Files (x86)\Dell\CommandUpdate\DellCommandUpdate.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion

    Write-Output "Comparing versions"
    if (($DCUExist -eq $true) -and ($App.DisplayVersion -lt "4.6.0")) {
        Write-Output "Exist"
        uninstallDCU
        Start-Sleep 5
        installNewDCU
    }
    
    elseif ($NOTLatitudeFolder -eq $true) {
        Write-Output "THIS IS NOT A LATITUDE SYSTEM"
        #Exit 0
    }
    
    elseif ($GetNewVersion -ge "4.6.0") {
        Write-Output "New version installed successfully"
        #Exit 0
    }
    else {
        Write-Output "Not Exist"
        installNewDCU
    }

}
else
{
    Write-Output "This system NOT a Dell Latitude"
    New-Item "C:\driversupdate\NOTLatitude" -ItemType Directory
}













