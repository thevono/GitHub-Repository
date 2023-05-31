





Get-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*" | Select-Object "DisplayName", "PSChildName"



Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\*" | Select-Object "PSChildName"




$CollectAppXPackageInventory = $true

Function Get-InstalledAppXPackages() {
	$AppXPackagePropertyNames= "Name", "Version", "PackageFullName"
	$AppXPackage = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object $AppXPackagePropertyNames | Sort-Object Name | Sort-Object DisplayName
	Start-Sleep -Seconds 5
	Return $AppXPackage
	
}

Get-InstalledAppXPackages


if ($CollectAppXPackageInventory) {
	$AppXPackages = Get-InstalledAppXPackages

	$AppXArray = @()
	foreach ($AppX in $AppXPackages) {
		$AppXDetails = New-Object -TypeName PSObject
		$AppXDetails | Add-Member -MemberType NoteProperty -Name "AppXName" -Value $AppX.Name -Force
		$AppXDetails | Add-Member -MemberType NoteProperty -Name "AppXVersion" -Value $AppX.Version -Force
		$AppXDetails | Add-Member -MemberType NoteProperty -Name "AppXPackageFullName" -Value $Appx.PackageFullName -Force
		$AppXArray += $AppXDetails
		$AppXPayload = $AppXArray
	}
}

$AppXPayload


#$AppXPayload | ConvertTo-Json | Out-File .\CustomAppXPackageReport.json
#$AppXPayload | ConvertTo-Csv | Out-File .\CustomAppXPackageReport.csv


$AppXPackagejson = $AppXPayload | ConvertTo-Json | Out-File .\CustomAppXPackageReport.json
$AppXPackagejson
$GetJson = Get-Content .\CustomAppXPackageReport.json | ConvertFrom-Json | ConvertTo-Csv | Out-File .\CustomAppXPackageReport.csv
$GetJson


<#
$ResponseAppXPackageInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($AppXPackagejson)) -logType $AppXPackageLogName

if ($CollectAppXPackageInventory) {
	if ($ResponseAppXPackageInventory -match "200 :") {

		$OutputMessage = $OutputMessage + " AppXPackageInventory:OK " + $ResponseAppXPackageInventory
	}
	else {
		$OutputMessage = $OutputMessage + " AppXPackageInventory:Fail " 
	}
}
#>














$CollectAppInventory = $true


function Get-InstalledApplications() {
    param(
        [string]$UserSid
    )
    
    New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
    $regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
    $regpath += "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
	#$regAppPackage = @("HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\*")
	#$regAppPackage += "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\*"
    if (-not ([IntPtr]::Size -eq 4)) {
        $regpath += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        $regpath += "HKU:\$UserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
		#$regAppPackage += "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\*"
    }
    $propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher' #, 'UninstallString'

	#$AppsObjects = "DisplayName", "DisplayVersion", "Publisher"
	#$Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | Select-Object $AppsObjects | Sort-Object DisplayName   

	
	

    $Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName 
    
	Remove-PSDrive -Name "HKU" | Out-Null

    Return $Apps

	

	#$AppPackage
	#$Apps

}#end function

#region APPINVENTORY
if ($CollectAppInventory) {
	#$AppLog = "AppInventory"
	
	#Get SID of current interactive users
	$CurrentLoggedOnUser = (Get-CimInstance win32_computersystem).UserName
	if (-not ([string]::IsNullOrEmpty($CurrentLoggedOnUser))) {
		$AdObj = New-Object System.Security.Principal.NTAccount($CurrentLoggedOnUser)
		$strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
		$UserSid = $strSID.Value
	} else {
		$UserSid = $null
	}
	
	#Get Apps for system and current user
	$MyApps = Get-InstalledApplications -UserSid $UserSid
	$UniqueApps = ($MyApps | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedApps = ($MyApps | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateApp = ($DuplicatedApps | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppList = $UniqueApps + $NewestDuplicateApp | Sort-Object DisplayName
	
	$AppArray = @()
	foreach ($App in $CleanAppList) {
		$tempapp = New-Object -TypeName PSObject
		$tempapp | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
		#$tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
		#$tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppName" -Value $App.DisplayName -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppVersion" -Value $App.DisplayVersion -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppInstallDate" -Value $App.InstallDate -Force -ErrorAction SilentlyContinue
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppPublisher" -Value $App.Publisher -Force
		#$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallString" -Value $App.UninstallString -Force
		#$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallRegPath" -Value $app.PSPath.Split("::")[-1]
		$AppArray += $tempapp
	}
	
	$AppPayLoad = $AppArray
}
#endregion APPINVENTORY

$AppPayload

$Appjson = $AppPayLoad | ConvertTo-Json | Out-File .\AppReport.json
$Appjson

#$AppXPayload 

Get-Content .\AppReport.json | ConvertFrom-Json | ConvertTo-Csv | Out-File .\AppReport.csv

























