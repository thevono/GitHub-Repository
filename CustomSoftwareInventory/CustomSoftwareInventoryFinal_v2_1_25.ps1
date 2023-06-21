<#
.SYNOPSIS
    Collect custom device inventory and upload to Log Analytics for further processing. 

.DESCRIPTION
    This script will collect device hardware and / or app inventory and upload this to a Log Analytics Workspace. This allows you to easily search in device hardware and installed apps inventory. 
    The script is meant to be runned on a daily schedule either via Proactive Remediations (RECOMMENDED) in Intune or manually added as local schedule task on your Windows 10 Computer. 

.EXAMPLE
    Invoke-CustomInventory.ps1 (Required to run as System or Administrator)      

.NOTES
    FileName:    Invoke-CustomInventory.ps1
    Author:      Jan Ketil Skanke
    Contributor: Sandy Zeng / Maurice Daly
    Contact:     @JankeSkanke
    Created:     2021-01-Feb
    Updated:     2021-Nov-07

	Path: C:\Windows\IMECache\HealthScripts\6148d74a-fbc1-45a7-84ce-dc1229fb5d69_21

    Version history:
    0.9.0 - (2021-01-02) Script created
    1.0.0 - (2021-01-02) Script polished cleaned up. 
    1.0.1 - (2021-04-05) Added NetworkAdapter array and fixed typo
    2.0.1 - (2021-09-01) Removed all location information for privacy reasons 
    2.1.0 - (2021-09-08) Added section to cater for BIOS release version information, for HP, Dell and Lenovo and general bugfixes
    2.1.1 - (2021-21-10) Added MACAddress to the inventory for each NIC. 
	2.1.2 - (05-10-2023) Edited to fit Booyah Advertising's needs. (By Von Ouch)
	2.1.3 - (05-15-2023) Added WIFI/LAN Info with Driver versions. (By Von Ouch)
	2.1.4 - (05-18-2023) Added CustomInventoryReportWorkspace. (By Von Ouch)
	2.1.22 - (05-22-2023) Added AppXPackage Inventory list. (By Von Ouch)
	2.1.23 - (06-09-2023) Remove duplicate results from AppXPackage Inventory list. (By Von Ouch)
	2.1.25 - (06-09-2023) Remove empty or null AppX Names from AppXPackage Inventory list, like DeploymentAgent.exe, V2.1.25 - forgot to add sort. (By Von Ouch)
	
#>
#region initialize
# Enable TLS 1.2 support 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Replace with your Log Analytics Workspace ID
$CustomerId = "VALUE"

# Replace with your Primary Key
$SharedKey = "VALUE"

#Control if you want to collect App or Device Inventory or both (True = Collect)
$CollectAppInventory = $true
$CollectDeviceInventory = $true
$CollectAppXPackageInventory = $true

$AppLogName = "CustomAppInventory"
$DeviceLogName = "CustomDeviceInventory"
$AppXPackageLogName = "CustomAppXPackageInventory"
$Date = (Get-Date)

# You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
# DO NOT DELETE THIS VARIABLE. Recommened keep this blank. 
$TimeStampField = ""

#endregion initialize

#region functions
function Get-AzureADTenantID {
	# Cloud Join information registry path
	$AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
	# Retrieve the child key name that is the tenant id for AzureAD
	$AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
	return $AzureADTenantID
}#end function
# Function to get Azure AD DeviceID
function Get-AzureADDeviceID {
    <#
    .SYNOPSIS
        Get the Azure AD device ID from the local device.
    
    .DESCRIPTION
        Get the Azure AD device ID from the local device.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-05-26
        Updated:     2021-05-26
    
        Version history:
        1.0.0 - (2021-05-26) Function created
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoThumbprint -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
			$AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
			if ($AzureADJoinCertificate -ne $null) {
				# Determine the device identifier from the subject name
				$AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
				# Handle return value
				return $AzureADDeviceID
			}
		}
	}
} #endfunction 
# Function to get Azure AD Device Join Date
function Get-AzureADJoinDate {
    <#
    .SYNOPSIS
        Get the Azure AD device join date 
    
    .DESCRIPTION
        Get the Azure AD device join date 
    
    .NOTES
        Author:      Jan Ketil Skanke
        Contact:     @JankeSkanke
        Created:     2021-11-11
        Updated:     2021-11-11
    
        Version history:
        1.0.0 - (2021-11-11) Function created
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoThumbprint -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
			$AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
			if ($AzureADJoinCertificate -ne $null) {
				# Determine the device identifier from the subject name
				$AzureADJoinDate = ($AzureADJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
				# Handle return value
				return $AzureADJoinDate
			}
		}
	}
} #endfunction 
# Function to get all Installed Application
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
    $propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher'
	$Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName 
	Remove-PSDrive -Name "HKU" | Out-Null
    Return $Apps

}#end function

# Function to send data to log analytics
Function Send-LogAnalyticsData() {
	<#
   .SYNOPSIS
	   Send log data to Azure Monitor by using the HTTP Data Collector API
   
   .DESCRIPTION
	   Send log data to Azure Monitor by using the HTTP Data Collector API
   
   .NOTES
	   Author:      Jan Ketil Skanke
	   Contact:     @JankeSkanke
	   Created:     2022-01-14
	   Updated:     2022-01-14
   
	   Version history:
	   1.0.0 - (2022-01-14) Function created
   #>
   param(
	   [string]$sharedKey,
	   [array]$body, 
	   [string]$logType,
	   [string]$customerId
   )
   #Defining method and datatypes
   $method = "POST"
   $contentType = "application/json"
   $resource = "/api/logs"
   $date = [DateTime]::UtcNow.ToString("r")
   $contentLength = $body.Length
   #Construct authorization signature
   $xHeaders = "x-ms-date:" + $date
   $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
   $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
   $keyBytes = [Convert]::FromBase64String($sharedKey)
   $sha256 = New-Object System.Security.Cryptography.HMACSHA256
   $sha256.Key = $keyBytes
   $calculatedHash = $sha256.ComputeHash($bytesToHash)
   $encodedHash = [Convert]::ToBase64String($calculatedHash)
   $signature = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
   
   #Construct uri 
   $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
   
   #validate that payload data does not exceed limits
   if ($body.Length -gt (31.9 *1024*1024))
   {
	   throw("Upload payload is too big and exceed the 32Mb limit for a single upload. Please reduce the payload size. Current payload size is: " + ($body.Length/1024/1024).ToString("#.#") + "Mb")
   }
   $payloadsize = ("Upload payload size is " + ($body.Length/1024).ToString("#.#") + "Kb ")
   
   #Create authorization Header
   $headers = @{
	   "Authorization"        = $signature;
	   "Log-Type"             = $logType;
	   "x-ms-date"            = $date;
	   "time-generated-field" = $TimeStampField;
   }
   #Sending data to log analytics 
   $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
   $statusmessage = "$($response.StatusCode) : $($payloadsize)"
   return $statusmessage 
}#end function
#Function to get AzureAD TenantID

#endregion functions

#region script
#Get Common data for App and Device Inventory: 
#Get Intune DeviceID 
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

# add user UPN info to the query
$UPN = Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Enrollments\* -Name "UPN" -ErrorAction SilentlyContinue | Select-Object UPN -ErrorAction SilentlyContinue

#Get Computer Info
$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$ComputerName = $ComputerInfo.Name
$ComputerManufacturer = $ComputerInfo.Manufacturer

if ($ComputerManufacturer -match "Dell") {
	$ComputerManufacturer = "Dell"
}

#region DEVICEINVENTORY
if ($CollectDeviceInventory) {
	
	# Get Computer Inventory Information 
	$ComputerOSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
	$ComputerBiosInfo = Get-CimInstance -ClassName Win32_Bios
	$ComputerModel = $ComputerInfo.Model
	$ComputerLastBoot = $ComputerOSInfo.LastBootUpTime
	$ComputerUptime = [int](New-TimeSpan -Start $ComputerLastBoot -End $Date).Days
	$ComputerInstallDate = $ComputerOSInfo.InstallDate
	$DisplayVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
	if ([string]::IsNullOrEmpty($DisplayVersion)) {
		$ComputerWindowsVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
	} else {
		$ComputerWindowsVersion = $DisplayVersion
	}
	$ComputerOSName = $ComputerOSInfo.Caption
	$ComputerSerialNr = $ComputerBiosInfo.SerialNumber
	$ComputerBiosVersion = $ComputerBiosInfo.SMBIOSBIOSVersion
	$ComputerBiosDate = $ComputerBiosInfo.ReleaseDate
	$ComputerFirmwareType = $env:firmware_type

	$ComputerPhysicalMemory = [Math]::Round(($ComputerInfo.TotalPhysicalMemory / 1GB))
	$ComputerOSBuild = $ComputerOSInfo.BuildNumber
	$ComputerOSRevision = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
	$ComputerCPU = Get-CimInstance win32_processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors
	$ComputerProcessorManufacturer = $ComputerCPU.Manufacturer | Get-Unique
	$ComputerProcessorName = $ComputerCPU.Name | Get-Unique
	$ComputerNumberOfCores = $ComputerCPU.NumberOfCores | Get-Unique
	$ComputerNumberOfLogicalProcessors = $ComputerCPU.NumberOfLogicalProcessors | Get-Unique
	
	try {
		$TPMValues = Get-Tpm -ErrorAction SilentlyContinue | Select-Object -Property TPMReady, TPMPresent, TPMEnabled, TPMActivated, ManagedAuthLevel
	} catch {
		$TPMValues = $null
	}

	try {
		$BitLockerInfo = Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object -Property *
	} catch {
		$BitLockerInfo = $null
	}
	
	$ComputerTPMReady = $TPMValues.TPMReady
	$ComputerTPMPresent = $TPMValues.TPMPresent
	$ComputerTPMEnabled = $TPMValues.TPMEnabled
	$ComputerTPMActivated = $TPMValues.TPMActivated
	
	$ComputerBitlockerCipher = $BitLockerInfo.EncryptionMethod
	$ComputerBitlockerStatus = $BitLockerInfo.VolumeStatus
	$ComputerBitlockerProtection = $BitLockerInfo.ProtectionStatus
	
	# Get BIOS information
	# Determine manufacturer specific information
	switch -Wildcard ($ComputerManufacturer) {
		"*Dell*" {
			$ComputerManufacturer = "Dell"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			#$ComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku.Trim()
			
			# Obtain current BIOS release
			$ComputerBiosVersion = (Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion).Trim()
			
		}

	}
	
    
	#Get network adapters
	$WifiArray = @()

	$WifiName = Get-NetAdapter | Where-Object {$_.Name -eq "Wi-Fi" } | Select-Object Name
	$WifiInterDesc = Get-NetAdapter | Where-Object {$_.Name -eq "Wi-Fi" } | Select-Object InterfaceDescription
	$WifiDriverVer = Get-NetAdapter | Where-Object {$_.Name -eq "Wi-Fi" } | Select-Object DriverVersion
	$WifiDriverDate = Get-NetAdapter | Where-Object {$_.Name -eq "Wi-Fi" } | Select-Object DriverDate
	$WifiDriverPub = Get-NetAdapter | Where-Object {$_.Name -eq "Wi-Fi" } | Select-Object DriverProvider

	$WifiInfo = New-Object -TypeName psobject
	$WifiInfo | Add-Member -MemberType NoteProperty -Name "InterfaceName" -Value "$WifiName" -Force
	$WifiInfo | Add-Member -MemberType NoteProperty -Name "WifiDescription" -Value "$WifiInterDesc" -Force
	$WifiInfo | Add-Member -MemberType NoteProperty -Name "WifiDriverVersion" -Value "$WifiDriverVer" -Force
	$WifiInfo | Add-Member -MemberType NoteProperty -Name "WifiDriverDate" -Value "$WifiDriverDate" -Force
	$WifiInfo | Add-Member -MemberType NoteProperty -Name "WifiDriverPublisher" -Value "$WifiDriverPub" -Force
	$WifiArray += $WifiInfo
	[System.Collections.ArrayList]$WifiArrayList = $WifiArray
	$WifiArrayList

	$EthernetArray = @()
	$LANName = Get-NetAdapter | Where-Object {$_.Name -eq "Ethernet" } | Select-Object Name
	$LANInterDesc = Get-NetAdapter | Where-Object {$_.Name -eq "Ethernet" } | Select-Object InterfaceDescription
	$LANDriverVer = Get-NetAdapter | Where-Object {$_.Name -eq "Ethernet" } | Select-Object DriverVersion
	$LANDriverDate = Get-NetAdapter | Where-Object {$_.Name -eq "Ethernet" } | Select-Object DriverDate
	$LANDriverPub = Get-NetAdapter | Where-Object {$_.Name -eq "Ethernet" } | Select-Object DriverProvider

	$LANInfo = new-object -TypeName PSObject
	$LANInfo | Add-Member -MemberType NoteProperty -Name "InterfaceName" -Value "$LANName" -Force
	$LANInfo | Add-Member -MemberType NoteProperty -Name "LANDescription" -Value "$LANInterDesc" -Force
	$LANInfo | Add-Member -MemberType NoteProperty -Name "LANDriverVersion" -Value "$LANDriverVer" -Force
	$LANInfo | Add-Member -MemberType NoteProperty -Name "LANDriverDate" -Value "$LANDriverDate" -Force
	$LANInfo | Add-Member -MemberType NoteProperty -Name "LANDriverPublisher" -Value "$LANDriverPub" -Force
	$EthernetArray += $LANInfo
	[System.Collections.ArrayList]$EthernetArrayList = $EthernetArray
	$EthernetArrayList

	# Get Disk Health
	$DiskArray = @()
	$Disks = Get-PhysicalDisk | Where-Object { $_.BusType -match "NVMe|SATA|SAS|ATAPI|RAID" }
	
	# Loop through each disk
	foreach ($Disk in ($Disks | Sort-Object DeviceID)) {
		# Obtain disk health information from current disk
		# Obtain media type
		$DriveDetails = Get-PhysicalDisk -UniqueId $($Disk.UniqueId) | Select-Object MediaType, HealthStatus
		$DriveMediaType = $DriveDetails.MediaType
		$DriveHealthState = $DriveDetails.HealthStatus
		
		# Create custom PSObject
		$DiskHealthState = new-object -TypeName PSObject
		
		# Create disk entry
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk Number" -Value $Disk.DeviceID
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $($Disk.FriendlyName)
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "HealthStatus" -Value $DriveHealthState
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "MediaType" -Value $DriveMediaType
		
		$DiskArray += $DiskHealthState
		[System.Collections.ArrayList]$DiskHealthArrayList = $DiskArray
	}
    
	
	
	# Create JSON to Upload to Log Analytics
	$Inventory = New-Object System.Object
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Model" -Value "$ComputerModel" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value "$ComputerManufacturer" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerUpTime" -Value "$ComputerUptime" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "LastBoot" -Value "$ComputerLastBoot" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value "$ComputerInstallDate" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "WindowsVersion" -Value "$ComputerWindowsVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value "$ComputerSerialNr" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BiosVersion" -Value "$ComputerBiosVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BiosDate" -Value "$ComputerBiosDate" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "FirmwareType" -Value "$ComputerFirmwareType" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Memory" -Value "$ComputerPhysicalMemory" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSBuild" -Value "$ComputerOSBuild" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSRevision" -Value "$ComputerOSRevision" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSName" -Value "$ComputerOSName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUManufacturer" -Value "$ComputerProcessorManufacturer" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUName" -Value "$ComputerProcessorName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUCores" -Value "$ComputerNumberOfCores" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPULogical" -Value "$ComputerNumberOfLogicalProcessors" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMReady" -Value "$ComputerTPMReady" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMPresent" -Value "$ComputerTPMPresent" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMEnabled" -Value "$ComputerTPMEnabled" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMActived" -Value "$ComputerTPMActivated" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerCipher" -Value "$ComputerBitlockerCipher" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerVolumeStatus" -Value "$ComputerBitlockerStatus" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerProtectionStatus" -Value "$ComputerBitlockerProtection" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "WifiInfo" -Value $WifiArrayList -Force	
	$Inventory | Add-Member -MemberType NoteProperty -Name "LANInfo" -Value $EthernetArrayList -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "DiskHealth" -Value $DiskHealthArrayList -Force
	
	
	$DevicePayLoad = $Inventory
	
}
#endregion DEVICEINVENTORY

#region APPXPACKAGEINVENTORY
if ($CollectAppXPackageInventory) {

	$AppXPackagePath = "C:\Program Files\WindowsApps\"
	$AppXExeFiles = Get-ChildItem -Path $AppXPackagePath -Filter "*.exe" -File -Recurse

	$AppXArray = @()
	foreach ($AppXExe in $AppXExeFiles) {

		$AppXInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AppXExe.FullName)

		$GetAppXObj = $AppXInfo | Select-Object ProductName, FileVersion, CompanyName 

		if (-not [string]::IsNullOrWhiteSpace($GetAppXObj.ProductName)) {
			$AppXObject = New-Object -TypeName PSObject
			$AppXObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
			$AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
			$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value $GetAppXObj.ProductName -Force
			$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXVersion" -Value $GetAppXObj.FileVersion -Force
			$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXCompany" -Value $GetAppXObj.CompanyName -Force
			$AppXArray += $AppXObject 
		}
	}

	$UniqueAppXData = $AppXArray | Group-Object -Property "AppXName" | ForEach-Object { $_.Group[0] } | Sort-Object -Property "AppXName"

    $AppXData = $UniqueAppXData
	#$AppXData = $AppXArray

}
#endregion APPXPACKAGEINVENTORY


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
		$tempapp | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppName" -Value $App.DisplayName -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppVersion" -Value $App.DisplayVersion -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppInstallDate" -Value $App.InstallDate -Force -ErrorAction SilentlyContinue
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppPublisher" -Value $App.Publisher -Force
		$AppArray += $tempapp
	}
	
	$AppPayLoad = $AppArray
}
#endregion APPINVENTORY

# Sending the data to Log Analytics Workspace
$Devicejson = $DevicePayLoad | ConvertTo-Json
$Appjson = $AppPayLoad | ConvertTo-Json
$AppXPackagejson = $AppXData | ConvertTo-Json


# Submit the data to the API endpoint
$ResponseDeviceInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($Devicejson)) -logType $DeviceLogName
$ResponseAppInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($Appjson)) -logType $AppLogName
$ResponseAppXPackageInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($AppXPackagejson)) -logType $AppXPackageLogName

#Report back status
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "


if ($CollectDeviceInventory) {
    if ($ResponseDeviceInventory -match "200 :") {
        
        $OutputMessage = $OutPutMessage + "DeviceInventory:OK " + $ResponseDeviceInventory
    }
    else {
        $OutputMessage = $OutPutMessage + "DeviceInventory:Fail "
    }
}
if ($CollectAppInventory) {
    if ($ResponseAppInventory -match "200 :") {
        
        $OutputMessage = $OutPutMessage + " AppInventory:OK " + $ResponseAppInventory
    }
    else {
        $OutputMessage = $OutPutMessage + " AppInventory:Fail "
    }
}

if ($CollectAppXPackageInventory) {
	if ($AppXData.Length -eq 0) {
		$AppXFailMessage = "AppXPackageInventory Failed due to AppXData being NULL"
	}

	if ($ResponseAppXPackageInventory -match "200 :") {

		$OutputMessage = $OutputMessage + " AppXPackageInventory:OK " + $ResponseAppXPackageInventory
	}
	else {
		$OutputMessage = $OutputMessage + " AppXPackageInventory:Fail " + $AppXFailMessage 
	}
}

Write-Output $OutputMessage
Exit 0
#endregion script
