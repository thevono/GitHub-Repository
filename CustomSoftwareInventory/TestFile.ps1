











$AppXPackagePath = "C:\Program Files\WindowsApps\"
$AppXExeFiles = Get-ChildItem -Path $AppXPackagePath -Filter "*.exe" -File -Recurse

$AppXArray = @()
foreach ($AppXExe in $AppXExeFiles) {
    $AppXInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AppXExe.FullName)
    $GetAppXObj = $AppXInfo | Select-Object ProductName, FileVersion, CompanyName 

    $AppXObject = New-Object -TypeName PSObject
    $AppXObject | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $ComputerName -Force
    $AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value $UPN.UPN -Force
    $AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value $GetAppXObj.ProductName -Force
    $AppXObject | Add-Member -MemberType NoteProperty -Name "AppXVersion" -Value $GetAppXObj.FileVersion -Force
    $AppXObject | Add-Member -MemberType NoteProperty -Name "AppXCompany" -Value $GetAppXObj.CompanyName -Force

    $AppXArray += $AppXObject 
}

$AppXData = $AppXArray
$AppXData


















$CollectAppXPackageInventory = $true

# add user UPN info to the query
$UPN = Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Enrollments\* -Name "UPN" -ErrorAction SilentlyContinue | Select-Object UPN -ErrorAction SilentlyContinue

#Get Computer Info
$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$ComputerName = $ComputerInfo.Name

#region APPXPACKAGEINVENTORY
if ($CollectAppXPackageInventory) {

	<#
	$UniqueAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateAppX = ($DuplicatedAppX | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppXList = $UniqueAppX + $NewestDuplicateAppX | Sort-Object DisplayName
	#>

	$AppXPackagePath = "C:\Program Files\WindowsApps\"
	$AppXExeFiles = Get-ChildItem -Path $AppXPackagePath -Filter "*.exe" -File -Recurse
	#$AppXExeFiles 

	$AppXArray = @()
	foreach ($AppXExe in $AppXExeFiles) {
		#$AppXExe

		$AppXInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AppXExe.FullName)
		#$AppXInfo # shows all the info
		$GetAppXObj = $AppXInfo | Select-Object ProductName, FileVersion, CompanyName 

		#$GetAppXObj
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

	# Remove duplicates based on AppXName property
    $UniqueAppXData = $AppXArray | Group-Object -Property "AppXName" | ForEach-Object { $_.Group[0] } | Sort-Object -Property "AppXName"

    $AppXData = $UniqueAppXData
	#$AppXData = $AppXArray

}
#endregion APPXPACKAGEINVENTORY
#$AppXData

$AppXData | Export-Csv -Path .\APPXReport13-Unique0.csv -NoTypeInformation

















#WORKING ************************************************

$AppXPackagePath = "C:\Program Files\WindowsApps\"
$AppXExeFiles = Get-ChildItem -Path $AppXPackagePath -Filter "*.exe" -File -Recurse
#$AppXExeFiles 

foreach ($AppXExe in $AppXExeFiles) {
	#$AppXExe

	$AppXInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AppXExe.FullName)
	#$AppXInfo # shows all the info
	$GetAppXObj = $AppXInfo | Select-Object ProductName, FileVersion, CompanyName 
	$GetAppXObj

}


























# Set the path to the WindowsApps directory
$windowsAppsPath = "C:\Program Files\WindowsApps\"

# Get a list of all the Appx packages in the directory
$appxPackages = Get-ChildItem -Path $windowsAppsPath -Filter "*.exe" -Recurse

# Loop through each Appx package
foreach ($package in $appxPackages) {
    # Extract the package name and version from the package's full name
    $packageName = $package.Name
    $packageVersion = [System.Version]::new($package.Version)

    # Get the path to the executable file within the package
    $packagePath = $package.FullName
    $executablePath = (Get-AppxPackageManifest $packagePath).Package.Applications.Application.Executable

    # Construct the full path to the executable
    $fullExecutablePath = Join-Path -Path $windowsAppsPath -ChildPath "$packageName\$executablePath"

    # Check if the executable file exists
    if (Test-Path -Path $fullExecutablePath) {
        # Get the product name and file version from the executable
        $fileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($fullExecutablePath)
        $productName = $fileVersionInfo.ProductName
        $fileVersion = $fileVersionInfo.FileVersion

        # Display the information
        Write-Host "Package: $packageName"
        Write-Host "Version: $packageVersion"
        Write-Host "Executable: $fullExecutablePath"
        Write-Host "Product Name: $productName"
        Write-Host "File Version: $fileVersion"
        Write-Host ""
    }
}
















Directory: C:\Program Files\WindowsApps\PandoraMediaInc.29680B314EFC2_15.0.3.0_x64__n619g4d5j0fnw\app


Mode                 LastWriteTime         Length Name                                                                                                                   
----                 -------------         ------ ----                                                                                                                   
-a----         5/26/2023  12:18 PM       92345856 Pandora.exe                                                                                                            
Method invocation failed because [System.Diagnostics.FileVersionInfo] does not contain a method named 'GetFileName'.
At line:13 char:2
+     $AppXInfo = [System.Diagnostics.FileVersionInfo]::GetFileName($Ap ...
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
    + FullyQualifiedErrorId : MethodNotFound
 

Comments           : 
CompanyName        : Pandora
FileBuildPart      : 3
FileDescription    : Pandora
FileMajorPart      : 15
FileMinorPart      : 0
FileName           : C:\Program Files\WindowsApps\PandoraMediaInc.29680B314EFC2_15.0.3.0_x64__n619g4d5j0fnw\app\Pandora.exe
FilePrivatePart    : 0
FileVersion        : 15.0.3
InternalName       : Pandora
IsDebug            : False
IsPatched          : False
IsPrivateBuild     : False
IsPreRelease       : False
IsSpecialBuild     : False
Language           : English (United States)
LegalCopyright     : Copyright © 2019 Pandora
LegalTrademarks    : 
OriginalFilename   : 
PrivateBuild       : 
ProductBuildPart   : 3
ProductMajorPart   : 15
ProductMinorPart   : 0
ProductName        : Pandora
ProductPrivatePart : 0
ProductVersion     : 15.0.3.0
SpecialBuild       : 
FileVersionRaw     : 15.0.3.0
ProductVersionRaw  : 15.0.3.0



















$ExePath = "C:\Program Files\WindowsApps\PandoraMediaInc.29680B314EFC2_15.0.3.0_x64__n619g4d5j0fnw\app\Pandora.exe"





$AppXPackagePath = "C:\Program Files\WindowsApps\"
$AppXExeFiles = Get-ChildItem -Path $AppXPackagePath -Filter "*.exe" -File -Recurse
#$AppXExeFiles 

foreach ($AppXExe in $AppXExeFiles) {
	#$AppXExe
	#$GetName = ($AppXExe)::GetFileName
	#$GetName
	#$GetInfo = $GetName #| Select-Object ProductName, ProductVersion, CompanyName
	#$GetInfo
	#[System.Diagnostics.FileVersionInfo]::GetFileName($AppXExeFiles.FullName)
	$AppX = $AppXExe 
	$AppXInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($AppX.FullName)
	$AppXInfo
	#$GetAppXObj = $AppXInfo | Select-Object ProductName, ProductVersion, CompanyName 
	#$AppXObj = $GetAppXObj #| Select-Object -Unique ProductName 
	#$AppXObj
}
#$AppXInfo


# Define the function to retrieve the product version
function Get-FileVersion {
    param([string]$FilePath)

    $fileVersionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
    $productVersion = $fileVersionInfo.ProductVersion

    return $productVersion
}

# Get the product version
$productVersion = Get-FileVersion -FilePath $ExePath

# Display the product version
$productVersion








$AppXPackagePath = "C:\Program Files\WindowsApps\"
$AppXExeFiles = Get-ChildItem -Path $AppXPackagePath -Filter "*.exe" -File -Recurse
$AppXExeFiles

foreach ($AppXFiles in $AppXExeFiles) {
	# Use Get-Command to retrieve the information
    $exeInfo = Get-Command -Type Application -Syntax -Name $exePath

    # Display the information
    Write-Host "Information for $exePath"
    $exeInfo
    Write-Host ""
}


foreach ($File in $ExeFiles) {
    $File | Where-Object {$_.Name -ne 0} | Select-Object Name, Version
	$AppXName = $File.ProductName
	$AppXVersion = $File.FileVersion
}








$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$ComputerName = $ComputerInfo.Name

$UPN = Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Enrollments\* -Name "UPN" -ErrorAction SilentlyContinue | Select-Object UPN -ErrorAction SilentlyContinue

$CollectAppXPackageInventory = $true


if ($CollectAppXPackageInventory) {


	$AppXRegPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"
	$AppXPackageNames = "PackageID"
	$GetRegistry = Get-ItemProperty -Path $AppXRegPath -Name $AppXPackageNames -ErrorAction SilentlyContinue | Select-Object PackageID | Sort-Object DisplayName

	$WindowsAppsPath = "C:\Program Files\WindowsApps"
	$GetWindowsApps = Get-ChildItem -Path $WindowsAppsPath -Directory | Select-Object -ExpandProperty Name | Select-Object 
	#$GetWindowsApps
	#$GetRegistry

	
	$SplitAppXArray = @()
	foreach ($AppX in $GetWindowsApps) {

		$string1 = $AppX
		$string1array = $string1 -split "_"
		#$string1array

		$Name = $string1array[0]
		$Version = $string1array[1]

		$NameWithID = $Name -split "="
		$NameOnly = $NameWithID[1]
		
		$AppXPackages = $NameOnly, $Version
		#$AppXPackages
		$AppXObject = New-Object -TypeName PSObject
		$AppXObject | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value "$ComputerName" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value "$NameOnly" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXVersion" -Value "$Version" -Force
		$SplitAppXArray += $AppXObject 
	}
	
	$AppXList = $SplitAppXArray
}
#endregion APPXPACKAGEINVENTORY

$AppXList

$AppXList | Export-Csv .\APPXReport7.csv -NoTypeInformation













$AppXRegPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"
$AppXPackageNames = "PackageID"
$GetRegistry = Get-ItemProperty -Path $AppXRegPath -Name $AppXPackageNames -ErrorAction SilentlyContinue | Select-Object PackageID | Sort-Object DisplayName

$SplitAppXArray = @()
	foreach ($AppX in $GetRegistry) {
		<#
		$UniqueAppX = ($AppX | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
		$DuplicatedAppX = ($AppX | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
		$NewestDuplicateAppX = ($AppX | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
		$CleanAppXList = $UniqueAppX + $NewestDuplicateAppX | Sort-Object DisplayName
		$CleanAppXList
		#>
		$AppX
	}














$AppXRegPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"
$GetRegistry = Get-ItemProperty -Path $AppXRegPath | Select-Object PackageID | Sort-Object DisplayName

foreach ($AppX in $GetRegistry) {
    $string1 = $AppX
    $string1array = $string1 -split "_"
    #$string1array

    $Name = $string1array[0]
    $Version = $string1array[1]

    $NameWithID = $Name -split "="
    $NameOnly = $NameWithID[1]
    
	$AppXClean = $NameOnly, $Version
	$AppXClean
}

#$AppXClean




$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$ComputerName = $ComputerInfo.Name

$UPN = Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Enrollments\* -Name "UPN" -ErrorAction SilentlyContinue | Select-Object UPN -ErrorAction SilentlyContinue

$CollectAppXPackageInventory = $true


if ($CollectAppXPackageInventory) {


	$AppXRegPath = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"
	$AppXPackageNames = "PackageID"
	$GetRegistry = Get-ItemProperty -Path $AppXRegPath -Name $AppXPackageNames -ErrorAction SilentlyContinue | Select-Object PackageID | Sort-Object DisplayName
	#$GetRegistry

	
	$SplitAppXArray = @()
	foreach ($AppX in $GetRegistry) {
		$UniqueAppX = ($AppX | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
		$DuplicatedAppX = ($AppX | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
		$NewestDuplicateAppX = ($AppX | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
		$CleanAppXList = $UniqueAppX + $NewestDuplicateAppX | Sort-Object DisplayName


		$string1 = $CleanAppXList
		$string1array = $string1 -split "_"
		#$string1array

		$Name = $string1array[0]
		$Version = $string1array[1]

		$NameWithID = $Name -split "="
		$NameOnly = $NameWithID[1]
		
		$AppXPackages = $NameOnly, $Version
		#$AppXPackages

		

		$AppXObject = New-Object -TypeName PSObject
		$AppXObject | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value "$ComputerName" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value "$NameOnly" -Force
		#$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXPackageFullName" -Value $Appx.PackageID -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXVersion" -Value "$Version" -Force
		$SplitAppXArray += $AppXObject 

		#Return $GetRegistry
	}
	
	$AppXList = $SplitAppXArray

	#endregion APPXPACKAGEINVENTORY

}

$AppXList









	#$AppXPackageObjects = "Name", "Version", "PackageFullName"
	#$AppXPackage = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object $AppXPackageObjects | Sort-Object DisplayName

	#New-PSDrive -PSProvider Registry -Name "HKCU" -Root HKEY_CURRENT_USER | Out-Null

	#$OutputMessageMain = $OutputMessageMain + "Getting APPX Packages"

	#$AppXReg = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"

	#$AppXPackagePropertyNames = "DisplayName", "PackageID"
	#$GetAppXPackage = Get-ItemProperty -Path $AppXReg -Name $AppXPackagePropertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, PackageID | Sort-Object DisplayName




	#$AppXData


	#$AppXPackages
	<#
	#$AppXPackages = Get-InstalledAppXPackages #-UserSid $UserSid
	$UniqueAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateAppX = ($DuplicatedAppX | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppXList = $UniqueAppX + $NewestDuplicateAppX | Sort-Object DisplayName
	#>

	<#
	$AppXArray = @()
	foreach ($AppX in $AppXPackages) {
		$AppXObject = New-Object -TypeName PSObject
		$AppXObject | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value "$ComputerName" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value "$NameOnly" -Force
		#$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXPackageFullName" -Value $Appx.PackageID -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXVersion" -Value "$Version" -Force
		$AppXArray += $AppXObject 
		
	}
	
	$AppXList = $AppXArray
	#>

	#Write-Output $OutputMessageMain
	
	#Return $CleanAppXList

	#Remove-PSDrive -Name "HKCU" | Out-Null
	#Write-Output $OutputMessageMain

	#Return $AppXInfo

$AppXList | Export-Csv -Path .\APPXReport6.csv -NoTypeInformation


$AppXArray | Export-Csv -Path .\APPXReport5.csv -NoTypeInformation

#Get-InstalledAppXPackages

if ($CollectAppXPackageInventory) {

	$AppXPackages = Get-InstalledAppXPackages

	$AppXArray = @()
		foreach ($AppX in $AppXPackages) {
			$AppXObject = New-Object -TypeName PSObject
			$AppXObject | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value "$ComputerName" -Force
			$AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
			$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value "$NameOnly" -Force
			#$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXPackageFullName" -Value $Appx.PackageID -Force
			$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXPackageFullName" -Value "$Version" -Force
			$AppXArray += $AppXObject 
			
		}
		#Write-Output $OutputMessageMain
		$AppXData = $AppXArray

		
}

$AppXData
#$AppXData | Export-Csv -Path .\APPXReport4.csv -NoTypeInformation

#Get-InstalledAppXPackages














#region APPXPACKAGEINVENTORY
if ($CollectAppXPackageInventory) {
	#$AppXPackages = Get-InstalledAppXPackages

	$OutputMessageMain = $OutputMessageMain + "Collecting AppX Package Inventory"

	#Get Apps for system and current user
	$AllAppXPackages = Get-InstalledAppXPackages #-UserSid $UserSid
	$UniqueAppX = ($AllAppXPackages | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedAppX = ($AllAppXPackages | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateAppX = ($DuplicatedAppX | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppXList = $UniqueAppX + $NewestDuplicateAppX | Sort-Object DisplayName

	$AppXArray = @()
	foreach ($AppX in $CleanAppXList) {
		$AppXObject = New-Object -TypeName PSObject
		$AppXObject | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value "$ComputerName" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value $AppX.DisplayName -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXPackageFullName" -Value $Appx.PackageID -Force
		$AppXArray += $AppXObject 
		
	}
	Write-Output $OutputMessageMain
	$AppXData = $AppXArray
}
#endregion APPXPACKAGEINVENTORY
$AppXData

$AppXData | Export-Csv -Path .\APPXReport4.csv -NoTypeInformation








$GetRegistry = Get-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*" | Select-Object PackageID
#$GetRegistry
foreach ($AppX in $GetRegistry) {
    $string1 = $AppX
    $string1array = $string1 -split "_"
    #$string1array

    $Name = $string1array[0]
    $Version = $string1array[1]

    $NameWithID = $Name -split "="
    $NameOnly = $NameWithID[1]
    $NameOnly
    $Version
}










#---------------------------------------------------------------------


$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$ComputerName = $ComputerInfo.Name

$UPN = Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Enrollments\* -Name "UPN" -ErrorAction SilentlyContinue | Select-Object UPN -ErrorAction SilentlyContinue

$CollectAppXPackageInventory = $true


function Get-InstalledAppXPackages() {

	#$AppXPackageObjects = "Name", "Version", "PackageFullName"
	#$AppXPackage = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object $AppXPackageObjects | Sort-Object DisplayName

	New-PSDrive -PSProvider Registry -Name "HKCU" -Root HKEY_CURRENT_USER | Out-Null

	$OutputMessageMain = $OutputMessageMain + "Getting APPX Packages"

	$AppXReg = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"

	$AppXPackagePropertyNames = "DisplayName", "PackageID"
	$GetAppXPackage = Get-ItemProperty -Path $AppXReg -Name $AppXPackagePropertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, PackageID | Sort-Object DisplayName

	#Remove-PSDrive -Name "HKCU" | Out-Null
	Write-Output $OutputMessageMain

	Remove-PSDrive -Name "HKCU" | Out-Null

	Return $GetAppXPackage
}
Get-InstalledAppXPackages


#region APPXPACKAGEINVENTORY
if ($CollectAppXPackageInventory) {
	#$AppXPackages = Get-InstalledAppXPackages

	$OutputMessageMain = $OutputMessageMain + "Collecting AppX Package Inventory"

	#Get Apps for system and current user
	$AppXPackages = Get-InstalledAppXPackages #-UserSid $UserSid
	$UniqueAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateAppX = ($DuplicatedAppX | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppXList = $UniqueAppX + $NewestDuplicateAppX | Sort-Object DisplayName

	$AppXArray = @()
	foreach ($AppX in $CleanAppXList) {
		$AppXObject = New-Object -TypeName PSObject
		$AppXObject | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value "$ComputerName" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value $AppX.DisplayName -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXPackageFullName" -Value $Appx.PackageID -Force
		$AppXArray += $AppXObject 
		
	}
	Write-Output $OutputMessageMain
	$AppXData = $AppXArray
}
#endregion APPXPACKAGEINVENTORY



$AppXPackagejson = $AppXData | ConvertTo-Json

$ResponseAppXPackageInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($AppXPackagejson)) -logType $AppXPackageLogName

if ($CollectAppXPackageInventory) {
	if ($ResponseAppXPackageInventory -match "200 :") {

		$OutputMessage = $OutputMessage + " AppXPackageInventory:OK " + $ResponseAppXPackageInventory
	}
	else {
		$OutputMessage = $OutputMessage + " AppXPackageInventory:Fail " 
	}
}



$AppXData | Export-Csv -Path .\APPXReport3.csv -NoTypeInformation




if ($AppXData.Length -eq 0) {
	Write-Output "APPXDATA is NULL"
}
else {
	Write-Output "APPXDATA is NOT NULL"
}











$GetRegistry = Get-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*" | Select-Object PackageID
#$GetRegistry
foreach ($AppX in $GetRegistry) {
    $string1 = $AppX
    $string1array = $string1 -split "_"
    #$string1array

    $Name = $string1array[0]
    $Version = $string1array[1]

    $NameWithID = $Name -split "="
    $NameOnly = $NameWithID[1]
    $NameOnly
    $Version

}


    <#
    $Name = $string1array[0]
    $Version = $string1array[1]
    $Sig = $string1array[3]

    $NewName = $Name.TrimStart("@{PackageID=")

    Write-Output "AppX Name: " $NewName
    Write-Output "AppX Version: " $Version

    #>



    #$Name

    <#
    $NewName = $Name.Remove("15")
    $NewName

    Write-Output "Name of the AppXPackage: " $NewName
    Write-Output "Version of the AppXPackage: " $Version
    #>




















Get-ItemProperty -Path "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*" | Select-Object "DisplayName", "PSChildName"



Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\*" | Select-Object "PSChildName"




$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$ComputerName = $ComputerInfo.Name

$UPN = Get-ItemProperty -Path HKLM:SOFTWARE\Microsoft\Enrollments\* -Name "UPN" -ErrorAction SilentlyContinue | Select-Object UPN -ErrorAction SilentlyContinue

$CollectAppXPackageInventory = $true


function Get-InstalledAppXPackages() {

	#$AppXPackageObjects = "Name", "Version", "PackageFullName"
	#$AppXPackage = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object $AppXPackageObjects | Sort-Object DisplayName

	#New-PSDrive -PSProvider Registry -Name "HKCU" -Root HKEY_CURRENT_USER | Out-Null
	$AppXReg = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"

	$AppXPackagePropertyNames = "DisplayName", "PackageID"
	$GetAppXPackage = Get-ItemProperty -Path $AppXReg -Name $AppXPackagePropertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, PackageID | Sort-Object DisplayName

	#Remove-PSDrive -Name "HKCU" | Out-Null

	Return $GetAppXPackage
}

#region APPXPACKAGEINVENTORY
if ($CollectAppXPackageInventory) {
	#$AppXPackages = Get-InstalledAppXPackages

	$OutputMessageMain = $OutputMessageMain + "Collecting AppX Package Inventory"

	#Get Apps for system and current user
	$AppXPackages = Get-InstalledAppXPackages($GetAppXPackage) #-UserSid $UserSid
	<#
	$UniqueAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateAppX = ($DuplicatedAppX | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppXList = $UniqueAppX + $NewestDuplicateAppX | Sort-Object DisplayName
	#>

	$AppXArray = @()
	foreach ($AppX in $AppXPackages) {
		$AppXObject = New-Object -TypeName PSObject
		$AppXObject | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value $AppX.DisplayName -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXPackageFullName" -Value $Appx.PackageID -Force
		$AppXArray += $AppXObject 
		
	}

	$AppXData = $AppXArray
}
#endregion APPXPACKAGEINVENTORY
Return $AppXData

$AppXData | Export-Csv -Path .\APPXReport3.csv -NoTypeInformation


















function Get-InstalledAppXPackages() {

	#$AppXPackageObjects = "Name", "Version", "PackageFullName"
	#$AppXPackage = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object $AppXPackageObjects | Sort-Object DisplayName

	#New-PSDrive -PSProvider Registry -Name "HKCU" -Root HKEY_CURRENT_USER | Out-Null
	$AppXReg = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"

	$AppXPackagePropertyNames = "DisplayName", "PackageID"
	$GetAppXPackage = Get-ItemProperty -Path $AppXReg -Name $AppXPackagePropertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, PackageID | Sort-Object DisplayName

	#Remove-PSDrive -Name "HKCU" | Out-Null

	Return $GetAppXPackage
}




function Get-InstalledAppXPackages() {

	#$AppXPackageObjects = "Name", "Version", "PackageFullName"
	#$AppXPackage = Get-AppxPackage -ErrorAction SilentlyContinue | Select-Object $AppXPackageObjects | Sort-Object DisplayName

	#New-PSDrive -PSProvider Registry -Name "HKCU" -Root HKEY_CURRENT_USER | Out-Null
	$AppXReg = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"

	#$AppXPackagePropertyNames = "DisplayName", "PackageID"
	#$GetAppXPackage = Get-ItemProperty -Path $AppXReg -Name $AppXPackagePropertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, PackageID | Sort-Object DisplayName

	$AppXReg = "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*"

	$GetRegistry = Get-ItemProperty -Path $AppXReg -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object PackageID | Sort-Object DisplayName
#$GetRegistry
	foreach ($AppX in $GetRegistry) {
		$string1 = $AppX
		$string1array = $string1 -split "_"
		#$string1array

		$Name = $string1array[0]
		$Version = $string1array[1]

		$NameWithID = $Name -split "="
		$NameOnly = $NameWithID[1]
		#$NameOnly
		#$Version
		$DisplayAppXPackage = Write-Output "AppX Results: " $NameOnly, $Version
		
		Return $DisplayAppXPackage
	}

	#Remove-PSDrive -Name "HKCU" | Out-Null

	#Return $DisplayAppXPackage
}

Get-InstalledAppXPackages


#region APPXPACKAGEINVENTORY
if ($CollectAppXPackageInventory) {
	#$AppXPackages = Get-InstalledAppXPackages

	$OutputMessageMain = $OutputMessageMain + "Collecting AppX Package Inventory"

	#Get Apps for system and current user
	$AppXPackages = Get-InstalledAppXPackages #-UserSid $UserSid
	$UniqueAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedAppX = ($AppXPackages | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateAppX = ($DuplicatedAppX | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppXList = $UniqueAppX + $NewestDuplicateAppX | Sort-Object DisplayName

	$AppXArray = @()
	foreach ($AppX in $CleanAppXList) {
		$AppXObject = New-Object -TypeName PSObject
		$AppXObject | Add-Member -MemberType NoteProperty -Name 'ComputerName' -Value $ComputerName -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "UserPrincipalName" -Value "$UPN" -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXName" -Value $AppX.DisplayName -Force
		$AppXObject | Add-Member -MemberType NoteProperty -Name "AppXPackageFullName" -Value $Appx.PackageID -Force
		$AppXArray += $AppXObject 
		
	}

	$AppXData = $AppXArray
}
#endregion APPXPACKAGEINVENTORY

#$AppXPayload 
$AppXPayload | Export-Csv -Path .\APPXReport2.csv -NoTypeInformation
#$AppXPayload












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

























