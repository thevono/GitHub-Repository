

$ComputerName = $env:COMPUTERNAME

$AllApps = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

#$Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)

#$RegKey = $Reg.OpenSubKey($AllApps)

#$SubKeys = $RegKey.GetSubKeyNames()

#$AllApps

foreach ($App in $AllApps)
{
    #$thisSubKey = $Reg.OpenSubKey($thisSubKey)
    #$DisplayName = $thisSubKey.GetValue("DisplayName")

    $GetAppName = ($App.GetValue("DisplayName"))

    Write-Host $GetAppName
    
}

$ComputerName = $env:COMPUTERNAME
Get-WmiObject Win32_Product -ComputerName $ComputerName | Select Name, Version



$InstalledSoftware = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
foreach($obj in $InstalledSoftware)
{
    write-host $obj.GetValue('DisplayName') -NoNewline; write-host " - " -NoNewline; write-host $obj.GetValue('DisplayVersion')
}










Get-NetAdapterAdvancedProperty -DisplayName "*Wireless*"

Get-NetAdapterAdvancedProperty -DisplayName "*Wireless*" -AllProperties




$wifiUP = Get-NetAdapter | Where-Object {$_.Name -eq "Wi-Fi" } | Where-Object {$_.Status -eq "Up"} | Select Name, InterfaceDescription,DriverVersion, DriverDate, DriverProvider
$LANUP = Get-NetAdapter | Where-Object {$_.Name -eq "Ethernet" } | Where-Object {$_.Status -eq "Up"} | Select Name, InterfaceDescription,DriverVersion, DriverDate, DriverProvider

if ($wifiUP)
{
    Write-Output "Wi-Fi is UP"
    $wifiUP
}
elseif ($LANUP)
{
    Write-Output "LAN is UP"
    $LANUP
}




