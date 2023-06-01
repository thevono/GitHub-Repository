# Check if Inprocserver exist in the registry, if not add it
# Inprocserver allows the right click to display all options, like Windows 10
# Created by Von Ouch


$testPath = Test-Path -Path "HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"

if ($testPath -eq $true)
{
    Write-Output "InprocServer32 already exist"
    Exit
}
else
{
    Write-Output "Adding registry key"
    start-process "C:\Windows\EndpointApps\CustomExplorer\Win11-RightClick-Reg.bat"
}

