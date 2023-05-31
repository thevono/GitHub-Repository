
if (!(Test-Path "C:\Windows\EndpointApps\InstallFonts")) {
    New-Item -Path C:\Windows\EndpointApps\InstallFonts -ItemType Directory
}

$ttfInstall = Get-ChildItem -Path C:\Windows\EndpointApps\InstallFonts\ | Where-Object Name -Like "*.ttf"
$otfInstall = Get-ChildItem -Path C:\Windows\EndpointApps\InstallFonts\ | Where-Object Name -Like "*.otf"

foreach ($FontFile in $ttfInstall)
{
    try
    {
        Write-Output "Copying items to: '$("$env:windir\Fonts\$($FontFile.Name)")'"
        Copy-Item -Path "C:\Windows\EndpointApps\InstallFonts\$($FontFile.Name)" -Destination "$env:windir\Fonts" -Force -PassThru -ErrorAction Stop

        Write-Output "Creating item: "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts\$($FontFile.Name)""
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts' -Name $($FontFile.Name) -PropertyType String -Value $($FontFile.Name) -Force
    }
    catch
    {
        Write-Error $_
    }
}


foreach ($FontFile2 in $otfInstall)
{
    try
    {
        Write-Output "Copying items to: '$("$env:windir\Fonts\$($FontFile2.Name)")'"
        Copy-Item -Path "C:\Windows\EndpointApps\InstallFonts\$($FontFile2.Name)" -Destination "$env:windir\Fonts" -Force -PassThru -ErrorAction Stop

        Write-Output "Creating item: "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts\$($FontFile2.Name)""
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts' -Name $($FontFile2.Name) -PropertyType String -Value $($FontFile2.Name) -Force
    }
    catch
    {
        Write-Error $_
    }
}

