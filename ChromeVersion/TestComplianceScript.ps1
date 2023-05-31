$chrome = Get-Package -Name "Google Chrome" -ErrorAction SilentlyContinue 
$chromeinstalled = $chrome.Name 
$chromeversion = $chrome.Version 
$hash = @{ Name = $chromeinstalled; Version = $chromeversion} 
$chromeHash| ConvertTo-Json | Out-File ".\TestVer.json"

return $hash | ConvertTo-Json -Compress 




$chromeinstalled = (Get-Package -Name "Google Chrome" -ErrorAction SilentlyContinue).Name 
$chromeVer = (Get-Package -Name "Google Chrome"-ErrorAction SilentlyContinue).Version
$chromeVer
$chromeHash = @{ Name = $chromeinstalled; Version = $chromeVer}

if ($chromeVer -le 112.0.5615.138)
{
    Write-Output "OLD VERSION DETECTED"
    Return $true
}
else {
    Write-Output "OLD VERSION NOT DETECTED"
    Return $false
}

#$chromeHash | ConvertTo-Json -depth 100 | Set-Content ".\TestVer.json"
$chromeHash| ConvertTo-Json | Out-File ".\TestVer.json"
#Get-Process powershell | ConvertTo-Json |  Tee-Object .\TestVer.json

return $chromeHash | ConvertTo-Json -Compress



$chrome = Get-Package -Name "Google Chrome"
$chromeinstalled = $chrome.Name 
$chromeversion = $chrome.Version 
$hash = @{ Name = $chromeinstalled; Version =$chromeversion} 
return $hash | ConvertTo-Json -Compress 







