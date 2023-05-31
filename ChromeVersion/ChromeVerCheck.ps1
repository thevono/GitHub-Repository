
# old version: 112.0.5615.138

$chrome = Get-Package -Name "Google Chrome" -ErrorAction SilentlyContinue
$chromeinstalled = $chrome.Name 
$chromeversion = $chrome.Version 
$hash = @{ Name = $chromeinstalled; Version =$chromeversion} 
return $hash | ConvertTo-Json -Compress 



