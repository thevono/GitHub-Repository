
$po_ps_output = .\TestVer.json
$po_json_output = .\ChromeVersion.json

$contentEqual = ($po_ps_output | ConvertTo-Json -Compress) -eq 
($po_json_output | ConvertTo-Json -Compress)

$po_ps_output
$po_json_output

$contentEqual

