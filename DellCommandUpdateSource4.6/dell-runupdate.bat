echo running Dell Command Updates
"C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" /scan -updateType=bios,firmware,driver -silent -outputlog="c:\driversupdate\ScanLog.log"
"C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" /configure -updateType=bios,firmware,driver -silent -outputlog="c:\driversupdate\ConfigureLog.log"
"C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" /applyUpdates -updateType=bios,firmware,driver -silent -outputlog="c:\driversupdate\UpdatesLog.log"
