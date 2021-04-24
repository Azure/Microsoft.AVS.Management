#!/usr/bin/pwsh
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$outputFolderName = "signedPSModules"

Write-Host "----AVS-Automation-AdminTools: creating directory $outputFolderName to hold signed PS modules----"
New-Item -Path $repoRoot -Name "$outputFolderName" -ItemType "directory"
Write-Host "----AVS-Automation-AdminTools: $outputFolderName directory created----"