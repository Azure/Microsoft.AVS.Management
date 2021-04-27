#!/usr/bin/pwsh
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$signedModulesLoc = "signedPSModules"
$outputFolderName = "adminToolBuildOutput"
# $artifactDirectoryRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"
# $modulesDirectory = "powercli"

New-Item -Path $repoRoot -Name "$outputFolderName" -ItemType "directory"
Copy-Item -Path "$repoRoot\$signedModulesLoc\*" -Destination "$repoRoot\$outputFolderName" -Recurse
Set-Location "$repoRoot\$outputFolderName"

Write-Host "----AVS-Automation-AdminTools: making nuget package ----"
nuget spec Azure.AVSPowerCLI
nuget pack Azure.AVSPowerCLI.nuspec -NonInteractive
Write-Host "----AVS-Automation-AdminTools: Azure.AVSPowerCLI nuget package deposited in $repoRoot\$outputFolderName----"

Set-Location "$repoRoot"