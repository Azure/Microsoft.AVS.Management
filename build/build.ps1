#!/usr/bin/pwsh
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
# $signedModulesLoc = "signedPSModules"
# $outputFolderName = "adminToolBuildOutput"
# $artifactDirectoryRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"
# $modulesDirectory = "powercli"
$newModuleFolder = "Azure.AVSPowerCLI"
# $moduleFile = "Azure.AVSPowerCLI.psd1"
# $pathToModule = (Join-Path "$repoRoot" "$moduleFolder" "$moduleFile")

# New-Item -Path $repoRoot -Name "$newModuleFolder" -ItemType "directory"
# Copy-Item -Path "$repoRoot\$s\*" -Destination "$repoRoot\$newModuleFolder" -Recurse
# Set-Location "$repoRoot\$outputFolderName"
Set-Location (Join-Path "$repoRoot" "$newModuleFolder")

Write-Host "----AVS-Automation-AdminTools: making nuget package ----"
nuget spec Azure.AVSPowerCLI
nuget pack Azure.AVSPowerCLI.nuspec -NonInteractive
Write-Host "----AVS-Automation-AdminTools: Azure.AVSPowerCLI nuget package deposited----"

Set-Location "$repoRoot"