#!/usr/bin/pwsh
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$artifactDirRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"

$newModuleFolder = "Azure.AVSPowerCLI"
Set-Location (Join-Path "$artifactDirRoot" "$newModuleFolder")
Get-Content "Azure.AVSPowerCLI.psd1"
Write-Host "----AVS-Automation-AdminTools: making nuget package ----"
nuget spec Azure.AVSPowerCLI
nuget pack Azure.AVSPowerCLI.nuspec -NonInteractive -Version "$env:BUILD_BUILDNUMBER"
Write-Host "----AVS-Automation-AdminTools: Azure.AVSPowerCLI nuget package deposited----"

Get-Content "Azure.AVSPowerCLI.psd1"
Set-Location "$repoRoot"