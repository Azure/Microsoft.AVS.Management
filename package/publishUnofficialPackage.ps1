#!/usr/bin/pwsh
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$artifactDirRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"

#$signedModulesLoc = "signedPSModules"
# $outputFolderName = "adminToolBuildOutput"
$feedSource = "Unofficial-AVS-Automation-AdminTools"
# $artifactDirectoryRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"
# $modulesDirectory = "powercli"
$newModuleFolder = "Azure.AVSPowerCLI"
Set-Location (Join-Path "$artifactDirRoot" "$newModuleFolder")
Get-ChildItem .
# Set-Location "$repoRoot\$outputFolderName"
Write-Host "----Unofficial-AVS-Automation-AdminTools: publish nuget package to $feedSource ----"

nuget.exe push *.nupkg -src 'https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v3/index.json' -ApiKey valueNotUsed
Set-Location "$repoRoot"