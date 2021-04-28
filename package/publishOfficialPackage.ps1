#!/usr/bin/pwsh
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
#$signedModulesLoc = "signedPSModules"
$outputFolderName = "adminToolBuildOutput"
$feedSource = "Unofficial-AVS-Automation-AdminTools"
# $artifactDirectoryRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"
# $modulesDirectory = "powercli"

Set-Location "$repoRoot\$outputFolderName"
Write-Host "----Unofficial-AVS-Automation-AdminTools: publish nuget package to $feedSource ----"

nuget.exe push *.nupkg -src 'https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v3/index.json' -ApiKey valueNotUsed
Set-Location "$repoRoot"