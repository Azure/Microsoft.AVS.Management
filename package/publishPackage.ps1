#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$false)][string]$buildType = 'unofficial'
)

$nugetSource = switch ($buildType) {
    'official' { "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v3/index.json" }
    Default {'https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v3/index.json'}
}

$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$artifactDirRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"

$feedSource = "Unofficial-AVS-Automation-AdminTools"
$newModuleFolder = "Azure.AVSPowerCLI"
Set-Location (Join-Path "$artifactDirRoot" "$newModuleFolder")
Get-ChildItem .
Write-Host "----Unofficial-AVS-Automation-AdminTools: publish nuget package to $feedSource ----"

nuget.exe push *.nupkg -src "$nugetSource" -ApiKey valueNotUsed
Set-Location "$repoRoot"