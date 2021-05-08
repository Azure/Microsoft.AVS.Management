#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$buildType,
    [Parameter(Mandatory=$true)][string]$relativePackageFolder
)

$nugetSource = switch ($buildType) {
    'official' { "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v3/index.json" }
    Default {'https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v3/index.json'}
}

$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$feedSource = "Unofficial-AVS-Automation-AdminTools"
Set-Location (Join-Path "$repoRoot" "$relativePackageFolder")
Get-ChildItem (Get-Location)
Write-Host "----Unofficial-AVS-Automation-AdminTools: publish nuget package to $feedSource ----"
nuget.exe push *.nupkg -src "$nugetSource" -ApiKey valueNotUsed
Set-Location "$repoRoot"