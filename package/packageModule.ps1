#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$srcFolder,
    [Parameter(Mandatory=$true)][string]$newModuleFolder
)
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
#$artifactDirRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"
$aboluteSrcFolderPath = (Join-Path -Path "$repoRoot" -ChildPath "$srcFolder")
$aboluteNewFolderPath = (Join-Path -Path "$repoRoot" -ChildPath "$newModuleFolder")
if (!(Test-Path "$aboluteNewFolderPath")) {
    New-Item -Path "$aboluteNewFolderPath" -ItemType Directory
    Copy-Item -Path "$aboluteSrcFolderPath" -Destination "$aboluteNewFolderPath"
}
$manifestFiles = (Get-ChildItem "$aboluteNewFolderPath\*" -Include "*.psd1")
$manifestFile = ""
if ($manifestFiles.Count -gt 0) {
    $manifestFile = $manifestFiles[0].FullName
}else {
    Write-Error -Message "----Packagin Failed: No manifest file found----" -ErrorAction Stop
}
Set-Location "$aboluteNewFolderPath"
Get-Content "$manifestFile"
Write-Host "----AVS-Automation-AdminTools: making nuget package ----"
nuget spec "$manifestFile"
nuget pack "$manifestFile.nuspec" -NonInteractive -Version "$env:BUILD_BUILDNUMBER"
Write-Host "----AVS-Automation-AdminTools: Azure.AVSPowerCLI nuget package deposited----"

Get-Content "$manifestFile"
#Set-Location "$repoRoot"