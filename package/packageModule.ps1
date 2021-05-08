#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$srcFolder,
    [Parameter(Mandatory=$true)][string]$newModuleFolder
)
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$aboluteSrcFolderPath = (Join-Path -Path "$repoRoot" -ChildPath "$srcFolder")
$aboluteNewFolderPath = (Join-Path -Path "$repoRoot" -ChildPath "$newModuleFolder")
if (!(Test-Path "$aboluteNewFolderPath")) {
    Write-Output "Copying directory contents: $aboluteSrcFolderPath --> $aboluteNewFolderPath"
    New-Item -Path "$aboluteNewFolderPath" -ItemType Directory
    Copy-Item -Path "$aboluteSrcFolderPath\*" -Destination "$aboluteNewFolderPath"
}else{
    Write-Output "----Path for new module directory already exists ----"
}
$manifestFiles = (Get-ChildItem "$aboluteNewFolderPath\*" -Include "*.psd1")
Write-Output "Contents of new directory: $aboluteNewFolderPath"
Get-ChildItem "$aboluteNewFolderPath"
$manifestFile = ""
if (($manifestFiles).Count -gt 0) {
    $manifestFile = $manifestFiles[0].FullName
}else {
    Write-Error -Message "----Packaging Failed: No manifest file found----" -ErrorAction Stop
}
Set-Location "$aboluteNewFolderPath"
Get-Content "$manifestFile"
Write-Host "----AVS-Automation-AdminTools: making nuget package ----"
nuget spec "$manifestFile"
$nugetFileName = (Get-ChildItem "$manifestFile").BaseName
nuget pack "$($nugetFileName).nuspec" -NonInteractive -Version "$env:BUILD_BUILDNUMBER"
Write-Host "----AVS-Automation-AdminTools: Azure.AVSPowerCLI nuget package deposited----"

Get-Content "$manifestFile"