#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest,
    [Parameter(Mandatory=$true)][string]$modulePatch

)

$psdFileObj = Import-PowerShellDataFile $absolutePathToManifest
$manifestVersionAsArray = $psdFileObj.ModuleVersion -split "\."
$MAJOR = $manifestVersionAsArray[0]
$minor = $manifestVersionAsArray[1]
$updatedBuildVersion = $MAJOR.$minor.$modulePatch
Write-Host "----- Setting Build Version to $updatedBuildVersion -----"
Write-Host "##vso[build.updatebuildnumber]$updatedBuildVersion"