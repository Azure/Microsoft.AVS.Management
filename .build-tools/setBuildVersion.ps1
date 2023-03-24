#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest,
    [Parameter(Mandatory=$true)][string]$buildPatch

)

$manifestVersionAsArray = (Import-PowerShellDataFile $absolutePathToManifest).ModuleVersion -split "\."
$buildPatchAsArray = $buildPatch -split "\."
$updatedBuildVersion = @( $manifestVersionAsArray[0], $manifestVersionAsArray[1], ($buildPatchAsArray | Select-Object -Last 1) ) | Join-String -Separator '.'
Write-Host "----- Setting Build Version to $updatedBuildVersion -----"
Write-Host "##vso[build.updatebuildnumber]$updatedBuildVersion"