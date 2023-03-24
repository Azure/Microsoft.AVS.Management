#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$buildPatch
)

Write-Host "----- Setting Build Version to $buildPatch -----"
Write-Host "##vso[build.updatebuildnumber]$buildPatch"
