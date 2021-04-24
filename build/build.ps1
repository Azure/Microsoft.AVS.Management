#!/usr/bin/pwsh
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
#$signedModulesLoc = "signedPSModules"
$modulesDirectory = "powercli"
$outputFolderName = "adminToolBuildOutput"

Set-Location "$repoRoot\$modulesDirectory"
#Create folder for build output
# $commit = (Get-Date -Format "yyyyMMddTHHmmssffffZ")
# if (($null -ne $env:CDP_COMMIT_ID) -and ($env:CDP_COMMIT_ID -ne "")) {
#     $commit = ${env:CDP_COMMIT_ID}
# } elseif (($null -ne $env:BUILD_SOURCEVERSION) -and ($env:BUILD_SOURCEVERSION -ne "*")) {
#     $commit = ${env:BUILD_SOURCEVERSION}.substring(0,8)
# }
New-Item -Path $repoRoot -Name "$outputFolderName" -ItemType "directory"

Write-Host "----AVS-Automation-AdminTools: making nuget package ----"
nuget spec Azure.AVSPowerCLI
nuget pack Azure.AVSPowerCLI.nuspec -NonInteractive -OutputDirectory "$repoRoot\$outputFolderName"
Write-Host "----AVS-Automation-AdminTools: Azure.AVSPowerCLI nuget package deposited in $repoRoot\$outputFolderName----"
