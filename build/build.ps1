#!/usr/bin/pwsh
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
#Set-Location $repoRoot

#Create folder for build output
# $commit = (Get-Date -Format "yyyyMMddTHHmmssffffZ")
# if (($null -ne $env:CDP_COMMIT_ID) -and ($env:CDP_COMMIT_ID -ne "")) {
#     $commit = ${env:CDP_COMMIT_ID}
# } elseif (($null -ne $env:BUILD_SOURCEVERSION) -and ($env:BUILD_SOURCEVERSION -ne "*")) {
#     $commit = ${env:BUILD_SOURCEVERSION}.substring(0,8)
# }
$outputFolderName = "adminToolBuildOutput"

Write-Host "----AVS-Automation-AdminTools: copying files to foler $outputFolderName ----"
New-Item -Path $repoRoot -Name "$outputFolderName" -ItemType "directory"
Copy-Item -Path "$repoRoot\powercli\scripts\*" -Destination "C:\Users\Administrator\Downloads\testCpIt" -Recurse