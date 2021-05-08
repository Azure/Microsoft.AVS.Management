#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$srcFolder,
    [Parameter(Mandatory=$true)][string]$newModuleFolder,
    [Parameter(Mandatory=$true)][string]$buildType

)
# $nugetSource = switch ($buildType) {
#     'official' { "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v3/index.json" }
#     Default {'https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v3/index.json'}
# }
$feedParameters = @{}
if ($buildType -eq 'official') {
    $feedParameters = @{
        Name = "AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v3/index.json"
        PublishLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v3/index.json"
        InstallationPolicy = 'Trusted'
    }
}elseif ($buildType -eq 'unofficial') {
    $feedParameters = @{
        Name = "Unofficial-AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v3/index.json"
        PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v3/index.json"
        InstallationPolicy = 'Trusted'
    }
}else {
    Write-Error -Message "----Error: Unsupported buildType: $buildType----" -ErrorAction Stop
}
Write-Output "feed parameters:"
Write-Output "$feedParameters"
Write-Output "----Registering PSRepository ----"
Register-PSRepository @feedParameters
if (!$?) {
    Write-Error -Message "----ERROR: Unable to register repository----" -ErrorAction Stop
}else {
    
    Write-Output "----SUCCEEDED: repository registered ----"
}

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
# $manifestFiles = (Get-ChildItem "$aboluteNewFolderPath\*" -Include "*.psd1")
Write-Output "Contents of new directory: $aboluteNewFolderPath"
Get-ChildItem "$aboluteNewFolderPath"
# $manifestFile = ""
# if (($manifestFiles).Count -gt 0) {
#     $manifestFile = $manifestFiles[0].FullName
# }else {
#     Write-Error -Message "----Packaging Failed: No manifest file found----" -ErrorAction Stop
# }
# Set-Location "$aboluteNewFolderPath"
# Get-Content "$manifestFile"
Write-Host "----AVS-Automation-AdminTools: publishing $buildType build package ----"
Publish-Module -Path "$aboluteNewFolderPath" -Repository ($feedParameters).Name
if (!$?) {
    Write-Error -Message "----ERROR: Unable to publish module----" -ErrorAction Stop
}else {
    Write-Output "SUCCEEDED: module published"
}
# $nugetFileName = (Get-ChildItem "$manifestFile").BaseName
# nuget spec "$nugetFileName"
# nuget pack "$($nugetFileName).nuspec" -NonInteractive -Version "$env:BUILD_BUILDNUMBER"
Write-Host "----AVS-Automation-AdminTools: Azure.AVSPowerCLI nuget package deposited----"

Get-Content "$manifestFile"