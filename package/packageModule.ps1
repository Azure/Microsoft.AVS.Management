#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$aboluteSrcFolderPath,
    [Parameter(Mandatory=$true)][string]$buildType
)
    
#### Declare all variables used
$artifactStagingRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"
$localFeedLocation = Join-Path -Path "$artifactStagingRoot" -ChildPath "LocalNugetFeed"
$localFeedParameters = @{}
$feedParameters = @{}
##################################

if ($buildType -eq 'official') {
    New-Item -ItemType Directory -Path "$localFeedLocation"
    $localFeedParameters = @{
        Name = 'Local-Feed'
        SourceLocation = "$localFeedLocation"
        PublishLocation = "$localFeedLocation"
        InstallationPolicy = 'Trusted'
    }
    Write-Output "Registering $(($localFeedParameters).Name)"
    Register-PSRepository @localFeedParameters
    if (!$?) {
        Write-Error -Message "----ERROR: Unable to register repository----"
        Throw "Must be able to register feed $(($localFeedParameters).Name) before publishing to it"
    }else {
        
        Write-Output "----SUCCEEDED: $(($localFeedParameters).Name) repository registered ----"
    }
    Write-Output "Contents of directory: $aboluteSrcFolderPath"
    Get-ChildItem "$aboluteSrcFolderPath"
    Remove-Item "$aboluteSrcFolderPath\CodeSignSummary*"
    Write-Output "Contents of directory after removing CodeSignSummary: $aboluteSrcFolderPath"
    Get-ChildItem "$aboluteSrcFolderPath"
    
}elseif ($buildType -eq 'unofficial') {
    $feedParameters = @{
        Name = "Unofficial-AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v3/index.json"
        PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v3/index.json"
        InstallationPolicy = 'Trusted'
    }
    Write-Output "----Registering PSRepository ----"
    Register-PSRepository @feedParameters
    if (!$?) {
        Write-Error -Message "----ERROR: Unable to register repository----"
        Throw "Must be able to register feed before publishing to it"
    }else {
        
        Write-Output "----SUCCEEDED: ($feedParameters).Name repository registered ----"
    }
}else {
    Write-Error -Message "----Error: Unsupported buildType: $buildType ----"
    Throw "The -buildType provided must be valid."
}

Write-Output "Currently Available repositories:"
Get-PSRepository

if (!(Test-Path "$aboluteSrcFolderPath")) {
    Write-Error "Error: Directory $aboluteSrcFolderPath does not exist!!"
    Throw "Source directory must be valid path"
}else{
    Write-Output "----Found module directory $aboluteSrcFolderPath ----"
}

Write-Output "Contents of directory: $aboluteSrcFolderPath"
Get-ChildItem "$aboluteSrcFolderPath"

Write-Host "----AVS-Automation-AdminTools: publishing $buildType build package ----"
if ($buildType -eq 'official') {
    Publish-Module -Path "$aboluteSrcFolderPath" -Repository $(($localFeedParameters).Name) -NuGetApiKey "valueNotUsed"

    Write-Output "Contents of directory: $localFeedLocation"
    Get-ChildItem "$localFeedLocation"

}else {
    Write-Output "Unofficial module published to ($feedParameters).Name"
    # Publish-Module -Path "$aboluteNewFolderPath" -Repository ($feedParameters).Name -NuGetApiKey "valueNotUsed"
    # if (!$?) {
        #     Write-Error -Message "----ERROR: Unable to publish module----" -ErrorAction Stop
        # }else {
            #     Write-Output "SUCCEEDED: module published"
            # }
}

Write-Host "----AVS-Automation-AdminTools: Modules successfully published----"