#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$absoluteSrcFolderPath,
    [Parameter(Mandatory=$true)][string]$buildType
)
    
#### Declare all variables used
$feedParameters = @{}
##################################

if ($buildType -eq 'official') {
    Write-Output "Contents of directory: $absoluteSrcFolderPath"
    Get-ChildItem "$absoluteSrcFolderPath"
    Remove-Item "$absoluteSrcFolderPath\CodeSignSummary*"
    Write-Output "Contents of directory after removing CodeSignSummary: $absoluteSrcFolderPath"
    Get-ChildItem "$absoluteSrcFolderPath"
    
}elseif ($buildType -eq 'unofficial') {
    $feedParameters = @{
        Name = "Unofficial-AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        InstallationPolicy = 'Trusted'
    }
    Write-Output "----Registering PSRepository ----"
    Register-PSRepository @feedParameters
    if (!$?) {
        Write-Error -Message "----ERROR: Unable to register repository----"
        Throw "Must be able to register feed before publishing to it"
    }else {
        
        Write-Output "----SUCCEEDED: $($feedParameters.Name) repository registered ----"
    }
}else {
    Write-Error -Message "----Error: Unsupported buildType: $buildType ----"
    Throw "The -buildType provided must be valid."
}

Write-Output "Currently Available repositories:"
Get-PSRepository

if (!(Test-Path "$absoluteSrcFolderPath")) {
    Write-Error "Error: Directory $absoluteSrcFolderPath does not exist!!"
    Throw "Source directory must be valid path"
}else{
    Write-Output "----Found module directory $absoluteSrcFolderPath ----"
}

Write-Output "Contents of directory: $absoluteSrcFolderPath"
Get-ChildItem "$absoluteSrcFolderPath"

Write-Host "----AVS-Automation-AdminTools: publishing $buildType build package ----"
if ($buildType -eq 'official') {
    Write-Output "----- PAUSED PUBLISHING TO PSGALLERY-----"
    #Publish-Module -Path "$absoluteSrcFolderPath" -NuGetApiKey "$env:AVS_PSGALLERY_APIKEY"
    if (!$?) {
            Write-Error -Message "----ERROR: Unable to publish module----"
            Throw "Could not publish $(Split-Path -Path "$absoluteSrcFolderPath" -Leaf) to PSGallery."
    }else {
                Write-Output "----AVS-Automation-AdminTools: $(Split-Path -Path "$absoluteSrcFolderPath" -Leaf) package published to PSGallery----"
    }
    
    Write-Output "Contents of directory: $localFeedLocation"
    Get-ChildItem "$localFeedLocation"

}else {
    Write-Output "Unofficial module published to $($feedParameters.Name)"
    Publish-Module -Path "$absoluteSrcFolderPath" -Repository ($feedParameters).Name -NuGetApiKey "valueNotUsed"
    if (!$?) {
            Write-Error -Message "----ERROR: Unable to publish module----"
            Throw "Could not publish $(Split-Path -Path "$absoluteSrcFolderPath" -Leaf) to unofficial feed."

    }else {
                Write-Output "SUCCEEDED: module published"
    }
}

Write-Host "----AVS-Automation-AdminTools: $(Split-Path -Path "$absoluteSrcFolderPath" -Leaf) nuget package deposited----"
