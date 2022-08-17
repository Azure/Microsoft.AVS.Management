#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest
)

Write-Output "----START: publishPreviewVersionToUnofficialFeed----"

#Append part of commit hash to Prerelease string
$prereleaseString = "-preview"
$absolutePathToManifestFolder = (Split-Path "$absolutePathToManifest")

Get-Content "$absolutePathToManifest"
Write-Output "---- Updating the module version to preview version $env:BUILD_BUILDNUMBER-$prereleaseString ----"

$targetModuleParams = @{ModuleVersion = "$env:BUILD_BUILDNUMBER"; Prerelease = "$prereleaseString"; Path = "$absolutePathToManifest"}
Update-ModuleManifest @targetModuleParams

if (!$?) {

    Write-Error -Message "FAILED: Could not update module version"
    Throw "Module version must be updated before proceeding with build."
    
}else {

    Write-Output "---- SUCCEED: updated the module version to $((Import-PowerShellDataFile $absolutePathToManifest).ModuleVersion) ----"
    Get-Content "$absolutePathToManifest"

}

Write-Output "----END: updateModuleVersion----"

$feedParameters = @{
        Name = "Unofficial-AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
        InstallationPolicy = 'Trusted'
}
# $feedParameters = @{
#         Name = "AVS-Automation-AdminTools"
#         SourceLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v2"
#         PublishLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v2"
#         InstallationPolicy = 'Trusted'
# }

Write-Output "----Registering PSRepository ----"
Unregister-PSRepository -Name $feedParameters.Name -ErrorAction SilentlyContinue
Register-PSRepository @feedParameters
if (!$?) {
    Write-Error -Message "----ERROR: Unable to register repository----"
    Throw "Must be able to register feed before publishing to it"
}else {
    
    Write-Output "----SUCCEEDED: $($feedParameters.Name) repository registered ----"
}

Write-Output "Unofficial module published to $($feedParameters.Name)"
Publish-Module -Path "$absolutePathToManifestFolder" -Repository ($feedParameters).Name -NuGetApiKey "$env:UNOFFICIAL_FEED_NUGET_APIKEY"
# Publish-Module -Path "$absolutePathToManifestFolder" -Repository ($feedParameters).Name -NuGetApiKey "$env:MICROSOFT_AVS_MANAGEMENT_OFFICIAL_FEED_AND_RELEASES_PAT"

if (!$?) {
        Write-Error -Message "----ERROR: Unable to publish module----"
        Throw "Could not publish $(Split-Path -Path "$absolutePathToManifestFolder" -Leaf) to unofficial feed."

}else {
            Write-Output "SUCCEEDED: module published"
}