#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$absolutePathToManifest
)

Write-Output "----START: publishPreviewVersionToUnofficialFeed----"

#Append part of commit hash to Prerelease string
$prereleaseString = @( "-", "Preview", ((git log --pretty=oneline origin/main -1)[0..10] -join '')) | Join-String -Separator ''
$absolutePathToManifestFolder = (Split-Path "$absolutePathToManifest")

Get-Content "$absolutePathToManifest"
Write-Output "---- Updating the module version to $env:BUILD_BUILDNUMBER-$prereleaseString ----"

Set-Location "$absolutePathToManifestFolder"
$targetModuleParams = @{ModuleVersion = "$env:BUILD_BUILDNUMBER"; Prerelease = "$prereleaseString"; Path = "$manifestAbsolutePath"}
Update-ModuleManifest @targetModuleParams

if (!$?) {

    Write-Error -Message "FAILED: Could not update module version"
    Throw "Module version must be updated before proceeding with build."
    
}else {

    Write-Output "---- SUCCEED: updated the module version to $env:BUILD_BUILDNUMBER-$prereleaseString ----"
    Get-Content "$absolutePathToManifest"

}

Write-Output "----END: updateModuleVersion----"

# $feedParameters = @{
#         Name = "Unofficial-AVS-Automation-AdminTools"
#         SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
#         PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
#         InstallationPolicy = 'Trusted'
# }
$feedParameters = @{
        Name = "AVS-Automation-AdminTools"
        SourceLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v2"
        PublishLocation = "https://pkgs.dev.azure.com/mseng/AzureDevOps/_packaging/AVS-Automation-AdminTools/nuget/v2"
        InstallationPolicy = 'Trusted'
}
Write-Output "----Registering PSRepository ----"
Register-PSRepository @feedParameters
if (!$?) {
    Write-Error -Message "----ERROR: Unable to register repository----"
    Throw "Must be able to register feed before publishing to it"
}else {
    
    Write-Output "----SUCCEEDED: $($feedParameters.Name) repository registered ----"

Write-Output "Unofficial module published to $($feedParameters.Name)"
Publish-Module -Path "$absolutePathToManifestFolder" -Repository ($feedParameters).Name -NuGetApiKey "valueNotUsed"

if (!$?) {
        Write-Error -Message "----ERROR: Unable to publish module----"
        Throw "Could not publish $(Split-Path -Path "$absolutePathToManifestFolder" -Leaf) to unofficial feed."

}else {
            Write-Output "SUCCEEDED: module published"
}