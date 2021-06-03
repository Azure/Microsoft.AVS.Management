#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$relativePathToManifest,
    [switch]$IsOfficial = $false
)
Write-Output "----START: updateModuleVersion----"
Write-Output "----IsOfficial: $IsOfficial----"

#Install all RequiredModules in the module manifests because the command Update-ModuleManifest 
# requires these modules to be on the host in order to run properly.
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$manifestAbsolutePath = Join-Path -Path "$repoRoot" -ChildPath "$relativePathToManifest"
$manifestFolder = (Split-Path "$manifestAbsolutePath")

Get-Content "$manifestAbsolutePath"
Write-Output "---- Updating the module version to $env:BUILD_BUILDNUMBER----"

Set-Location "$manifestFolder"
$targetModuleParams = @{ModuleVersion = "$env:BUILD_BUILDNUMBER"; Path = "$manifestAbsolutePath"}
Update-ModuleManifest @targetModuleParams
if (!$?) {
    Write-Error -Message "FAILED: Could not update module version"
    Throw "Module version must be updated before proceeding with build."
    
}else {
    Write-Output "---- SUCCEED: updated the module version to $env:BUILD_BUILDNUMBER----"
    Get-Content "$manifestAbsolutePath"
}
Write-Output "----END: updateModuleVersion----"