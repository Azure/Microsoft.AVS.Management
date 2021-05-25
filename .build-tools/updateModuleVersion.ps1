#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$relativePathToManifest,
    [switch]$IsOfficial = $false
)
Write-Output "----START: updateModuleVersion----"
#Install all RequiredModules in the module manifests because the command Update-ModuleManifest 
# requires these modules to be on the host in order to run properly.
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$manifestAbsolutePath = Join-Path -Path "$repoRoot" -ChildPath "$relativePathToManifest"
$manifestFolder = (Split-Path "$manifestAbsolutePath")

Get-Content "$manifestAbsolutePath"
Write-Output "---- Updating the module version to $env:BUILD_BUILDNUMBER----"

Set-Location "$manifestFolder"
$targetModuleParams = @{}
if (!$IsOfficial) {
    $extModuleArray = @()
    $requiredModules = (Test-ModuleManifest "$manifestAbsolutePath" -ErrorAction SilentlyContinue).RequiredModules
    foreach ($module in $requiredModules) {
        $extModuleArray += $($module.Name)
    }
    $targetModuleParams = @{ModuleVersion = "$env:BUILD_BUILDNUMBER"; ExternalModuleDependencies = $extModuleArray ; Path = "$manifestAbsolutePath"}
    
}else {
    $targetModuleParams = @{ModuleVersion = "$env:BUILD_BUILDNUMBER"; Path = "$manifestAbsolutePath"}
}
Update-ModuleManifest @targetModuleParams
if (!$?) {
    Write-Error -Message "FAILED: Could not update module version" -ErrorAction Stop
    
}else {
    Write-Output "---- SUCCEED: updated the module version to $env:BUILD_BUILDNUMBER----"
    Get-Content "$manifestAbsolutePath"
}
Write-Output "----END: updateModuleVersion----"