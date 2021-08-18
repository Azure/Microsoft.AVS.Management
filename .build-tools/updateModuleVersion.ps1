#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$manifestAbsolutePath,
    [switch]$IsPR = $false
)

Write-Output "----START: updateModuleVersion----"
$manifestFolder = (Split-Path "$manifestAbsolutePath")
Get-Content "$manifestAbsolutePath"
Write-Output "---- Updating the module version to $env:BUILD_BUILDNUMBER----"
$targetModuleParams = @{}

if($IsPR){
    $targetModuleParams = @{ModuleVersion = "$env:BUILD_BUILDNUMBER"; Prerelease = "-aPR"; Path = "$manifestAbsolutePath"}

}else{
    $targetModuleParams = @{ModuleVersion = "$env:BUILD_BUILDNUMBER"; Path = "$manifestAbsolutePath"}

}

Update-ModuleManifest @targetModuleParams

if (!$?) {
    Write-Error -Message "FAILED: Could not update module version"
    Throw "Module version must be updated before proceeding with build."
    
}else {
    Write-Output "---- SUCCEED: updated the module version to $((Import-PowerShellDataFile $absolutePathToManifest).ModuleVersion)----"
    Get-Content "$manifestAbsolutePath"

}

Write-Output "----END: updateModuleVersion----"