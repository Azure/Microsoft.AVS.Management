#!/usr/bin/pwsh

param (
    [Parameter(Mandatory=$true)][string]$manifestAbsolutePath,
    [switch]$IsPR = $false
)

Write-Output "----START: updateModuleVersion----"
Write-Output "Given path to manifest: $manifestAbsolutePath"
Get-Content "$manifestAbsolutePath"

$manifestVersionAsArray = (Import-PowerShellDataFile $manifestAbsolutePath).ModuleVersion -split "\."
$updatedModuleVersion = @( $manifestVersionAsArray[0], $manifestVersionAsArray[1],  $env:BUILD_BUILDNUMBER ) | Join-String -Separator '.'
Write-Output "---- Updating the module version to $updatedModuleVersion----"
$script:targetModuleParams = @{}

if($IsPR){
    Write-Host "Executing PR versioning"
    $targetModuleParams = @{ModuleVersion = "$updatedModuleVersion"; Prerelease = "-aPR"; Path = "$manifestAbsolutePath"}
}else{
    Write-Host "Executing official versioning"
    $targetModuleParams = @{ModuleVersion = "$updatedModuleVersion"; Path = "$manifestAbsolutePath"}
}

Update-ModuleManifest @targetModuleParams

if (!$?) {
    Write-Error -Message "FAILED: Could not update module version"
    Throw "Module version must be updated before proceeding with build."
    
}else {
    Write-Host "##vso[task.setvariable variable=moduleVersion]$updatedModuleVersion"
    Write-Output "---- SUCCEED: updated the module version to $((Import-PowerShellDataFile $manifestAbsolutePath).ModuleVersion)----"
    Get-Content "$manifestAbsolutePath"
}

Write-Output "----END: updateModuleVersion----"