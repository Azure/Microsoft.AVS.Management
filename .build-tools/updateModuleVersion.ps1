#!/usr/bin/pwsh
#Install all RequiredModules in the module manifests because the command Update-ModuleManifest 
# requires these modules to be on the host to update properly.
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$artifactDirRoot = "$env:BUILD_ARTIFACTSTAGINGDIRECTORY"
$manifestFolder = (Join-Path "powercli" "Azure.AVSPowerCLI")
$manifestFile = "Azure.AVSPowerCLI.psd1"

$newModuleFolder = "Azure.AVSPowerCLI"
New-Item -Path "$artifactDirRoot" -Name "$newModuleFolder" -ItemType "directory"
$pathToNewModuleFolder = (Join-Path "$artifactDirRoot" "$newModuleFolder")
Copy-Item -Path "$repoRoot\$manifestFolder\*" -Destination "$pathToNewModuleFolder" -Recurse
$newPathToManifest = (Join-Path "$pathToNewModuleFolder" "$manifestFile")

Get-Content "$newPathToManifest"
Write-Output "---- Updating the module version to $env:BUILD_BUILDNUMBER----"
Set-Location "$pathToNewModuleFolder"
$targetModuleParams = @{ModuleVersion = "$env:BUILD_BUILDNUMBER"; Path = "$newPathToManifest"}
Update-ModuleManifest @targetModuleParams
Write-Output "---- SUCCESS: updated the module version to $env:BUILD_BUILDNUMBER----"
Get-Content "$newPathToManifest"
Set-Location "$repoRoot"