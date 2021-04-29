#!/usr/bin/pwsh
#Install all RequiredModules in the module manifests because the command Update-ModuleManifest 
# requires these modules to be on the host to update properly.
$repoRoot = "$env:SYSTEM_DEFAULTWORKINGDIRECTORY"
$manifestFolder = (Join-Path "powercli" "Azure.AVSPowerCLI")
$manifestFile = "Azure.AVSPowerCLI.psd1"
$pathToManifest = (Join-Path "$repoRoot" "$manifestFolder" "$manifestFile")

Write-Output "---- Updating the module version to $env:BUILD_BUILDNUMBER----"
$targetModuleParams = @{ModuleVersion = "$env:BUILD_BUILDNUMBER"; Path = "$pathToManifest"}
Update-ModuleManifest @targetModuleParams
Write-Output "---- SUCCESS: updated the module version to $env:BUILD_BUILDNUMBER----"