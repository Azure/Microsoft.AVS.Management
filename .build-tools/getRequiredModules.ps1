#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$psdPath
)
$requiredModules = (Test-ModuleManifest "$psdPath" -ErrorAction SilentlyContinue).RequiredModules
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

foreach ($module in $requiredModules) {
    $targetModule = $($module.Name)
    $targetVersion = $($module.Version)
    Write-Host "Installing $targetModule-$targetVersion ...."
    Install-Module $targetModule -RequiredVersion $targetVersion -Repository PSGallery
    Write-Host "----COMPLETED installation of $targetModule-$targetVersion----"
}


Write-Host "----SUCCESS: installed all required modules----"