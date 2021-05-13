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
    Install-Module $targetModule -RequiredVersion $targetVersion
    Write-Host "----COMPLETED installation of $targetModule-$targetVersion----"
}

Install-Module -Name "PSScriptAnalyzer" -RequiredVersion 1.19.1 -Force
Write-Host "----SUCCESS: installed all required modules----"