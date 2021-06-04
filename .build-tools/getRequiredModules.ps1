#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$psdPath
)
$feedParameters = @{
    Name = "Unofficial-AVS-Automation-AdminTools"
    SourceLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
    PublishLocation = "https://pkgs.dev.azure.com/avs-oss/Public/_packaging/Unofficial-AVS-Automation-AdminTools/nuget/v2"
    InstallationPolicy = 'Trusted'
}
Write-Output "Running Get-PackageProviders:"
Get-PackageProvider
Get-Package

$requiredModules = (Test-ModuleManifest "$psdPath" -ErrorAction SilentlyContinue).RequiredModules
Register-PSRepository @feedParameters
Set-PSRepository -Name "$($feedParameters.Name)" -InstallationPolicy Trusted

foreach ($module in $requiredModules) {
    $targetModule = $($module.Name)
    $targetVersion = $($module.Version)
    Write-Host "Installing $targetModule-$targetVersion ...."
    Install-Module "$targetModule" -RequiredVersion $targetVersion -Repository "$($feedParameters.Name)" | Format-Table *
    Write-Host "----COMPLETED installation of $targetModule-$targetVersion----"
}


Write-Host "----SUCCESS: installed all required modules----"