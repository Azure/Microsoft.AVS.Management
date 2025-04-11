#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$accessToken,
    [Parameter(Mandatory=$true)][string]$psdPath
)
$c =  [PSCredential]::new("ado", ($accessToken | ConvertTo-SecureString -AsPlainText -Force))
# https://github.com/PowerShell/PSResourceGet/issues/1777
Install-Module Microsoft.PowerShell.PSResourceGet -requiredversion 1.1.1 -Repository Consumption -Credential $c -Force -SkipPublisherCheck

$requiredModules = (Test-ModuleManifest "$psdPath" -ErrorAction SilentlyContinue).RequiredModules
foreach ($module in $requiredModules) {
    $targetModule = $($module.Name)
    $targetVersion = $($module.Version)
    Write-Host "Installing $targetModule-$targetVersion ...."
    Install-Module $targetModule -RequiredVersion $targetVersion -Repository Consumption -Credential $c
}

Install-Module PSScriptAnalyzer -RequiredVersion 1.21.0 -Repository Consumption -Credential $c
Install-Module Pester -SkipPublisherCheck -MinimumVersion 5.0 -Repository Consumption -Credential $c
