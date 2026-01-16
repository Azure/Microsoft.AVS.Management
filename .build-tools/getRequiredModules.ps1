#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$accessToken,
    [Parameter(Mandatory=$true)][string]$psdPath
)
$c =  [PSCredential]::new("ado", ($accessToken | ConvertTo-SecureString -AsPlainText -Force))
# https://github.com/PowerShell/PSResourceGet/issues/1777
Install-PSResource Microsoft.PowerShell.PSResourceGet -Version 1.2.0-rc1 -Prerelease -Repository ConsumptionV3 -Credential $c

$requiredModules = @((Test-ModuleManifest "$psdPath" -ErrorAction SilentlyContinue).RequiredModules | select -Property Name, Version)
$requiredModules += @(
    @{ Name = "PSScriptAnalyzer"; Version = "1.21.0" }
    @{ Name = "Pester"; Version = "5.7.1" }
)
foreach ($module in $requiredModules) {
    Write-Host "Installing $($module.Name)@$($module.Version) ...."
    Find-PSResource $module.Name -Version $module.Version -IncludeDependencies -Repository Consumption -Credential $c | Install-PSResource -Verbose -SkipDependencyCheck -Credential $c
}