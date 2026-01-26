#!/usr/bin/pwsh
param (
    [Parameter(Mandatory=$true)][string]$accessToken,
    [Parameter(Mandatory=$true)][string]$psdPath,
    [switch]$SkipPrereq
)

if (-not $SkipPrereq) {
    $requiredModules = @(
        @{ Name = "PSScriptAnalyzer"; Version = "1.21.0" }
        @{ Name = "Pester"; Version = "5.7.1" }
        @{ Name = "Microsoft.PowerShell.PSResourceGet"; Version = "1.2.0-rc1" }
    )
    foreach ($module in $requiredModules) {
        Write-Host "Installing $($module.Name)@$($module.Version) ...."
        Find-PSResource $module.Name -Version $module.Version -IncludeDependencies -Repository Consumption -Credential $c | Install-PSResource -Verbose -SkipDependencyCheck -Credential $c
    }

    & pwsh -NoProfile -File $PSCommandPath -accessToken $accessToken -psdPath $psdPath -SkipPrereq
    if( $LASTEXITCODE -ne 0 ) {
        throw "Failed to get required modules."
    }
}

import-module Microsoft.AVS.CDR

$c = [PSCredential]::new("ado", ($accessToken | ConvertTo-SecureString -AsPlainText -Force))
Install-PSResourceDependencies -ModulePath $psdPath -Repository ConsumptionV3 -Credential $c
